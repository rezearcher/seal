/**
 * Tests for seal-vpe: signing, verification, tamper detection.
 * Mirrors the Python test suite at ~/projects/seal/tests/test_core.py
 */

import * as crypto from 'crypto';
import {
  VPE_VERSION,
  ENVELOPE_FIELDS,
  generateKeyPair,
  canonicalJson,
  vpeSign,
  vpeVerify,
  vpeSignHmac,
  vpeVerifyHmac,
  NonceStore,
} from '../src/index';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const HMAC_SECRET=Buffer.from('donkeykong_test_secret_2026');

function makeEnvelope(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const base: Record<string, unknown> = {
    vpe_version: '1.0',
    prompt: 'hello',
    scope: {},
    issuer: '',
    audience: '',
    doc_sha256: '',
    ttl_seconds: 300,
    nonce: 'abc',
    counter: null,
    cert_chain: null,
  };
  return { ...base, ...overrides };
}

// ---------------------------------------------------------------------------
// Canonical JSON serialisation
// ---------------------------------------------------------------------------

describe('CanonicalJSON', () => {
  test('compact no whitespace', () => {
    const env = makeEnvelope();
    const raw = canonicalJson(env).toString('utf-8');
    expect(raw).not.toContain(' ');
    expect(raw).not.toContain('\n');
    expect(raw).not.toContain(': ');
    expect(raw).not.toContain(', ');
  });

  test('deterministic', () => {
    const env = makeEnvelope();
    expect(canonicalJson(env)).toEqual(canonicalJson(env));
  });

  test('field ordering', () => {
    const env = makeEnvelope();
    const raw = canonicalJson(env).toString('utf-8');
    const topKeys = Object.keys(JSON.parse(raw));
    const expected = ENVELOPE_FIELDS.filter(
      (f: any) => f !== 'cert_chain',
    );
    expect(topKeys).toEqual(expected);
  });

  test('field ordering with cert_chain', () => {
    const env = makeEnvelope({ cert_chain: [{ subject_id: "leaf" }] });
    const raw = canonicalJson(env).toString('utf-8');
    const topKeys = Object.keys(JSON.parse(raw));
    const expected = [...ENVELOPE_FIELDS];
    expect(topKeys).toEqual(expected);
  });

  test('scope keys sorted', () => {
    const env = makeEnvelope({ scope: { z: 1, a: 2, m: 3 } });
    const raw = canonicalJson(env).toString('utf-8');
    const parsed = JSON.parse(raw);
    expect(JSON.stringify(parsed.scope)).toBe('{"a":2,"m":3,"z":1}');
  });

  test('cert_chain included when present', () => {
    const env = makeEnvelope({ cert_chain: [{ subject_id: "leaf" }] });
    const raw = canonicalJson(env).toString('utf-8');
    expect(raw).toContain("cert_chain");
  });

  test('cert_chain omitted when null', () => {
    const env = makeEnvelope({ cert_chain: null });
    const raw = canonicalJson(env).toString('utf-8');
    expect(raw).not.toContain("cert_chain");
  });

  test('missing keys resolve to defaults', () => {
    const env: Record<string, unknown> = { prompt: 'hello' };
    const raw = canonicalJson(env).toString('utf-8');
    expect(raw).toContain('"prompt"');
    expect(raw).toContain('"scope"');
    expect(raw).toContain('"nonce"');
  });

  test('counter null produces null', () => {
    const env = makeEnvelope({ counter: null });
    const raw = canonicalJson(env).toString('utf-8');
    expect(raw).toContain('"counter":null');
  });

  test('compact lightweight overhead', () => {
    const testCases: [number, number][] = [[1, 200], [50, 250]];
    for (const [plen, expectedMax] of testCases) {
      const env = makeEnvelope({ prompt: 'X'.repeat(plen) });
      const overhead = canonicalJson(env).length;
      expect(overhead).toBeLessThan(expectedMax);
    }
  });
});

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

describe('KeyGeneration', () => {
  test('generates 32 byte keys', () => {
    const keys = generateKeyPair();
    expect(keys.privateKey).toHaveLength(32);
    expect(keys.publicKey).toHaveLength(32);
  });

  test('keys are different', () => {
    const keys = generateKeyPair();
    expect(keys.privateKey).not.toEqual(keys.publicKey);
  });

  test('consecutive calls differ', () => {
    const a = generateKeyPair();
    const b = generateKeyPair();
    expect(a.privateKey).not.toEqual(b.privateKey);
    expect(a.publicKey).not.toEqual(b.publicKey);
  });
});

// ---------------------------------------------------------------------------
// Basic signing (Ed25519)
// ---------------------------------------------------------------------------

describe('Signing', () => {
  let keys: ReturnType<typeof generateKeyPair>;
  beforeEach(() => {
    keys = generateKeyPair();
  });

  test('sign returns JSON string', () => {
    const env = vpeSign('hello', { privateKey: keys.privateKey });
    expect(typeof env).toBe('string');
  });

  test('envelope contains all fields', () => {
    const env = vpeSign('hello', { privateKey: keys.privateKey });
    const data = JSON.parse(env);
    const expected = new Set([
      'vpe_version', 'prompt', 'scope', 'issuer', 'audience',
      'doc_sha256', 'iat', 'ttl_seconds', 'nonce', 'counter',
      'cert_chain', 'signature',
    ]);
    expect(new Set(Object.keys(data))).toEqual(expected);
  });

  test('version is current', () => {
    const env = JSON.parse(vpeSign('hello', { privateKey: keys.privateKey }));
    expect(env.vpe_version).toBe(VPE_VERSION);
  });

  test('signature is hex string', () => {
    const env = JSON.parse(vpeSign('hello', { privateKey: keys.privateKey }));
    const sig = env.signature as string;
    expect(typeof sig).toBe('string');
    expect(/^[0-9a-f]+$/.test(sig)).toBe(true);
  });

  test('signature is 64 bytes (128 hex chars)', () => {
    const env = JSON.parse(vpeSign('hello', { privateKey: keys.privateKey }));
    const sig = env.signature as string;
    expect(sig).toHaveLength(128);
  });

  test('prompt is preserved', () => {
    const env = JSON.parse(vpeSign('my specific prompt', { privateKey: keys.privateKey }));
    expect(env.prompt).toBe('my specific prompt');
  });

  test('scope is preserved', () => {
    const scope = { allowed_tools: ['search', 'read_file'] };
    const env = JSON.parse(vpeSign('test', { scope, privateKey: keys.privateKey }));
    expect(env.scope).toEqual(scope);
  });

  test('different prompts different signatures', () => {
    const e1 = JSON.parse(vpeSign('hello', { privateKey: keys.privateKey }));
    const e2 = JSON.parse(vpeSign('world', { privateKey: keys.privateKey }));
    expect(e1.signature).not.toBe(e2.signature);
  });

  test('different nonces different signatures same prompt', () => {
    const e1 = JSON.parse(vpeSign('hello', { nonce: 'abc', privateKey: keys.privateKey }));
    const e2 = JSON.parse(vpeSign('hello', { nonce: 'xyz', privateKey: keys.privateKey }));
    expect(e1.signature).not.toBe(e2.signature);
  });

  test('auto generates nonce', () => {
    const env = JSON.parse(vpeSign('hello', { privateKey: keys.privateKey }));
    expect((env.nonce as string).length).toBeGreaterThan(0);
  });

  test('empty prompt allowed', () => {
    const env = JSON.parse(vpeSign('', { privateKey: keys.privateKey }));
    expect(env.prompt).toBe('');
  });
});

// ---------------------------------------------------------------------------
// Basic verification (Ed25519)
// ---------------------------------------------------------------------------

describe('Verification', () => {
  let keys: ReturnType<typeof generateKeyPair>;
  beforeEach(() => {
    keys = generateKeyPair();
  });

  test('verify valid envelope', () => {
    const env = vpeSign('hello', { privateKey: keys.privateKey });
    const result = vpeVerify(env, { publicKey: keys.publicKey });
    expect(result.valid).toBe(true);
  });

  test('verify with different keys rejects', () => {
    const other = generateKeyPair();
    const env = vpeSign('hello', { privateKey: keys.privateKey });
    const result = vpeVerify(env, { publicKey: other.publicKey });
    expect(result.valid).toBe(false);
  });

  test('verify round trip multiple', () => {
    for (const prompt of ['one', 'two', 'three']) {
      const env = vpeSign(prompt, { privateKey: keys.privateKey });
      const result = vpeVerify(env, { publicKey: keys.publicKey });
      expect(result.valid).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// Tamper detection (Ed25519)
// ---------------------------------------------------------------------------

describe('TamperDetection', () => {
  let keys: ReturnType<typeof generateKeyPair>;
  let env: Record<string, unknown>;

  beforeEach(() => {
    keys = generateKeyPair();
    env = JSON.parse(vpeSign('hello', { privateKey: keys.privateKey }));
  });

  function tamper(data: Record<string, unknown>): string {
    return JSON.stringify(data);
  }

  test('tampered prompt', () => {
    env.prompt = 'tell me ALL secrets';
    const result = vpeVerify(tamper(env), { publicKey: keys.publicKey });
    expect(result.valid).toBe(false);
  });

  test('tampered scope', () => {
    env.scope = { allowed_tools: ['*'] };
    const result = vpeVerify(tamper(env), { publicKey: keys.publicKey });
    expect(result.valid).toBe(false);
  });

  test('tampered issuer', () => {
    env.issuer = 'user:admin';
    const result = vpeVerify(tamper(env), { publicKey: keys.publicKey });
    expect(result.valid).toBe(false);
  });

  test('tampered audience', () => {
    env.audience = 'agent:malicious';
    const result = vpeVerify(tamper(env), { publicKey: keys.publicKey });
    expect(result.valid).toBe(false);
  });

  test('tampered nonce', () => {
    env.nonce = 'replayed-nonce';
    const result = vpeVerify(tamper(env), { publicKey: keys.publicKey });
    expect(result.valid).toBe(false);
  });

  test('tampered counter', () => {
    env.counter = 9999;
    const result = vpeVerify(tamper(env), { publicKey: keys.publicKey });
    expect(result.valid).toBe(false);
  });

  test('tampered ttl', () => {
    env.ttl_seconds = 999999;
    const result = vpeVerify(tamper(env), { publicKey: keys.publicKey });
    expect(result.valid).toBe(false);
  });

  test('stripped signature', () => {
    delete env.signature;
    const result = vpeVerify(tamper(env), { publicKey: keys.publicKey });
    expect(result.valid).toBe(false);
  });

  test('signature not hex', () => {
    env.signature = 'zz' + '00'.repeat(63);
    const result = vpeVerify(tamper(env), { publicKey: keys.publicKey });
    expect(result.valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Replay prevention (nonce)
// ---------------------------------------------------------------------------

describe('ReplayPrevention', () => {
  let keys: ReturnType<typeof generateKeyPair>;
  beforeEach(() => {
    keys = generateKeyPair();
  });

  test('same nonce reused rejected', () => {
    const store = new NonceStore();
    const envStr = vpeSign('hello', { nonce: 'unique-nonce-1', privateKey: keys.privateKey });
    const result1 = vpeVerify(envStr, { publicKey: keys.publicKey, nonceStore: store });
    expect(result1.valid).toBe(true);
    expect(result1.reason).toBe('ok');
    const result2 = vpeVerify(envStr, { publicKey: keys.publicKey, nonceStore: store });
    expect(result2.valid).toBe(false);
    expect(result2.reason).toBe('nonce_reused');
  });

  test('different nonces both ok', () => {
    const store = new NonceStore();
    const env1 = vpeSign('hello', { nonce: 'nonce-a', privateKey: keys.privateKey });
    const env2 = vpeSign('hello', { nonce: 'nonce-b', privateKey: keys.privateKey });
    expect(vpeVerify(env1, { publicKey: keys.publicKey, nonceStore: store }).valid).toBe(true);
    expect(vpeVerify(env2, { publicKey: keys.publicKey, nonceStore: store }).valid).toBe(true);
  });

  test('no nonce store skips replay check', () => {
    const env = vpeSign('hello', { nonce: 'compat-nonce', privateKey: keys.privateKey });
    expect(vpeVerify(env, { publicKey: keys.publicKey }).valid).toBe(true);
    expect(vpeVerify(env, { publicKey: keys.publicKey }).valid).toBe(true);
  });

  test('ttl zero skips replay check', () => {
    const store = new NonceStore();
    const env = vpeSign('hello', { nonce: 'ttlzero-nonce', ttlSeconds: 0, privateKey: keys.privateKey });
    expect(vpeVerify(env, { publicKey: keys.publicKey, nonceStore: store }).valid).toBe(true);
    expect(vpeVerify(env, { publicKey: keys.publicKey, nonceStore: store }).valid).toBe(true);
  });

  test('missing nonce rejected', () => {
    const envParsed = JSON.parse(vpeSign('hello', { privateKey: keys.privateKey }));
    delete envParsed.nonce;
    const result = vpeVerify(JSON.stringify(envParsed), { publicKey: keys.publicKey });
    expect(result.valid).toBe(false);
  });

  test('empty nonce rejected', () => {
    const env = vpeSign('hello', { nonce: '', privateKey: keys.privateKey });
    const result = vpeVerify(env, { publicKey: keys.publicKey });
    expect(result.valid).toBe(false);
  });

  test('nonce is string', () => {
    const env = JSON.parse(vpeSign('hello', { nonce: 'abc', privateKey: keys.privateKey }));
    expect(typeof env.nonce).toBe('string');
  });
});

// ---------------------------------------------------------------------------
// Counter
// ---------------------------------------------------------------------------

describe('Counter', () => {
  let keys: ReturnType<typeof generateKeyPair>;
  beforeEach(() => {
    keys = generateKeyPair();
  });

  test('counter accepted when present', () => {
    const env = vpeSign('hello', { counter: 42, privateKey: keys.privateKey });
    const result = vpeVerify(env, { publicKey: keys.publicKey });
    expect(result.valid).toBe(true);
  });

  test('counter optional', () => {
    const env = vpeSign('hello', { privateKey: keys.privateKey });
    const result = vpeVerify(env, { publicKey: keys.publicKey });
    expect(result.valid).toBe(true);
  });

  test('counter tampered', () => {
    const envParsed = JSON.parse(vpeSign('hello', { counter: 42, privateKey: keys.privateKey }));
    envParsed.counter = 99;
    const result = vpeVerify(JSON.stringify(envParsed), { publicKey: keys.publicKey });
    expect(result.valid).toBe(false);
  });

  test('counter non integer rejected', () => {
    const envParsed = JSON.parse(vpeSign('hello', { counter: 42, privateKey: keys.privateKey }));
    envParsed.counter = 'not-an-int';
    const result = vpeVerify(JSON.stringify(envParsed), { publicKey: keys.publicKey });
    expect(result.valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

describe('ScopeVerification', () => {
  let keys: ReturnType<typeof generateKeyPair>;
  beforeEach(() => {
    keys = generateKeyPair();
  });

  test('scope must be dict', () => {
    const envParsed = JSON.parse(vpeSign('hello', { scope: { a: 1 }, privateKey: keys.privateKey }));
    envParsed.scope = 'not-a-dict';
    const result = vpeVerify(JSON.stringify(envParsed), { publicKey: keys.publicKey });
    expect(result.valid).toBe(false);
  });

  test('scope verifies when valid', () => {
    const scope = { allowed_tools: ['read_file'] };
    const env = vpeSign('hello', { scope, privateKey: keys.privateKey });
    const result = vpeVerify(env, { publicKey: keys.publicKey });
    expect(result.valid).toBe(true);
  });

  test('empty scope allowed', () => {
    const env = vpeSign('hello', { scope: {}, privateKey: keys.privateKey });
    const result = vpeVerify(env, { publicKey: keys.publicKey });
    expect(result.valid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Scope & field escalation attacks
// ---------------------------------------------------------------------------

describe('ScopeEscalation', () => {
  let keys: ReturnType<typeof generateKeyPair>;
  let env: Record<string, unknown>;

  beforeEach(() => {
    keys = generateKeyPair();
    env = JSON.parse(
      vpeSign('search for customer X',
        {
          scope: { allowed_tools: ['search'], max_tokens: 2000 },
          issuer: 'user:alice',
          audience: 'agent:hermes-default',
          ttlSeconds: 300,
          privateKey: keys.privateKey,
        },
      ),
    );
  });

  function tamper(data: Record<string, unknown>): string {
    return JSON.stringify(data);
  }

  function verify(tamperedStr: string): ReturnType<typeof vpeVerify> {
    return vpeVerify(tamperedStr, { publicKey: keys.publicKey });
  }

  test('scope entirely replaced after signing', () => {
    env.scope = { allowed_tools: ['*'] };
    expect(verify(tamper(env)).valid).toBe(false);
  });

  test('scope restrictions removed emptied', () => {
    env.scope = {};
    expect(verify(tamper(env)).valid).toBe(false);
  });

  test('scope allowed_tools popped', () => {
    env.scope = { allowed_tools: [] };
    expect(verify(tamper(env)).valid).toBe(false);
  });

  test('scope max_tokens inflated', () => {
    env.scope = { allowed_tools: ['search'], max_tokens: 999999 };
    expect(verify(tamper(env)).valid).toBe(false);
  });

  test('scope extra domains injected', () => {
    (env.scope as Record<string, unknown>).allowed_domains = ['*.evil.com'];
    expect(verify(tamper(env)).valid).toBe(false);
  });

  test('scope as null', () => {
    env.scope = null;
    expect(verify(tamper(env)).valid).toBe(false);
  });

  test('scope as list', () => {
    env.scope = [1, 2, 3];
    expect(verify(tamper(env)).valid).toBe(false);
  });

  test('extra tools appended', () => {
    (env.scope as Record<string, unknown>).allowed_tools = ['search', 'delete_all'];
    expect(verify(tamper(env)).valid).toBe(false);
  });

  test('extra tools prepended', () => {
    (env.scope as Record<string, unknown>).allowed_tools = ['delete_all', 'search'];
    expect(verify(tamper(env)).valid).toBe(false);
  });

  test('all wildcard tools', () => {
    (env.scope as Record<string, unknown>).allowed_tools = ['*'];
    expect(verify(tamper(env)).valid).toBe(false);
  });

  test('ttl extended long', () => {
    env.ttl_seconds = 86400 * 365;
    expect(verify(tamper(env)).valid).toBe(false);
  });

  test('ttl extended to infinite', () => {
    env.ttl_seconds = 0;
    expect(verify(tamper(env)).valid).toBe(false);
  });

  test('ttl extended negative', () => {
    env.ttl_seconds = -1;
    expect(verify(tamper(env)).valid).toBe(false);
  });

  test('audience redirected', () => {
    env.audience = 'agent:malicious-actor';
    expect(verify(tamper(env)).valid).toBe(false);
  });

  test('issuer spoofed', () => {
    env.issuer = 'user:admin';
    expect(verify(tamper(env)).valid).toBe(false);
  });

  test('audience and issuer swapped', () => {
    [env.audience, env.issuer] = [env.issuer, env.audience];
    expect(verify(tamper(env)).valid).toBe(false);
  });

  test('multi field escalation', () => {
    env.scope = { allowed_tools: ['*'] };
    env.ttl_seconds = 999999;
    env.audience = 'agent:eve';
    env.issuer = 'user:eve';
    expect(verify(tamper(env)).valid).toBe(false);
  });

  test('scope cert_chain injected', () => {
    env.cert_chain = [
      { subject_id: 'ca:attacker-root', subject_public_key: '00'.repeat(32), issuer_id: 'ca:attacker-root', issuer_public_key: '00'.repeat(32) },
    ];
    expect(verify(tamper(env)).valid).toBe(false);
  });

  test('doc_sha256 rewritten', () => {
    env.doc_sha256 = 'deadbeef'.repeat(8);
    expect(verify(tamper(env)).valid).toBe(false);
  });

  test('vpe_version downgrade', () => {
    env.vpe_version = '0.1';
    expect(verify(tamper(env)).valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// TTL
// ---------------------------------------------------------------------------

describe('TTL', () => {
  let keys: ReturnType<typeof generateKeyPair>;
  beforeEach(() => {
    keys = generateKeyPair();
  });

  test('ttl zero means no expiry', () => {
    const env = vpeSign('hello', { ttlSeconds: 0, privateKey: keys.privateKey });
    const result = vpeVerify(env, { publicKey: keys.publicKey });
    expect(result.valid).toBe(true);
  });

  test('ttl preserved in envelope', () => {
    const env = JSON.parse(vpeSign('hello', { ttlSeconds: 120, privateKey: keys.privateKey }));
    expect(env.ttl_seconds).toBe(120);
  });

  test('ttl non integer rejected', () => {
    const envParsed = JSON.parse(vpeSign('hello', { ttlSeconds: 120, privateKey: keys.privateKey }));
    envParsed.ttl_seconds = 'not-an-int';
    const result = vpeVerify(JSON.stringify(envParsed), { publicKey: keys.publicKey });
    expect(result.valid).toBe(false);
  });

  test('default ttl is 300', () => {
    const env = JSON.parse(vpeSign('hello', { privateKey: keys.privateKey }));
    expect(env.ttl_seconds).toBe(300);
  });
});

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

describe('EdgeCases', () => {
  let keys: ReturnType<typeof generateKeyPair>;
  beforeEach(() => {
    keys = generateKeyPair();
  });

  test('invalid json', () => {
    const result = vpeVerify('not json', { publicKey: keys.publicKey });
    expect(result.valid).toBe(false);
  });

  test('json not dict', () => {
    const result = vpeVerify('[]', { publicKey: keys.publicKey });
    expect(result.valid).toBe(false);
  });

  test('wrong version', () => {
    const envParsed = JSON.parse(vpeSign('hello', { privateKey: keys.privateKey }));
    envParsed.vpe_version = '0.9';
    const result = vpeVerify(JSON.stringify(envParsed), { publicKey: keys.publicKey });
    expect(result.valid).toBe(false);
  });

  test('missing signature field', () => {
    const envParsed = JSON.parse(vpeSign('hello', { privateKey: keys.privateKey }));
    delete envParsed.signature;
    const result = vpeVerify(JSON.stringify(envParsed), { publicKey: keys.publicKey });
    expect(result.valid).toBe(false);
  });

  test('long prompt round trip', () => {
    const prompt = 'A'.repeat(100_000);
    const env = vpeSign(prompt, { privateKey: keys.privateKey });
    const result = vpeVerify(env, { publicKey: keys.publicKey });
    expect(result.valid).toBe(true);
  });

  test('unicode prompt', () => {
    const prompt = '\u65e5\u672c\u8a9e \u{1F680}';
    const env = vpeSign(prompt, { privateKey: keys.privateKey });
    const result = vpeVerify(env, { publicKey: keys.publicKey });
    expect(result.valid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Key time constraints (not_before / not_after)
// ---------------------------------------------------------------------------

describe('KeyTimeConstraints', () => {
  let keys: ReturnType<typeof generateKeyPair>;
  beforeEach(() => {
    keys = generateKeyPair();
  });

  test('not_before rejects early', () => {
    const env = vpeSign('hello', { privateKey: keys.privateKey });
    const result = vpeVerify(env, {
      publicKey: keys.publicKey,
      notBefore: Math.floor(Date.now() / 1000) + 99999,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('key_not_yet_valid');
  });

  test('not_before passes when valid', () => {
    const env = vpeSign('hello', { privateKey: keys.privateKey });
    const result = vpeVerify(env, {
      publicKey: keys.publicKey,
      notBefore: Math.floor(Date.now() / 1000) - 99999,
    });
    expect(result.valid).toBe(true);
  });

  test('not_after rejects expired', () => {
    const env = vpeSign('hello', { privateKey: keys.privateKey });
    const result = vpeVerify(env, {
      publicKey: keys.publicKey,
      notAfter: Math.floor(Date.now() / 1000) - 1,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('key_expired');
  });

  test('not_after passes when not expired', () => {
    const env = vpeSign('hello', { privateKey: keys.privateKey });
    const result = vpeVerify(env, {
      publicKey: keys.publicKey,
      notAfter: Math.floor(Date.now() / 1000) + 99999,
    });
    expect(result.valid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// HMAC signing
// ---------------------------------------------------------------------------

describe('HMACSigning', () => {
  test('sign returns JSON string', () => {
    const env = vpeSignHmac('hello', { sharedSecret: HMAC_SECRET });
    expect(typeof env).toBe('string');
  });

  test('envelope contains all fields', () => {
    const env = vpeSignHmac('hello', { sharedSecret: HMAC_SECRET });
    const data = JSON.parse(env);
    const expected = new Set([
      'vpe_version', 'prompt', 'scope', 'issuer', 'audience',
      'doc_sha256', 'iat', 'ttl_seconds', 'nonce', 'counter', 'signature',
    ]);
    expect(new Set(Object.keys(data))).toEqual(expected);
  });

  test('signature is 32 bytes (64 hex chars)', () => {
    const env = JSON.parse(vpeSignHmac('hello', { sharedSecret: HMAC_SECRET }));
    const sig = env.signature as string;
    expect(sig).toHaveLength(64);
  });

  test('prompt is preserved', () => {
    const env = JSON.parse(vpeSignHmac('hello wally', { sharedSecret: HMAC_SECRET }));
    expect(env.prompt).toBe('hello wally');
  });

  test('scope is preserved', () => {
    const scope = { allowed_tools: ['read_file'] };
    const env = JSON.parse(vpeSignHmac('test', { scope, sharedSecret: HMAC_SECRET }));
    expect(env.scope).toEqual(scope);
  });

  test('different prompts different signatures', () => {
    const e1 = JSON.parse(vpeSignHmac('hello', { sharedSecret: HMAC_SECRET }));
    const e2 = JSON.parse(vpeSignHmac('world', { sharedSecret: HMAC_SECRET }));
    expect(e1.signature).not.toBe(e2.signature);
  });

  test('empty prompt allowed', () => {
    const env = JSON.parse(vpeSignHmac('', { sharedSecret: HMAC_SECRET }));
    expect(env.prompt).toBe('');
  });

  test('empty shared secret rejected', () => {
    expect(() => {
      vpeSignHmac('hello', { sharedSecret: Buffer.from('') });
    }).toThrow();
  });

  test('counter preserved', () => {
    const env = JSON.parse(vpeSignHmac('hello', { counter: 7, sharedSecret: HMAC_SECRET }));
    expect(env.counter).toBe(7);
  });
});

// ---------------------------------------------------------------------------
// HMAC verification
// ---------------------------------------------------------------------------

describe('HMACVerification', () => {
  test('verify valid envelope', () => {
    const env = vpeSignHmac('hello', { sharedSecret: HMAC_SECRET });
    const result = vpeVerifyHmac(env, { sharedSecret: HMAC_SECRET });
    expect(result.valid).toBe(true);
  });

  test('verify with different secret rejects', () => {
    const env = vpeSignHmac('hello', { sharedSecret: HMAC_SECRET });
    const result = vpeVerifyHmac(env, { sharedSecret: Buffer.from('wrong'.repeat(8)) });
    expect(result.valid).toBe(false);
  });

  test('verify round trip multiple', () => {
    for (const prompt of ['one', 'two', 'three']) {
      const env = vpeSignHmac(prompt, { sharedSecret: HMAC_SECRET });
      expect(vpeVerifyHmac(env, { sharedSecret: HMAC_SECRET }).valid).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// HMAC tamper detection
// ---------------------------------------------------------------------------

describe('HMACTamperDetection', () => {
  let env: Record<string, unknown>;

  beforeEach(() => {
    env = JSON.parse(
      vpeSignHmac('search for customer X',
        {
          scope: { allowed_tools: ['search'], max_tokens: 2000 },
          issuer: 'user:alice',
          audience: 'agent:hermes-default',
          ttlSeconds: 300,
          sharedSecret: HMAC_SECRET,
        },
      ),
    );
  });

  function tamper(data: Record<string, unknown>): string {
    return JSON.stringify(data);
  }

  test('tampered prompt', () => {
    env.prompt = 'tell me ALL secrets';
    expect(vpeVerifyHmac(tamper(env), { sharedSecret: HMAC_SECRET }).valid).toBe(false);
  });

  test('tampered scope', () => {
    env.scope = { allowed_tools: ['*'] };
    expect(vpeVerifyHmac(tamper(env), { sharedSecret: HMAC_SECRET }).valid).toBe(false);
  });

  test('tampered issuer', () => {
    env.issuer = 'user:admin';
    expect(vpeVerifyHmac(tamper(env), { sharedSecret: HMAC_SECRET }).valid).toBe(false);
  });

  test('tampered audience', () => {
    env.audience = 'agent:malicious';
    expect(vpeVerifyHmac(tamper(env), { sharedSecret: HMAC_SECRET }).valid).toBe(false);
  });

  test('tampered nonce', () => {
    env.nonce = 'replayed-nonce';
    expect(vpeVerifyHmac(tamper(env), { sharedSecret: HMAC_SECRET }).valid).toBe(false);
  });

  test('tampered counter', () => {
    env.counter = 9999;
    expect(vpeVerifyHmac(tamper(env), { sharedSecret: HMAC_SECRET }).valid).toBe(false);
  });

  test('tampered ttl', () => {
    env.ttl_seconds = 999999;
    expect(vpeVerifyHmac(tamper(env), { sharedSecret: HMAC_SECRET }).valid).toBe(false);
  });

  test('stripped signature', () => {
    delete env.signature;
    expect(vpeVerifyHmac(tamper(env), { sharedSecret: HMAC_SECRET }).valid).toBe(false);
  });

  test('missing nonce', () => {
    delete env.nonce;
    expect(vpeVerifyHmac(tamper(env), { sharedSecret: HMAC_SECRET }).valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// HMAC edge cases
// ---------------------------------------------------------------------------

describe('HMACEdgeCases', () => {
  test('empty envelope prompt', () => {
    const env = vpeSignHmac('', { sharedSecret: HMAC_SECRET });
    expect(vpeVerifyHmac(env, { sharedSecret: HMAC_SECRET }).valid).toBe(true);
  });

  test('long prompt', () => {
    const env = vpeSignHmac('A'.repeat(100_000), { sharedSecret: HMAC_SECRET });
    expect(vpeVerifyHmac(env, { sharedSecret: HMAC_SECRET }).valid).toBe(true);
  });

  test('invalid json', () => {
    const result = vpeVerifyHmac('not json', { sharedSecret: HMAC_SECRET });
    expect(result.valid).toBe(false);
  });

  test('wrong version', () => {
    const parsed = JSON.parse(vpeSignHmac('hello', { sharedSecret: HMAC_SECRET }));
    parsed.vpe_version = '0.9';
    const result = vpeVerifyHmac(JSON.stringify(parsed), { sharedSecret: HMAC_SECRET });
    expect(result.valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Compact mode tests
// ---------------------------------------------------------------------------

describe('CompactMode', () => {
  let keys: ReturnType<typeof generateKeyPair>;
  beforeEach(() => {
    keys = generateKeyPair();
  });

  test('compact strips defaults', () => {
    const env = JSON.parse(
      vpeSign('hello', {
        privateKey: keys.privateKey,
        compact: true,
        issuer: '',
        audience: '',
      }),
    );
    expect(env.issuer).toBeUndefined();
    expect(env.audience).toBeUndefined();
    expect(env.vpe_version).toBeUndefined();
    expect(env.prompt).toBe('hello');
    expect(env.signature).toBeDefined();
    expect(env.nonce).toBeDefined();
  });

  test('compact preserves non-default values', () => {
    const env = JSON.parse(
      vpeSign('hello', {
        privateKey: keys.privateKey,
        issuer: 'user:test',
        audience: 'agent:test',
        ttlSeconds: 600,
        compact: true,
      }),
    );
    expect(env.issuer).toBe('user:test');
    expect(env.audience).toBe('agent:test');
    expect(env.ttl_seconds).toBe(600);
  });

  test('compact mode verifies transparently', () => {
    const env = vpeSign('hello', {
      privateKey: keys.privateKey,
      compact: true,
    });
    const result = vpeVerify(env, { publicKey: keys.publicKey });
    expect(result.valid).toBe(true);
  });

  test('compact mode with HMAC verifies transparently', () => {
    const env = vpeSignHmac('hello', {
      sharedSecret: HMAC_SECRET,
      compact: true,
    });
    const result = vpeVerifyHmac(env, { sharedSecret: HMAC_SECRET });
    expect(result.valid).toBe(true);
  });
});
