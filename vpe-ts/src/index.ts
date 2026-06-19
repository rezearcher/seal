/**
 * VPE (Verified Prompt Envelope) — TypeScript port.
 *
 * Port of the Python reference at ~/projects/seal/seal/core.py.
 * Uses Ed25519 (tweetnacl) for asymmetric signatures and Node crypto
 * for HMAC-SHA256.
 */

import * as crypto from 'crypto';
import nacl from 'tweetnacl';

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

export const VPE_VERSION = '1.0';

/** Ordered field list — the canonical serialisation order used for signing. */
export const ENVELOPE_FIELDS = [
  'vpe_version',
  'prompt',
  'scope',
  'issuer',
  'audience',
  'doc_sha256',
  'iat',
  'ttl_seconds',
  'nonce',
  'counter',
  'cert_chain',
] as const;

/** Fields that can be stripped from wire format when at default value. */
const STRIPPABLE_FIELD_DEFAULTS: Record<string, unknown> = {
  vpe_version: VPE_VERSION,
  scope: {},
  issuer: '',
  audience: '',
  doc_sha256: '',
  iat: null,
  counter: null,
  cert_chain: null,
};

const DEFAULT_TTL = 300;

/** Per-field defaults for canonical JSON reconstruction. */
const CANONICAL_DEFAULTS: Record<string, unknown> = {
  vpe_version: VPE_VERSION,
  scope: {},
  issuer: '',
  audience: '',
  doc_sha256: '',
  iat: null,
  ttl_seconds: 300,
  nonce: '',
  counter: null,
  cert_chain: null,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isStrippableTtl(value: unknown): boolean {
  return value === DEFAULT_TTL || value === 0;
}

function stripEmptyFields(envelope: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(envelope)) {
    if (key === 'ttl_seconds') {
      if (isStrippableTtl(value)) continue;
    } else if (key in STRIPPABLE_FIELD_DEFAULTS) {
      const def = STRIPPABLE_FIELD_DEFAULTS[key];
      if (value === def) continue;
    }
    result[key] = value;
  }
  return result;
}

function makeNonce(): string {
  return crypto.randomBytes(16).toString('hex');
}

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

export interface KeyPair {
  privateKey: Buffer;
  publicKey: Buffer;
}

/**
 * Generate a new Ed25519 key pair.
 * Returns { privateKey, publicKey } — 32 bytes each.
 */
export function generateKeyPair(): KeyPair {
  const kp = nacl.sign.keyPair();
  return {
    privateKey: Buffer.from(kp.secretKey.subarray(0, 32)),
    publicKey: Buffer.from(kp.publicKey),
  };
}

// ---------------------------------------------------------------------------
// Canonical JSON serialisation
// ---------------------------------------------------------------------------

/**
 * Deterministic JSON serialization of VPE fields (minus signature) for signing.
 *
 * Rules:
 * 1. Field order from ENVELOPE_FIELDS
 * 2. Skip "signature" field
 * 3. Omit cert_chain when null/undefined
 * 4. Include counter: null when null
 * 5. Scope keys sorted alphabetically
 * 6. Per-field defaults for missing keys
 * 7. Compact separators: "," and ":"
 * 8. Encode as UTF-8 Buffer
 */
export function canonicalJson(envelope: Record<string, unknown>): Buffer {
  const ordered: Record<string, unknown> = {};

  for (const field of ENVELOPE_FIELDS) {
    const defaultValue = CANONICAL_DEFAULTS[field];
    let value: unknown;

    if (field === 'scope') {
      value = envelope.scope ?? defaultValue;
      if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        const sorted: Record<string, unknown> = {};
        const keys = Object.keys(value as Record<string, unknown>).sort();
        for (const k of keys) {
          sorted[k] = (value as Record<string, unknown>)[k];
        }
        value = sorted;
      }
      ordered[field] = value;
    } else if (field === 'cert_chain') {
      value = envelope.cert_chain ?? defaultValue;
      if (value !== null && value !== undefined) {
        ordered[field] = value;
      }
    } else {
      value = envelope[field] ?? defaultValue;
      ordered[field] = value;
    }
  }

  const json = JSON.stringify(ordered, (_, val) => {
    // Ensure undefined is serialized as null to match Python's None → null
    return val === undefined ? null : val;
  });
  return Buffer.from(json, 'utf-8');
}

// ---------------------------------------------------------------------------
// Ed25519 Sign
// ---------------------------------------------------------------------------

export interface SignOptions {
  scope?: Record<string, unknown>;
  issuer?: string;
  audience?: string;
  docSha256?: string;
  ttlSeconds?: number;
  nonce?: string;
  counter?: number | null;
  privateKey: Buffer;
  certChain?: unknown[];
  compact?: boolean;
}

/**
 * Create a signed VPE envelope JSON string using Ed25519.
 *
 * Args follow Python vpe_sign() semantics:
 *  - Auto-generates nonce (32 hex chars) if not provided
 *  - Computes doc_sha256 = SHA256(prompt).hex() if not provided
 *  - Sets iat = Math.floor(Date.now()/1000)
 *  - Signs canonical JSON with Ed25519
 *  - If compact=true, strips default/empty fields from output
 */
export function vpeSign(prompt: string, opts: SignOptions): string {
  const scope = opts.scope ?? {};
  const issuer = opts.issuer ?? '';
  const audience = opts.audience ?? '';
  const docSha256 = opts.docSha256 || sha256Hex(prompt);
  const ttlSeconds = opts.ttlSeconds ?? 300;
  const nonce = opts.nonce ?? makeNonce();
  const counter = opts.counter ?? null;
  const certChain = opts.certChain ?? null;
  const compact = opts.compact ?? false;

  const privateKey = opts.privateKey;
  if (!Buffer.isBuffer(privateKey) || privateKey.length !== 32) {
    throw new Error('privateKey must be a 32-byte Buffer');
  }

  const fullSeed = Buffer.alloc(64);
  privateKey.copy(fullSeed);
  const kp = nacl.sign.keyPair.fromSeed(new Uint8Array(fullSeed.subarray(0, 32)));

  const envelope: Record<string, unknown> = {
    vpe_version: VPE_VERSION,
    prompt,
    scope,
    issuer,
    audience,
    doc_sha256: docSha256,
    iat: Math.floor(Date.now() / 1000),
    ttl_seconds: ttlSeconds,
    nonce,
    counter,
    cert_chain: certChain,
    signature: '',
  };

  const canon = canonicalJson(envelope);
  const sig = nacl.sign.detached(
    new Uint8Array(canon),
    new Uint8Array(kp.secretKey),
  );
  const sigHex = Buffer.from(sig).toString('hex');
  envelope.signature = sigHex;

  let output = envelope;
  if (compact) {
    output = stripEmptyFields(envelope);
    // Ensure signature is always present in output
    output.signature = sigHex;
  }

  return JSON.stringify(output);
}

function sha256Hex(input: string): string {
  return crypto.createHash('sha256').update(input, 'utf-8').digest('hex');
}

// ---------------------------------------------------------------------------
// Ed25519 Verify
// ---------------------------------------------------------------------------

export interface VerifyResult {
  valid: boolean;
  reason: string;
}

export interface VerifyOptions {
  publicKey?: Buffer;
  trustAnchor?: Buffer;
  notBefore?: number;
  notAfter?: number;
  nonceStore?: NonceStore;
}

/**
 * Verify a VPE envelope string (Ed25519).
 *
 * Checks performed (matching Python vpe_verify()):
 *  1. JSON parse validity
 *  2. Version match ("1.0")
 *  3. Signature field present
 *  4. Scope is an object
 *  5. Nonce is string, non-empty
 *  6. Counter is int or null
 *  7. ttl_seconds is int
 *  8. Nonce replay (if nonceStore and ttl>0)
 *  9. Resolve public key (from cert_chain + trustAnchor, or direct publicKey)
 * 10. Ed25519 signature verification
 * 11. TTL expiry
 * 12. not_before / not_after constraints
 */
export function vpeVerify(
  envelopeStr: string,
  opts: VerifyOptions,
): VerifyResult {
  const { publicKey, trustAnchor, notBefore, notAfter, nonceStore } = opts;

  // 1. Parse
  let envelope: Record<string, unknown>;
  try {
    envelope = JSON.parse(envelopeStr);
  } catch {
    return { valid: false, reason: 'invalid_json' };
  }

  if (typeof envelope !== 'object' || envelope === null || Array.isArray(envelope)) {
    return { valid: false, reason: 'invalid_json: not a dict' };
  }

  // 2. Version
  const version = (envelope.vpe_version as string) ?? VPE_VERSION;
  if (version !== VPE_VERSION) {
    return { valid: false, reason: `unsupported_version: ${version}` };
  }

  // 3. Signature present
  const sigHex = (envelope.signature as string) ?? '';
  if (!sigHex) {
    return { valid: false, reason: 'missing_signature' };
  }

  // 4. Scope is dict
  const scope = envelope.scope ?? {};
  if (typeof scope !== 'object' || scope === null || Array.isArray(scope)) {
    return { valid: false, reason: 'scope_not_dict' };
  }

  // 5. Nonce present
  const nonce = (envelope.nonce as string) ?? '';
  if (typeof nonce !== 'string' || nonce === '') {
    return { valid: false, reason: 'missing_or_empty_nonce' };
  }

  // 6. Counter type check (if present)
  const counter = envelope.counter;
  if (counter !== null && counter !== undefined && typeof counter !== 'number') {
    return { valid: false, reason: 'counter_not_integer' };
  }
  if (counter !== null && counter !== undefined && !Number.isInteger(counter)) {
    return { valid: false, reason: 'counter_not_integer' };
  }

  // 7. TTL check
  const ttl = (envelope.ttl_seconds as number) ?? 0;
  if (typeof ttl !== 'number' || !Number.isInteger(ttl)) {
    return { valid: false, reason: 'ttl_not_integer' };
  }

  // 8. Nonce replay check (skip when ttl=0)
  if (nonceStore !== undefined && ttl > 0) {
    if (nonceStore instanceof NonceStore) {
      if (!nonceStore.add(nonce)) {
        return { valid: false, reason: 'nonce_reused' };
      }
    }
  }

  // 9. Determine effective public key
  const certChain = envelope.cert_chain;
  let effectivePkBytes: Buffer | null = null;

  if (trustAnchor !== undefined && certChain !== null && certChain !== undefined) {
    // Cert chain verification (simplified — just use trust anchor as the key for now)
    effectivePkBytes = trustAnchor;
  } else if (publicKey !== undefined) {
    effectivePkBytes = publicKey;
  } else {
    return { valid: false, reason: 'no_verification_key: provide publicKey or trustAnchor' };
  }

  if (!Buffer.isBuffer(effectivePkBytes) || effectivePkBytes.length !== 32) {
    return { valid: false, reason: 'invalid_public_key' };
  }

  // 10. Cryptographic signature verification
  const verifyEnvelope = { ...envelope };
  verifyEnvelope.signature = '';
  const canon = canonicalJson(verifyEnvelope);

  let sigBytes: Buffer;
  try {
    sigBytes = Buffer.from(sigHex, 'hex');
  } catch {
    return { valid: false, reason: 'invalid_signature_encoding' };
  }

  if (sigBytes.length !== 64) {
    return { valid: false, reason: 'invalid_signature_encoding' };
  }

  const verified = nacl.sign.detached.verify(
    new Uint8Array(canon),
    new Uint8Array(sigBytes),
    new Uint8Array(effectivePkBytes),
  );

  if (!verified) {
    return { valid: false, reason: 'signature_mismatch' };
  }

  // 11. TTL expiry
  const now = Math.floor(Date.now() / 1000);
  if (ttl > 0) {
    const iat = envelope.iat;
    if (iat !== null && iat !== undefined) {
      if (typeof iat !== 'number' || !Number.isInteger(iat)) {
        return { valid: false, reason: 'iat_not_integer' };
      }
      if (now - iat > ttl) {
        return { valid: false, reason: 'envelope_expired' };
      }
    }
  }

  // 12. Key time constraints
  if (notBefore !== undefined && now < notBefore) {
    return { valid: false, reason: 'key_not_yet_valid' };
  }
  if (notAfter !== undefined && now >= notAfter) {
    return { valid: false, reason: 'key_expired' };
  }

  return { valid: true, reason: 'ok' };
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 Sign
// ---------------------------------------------------------------------------

export interface HmacSignOptions {
  scope?: Record<string, unknown>;
  issuer?: string;
  audience?: string;
  docSha256?: string;
  ttlSeconds?: number;
  nonce?: string;
  counter?: number | null;
  sharedSecret: Buffer;
  compact?: boolean;
}

/**
 * Sign a prompt with HMAC-SHA256 for internal/low-security contexts.
 * Same envelope format as vpeSign() but symmetric HMAC.
 */
export function vpeSignHmac(prompt: string, opts: HmacSignOptions): string {
  const scope = opts.scope ?? {};
  const issuer = opts.issuer ?? '';
  const audience = opts.audience ?? '';
  const docSha256 = opts.docSha256 || sha256Hex(prompt);
  const ttlSeconds = opts.ttlSeconds ?? 300;
  const nonce = opts.nonce ?? makeNonce();
  const counter = opts.counter ?? null;
  const sharedSecret = opts.sharedSecret;
  const compact = opts.compact ?? false;

  if (!Buffer.isBuffer(sharedSecret) || sharedSecret.length === 0) {
    throw new Error('shared_secret must be non-empty bytes');
  }

  const envelope: Record<string, unknown> = {
    vpe_version: VPE_VERSION,
    prompt,
    scope,
    issuer,
    audience,
    doc_sha256: docSha256,
    iat: Math.floor(Date.now() / 1000),
    ttl_seconds: ttlSeconds,
    nonce,
    counter,
    signature: '',
  };

  const canon = canonicalJson(envelope);
  const sig = crypto.createHmac('sha256', sharedSecret).update(canon).digest('hex');
  envelope.signature = sig;

  let output = envelope;
  if (compact) {
    output = stripEmptyFields(envelope);
    output.signature = sig;
  }

  return JSON.stringify(output);
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 Verify
// ---------------------------------------------------------------------------

export interface HmacVerifyOptions {
  sharedSecret: Buffer;
  notBefore?: number;
  notAfter?: number;
}

/**
 * Verify an HMAC-SHA256 signed VPE envelope.
 * Same checks as vpeVerify() but uses HMAC instead of Ed25519.
 */
export function vpeVerifyHmac(
  envelopeStr: string,
  opts: HmacVerifyOptions,
): VerifyResult {
  const { sharedSecret, notBefore, notAfter } = opts;

  // 1. Parse
  let envelope: Record<string, unknown>;
  try {
    envelope = JSON.parse(envelopeStr);
  } catch {
    return { valid: false, reason: 'invalid_json' };
  }

  if (typeof envelope !== 'object' || envelope === null || Array.isArray(envelope)) {
    return { valid: false, reason: 'invalid_json: not a dict' };
  }

  // 2. Version
  const version = (envelope.vpe_version as string) ?? VPE_VERSION;
  if (version !== VPE_VERSION) {
    return { valid: false, reason: `unsupported_version: ${version}` };
  }

  // 3. Signature present
  const sigHex = (envelope.signature as string) ?? '';
  if (!sigHex) {
    return { valid: false, reason: 'missing_signature' };
  }

  // 4. Scope is dict
  const scope = envelope.scope ?? {};
  if (typeof scope !== 'object' || scope === null || Array.isArray(scope)) {
    return { valid: false, reason: 'scope_not_dict' };
  }

  // 5. Nonce present
  const nonce = (envelope.nonce as string) ?? '';
  if (typeof nonce !== 'string' || nonce === '') {
    return { valid: false, reason: 'missing_or_empty_nonce' };
  }

  // 6. Counter type check (if present)
  const counter = envelope.counter;
  if (counter !== null && counter !== undefined && typeof counter !== 'number') {
    return { valid: false, reason: 'counter_not_integer' };
  }
  if (counter !== null && counter !== undefined && !Number.isInteger(counter)) {
    return { valid: false, reason: 'counter_not_integer' };
  }

  // 7. TTL check
  const ttl = (envelope.ttl_seconds as number) ?? 0;
  if (typeof ttl !== 'number' || !Number.isInteger(ttl)) {
    return { valid: false, reason: 'ttl_not_integer' };
  }

  // 8. HMAC-SHA256 signature verification
  const verifyEnvelope = { ...envelope };
  verifyEnvelope.signature = '';
  const canon = canonicalJson(verifyEnvelope);

  const expected = crypto.createHmac('sha256', sharedSecret).update(canon).digest('hex');

  // Constant-time comparison
  if (sigHex.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sigHex), Buffer.from(expected))) {
    return { valid: false, reason: 'signature_mismatch' };
  }

  // 9. TTL expiry
  const now = Math.floor(Date.now() / 1000);
  if (ttl > 0) {
    const iat = envelope.iat;
    if (iat !== null && iat !== undefined) {
      if (typeof iat !== 'number' || !Number.isInteger(iat)) {
        return { valid: false, reason: 'iat_not_integer' };
      }
      if (now - iat > ttl) {
        return { valid: false, reason: 'envelope_expired' };
      }
    }
  }

  // 10. Key time constraints
  if (notBefore !== undefined && now < notBefore) {
    return { valid: false, reason: 'key_not_yet_valid' };
  }
  if (notAfter !== undefined && now >= notAfter) {
    return { valid: false, reason: 'key_expired' };
  }

  return { valid: true, reason: 'ok' };
}

// ---------------------------------------------------------------------------
// NonceStore (in-memory for testing, mirrors Python NonceStore API)
// ---------------------------------------------------------------------------

/**
 * Simple in-memory nonce store for replay detection.
 * Mirrors the Python NonceStore.add() interface.
 */
export class NonceStore {
  private nonces: Set<string> = new Set();

  /**
   * Add a nonce to the store.
   * Returns true if the nonce was added (first time seen),
   * false if it already exists (replay detected).
   */
  add(nonce: string): boolean {
    if (this.nonces.has(nonce)) {
      return false;
    }
    this.nonces.add(nonce);
    return true;
  }

  /** Clear all stored nonces. */
  clear(): void {
    this.nonces.clear();
  }
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

export { ENVELOPE_FIELDS as _ENVELOPE_FIELDS };
