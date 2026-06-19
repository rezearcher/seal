/**
 * Interop test: verify TypeScript port against shared test-vector fixture.
 *
 * Reads vpe_vectors.json and verifies every vector using the TS VPE implementation.
 */
import * as fs from 'fs';
import * as path from 'path';
import { vpeVerify, vpeVerifyHmac } from '../src/index';

interface VectorParams {
  prompt: string;
  scope: Record<string, unknown> | null;
  issuer: string;
  audience: string;
  doc_sha256: string;
  ttl_seconds: number;
  nonce: string;
  counter: number | null;
  compact: boolean;
}

interface Vector {
  id: string;
  description: string;
  signature_type: string;
  params: VectorParams;
  expected_canonical_hex: string;
  expected_signature_hex: string;
  signed_envelope_json: string;
  expected_verify: boolean;
  tampered_envelope_json: string | null;
}

interface Fixture {
  version: number;
  ed25519_public_key_hex: string;
  hmac_secret_hex: string;
  vectors: Vector[];
}

function loadFixture(): Fixture {
  const fixturePath = path.resolve(__dirname, '..', '..', 'tests', 'vectors', 'vpe_vectors.json');
  const raw = fs.readFileSync(fixturePath, 'utf-8');
  return JSON.parse(raw);
}

const fixture = loadFixture();
const publicKey = Buffer.from(fixture.ed25519_public_key_hex, 'hex');
const hmacSecret = Buffer.from(fixture.hmac_secret_hex, 'hex');

describe('InteropVector', () => {
  fixture.vectors.forEach((vec) => {
    it(`[${vec.id}] ${vec.description}`, () => {
      const envStr = vec.tampered_envelope_json ?? vec.signed_envelope_json;

      let result: { valid: boolean; reason: string };
      if (vec.signature_type === 'hmac-sha256') {
        result = vpeVerifyHmac(envStr, { sharedSecret: hmacSecret });
      } else {
        result = vpeVerify(envStr, { publicKey });
      }

      expect(result.valid).toBe(vec.expected_verify);
    });
  });
});
