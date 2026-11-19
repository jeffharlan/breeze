/**
 * Node-only half of the operator-signing twin: the SHA-256 parts of
 * agent/internal/opsign. Kept out of ./index so that stays free of Node
 * imports; like @breeze/shared/canonicalize it is not in the root barrel.
 */
import { createHash, createPublicKey } from 'node:crypto';
import { payloadHashInput, type OperatorTrustBundleV1 } from './index';

const sha256Hex = (data: Buffer | string): string => createHash('sha256').update(data).digest('hex');

/** Lowercase hex SHA-256 of the canonical payload JSON (see `payloadHashInput`). */
export function payloadHash(commandType: string, payload: Record<string, unknown>): string {
  return sha256Hex(payloadHashInput(commandType, payload));
}

/** First 128 bits of SHA-256 of the SPKI DER, as lowercase hex. */
export function keyIdFromSpki(spkiDer: Buffer): string {
  return sha256Hex(spkiDer).slice(0, 32);
}

/** First 128 bits of SHA-256 of a bundle's canonical text, as lowercase hex: what operators compare by eye. */
export function fingerprint(canonical: string): string {
  return sha256Hex(canonical).slice(0, 32);
}

/**
 * The key checks Go's BundleKey.validate makes that the pure canonicalBundle
 * cannot: every key id is the hash of its key, and every key is a real P-256
 * point. Throws on the first key that fails.
 */
export function assertBundleKeyIds(bundle: OperatorTrustBundleV1): void {
  for (const k of bundle.keys) {
    const der = Buffer.from(k.spkiB64, 'base64');
    createPublicKey({ key: der, format: 'der', type: 'spki' });
    if (keyIdFromSpki(der) !== k.keyId) throw new Error(`opsign: keyId ${k.keyId} does not match its public key`);
  }
}
