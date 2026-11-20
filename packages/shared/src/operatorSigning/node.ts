/**
 * Node-only half of the operator-signing twin: the SHA-256 parts of
 * agent/internal/opsign. Kept out of ./index so that stays free of Node
 * imports; like @breeze/shared/canonicalize it is not in the root barrel.
 */
import { createHash } from 'node:crypto';
import { payloadHashInput } from './index';

const sha256Hex = (data: Buffer | string): string => createHash('sha256').update(data).digest('hex');

/** Lowercase hex SHA-256 of the canonical payload JSON (see `payloadHashInput`). */
export function payloadHash(commandType: string, payload: Record<string, unknown>): string {
  return sha256Hex(payloadHashInput(commandType, payload));
}

/**
 * The payload hash of an `agent_update` approval: lowercase hex SHA-256 of the
 * UTF-8 bytes of the update manifest text exactly as the agent is served it,
 * the bytes its signature covers. Never parse and re-encode it first; unlike
 * every other command type this is not canonical JSON.
 */
export function agentUpdatePayloadHash(manifestText: string): string {
  return sha256Hex(manifestText);
}

/** First 128 bits of SHA-256 of the SPKI DER, as lowercase hex. */
export function keyIdFromSpki(spkiDer: Buffer): string {
  return sha256Hex(spkiDer).slice(0, 32);
}

/** First 128 bits of SHA-256 of a bundle's canonical text, as lowercase hex: what operators compare by eye. */
export function fingerprint(canonical: string): string {
  return sha256Hex(canonical).slice(0, 32);
}
