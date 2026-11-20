/**
 * TypeScript twin of the Go agent's agent/internal/opsign formats (jcs.go,
 * payloadhash.go, format.go). The phone builds the exact text an operator signs
 * and the agent verifies, so every builder produces the same bytes as Go's
 * CanonicalBytes and throws where Go returns an error, with one gap: Go also
 * checks that each bundle key id is the hash of its key and that the key is a
 * real P-256 point, and these builders check neither (that needs SHA-256 and a
 * curve library). interop.test.ts proves the rest against the shared vectors
 * the Go tests write.
 *
 * Pure on purpose: no Node imports, so React Native can use it. Hashing
 * (payloadHash, agentUpdatePayloadHash, keyIdFromSpki, fingerprint) lives in ./node.
 */

export type OperatorRole = 'admin' | 'approver';
export type OperatorMode = 'audit' | 'enforce';

export interface OperatorBundleKeyV1 {
  keyId: string;
  spkiB64: string;
  role: OperatorRole;
  label: string;
}

export interface OperatorTrustBundleV1 {
  partnerId: string;
  /** A safe integer: Go reads up to 2^64-1, but a JS number cannot carry more than 2^53-1 exactly. */
  epoch: number;
  mode: OperatorMode;
  threshold: number;
  /** Empty string means no floor. */
  minAgentVersion: string;
  keys: OperatorBundleKeyV1[];
}

/** An approval entry carries the hash of what the device may run; a rule's scope device carries none. */
export interface OperatorDeviceEntryV1 {
  deviceId: string;
  hostname: string;
  payloadHash?: string;
}

/** Times are RFC 3339 UTC whole seconds with a `Z`, e.g. `2026-11-19T12:00:00Z`, and no other spelling. */
export interface OperatorActionApprovalV1 {
  approvalId: string;
  partnerId: string;
  commandType: string;
  entries: OperatorDeviceEntryV1[];
  issuedAt: string;
  expiresAt: string;
  keyId: string;
}

/** Exactly one of `scopeOrgId` or a non-empty `scopeDevices`. */
export interface OperatorRuleV1 {
  ruleId: string;
  ruleEpoch: number;
  partnerId: string;
  scopeOrgId?: string;
  scopeDevices?: OperatorDeviceEntryV1[];
  commandType: string;
  matchKind: 'payloadHashes' | 'patchItems';
  matchItems: string[];
  once: boolean;
  notAfter: string;
  keyId: string;
}

// ---- RFC 8785 canonical JSON (jcs.go) ----

const MAX_DEPTH = 32;

/** True when `s` has no lone surrogate, i.e. it could be encoded as UTF-8. */
function isWellFormed(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return false;
    }
  }
  return true;
}

// A Go string cannot hold a lone surrogate (it is invalid UTF-8) and Go refuses
// one. A JS string can, and JSON.stringify would write it as a \udXXX escape
// that Go never produces, so it is refused here too.
function writeString(s: string): string {
  if (!isWellFormed(s)) throw new Error('canonical json: string is not valid UTF-16');
  return JSON.stringify(s);
}

function writeValue(v: unknown, depth: number): string {
  if (v === null) return 'null';
  switch (typeof v) {
    case 'boolean':
      return v ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(v)) throw new Error('canonical json: NaN and Infinity are not representable');
      return JSON.stringify(v); // ECMAScript Number::toString, which is what RFC 8785 mandates
    case 'string':
      return writeString(v);
    case 'object':
      break;
    default:
      throw new Error(`canonical json: unsupported type ${typeof v}`);
  }
  if (depth >= MAX_DEPTH) throw new Error('canonical json: nesting too deep');
  if (Array.isArray(v)) return `[${Array.from(v, (e) => writeValue(e, depth + 1)).join(',')}]`;
  const proto: unknown = Object.getPrototypeOf(v);
  if (proto !== Object.prototype && proto !== null) throw new Error('canonical json: unsupported object');
  const obj = v as Record<string, unknown>;
  // The default sort compares UTF-16 code units, the order RFC 8785 requires.
  const members = Object.keys(obj)
    .sort()
    .map((k) => `${writeString(k)}:${writeValue(obj[k], depth + 1)}`);
  return `{${members.join(',')}}`;
}

/**
 * Strict RFC 8785 text of a JSON value. Unlike packages/shared/src/canonicalize
 * it does not drop undefined: anything JSON cannot carry is an error, so the
 * phone and the agent can never hash different readings of one payload.
 */
export function jcsCanonicalize(value: unknown): string {
  return writeValue(value, 0);
}

// ---- payload hash input (payloadhash.go) ----

const PAYLOAD_KEY = 'operatorApproval';

// Top-level fields the server sets at delivery time that cannot change what
// runs; see payloadExclusions in payloadhash.go for the reasons.
const PAYLOAD_EXCLUSIONS = new Map<string, readonly string[]>([
  ['script', ['executionId', 'batchId', 'restorePoint', 'secretEnv', 'secretEnvEnvelope']],
]);

/** The JCS text a payload hash is taken over: the payload minus `operatorApproval` and the type's exclusions. */
export function payloadHashInput(commandType: string, payload: Record<string, unknown>): string {
  const excluded = new Set([PAYLOAD_KEY, ...(PAYLOAD_EXCLUSIONS.get(commandType) ?? [])]);
  return jcsCanonicalize(Object.fromEntries(Object.entries(payload).filter(([key]) => !excluded.has(key))));
}

// ---- approval and bundle text (format.go) ----

const BUNDLE_DOMAIN = 'breeze-operator-trust-bundle-v1';
const APPROVAL_DOMAIN = 'breeze-operator-approval-v1';

const MAX_ENTRIES = 500;
const MAX_ACTION_LIFETIME_MS = 24 * 60 * 60 * 1000;
const MAX_SESSION_LIFETIME_MS = 2 * 60 * 1000;
const SESSION_TYPES: ReadonlySet<string> = new Set(['terminal_start', 'start_desktop', 'desktop_stream_start', 'tunnel_open']);

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX32 = /^[0-9a-f]{32}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const HOSTNAME = /^[a-z0-9._-]{1,253}$/;
const COMMAND_TYPE = /^[a-z][a-z0-9_]{0,63}$/;
const VERSION = /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
// The only P-256 SPKI encoding: a fixed 26-byte header, 0x04, then X and Y, in
// canonical padded base64 (the last character before == carries no stray bits).
// That a key id is the hash of its key, and that the point is on the curve,
// are not checked here (see the header).
const P256_SPKI_B64 = /^MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE[A-Za-z0-9+/]{85}[AQgw]==$/;

const invalid = (field: string, v: unknown) => new Error(`opsign: invalid ${field} ${JSON.stringify(v)}`);

function check(re: RegExp, field: string, v: unknown): void {
  if (typeof v !== 'string' || !re.test(v)) throw invalid(field, v);
}

function checkCount(field: string, v: unknown): void {
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0) throw invalid(field, v);
}

// Free text that sits inside one line (labels, patch items). A control
// character, LF included, would let a value forge extra lines. Only an ASCII
// space at either edge is refused: Unicode whitespace tables differ between Go
// and JS, so a wider rule could not be mirrored exactly (ruling R12).
function checkLine(field: string, s: unknown): void {
  if (
    typeof s !== 'string' ||
    s === '' ||
    s.startsWith(' ') ||
    s.endsWith(' ') ||
    !isWellFormed(s) ||
    [...s].some((ch) => ch < ' ' || ch === '\x7f')
  ) {
    throw invalid(field, s);
  }
}

// Only `YYYY-MM-DDTHH:MM:SSZ` is accepted, so a time with sub-second precision
// is an error (never truncated); the round trip rejects dates JS would roll
// over, such as Feb 30 or hour 24.
function wholeSecondMs(field: string, v: unknown): number {
  const ms = typeof v === 'string' && TIME.test(v) ? Date.parse(v) : NaN;
  if (Number.isNaN(ms) || new Date(ms).toISOString().replace('.000Z', 'Z') !== v) throw invalid(field, v);
  return ms;
}

const compareText = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

// Byte order of UTF-8, which is code point order. The default JS sort is UTF-16
// order and would put an astral character before U+E000..U+FFFF.
function compareUtf8(a: string, b: string): number {
  const ca = Array.from(a, (ch) => ch.codePointAt(0)!);
  const cb = Array.from(b, (ch) => ch.codePointAt(0)!);
  for (let i = 0; i < ca.length && i < cb.length; i++) {
    if (ca[i] !== cb[i]) return ca[i]! < cb[i]! ? -1 : 1;
  }
  return ca.length - cb.length;
}

/** A sorted copy of `items`; two items comparing equal are an error. */
function sortedUnique<T>(items: readonly T[], compare: (a: T, b: T) => number, what: string): T[] {
  const sorted = [...items].sort(compare);
  for (let i = 1; i < sorted.length; i++) {
    if (compare(sorted[i - 1]!, sorted[i]!) === 0) throw new Error(`opsign: duplicate in ${what}`);
  }
  return sorted;
}

// A device appears once, whatever its hostname or hash (ruling R11).
function sortedEntries(list: readonly OperatorDeviceEntryV1[], what: string, withHash: boolean): OperatorDeviceEntryV1[] {
  if (list.length === 0 || list.length > MAX_ENTRIES) {
    throw new Error(`opsign: ${what} holds ${list.length} entries, want 1 to ${MAX_ENTRIES}`);
  }
  for (const e of list) {
    check(UUID, 'deviceId', e.deviceId);
    check(HOSTNAME, 'hostname', e.hostname);
    if (withHash) check(HEX64, 'payloadHash', e.payloadHash);
    else if ((e.payloadHash ?? '') !== '') throw new Error(`opsign: ${what} entry carries a payloadHash`);
  }
  return sortedUnique(list, (a, b) => compareText(a.deviceId, b.deviceId), what);
}

export function canonicalBundle(b: OperatorTrustBundleV1): string {
  const keys = sortedUnique(b.keys, (x, y) => compareText(x.keyId, y.keyId), 'keys');
  check(UUID, 'partnerId', b.partnerId);
  checkCount('epoch', b.epoch);
  let admins = 0;
  for (const k of keys) {
    check(HEX32, 'keyId', k.keyId);
    check(P256_SPKI_B64, 'spkiB64', k.spkiB64);
    if (k.role !== 'admin' && k.role !== 'approver') throw invalid('role', k.role);
    checkLine('label', k.label);
    if (k.role === 'admin') admins++;
  }
  if (b.mode !== 'audit' && b.mode !== 'enforce') throw invalid('mode', b.mode);
  if (!Number.isInteger(b.threshold) || b.threshold < 1 || b.threshold > admins) {
    throw new Error(`opsign: threshold ${b.threshold} must be between 1 and the ${admins} admin keys`);
  }
  if (b.minAgentVersion !== '') check(VERSION, 'minAgentVersion', b.minAgentVersion);

  return [
    BUNDLE_DOMAIN,
    `partnerId=${b.partnerId}`,
    `epoch=${b.epoch}`,
    `mode=${b.mode}`,
    `threshold=${b.threshold}`,
    `minAgentVersion=${b.minAgentVersion}`,
    `keys=${keys.length}`,
    ...keys.map((k) => `${k.keyId} ${k.role} ${k.spkiB64} ${k.label}`),
  ].join('\n');
}

export function canonicalActionApproval(a: OperatorActionApprovalV1): string {
  const entries = sortedEntries(a.entries, 'entries', true);
  check(HEX32, 'approvalId', a.approvalId);
  check(UUID, 'partnerId', a.partnerId);
  check(COMMAND_TYPE, 'commandType', a.commandType);
  check(HEX32, 'keyId', a.keyId);
  const lifetime = wholeSecondMs('expiresAt', a.expiresAt) - wholeSecondMs('issuedAt', a.issuedAt);
  const limit = SESSION_TYPES.has(a.commandType) ? MAX_SESSION_LIFETIME_MS : MAX_ACTION_LIFETIME_MS;
  if (lifetime <= 0 || lifetime > limit) {
    throw new Error(`opsign: ${a.commandType} approval must expire within ${limit / 1000}s of issue, got ${lifetime / 1000}s`);
  }

  return [
    APPROVAL_DOMAIN,
    'kind=action',
    `approvalId=${a.approvalId}`,
    `partnerId=${a.partnerId}`,
    `commandType=${a.commandType}`,
    `entries=${entries.length}`,
    ...entries.map((e) => `${e.deviceId} ${e.hostname} ${e.payloadHash}`),
    `issuedAt=${a.issuedAt}`,
    `expiresAt=${a.expiresAt}`,
    `keyId=${a.keyId}`,
  ].join('\n');
}

export function canonicalRule(r: OperatorRuleV1): string {
  check(HEX32, 'ruleId', r.ruleId);
  checkCount('ruleEpoch', r.ruleEpoch);
  check(UUID, 'partnerId', r.partnerId);
  check(COMMAND_TYPE, 'commandType', r.commandType);
  wholeSecondMs('notAfter', r.notAfter);
  check(HEX32, 'keyId', r.keyId);
  if (typeof r.once !== 'boolean') throw invalid('once', r.once);

  const hasOrg = (r.scopeOrgId ?? '') !== '';
  const listed = r.scopeDevices ?? [];
  let scope: string[];
  if (hasOrg && listed.length === 0) {
    check(UUID, 'scope org', r.scopeOrgId);
    scope = [`scope=org:${r.scopeOrgId}`];
  } else if (!hasOrg && listed.length > 0) {
    const devices = sortedEntries(listed, 'scopeDevices', false);
    scope = ['scope=devices', `scopeDevices=${devices.length}`, ...devices.map((d) => `${d.deviceId} ${d.hostname}`)];
  } else {
    throw new Error('opsign: a rule needs exactly one of an org scope or a device list');
  }

  if (r.matchItems.length === 0) throw new Error('opsign: a rule needs at least one match item');
  const items = sortedUnique(r.matchItems, compareUtf8, 'matchItems');
  if (r.matchKind === 'payloadHashes') items.forEach((item) => check(HEX64, 'match item', item));
  else if (r.matchKind === 'patchItems') items.forEach((item) => checkLine('match item', item));
  else throw invalid('match kind', r.matchKind);

  return [
    APPROVAL_DOMAIN,
    'kind=rule',
    `ruleId=${r.ruleId}`,
    `ruleEpoch=${r.ruleEpoch}`,
    `partnerId=${r.partnerId}`,
    ...scope,
    `commandType=${r.commandType}`,
    `match=${r.matchKind}`,
    `matchItems=${items.length}`,
    ...items,
    `once=${r.once}`,
    `notAfter=${r.notAfter}`,
    `keyId=${r.keyId}`,
  ].join('\n');
}
