import { describe, expect, it } from 'vitest';
import { verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  canonicalActionApproval,
  canonicalBundle,
  canonicalRule,
  jcsCanonicalize,
  payloadHashInput,
  type OperatorActionApprovalV1,
  type OperatorDeviceEntryV1,
  type OperatorRuleV1,
  type OperatorTrustBundleV1,
} from './index';
import { agentUpdatePayloadHash, fingerprint, keyIdFromSpki, payloadHash } from './node';

const HERE = dirname(fileURLToPath(import.meta.url));

/** Written by the Go agent package (`go test ./internal/opsign -run TestGenerateVectors -update`). */
interface Signed<S> {
  struct: S;
  canonicalB64: string;
  signatureB64: string;
}
interface Vectors {
  jcs: { name: string; input: unknown; canonical: string }[];
  payloadHash: { name: string; commandType: string; payload: Record<string, unknown>; hash: string }[];
  keys: { keyId: string; spkiB64: string; role: string; label: string }[];
  bundle: {
    struct: OperatorTrustBundleV1;
    canonicalB64: string;
    fingerprint: string;
    signatures: { keyId: string; signatureB64: string }[];
  };
  action: Signed<OperatorActionApprovalV1>;
  rule: Signed<OperatorRuleV1>;
  ruleOrg: Signed<OperatorRuleV1>;
  agentUpdate: { name: string; manifest: string; hash: string }[];
}
const vectors: Vectors = JSON.parse(
  readFileSync(join(HERE, '../../../../agent/internal/opsign/testdata/operator_signing_v1_vectors.json'), 'utf8'),
);

// Every refusal must come from the validators themselves, not from an accidental TypeError.
const REFUSED = /^(opsign|canonical json): /;
const textOf = (b64: string) => Buffer.from(b64, 'base64').toString('utf8');
const spkiOf = (keyId: string) => vectors.keys.find((k) => k.keyId === keyId)!.spkiB64;
const signatureVerifies = (keyId: string, message: string, sigB64: string) =>
  verify(
    'sha256',
    Buffer.from(message, 'utf8'),
    { key: Buffer.from(spkiOf(keyId), 'base64'), format: 'der', type: 'spki', dsaEncoding: 'ieee-p1363' },
    Buffer.from(sigB64, 'base64'),
  );
const edit = <T>(base: T, change: (draft: T) => void): T => {
  const copy = structuredClone(base);
  change(copy);
  return copy;
};
const devices = (n: number, withHash: boolean): OperatorDeviceEntryV1[] =>
  Array.from({ length: n }, (_, i) => ({
    deviceId: `00000000-0000-4000-8000-${i.toString(16).padStart(12, '0')}`,
    hostname: 'srv',
    ...(withHash ? { payloadHash: 'a'.repeat(64) } : {}),
  }));

describe('golden vectors written by the Go agent', () => {
  it.each(vectors.jcs)('jcs: $name', (v) => {
    expect(jcsCanonicalize(v.input)).toBe(v.canonical);
  });

  it.each(vectors.payloadHash)('payload hash: $name', (v) => {
    expect(payloadHash(v.commandType, v.payload)).toBe(v.hash);
  });

  it.each(vectors.agentUpdate)('agent_update payload hash: $name', (v) => {
    expect(agentUpdatePayloadHash(v.manifest)).toBe(v.hash);
    // The manifest is hashed as served; hashing re-encoded JSON is the mistake this vector catches.
    expect(agentUpdatePayloadHash(jcsCanonicalize(JSON.parse(v.manifest)))).not.toBe(v.hash);
  });

  it.each(vectors.keys)('key id: $label', (k) => {
    expect(keyIdFromSpki(Buffer.from(k.spkiB64, 'base64'))).toBe(k.keyId);
  });

  it('trust bundle: same text, fingerprint and verifying signatures', () => {
    const text = textOf(vectors.bundle.canonicalB64);
    expect(canonicalBundle(vectors.bundle.struct)).toBe(text);
    expect(fingerprint(text)).toBe(vectors.bundle.fingerprint);
    expect(vectors.bundle.signatures).toHaveLength(vectors.bundle.struct.threshold);
    for (const s of vectors.bundle.signatures) {
      expect(signatureVerifies(s.keyId, text, s.signatureB64)).toBe(true);
      expect(signatureVerifies(s.keyId, `${text}\n`, s.signatureB64)).toBe(false);
    }
  });

  const expectSigned = (built: string, v: Signed<unknown>, signer: string) => {
    const text = textOf(v.canonicalB64);
    expect(built).toBe(text);
    expect(signatureVerifies(signer, text, v.signatureB64)).toBe(true);
  };
  it('action approval: same text and a verifying signature', () => {
    expectSigned(canonicalActionApproval(vectors.action.struct), vectors.action, vectors.action.struct.keyId);
  });
  it('device-scoped rule: same text and a verifying signature', () => {
    expectSigned(canonicalRule(vectors.rule.struct), vectors.rule, vectors.rule.struct.keyId);
  });
  it('org-scoped rule: same text and a verifying signature', () => {
    expectSigned(canonicalRule(vectors.ruleOrg.struct), vectors.ruleOrg, vectors.ruleOrg.struct.keyId);
  });

  it('builds the same text whatever order the lists arrive in', () => {
    const { bundle, action, rule } = vectors;
    expect(canonicalBundle(edit(bundle.struct, (d) => d.keys.reverse()))).toBe(textOf(bundle.canonicalB64));
    expect(canonicalActionApproval(edit(action.struct, (d) => d.entries.reverse()))).toBe(textOf(action.canonicalB64));
    expect(
      canonicalRule(
        edit(rule.struct, (d) => {
          d.scopeDevices!.reverse();
          d.matchItems.reverse();
        }),
      ),
    ).toBe(textOf(rule.canonicalB64));
  });

  it('keeps the pure module free of Node APIs', () => {
    const source = readFileSync(join(HERE, 'index.ts'), 'utf8');
    expect(source).not.toMatch(/['"]node:/);
    expect(source).not.toMatch(/\bBuffer\b/);
  });
});

describe('jcsCanonicalize refuses what the Go twin refuses', () => {
  const nested = (depth: number): unknown => {
    let v: unknown = 'leaf';
    for (let i = 0; i < depth; i++) v = [v];
    return v;
  };

  it('allows 32 levels of nesting and rejects 33', () => {
    expect(jcsCanonicalize(nested(32))).toBe(`${'['.repeat(32)}"leaf"${']'.repeat(32)}`);
    expect(() => jcsCanonicalize(nested(33))).toThrow(/^canonical json: nesting too deep/);
  });

  it.each([
    ['NaN', NaN],
    ['Infinity', Infinity],
    ['-Infinity', -Infinity],
    ['undefined', undefined],
    ['undefined member', { a: undefined }],
    ['undefined element', [1, undefined]],
    ['sparse array', [1, , 3]],
    ['bigint', 1n],
    ['function', () => 1],
    ['symbol', Symbol('x')],
    ['Date', new Date(0)],
    ['Map', new Map()],
    ['lone high surrogate', 'a\ud800b'],
    ['lone low surrogate', 'a\udc00b'],
    ['lone surrogate in a key', { 'a\ud800': 1 }],
  ])('rejects %s', (_name, value) => {
    expect(() => jcsCanonicalize(value)).toThrow(REFUSED);
  });

  it('keeps a well-formed surrogate pair and -0 as 0', () => {
    expect(jcsCanonicalize(['😀', -0])).toBe('["\u{1F600}",0]');
  });

  it('keeps a __proto__ key that came from JSON.parse', () => {
    expect(jcsCanonicalize(JSON.parse('{"a":2,"__proto__":1}'))).toBe('{"__proto__":1,"a":2}');
  });
});

describe('payloadHashInput mirrors the Go exclusions', () => {
  const script = { content: 'echo', executionId: 'e', batchId: 'b', restorePoint: { enabled: true }, secretEnv: { A: 'b' }, secretEnvEnvelope: 'x' };

  it('drops operatorApproval and the per-delivery script fields, top level only', () => {
    expect(payloadHashInput('script', { ...script, operatorApproval: { v: 1 }, nested: { executionId: 'kept', restorePoint: 'kept' } })).toBe(
      '{"content":"echo","nested":{"executionId":"kept","restorePoint":"kept"}}',
    );
  });

  it('keeps every other key for other command types, whatever the type is called', () => {
    expect(payloadHashInput('file_delete', script)).toBe(jcsCanonicalize(script));
    expect(payloadHashInput('constructor', { a: 1, operatorApproval: 1 })).toBe('{"a":1}');
    expect(payloadHashInput('__proto__', { a: 1 })).toBe('{"a":1}');
  });

  it('does not modify its input', () => {
    const payload = { ...script, operatorApproval: 1 };
    payloadHashInput('script', payload);
    expect(payload).toEqual({ ...script, operatorApproval: 1 });
  });
});

describe('canonicalBundle refuses what the Go twin refuses', () => {
  const base = vectors.bundle.struct;
  it.each([
    ['threshold 0', (d: OperatorTrustBundleV1) => { d.threshold = 0; }],
    ['threshold above the admin count', (d: OperatorTrustBundleV1) => { d.threshold = 3; }],
    ['fractional threshold', (d: OperatorTrustBundleV1) => { d.threshold = 1.5; }],
    ['no keys', (d: OperatorTrustBundleV1) => { d.keys = []; }],
    ['mode off', (d: OperatorTrustBundleV1) => { d.mode = 'off' as never; }],
    ['unknown role', (d: OperatorTrustBundleV1) => { d.keys[0]!.role = 'owner' as never; }],
    ['duplicate keyId', (d: OperatorTrustBundleV1) => { d.keys.push({ ...d.keys[0]! }); }],
    ['uppercase keyId', (d: OperatorTrustBundleV1) => { d.keys[0]!.keyId = d.keys[0]!.keyId.toUpperCase(); }],
    ['uppercase partnerId', (d: OperatorTrustBundleV1) => { d.partnerId = d.partnerId.toUpperCase(); }],
    ['negative epoch', (d: OperatorTrustBundleV1) => { d.epoch = -1; }],
    ['fractional epoch', (d: OperatorTrustBundleV1) => { d.epoch = 1.5; }],
    ['epoch past 2^53', (d: OperatorTrustBundleV1) => { d.epoch = 2 ** 53; }],
    ['minAgentVersion without v', (d: OperatorTrustBundleV1) => { d.minAgentVersion = '0.70.0'; }],
    ['minAgentVersion with leading zero', (d: OperatorTrustBundleV1) => { d.minAgentVersion = 'v0.070.0'; }],
    ['key that is not a P-256 SPKI', (d: OperatorTrustBundleV1) => { d.keys[0]!.spkiB64 = d.keys[0]!.spkiB64.replace(/^MFkw/, 'MFkx'); }],
    ['key with stray bits in its base64', (d: OperatorTrustBundleV1) => { d.keys[0]!.spkiB64 = d.keys[0]!.spkiB64.replace(/.==$/, 'B=='); }],
    ['empty label', (d: OperatorTrustBundleV1) => { d.keys[0]!.label = ''; }],
    ['label starting with a space', (d: OperatorTrustBundleV1) => { d.keys[0]!.label = ' Jeff'; }],
    ['label ending with a space', (d: OperatorTrustBundleV1) => { d.keys[0]!.label = 'Jeff '; }],
    ['label with a line feed', (d: OperatorTrustBundleV1) => { d.keys[0]!.label = 'a\nb'; }],
    ['label with DEL', (d: OperatorTrustBundleV1) => { d.keys[0]!.label = 'a\x7fb'; }],
    ['label with a lone surrogate', (d: OperatorTrustBundleV1) => { d.keys[0]!.label = 'a\ud800'; }],
  ])('rejects %s', (_name, change) => {
    expect(() => canonicalBundle(edit(base, change))).toThrow(REFUSED);
  });

  it('accepts a label with inner spaces and with Unicode whitespace at the edge (ASCII-only edge rule)', () => {
    const label = ' Jeff ';
    const firstKeyLine = canonicalBundle(edit(base, (d) => { d.keys[0]!.label = label; })).split('\n')[7]!;
    expect(firstKeyLine.endsWith(` ${label}`)).toBe(true);
  });
});

describe('canonicalActionApproval refuses what the Go twin refuses', () => {
  const base = vectors.action.struct;
  const times = (issuedAt: string, expiresAt: string, commandType = 'script') => (d: OperatorActionApprovalV1) => {
    d.issuedAt = issuedAt;
    d.expiresAt = expiresAt;
    d.commandType = commandType;
  };
  const T0 = '2026-11-19T12:00:00Z';

  it.each([
    ['uppercase commandType', (d: OperatorActionApprovalV1) => { d.commandType = 'Script'; }],
    ['commandType starting with a digit', (d: OperatorActionApprovalV1) => { d.commandType = '1script'; }],
    ['commandType of 65 characters', (d: OperatorActionApprovalV1) => { d.commandType = 'a'.repeat(65); }],
    ['no entries', (d: OperatorActionApprovalV1) => { d.entries = []; }],
    ['501 entries', (d: OperatorActionApprovalV1) => { d.entries = devices(501, true); }],
    ['the same device twice under two hostnames', (d: OperatorActionApprovalV1) => { d.entries.push({ ...d.entries[0]!, hostname: 'other', payloadHash: 'b'.repeat(64) }); }],
    ['an entry without a payload hash', (d: OperatorActionApprovalV1) => { delete d.entries[0]!.payloadHash; }],
    ['an uppercase hostname', (d: OperatorActionApprovalV1) => { d.entries[0]!.hostname = 'SRV-01'; }],
    ['approvalId that is not 32 hex', (d: OperatorActionApprovalV1) => { d.approvalId = d.approvalId.slice(1); }],
    ['expiry equal to issue time', times(T0, T0)],
    ['expiry before issue time', times(T0, '2026-11-19T11:59:59Z')],
    ['expiry over 24 hours', times(T0, '2026-11-20T12:00:01Z')],
    ['a session type over 2 minutes', times(T0, '2026-11-19T12:02:01Z', 'tunnel_open')],
    ['a time with fractional seconds', times(T0, '2026-11-19T12:30:00.5Z')],
    ['a time spelled with zero fractional seconds', times(T0, '2026-11-19T12:30:00.000Z')],
    ['a time with an offset', times(T0, '2026-11-19T12:30:00+00:00')],
    ['an issue time on a day that does not exist', times('2026-11-31T12:00:00Z', '2026-12-01T12:30:00Z')],
    ['an issue time at hour 24', times('2026-11-19T24:00:00Z', '2026-11-20T00:30:00Z')],
  ])('rejects %s', (_name, change) => {
    expect(() => canonicalActionApproval(edit(base, change))).toThrow(REFUSED);
  });

  it.each(['terminal_start', 'start_desktop', 'desktop_stream_start', 'tunnel_open'])('refuses a 3-minute %s approval', (type) => {
    expect(() => canonicalActionApproval(edit(base, times(T0, '2026-11-19T12:03:00Z', type)))).toThrow(REFUSED);
  });

  it('accepts the limits themselves: 500 entries, 24 hours, 2 minutes for a session type, a 64-character type', () => {
    expect(() => canonicalActionApproval(edit(base, (d) => { d.entries = devices(500, true); }))).not.toThrow();
    expect(() => canonicalActionApproval(edit(base, times(T0, '2026-11-20T12:00:00Z')))).not.toThrow();
    for (const type of ['terminal_start', 'start_desktop', 'desktop_stream_start', 'tunnel_open']) {
      expect(() => canonicalActionApproval(edit(base, times(T0, '2026-11-19T12:02:00Z', type)))).not.toThrow();
    }
    expect(() => canonicalActionApproval(edit(base, (d) => { d.commandType = 'a'.repeat(64); }))).not.toThrow();
  });
});

describe('canonicalRule refuses what the Go twin refuses', () => {
  const devicesRule = vectors.rule.struct;
  const orgRule = vectors.ruleOrg.struct;
  it.each([
    ['neither an org nor devices', edit(devicesRule, (d) => { delete d.scopeDevices; })],
    ['both an org and devices', edit(devicesRule, (d) => { d.scopeOrgId = orgRule.scopeOrgId!; })],
    ['an empty device list', edit(devicesRule, (d) => { d.scopeDevices = []; })],
    ['501 scope devices', edit(devicesRule, (d) => { d.scopeDevices = devices(501, false); })],
    ['a scope device twice under two hostnames', edit(devicesRule, (d) => { d.scopeDevices!.push({ ...d.scopeDevices![0]!, hostname: 'other' }); })],
    ['a scope device carrying a payload hash', edit(devicesRule, (d) => { d.scopeDevices![0]!.payloadHash = 'a'.repeat(64); })],
    ['no match items', edit(devicesRule, (d) => { d.matchItems = []; })],
    ['a duplicate match item', edit(devicesRule, (d) => { d.matchItems.push(d.matchItems[0]!); })],
    ['an unknown match kind', edit(devicesRule, (d) => { d.matchKind = 'regex' as never; })],
    ['a patch item with a leading space', edit(devicesRule, (d) => { d.matchItems[0] = ' KB1'; })],
    ['a patch item with a trailing space', edit(devicesRule, (d) => { d.matchItems[0] = 'KB1 '; })],
    ['a patch item with a tab', edit(devicesRule, (d) => { d.matchItems[0] = 'KB\t1'; })],
    ['a payload hash that is not 64 lowercase hex', edit(orgRule, (d) => { d.matchItems[0] = d.matchItems[0]!.toUpperCase(); })],
    ['an org id in uppercase', edit(orgRule, (d) => { d.scopeOrgId = 'AAAAAAAA-2222-4333-8444-555555555555'; })],
    ['a notAfter with fractional seconds', edit(orgRule, (d) => { d.notAfter = '2026-12-19T12:00:00.5Z'; })],
    ['a ruleId that is not 32 hex', edit(orgRule, (d) => { d.ruleId = d.ruleId.slice(1); })],
    ['a non-boolean once', edit(orgRule, (d) => { d.once = 'false' as never; })],
  ])('rejects %s', (_name, rule) => {
    expect(() => canonicalRule(rule)).toThrow(REFUSED);
  });

  it('has no cap on match items, and orders them by UTF-8 bytes rather than UTF-16 units', () => {
    const many = Array.from({ length: 600 }, (_, i) => i.toString(16).padStart(64, '0'));
    expect(() => canonicalRule(edit(orgRule, (d) => { d.matchItems = many; }))).not.toThrow();
    const lines = canonicalRule(edit(devicesRule, (d) => { d.matchItems = ['x\u{1F600}', 'xדּ']; })).split('\n');
    expect(lines.slice(lines.indexOf('matchItems=2') + 1, lines.indexOf('once=true'))).toEqual(['xדּ', 'x\u{1F600}']);
  });
});
