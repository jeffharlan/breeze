---
issue: 12257
delivery_step: 1 of 7
status: draft 2026-11-19 — maintainer reply on #12257 still pending; do not open a PR past this step without one
---

# Operator-signed commands — Step 1: format freeze + agent core — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Freeze the signed formats (with Go + TS golden vectors) and ship an agent that can pin an operator trust bundle and, under `enforce`, refuse every Tier A command and every deployment-key-only agent update that lacks a valid operator approval — proven end to end for `script`.

**Architecture:** A new Go package `agent/internal/opsign` holds the formats, the tier table, an on-disk state store (pin, high-water time, replay set) and one gate. The gate is called once in `dispatchCommand` and once in `Updater.verifyUpdateManifest`, which every update, rollback-staging, helper, watchdog and watchdog-failover path already passes through. A pure TS twin in `packages/shared/src/operatorSigning/` builds the same bytes for the API (step 3) and the mobile app (step 2). The server still signs nothing.

**Tech Stack:** Go 1.x stdlib (`crypto/ecdsa`, `crypto/elliptic`, `crypto/x509`, `crypto/sha256`), cobra, `golang.org/x/mod/semver` via `internal/versionpolicy`; TypeScript + Vitest in `packages/shared`.

**Spec:** `docs/superpowers/specs/security/2026-11-19-12257-operator-signed-commands-design.md` (§1 tiers, §2 trust root, §3 envelopes, §4 updater, §6 gate). Read it before any task.

## Global Constraints

- No new third-party dependency in `agent/go.mod` or any `package.json` (supply-chain hardening). JCS is hand-written here.
- Domain lines, verbatim: `breeze-operator-trust-bundle-v1`, `breeze-operator-approval-v1`.
- Canonical text: UTF-8, LF line ends, **no trailing newline**, any rune `< 0x20` or `== 0x7f` in a field is rejected (copy `rejectControl` from `agent/internal/remote/tools/diagaccess_grant.go:126`).
- Signature: ECDSA P-256 over SHA-256(canonical bytes); wire form **raw `r||s`, 64 bytes, standard base64** (JOSE ES256). Step 2's app converts Secure Enclave/StrongBox DER output to this.
- `keyId` = lowercase hex of the first 16 bytes of SHA-256(SPKI DER) (32 chars). The agent recomputes it from `spkiB64`; a mismatch is malformed.
- Bundle fingerprint = lowercase hex of the first 16 bytes of SHA-256(bundle canonical bytes) (32 chars, 128 bits). Display as 8 groups of 4.
- Times: RFC 3339 UTC, whole seconds, `Z` suffix (`2006-01-02T15:04:05Z`).
- IDs (`partnerId`, `deviceId`, `orgId`) lowercase UUID text. `approvalId`/`ruleId` = 32 lowercase hex. Hostnames lowercase, `[a-z0-9._-]{1,253}`.
- Action envelope: `expiresAt - issuedAt` ≤ 24h; ≤ 2 min for session types (`terminal_start`, `start_desktop`, `desktop_stream_start`, `tunnel_open`). ≤ 500 entries.
- Rule `notAfter` ≤ 90 days after signing time is a phone/API rule; the agent only parses rules in this step.
- `issuedAt` more than 5 minutes ahead of the agent clock → refuse (`opsign_malformed`).
- Payload key carrying the approval: `operatorApproval`. Always stripped before any handler runs, whatever the tier.
- Wire error codes (lowercase, mirrored in TS): `opsign_no_approval`, `opsign_malformed`, `opsign_bad_signature`, `opsign_unknown_key`, `opsign_wrong_target`, `opsign_payload_mismatch`, `opsign_expired`, `opsign_replayed`, `opsign_pin_unreadable`, `opsign_identity_changed`, `opsign_rule_unsupported`, `opsign_update_unapproved`, `opsign_below_floor`.
- Mode `off` = no pin on disk. `audit` = log and allow. `enforce` = refuse. A pin that exists but cannot be read refuses Tier A in every mode.
- Go tests in `internal/heartbeat` need `CGO_ENABLED=0` on this machine (missing `pcap.h`).
- TS scoped runs: `cd packages/shared && npx vitest run <path>` — never `pnpm --filter … test -- --run`.
- Commits start `#12257`; author "Jeff Harlan" <jeff@harlanfamily.com> (repo-local config, already set).

## Review Focus

1. **Old agents with an empty `config.DeviceID`** (enrolled before the field existed): pinning must be refused and logged, not pinned with an empty identity — otherwise every Tier A command is later refused with a confusing code. → Task 6 test `TestPinRefusedWithoutDeviceID`.
2. **A Windows hostname with upper case or an underscore** (`ACCT-PC_02`): the agent must lower-case before comparing, and `_` must be allowed, or enforce breaks real machines. → Task 7 test `TestGateHostnameCaseInsensitive`.
3. **Clock jumps far forward** (bad NTP, BIOS battery): high-water time jumps and every approval looks expired forever. The documented way out is `trust reset`, which must also reset high-water to the current clock. → Task 9 test `TestTrustResetResetsHighWater`.
4. **Two commands with the same approval arrive at once** (poll + WebSocket race): exactly one may run. → Task 5 test `TestReplayConcurrentClaim`.
5. **A payload number written as `1` by the API and decoded by Go as `float64(1)`**: both sides must hash to the same text, and large integers must not drift. → Task 1 vectors `num-int`, `num-2^53`.

Not covered here, flagged for the reviewer: the watchdog reads the same state file through `config.GetDataDir()`; when a support-session workspace is registered, `GetDataDir` returns the workspace path in the agent but maybe not in the watchdog (unverified, design hand-off). Task 8 tests the default path only.

## Not in this step (later delivery steps)

- Reporting fingerprint / mode / refusals to the server in the heartbeat (step 3 — the API's heartbeat schema must accept it first).
- Installer property for `operator-trust.json` (MSI/pkg work; step 3).
- Gating heartbeat fields other than updates — rebind, identity sync, time-sync settings, containment state (step 4). Step 1 does the **identity pin**: Tier A is refused if the live identity drifted from the pin.
- Rule verification (step 5). The gate refuses rule envelopes with `opsign_rule_unsupported`.
- Live-session check for session data frames (step 6).

---

### Task 1: Canonical JSON (RFC 8785) and payload hash — Go

**Files:**
- Create: `agent/internal/opsign/jcs.go`, `agent/internal/opsign/payloadhash.go`
- Test: `agent/internal/opsign/jcs_test.go`, `agent/internal/opsign/payloadhash_test.go`

**Interfaces:**
- Produces: `func Canonicalize(v any) ([]byte, error)`; `const PayloadKey = "operatorApproval"`; `func PayloadHash(commandType string, payload map[string]any) (string, error)` (64 lowercase hex); `var payloadExclusions = map[string][]string{"script": {"executionId", "batchId", "secretEnv", "secretEnvEnvelope", "restorePoint"}}`.

- [ ] **Step 1: Write the failing tests.** Table test `TestCanonicalizeVectors` with exact expected strings:
  - `map[string]any{"b":1.0,"a":"x"}` → `{"a":"x","b":1}`
  - numbers: `0`→`0`, `math.Copysign(0,-1)`→`0`, `1e21`→`1e+21`, `1e20`→`100000000000000000000`, `0.000001`→`0.000001`, `1e-7`→`1e-7`, `5e-324`→`5e-324`, `1.7976931348623157e308`→`1.7976931348623157e+308`, `9007199254740992`→`9007199254740992` (vector `num-2^53`), `333333333.33333329`→`333333333.3333333`, `float64(1)`→`1` (vector `num-int`)
  - strings: `" <&>é"` → `" <&>é"` raw (no HTML escaping), `"\n\t\"\\"` → `"\n\t\"\\"`, `"\x01"` → `"\u0001"`
  - keys sorted by UTF-16 code units: `{"€":1,"\U0001F600":2}` → `€` key first (0x20AC < 0xD83D in UTF-16).
  - errors: `math.NaN()`, `math.Inf(1)`, invalid UTF-8 string, nesting depth 33.
  - `json.Number("1.50")` → `1.5`.
- [ ] **Step 2:** `cd agent && go test ./internal/opsign/ -run TestCanonicalize` → FAIL (undefined).
- [ ] **Step 3: Implement `Canonicalize`.** Accept `nil, bool, float64, json.Number, string, []any, map[string]any`; anything else is an error. Max depth 32. Number formatting is ES6 `Number::toString`, which Go has no direct call for:

```go
// s = shortest digits, n = decimal exponent position, from strconv.FormatFloat(abs, 'e', -1, 64)
// k = len(s)
// k <= n <= 21      → s + strings.Repeat("0", n-k)
// 0 < n <= 21       → s[:n] + "." + s[n:]
// -6 < n <= 0       → "0." + strings.Repeat("0", -n) + s
// otherwise         → d[.ddd] + "e" + ("+"|"-") + abs(n-1)
// negative values get a leading "-"; -0 prints "0"
```

  Strings: escape `"` `\` `\b` `\f` `\n` `\r` `\t`, other `< 0x20` as `\u00xx` (lowercase hex), everything else raw.
- [ ] **Step 4:** run → PASS.
- [ ] **Step 5: Payload-hash tests** `TestPayloadHash`: (a) `operatorApproval` key never affects the hash; (b) for `script`, changing `executionId`, `batchId`, `secretEnv`, `secretEnvEnvelope` does not change the hash, changing `content`, `parameters`, `runAs`, `language`, `timeoutSeconds`, `acknowledgedSecurityPatterns`, `targetSessionId` does; (c) for `file_delete` (no exclusion list) every key counts; (d) the input map is not mutated.
- [ ] **Step 6: Implement `PayloadHash`**: shallow-copy, drop `PayloadKey` and the type's exclusions, `Canonicalize`, SHA-256, hex. Exclusion source for `script`: `apps/api/src/services/scriptDispatch.ts:744-776` — `executionId`/`batchId` are per-delivery IDs; secrets are server-held values the operator must not see (accepted limit: a script that executes a secret's value as code can be steered — say so in the PR).
- [ ] **Step 7:** run both tests → PASS. Commit `#12257 opsign: RFC 8785 canonical JSON and payload hash`.

### Task 2: Signed formats — Go

**Files:**
- Create: `agent/internal/opsign/format.go`, `agent/internal/opsign/sig.go`
- Test: `agent/internal/opsign/format_test.go`, `agent/internal/opsign/sig_test.go`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces:
  - `type Role string` (`RoleAdmin = "admin"`, `RoleApprover = "approver"`); `type Mode string` (`ModeAudit = "audit"`, `ModeEnforce = "enforce"`).
  - `type BundleKey struct{ KeyID, SPKIB64 string; Role Role; Label string }`
  - `type Bundle struct{ PartnerID string; Epoch uint64; Mode Mode; Threshold int; MinAgentVersion string; Keys []BundleKey }`; `func (b Bundle) CanonicalBytes() ([]byte, error)`; `func ParseBundle(canonical []byte) (Bundle, error)`; `func Fingerprint(canonical []byte) string`.
  - `type Entry struct{ DeviceID, Hostname, PayloadHash string }`
  - `type ActionApproval struct{ ApprovalID, PartnerID, CommandType string; Entries []Entry; IssuedAt, ExpiresAt time.Time; KeyID string }`
  - `type Rule struct{ RuleID string; RuleEpoch uint64; PartnerID string; ScopeOrgID string; ScopeDevices []Entry /*PayloadHash empty*/; CommandType, MatchKind string; MatchItems []string; Once bool; NotAfter time.Time; KeyID string }`
  - `func ParseEnvelope(canonical []byte) (any /* ActionApproval | Rule */, error)`; `CanonicalBytes()` on both.
  - `type Carrier struct{ V int \`json:"v"\`; CanonicalB64 string \`json:"canonicalB64"\`; SignatureB64 string \`json:"signatureB64"\` }`
  - `type SignedBundle struct{ CanonicalB64 string \`json:"canonicalB64"\`; Signatures []BundleSig \`json:"signatures"\` }`; `type BundleSig struct{ KeyID, SignatureB64 string }` (json `keyId`, `signatureB64`).
  - `func KeyIDFromSPKI(spkiDER []byte) string`; `func VerifyES256(spkiB64 string, msg, sigB64 string) error` (msg = canonical bytes; hashes inside).

Exact layouts (one field per line, `key=value`; list = count line then one item per line, item fields separated by one space):

```
breeze-operator-trust-bundle-v1      breeze-operator-approval-v1      breeze-operator-approval-v1
partnerId=<uuid>                     kind=action                      kind=rule
epoch=<uint>                         approvalId=<32hex>               ruleId=<32hex>
mode=audit|enforce                   partnerId=<uuid>                 ruleEpoch=<uint>
threshold=<int>                      commandType=<type>               partnerId=<uuid>
minAgentVersion=<vX.Y.Z or empty>    entries=<n>                      scope=org:<uuid> | scope=devices
keys=<n>                             <deviceId> <hostname> <hash>     [scopeDevices=<n> + "<deviceId> <hostname>" lines]
<keyId> <role> <spkiB64> <label>     issuedAt=<time>                  commandType=<type>
                                     expiresAt=<time>                 match=payloadHashes|patchItems
                                     keyId=<32hex>                    matchItems=<n> + one item per line
                                                                      once=true|false
                                                                      notAfter=<time>
                                                                      keyId=<32hex>
```

Sorting: keys by `keyId`; entries/scopeDevices by `deviceId` then `hostname`; matchItems bytewise. Label is the remainder of its line (may contain spaces, not empty). Duplicates in any list are malformed.

- [ ] **Step 1: Tests** `TestBundleRoundTrip`, `TestActionRoundTrip`, `TestRuleRoundTrip`: build → `CanonicalBytes` → `Parse` → equal struct and byte-identical re-serialization. `TestParseRejects` table: trailing newline, CRLF, unsorted keys, duplicate entry, unknown kind, wrong domain line, `keyId` not matching its SPKI, uppercase hex, 501 entries, threshold 0, threshold > admin count, empty label, control char in label, unknown mode `off`, expiry > 24h, session type with expiry 3 min, extra trailing line. `TestVerifyES256`: generate a P-256 key, sign SHA-256 of bytes, encode raw r||s → ok; flipped byte → error; DER-encoded sig → error; 63-byte sig → error.
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3: Implement.** `Parse*` reads strictly, then calls `CanonicalBytes()` on the result and requires byte equality with the input (one rule to reject every non-canonical form).
- [ ] **Step 4:** run → PASS. Commit `#12257 opsign: freeze bundle, action and rule formats`.

### Task 3: Shared golden vectors + TS twin

**Files:**
- Create: `agent/internal/opsign/testdata/operator_signing_v1_vectors.json`, `agent/internal/opsign/vectors_test.go`
- Create: `packages/shared/src/operatorSigning/index.ts`, `packages/shared/src/operatorSigning/node.ts`, `packages/shared/src/operatorSigning/interop.test.ts`
- Modify: `packages/shared/package.json` (exports `./operatorSigning` and `./operatorSigning/node`)

**Interfaces:**
- Consumes: Task 1 `Canonicalize`, `PayloadHash`; Task 2 types and `CanonicalBytes`.
- Produces (TS, `index.ts`, pure — no `node:*` imports, so React Native can use it in step 2): `jcsCanonicalize(value: unknown): string`; `payloadHashInput(commandType: string, payload: Record<string, unknown>): string` (the JCS text the hash is taken over); `canonicalBundle(b: OperatorTrustBundleV1): string`; `canonicalActionApproval(a: OperatorActionApprovalV1): string`; `canonicalRule(r: OperatorRuleV1): string`; types mirroring Task 2 with camelCase fields and ISO time strings. `node.ts`: `payloadHash(...)`, `keyIdFromSpki(spkiDer: Buffer)`, `fingerprint(canonical: string)` using `node:crypto`.
- Fixture shape: `{ "jcs": [{name, input, canonical}], "payloadHash": [{name, commandType, payload, hash}], "keys": [{keyId, spkiB64, role, label}], "bundle": {struct, canonicalB64, fingerprint, signatures:[{keyId, signatureB64}]}, "action": {struct, canonicalB64, signatureB64}, "rule": {struct, canonicalB64, signatureB64} }`. Test private keys are **not** stored; only public keys and signatures.

- [ ] **Step 1:** Write `TestGenerateVectors` guarded by `-update` flag (`flag.Bool("update", …)`) that creates two P-256 keys, builds a sample bundle (2 admins, threshold 2, mode `audit`, `minAgentVersion=v0.70.0`), a `script` action approval with 2 entries whose hashes come from `PayloadHash`, and one rule, signs them, and writes the fixture. Include the Task 1 vectors `num-int` and `num-2^53`.
- [ ] **Step 2:** `cd agent && go test ./internal/opsign/ -run TestGenerateVectors -update` → fixture written. Commit fixture.
- [ ] **Step 3:** Write `TestVectorsVerify` (no flag): parse each canonical, compare to struct, re-run `PayloadHash` and `Canonicalize`, verify every signature, check fingerprint. Run → PASS.
- [ ] **Step 4:** Write `interop.test.ts`: read the fixture via `readFileSync(join(__dirname, '../../../../agent/internal/opsign/testdata/operator_signing_v1_vectors.json'))`; for each vector assert TS canonical text equals `Buffer.from(canonicalB64,'base64').toString('utf8')`, JCS equals, payload hash equals, fingerprint and keyIds equal, and each signature verifies with `crypto.verify('sha256', bytes, {key: spki DER, format:'der', type:'spki', dsaEncoding:'ieee-p1363'}, sig)`. Also assert `index.ts` source contains no `node:` import.
- [ ] **Step 5:** `cd packages/shared && npx vitest run src/operatorSigning/interop.test.ts` → FAIL, implement `index.ts`/`node.ts` (JCS in TS = sorted keys by default string order + `JSON.stringify` for primitives; reject non-finite numbers), run → PASS.
- [ ] **Step 6:** Commit `#12257 opsign: Go/TS golden vectors and shared TS builders`.

### Task 4: Tier table

**Files:**
- Create: `agent/internal/opsign/tiers.go`
- Test: `agent/internal/heartbeat/opsign_tiers_test.go` (lives in `heartbeat` because `handlerRegistry` is unexported there)

**Interfaces:**
- Produces: `type Tier int` (`TierA`, `TierB`, `TierC`); `func TierOf(commandType string) Tier` (unknown → `TierA`); `func KnownTypes() []string`; `func IsSessionType(commandType string) bool`.

Classification (165 registry keys: 68 A, 35 B, 62 C; everything not listed under A or B is C):

- **A:** `actuate_elevation agent_rollback_v1 apply_audit_policy_baseline apply_cis_remediation backup_cleanup backup_restore backup_run backup_test_restore bare_metal_rebuild bmr_recover computer_action desktop_stream_start dev_update encrypt_file encryption_rotate_key execute_containment file_copy file_delete file_mkdir file_rename file_trash_purge file_trash_restore file_write homebrew_bootstrap http_request hyperv_backup hyperv_checkpoint hyperv_restore install_patches manage_startup_item mssql_backup mssql_restore network_http_check oem_update_release oem_update_run pam_apply_v2 pam_cleanup_v2 pam_reconcile_v2 peripheral_policy_sync peripheral_policy_sync_v2 quarantine_file registry_delete registry_key_create registry_key_delete registry_set release_containment rollback_patches run_script script secure_delete_file security_threat_quarantine security_threat_remove security_threat_restore self_uninstall set_auto_update software_install software_uninstall software_update start_desktop system_cleanup_run task_run terminal_start time_apply_policy time_set_timezone tunnel_open vault_configure vm_instant_boot vm_restore_from_backup`
- **B:** `backup_stop cancel_reboot chat_close chat_message chat_open desktop_stream_stop download_patches force_reboot hyperv_vm_state kill_process lock network_diagnostic_cancel notify_user pam_request_notify reboot reboot_safe_mode restart_service retract_message schedule_reboot script_cancel security_scan set_log_level shutdown start_service stop_desktop stop_service support_end task_disable task_enable terminal_stop time_resync tray_update tunnel_close vault_sync wake_on_lan`
- **C note:** `terminal_data terminal_resize tunnel_data desktop_input desktop_config` are session frames; step 6 adds the live-session check.
- Judgement calls the reviewer must confirm: `oem_update_release` (A, unclear effect), `backup_test_restore` (A, writes files), `tray_update`, `vault_sync`, `hyperv_vm_state`, `chat_*`, `notify_user`, `security_scan` (B; its auto-quarantine destination is agent-owned). Moved to A after review: `backup_run`, `mssql_backup`, `hyperv_backup` (payload chooses destination and credentials), `security_threat_remove`, `security_threat_quarantine`, `quarantine_file` (caller-chosen path or directory), `network_http_check` (any-method, any-URL request).

- [ ] **Step 1:** Tests: `TestEveryRegisteredTypeHasATier` (every `handlerRegistry` key is in `KnownTypes()`), `TestNoStaleTierEntries` (every `KnownTypes()` entry is registered), `TestUnknownTypeIsTierA`, `TestDesignTierAListIsTierA` (the spec §1 Tier A names that exist in the registry), `TestSessionTypes`.
- [ ] **Step 2:** `cd agent && CGO_ENABLED=0 go test ./internal/heartbeat/ -run 'Tier|SessionTypes'` → FAIL.
- [ ] **Step 3:** Implement as one `map[string]Tier` literal.
- [ ] **Step 4:** run → PASS. Commit `#12257 opsign: tier table with registry-completeness test`.

### Task 5: State store (pin, high-water time, replay)

**Files:**
- Create: `agent/internal/opsign/store.go`
- Test: `agent/internal/opsign/store_test.go`

**Interfaces:**
- Produces:
  - `type Pin struct{ Bundle SignedBundle; Fingerprint, DeviceID, OrgID, PartnerID, Hostname string; PinnedAt time.Time }`
  - `type Store struct{ … }`; `func OpenStore(path string) *Store`; `var DefaultStorePath = func() string { return filepath.Join(config.GetDataDir(), "opsign", "state.json") }` (tests override).
  - `func (s *Store) Load() (pin *Pin, err error)` — `nil, nil` when no file; `ErrPinUnreadable` when the file exists but fails to parse or its bundle fails `ParseBundle`/fingerprint check.
  - `func (s *Store) SavePin(p Pin) error`; `func (s *Store) ClearPin(expectFingerprint string) error`; `func (s *Store) ExpectFingerprint() string`.
  - `func (s *Store) Now(clock time.Time) time.Time` — returns `max(highWater, clock)` and raises high-water.
  - `func (s *Store) ObserveIssuedAt(t time.Time)` — raises high-water.
  - `func (s *Store) ClaimApproval(approvalID string, expiresAt time.Time) error` — `ErrReplayed` if present; prunes entries with `expiresAt <= highWater`.
  - `func (s *Store) ResetHighWater(clock time.Time) error`.

File: JSON, mode `0600`, dir `0700`, temp-file + fsync + rename (same approach as `atomicWriteFile` in `internal/config`). One `sync.Mutex` per store; a package-level map makes `OpenStore` return the same `*Store` for the same path. High-water is persisted on every `ClaimApproval` and otherwise at most once a minute.

- [ ] **Step 1:** Tests: `TestLoadNoFile`, `TestLoadCorruptIsUnreadable` (garbage bytes, valid JSON with a tampered bundle), `TestPinRoundTrip`, `TestHighWaterNeverMovesBack` (feed clock 10:00, then 09:00 → `Now` returns 10:00; survives reopen), `TestReplayRejected`, `TestReplaySurvivesRestart`, `TestReplayPruned`, `TestReplayConcurrentClaim` (100 goroutines claim the same ID → exactly one nil), `TestFileMode0600` (skip on Windows).
- [ ] **Step 2:** run → FAIL. **Step 3:** implement. **Step 4:** run → PASS.
- [ ] **Step 5:** Commit `#12257 opsign: on-disk pin, high-water time and replay store`.

### Task 6: Trust — first pin, bundle change, identity pin, pin sources

**Files:**
- Create: `agent/internal/opsign/trust.go`
- Modify: `agent/internal/heartbeat/heartbeat.go` (field `OperatorTrustBundle *opsign.SignedBundle \`json:"operatorTrustBundle,omitempty"\`` on `HeartbeatResponse` at :387; apply call next to `applyManifestKeyDelegations` at :6261), agent start-up in `agent/internal/agentapp/main.go` (read `<config.ConfigDir()>/operator-trust.json` once)
- Test: `agent/internal/opsign/trust_test.go`, `agent/internal/heartbeat/opsign_pin_test.go`

**Interfaces:**
- Consumes: Task 2 `ParseBundle`, `VerifyES256`, `Fingerprint`; Task 5 `Store`.
- Produces: `type Identity struct{ DeviceID, OrgID, Hostname string }`; `func LocalIdentity(deviceID, orgID string) (Identity, error)` (lower-cases `os.Hostname()`); `func ApplyBundle(s *Store, sb SignedBundle, id Identity, now time.Time) (applied bool, err error)`; errors `ErrPinIdentityMissing`, `ErrBundleRejected`.

Rules (spec §2):
- **No pin:** require `id.DeviceID` and `id.OrgID` non-empty; require ≥ `threshold` valid signatures from distinct **admin** keys of the bundle itself; if `ExpectFingerprint()` is set the fingerprint must equal it. Save `Pin` with `PartnerID = bundle.PartnerID` (the agent has no other partner source). Log the fingerprint at INFO.
- **Pin exists:** same `partnerId`; epoch strictly greater; ≥ pinned `threshold` signatures from distinct admin keys of the **pinned** bundle over the new bytes; and the new bundle must also meet its own threshold with its own admin keys (no lock-out bundles). Identity fields in `Pin` are never changed here.
- Same bundle again (equal fingerprint) → `applied=false, nil` (no log noise).

- [ ] **Step 1:** Tests: `TestFirstPin`, `TestFirstPinNeedsOwnThreshold`, `TestPinRefusedWithoutDeviceID`, `TestFirstPinHonoursExpectFingerprint`, `TestChangeNeedsPinnedAdmins` (signed by an approver key → rejected; by one admin when threshold 2 → rejected; by a key only in the new bundle → rejected), `TestChangeEpochMustIncrease`, `TestChangePartnerFixed`, `TestChangeKeepsIdentity`, `TestReapplySameBundleIsNoop`. Heartbeat test: a response with `operatorTrustBundle` pins on a fresh store and a bad one leaves the store byte-identical.
- [ ] **Step 2:** run → FAIL. **Step 3:** implement. **Step 4:** `cd agent && go test ./internal/opsign/ && CGO_ENABLED=0 go test ./internal/heartbeat/ -run Opsign` → PASS.
- [ ] **Step 5:** Commit `#12257 opsign: first pin, bundle change and identity pin`.

### Task 7: Gate + `dispatchCommand` wiring + error codes

**Files:**
- Create: `agent/internal/opsign/gate.go`
- Modify: `agent/internal/heartbeat/handlers.go:119-140` (call the gate after the diagnostic-authorization guard, before `handler(h, cmd)`), `agent/internal/heartbeat/heartbeat.go` (a `opsignGate *opsign.Gate` field, built where `Heartbeat` is constructed), `agent/internal/wire/errorcodes.go` (the 13 codes + `AllCommandErrorCodes`), `apps/api/src/routes/agents/schemas.ts` (`AGENT_COMMAND_ERROR_CODES` mirror)
- Test: `agent/internal/opsign/gate_test.go`, `agent/internal/heartbeat/opsign_dispatch_test.go`

**Interfaces:**
- Consumes: Tasks 1, 2, 4, 5, 6.
- Produces: `type Decision struct{ Allow bool; Mode Mode; Code wire.CommandErrorCode; Reason string }`; `type Gate struct{ Store *Store; Identity func() (Identity, error) }`; `func (g *Gate) Check(commandType string, payload map[string]any, clock time.Time) Decision`; `func (g *Gate) CheckUpdate(u UpdateCheck) error` (Task 8).

`Check` order (spec §6): tier ≠ A → allow. `Load`: none → allow (mode off); unreadable → refuse `opsign_pin_unreadable` **in every mode**. Live identity ≠ pin (`DeviceID`, `OrgID`) → `opsign_identity_changed`. No `operatorApproval` → `opsign_no_approval`. Decode `Carrier` → `ParseEnvelope`; a `Rule` → `opsign_rule_unsupported`. Key must be in pinned bundle (admin or approver) → else `opsign_unknown_key`; `VerifyES256` → `opsign_bad_signature`. `partnerId` = pin, `commandType` = this type, an entry with `deviceId` = pin and `hostname` = live lower-cased hostname → else `opsign_wrong_target`; that entry's hash = `PayloadHash(type, payload)` → else `opsign_payload_mismatch`. `issuedAt` > clock + 5 min → `opsign_malformed`; `ObserveIssuedAt`; `expiresAt <= Store.Now(clock)` → `opsign_expired`. `ClaimApproval` → `opsign_replayed`. In `audit` every refusal becomes `Allow=true` with the code kept for the log line. Claim only after every other check passes.

In `dispatchCommand`: `d := h.opsignGate.Check(cmd.Type, cmd.Payload, time.Now())`; if `!d.Allow` return `tools.NewErrorResult(withErrorCode(d.Code, …), ms), true` (export a small helper from `tools` if `withErrorCode` is unexported); log every non-empty `d.Code` with `type`, `commandId`, `mode`, `code`; then `delete(cmd.Payload, opsign.PayloadKey)` unconditionally.

- [ ] **Step 1: Tests** (gate, all with a fixture pin in `enforce` unless named): `TestGateTierCAllowed`, `TestGateNoPinAllows`, `TestGateUnreadablePinRefusesInAudit`, `TestGateValidScriptApproval`, `TestGateEachRefusalCode` (one sub-test per code above, except update codes), `TestGateHostnameCaseInsensitive` (pin `acct-pc_02`, `os.Hostname` stub `ACCT-PC_02`), `TestGateIdentityDrift`, `TestGateAuditAllowsButReportsCode`, `TestGateExpiryUsesHighWater` (approval valid at 10:00, high-water already 12:00, clock 10:00 → expired), `TestGateReplayAfterRestart`, `TestGateUnknownTypeNeedsApproval`, `TestGateExcludedScriptFieldsDoNotBreakHash`. Dispatch tests: an enforce pin + unsigned `script` returns `Status:"failed"`, `ErrorCode:"opsign_no_approval"` and the handler is never called (swap the registry entry for a spy); a signed `script` reaches the handler without `operatorApproval` in its payload; a Tier C command with a stray `operatorApproval` key reaches its handler with the key removed.
- [ ] **Step 2:** run → FAIL. **Step 3:** implement and wire. Add the codes to both lists.
- [ ] **Step 4:** `cd agent && go test ./internal/opsign/ ./internal/wire/ && CGO_ENABLED=0 go test ./internal/heartbeat/` → PASS; `cd apps/api && npx vitest run src/routes/agents/schemas.commandResult.test.ts` → PASS.
- [ ] **Step 5:** Commit `#12257 opsign: gate every Tier A command in dispatchCommand`.

### Task 8: Updater — approval for deployment-signed manifests, version floor, watchdog

**Files:**
- Modify: `agent/internal/updater/updater.go` — `verifyManifestSignature` (:859) returns the key ID that verified; `downloadInfo` (:1226) gains `OperatorApproval *opsign.Carrier \`json:"operatorApproval,omitempty"\``; `verifyUpdateManifest` (:1294) calls the gate after the signature and field checks pass.
- Modify: `agent/internal/opsign/gate.go` (`CheckUpdate`)
- Test: `agent/internal/opsign/gate_update_test.go`, `agent/internal/updater/updater_opsign_test.go`, `agent/cmd/breeze-watchdog/opsign_floor_test.go`

**Interfaces:**
- Consumes: Task 7 `Gate`, `versionpolicy.Normalize`.
- Produces: `func (u *Updater) verifyManifestSignature(payload, signature []byte, signingKeyID string) (matchedKeyID string, err error)`; `type UpdateCheck struct{ Version, ArtifactSHA256 string; VendorSigned bool; Approval *Carrier; Clock time.Time }`; `func DefaultGate() *Gate` (store at `DefaultStorePath()`, identity from `config.Load("")`), used by the updater so every caller — `updateTo`, `DownloadBinary`, `StageRollbackArtifacts`, helper downloads, watchdog `doUpdateAgent`/`doUpdateWatchdog` — inherits it with no wiring.

`CheckUpdate` (spec §4), only when a pin exists (unreadable pin → refuse):
- `Version < bundle.MinAgentVersion` (both via `versionpolicy.Normalize`; an unparsable target is below the floor) → `opsign_below_floor`, **whoever signed it**.
- `VendorSigned` = the matched key is one of `embeddedManifestPublicKeys`. If not vendor-signed: require `Approval` as an action envelope with `commandType = "agent_update"` and an entry for this device whose `payloadHash` = `ArtifactSHA256` (plain artifact hash, not JCS), plus the same key/signature/expiry/replay checks as `Check` → else `opsign_update_unapproved`.
- `audit` logs and allows.
- Artifact SHA-256 and version: `updateManifest.Checksum` / `.Version`; for release-style manifests the asset `verifyReleaseArtifactManifest` selected and `.Release`.

Out of reach of this gate, by design: `dev_update` uses checksum-only `DownloadAndVerify`/`UpdateFromURL` (`handlers_devupdate.go:143,354,394`) — it is a Tier A command and already gated in `dispatchCommand`. State this in the PR.

- [ ] **Step 1: Tests:** `TestCheckUpdateFloor` (enforce: v0.69.9 refused, v0.70.0 allowed, garbage refused, vendor-signed below floor refused), `TestCheckUpdateDeploymentKeyNeedsApproval`, `TestCheckUpdateVendorSignedNeedsNoApproval`, `TestCheckUpdateAuditAllows`, `TestCheckUpdateNoPinAllows`. Updater test (httptest server, existing fakes in `updater_test.go`): a deployment-key-signed manifest under an enforce pin fails `UpdateTo` with `opsign_update_unapproved`; same with a valid approval passes; `StageRollbackArtifacts` to a version below the floor fails `opsign_below_floor`. Watchdog test: `doUpdateAgent` to a below-floor version with an enforce pin in a temp store returns an error containing `opsign_below_floor`.
- [ ] **Step 2:** run → FAIL. **Step 3:** implement. **Step 4:** `cd agent && go test ./internal/opsign/ ./internal/updater/ ./cmd/breeze-watchdog/ && CGO_ENABLED=0 go test ./internal/heartbeat/` → PASS.
- [ ] **Step 5:** Commit `#12257 opsign: version floor and operator approval in the updater`.

### Task 9: CLI `breeze-agent trust show | reset`

**Files:**
- Create: `agent/internal/agentapp/trust_cmd.go` (pattern: `containment_cmd.go`, `newTrustCommand(store func() *opsign.Store) *cobra.Command`)
- Modify: `agent/internal/agentapp/main.go:336-346` (register)
- Test: `agent/internal/agentapp/trust_cmd_test.go`

**Interfaces:**
- Consumes: Task 5 `Store`, Task 6 `ApplyBundle`.
- Produces: `trust show` prints, one per line: `mode`, `epoch`, `fingerprint` (8 groups of 4), `partner`, `device`, `org`, `hostname`, `highWater`, then `key <keyId> <role> <label>` lines; prints `mode: off` with no pin; exits 2 on an unreadable pin. `trust reset --expect <32 hex, groups/spaces allowed>`: requires elevation (reuse the containment command's elevation check), clears the pin, sets `ExpectFingerprint`, resets high-water to the current clock, and if `<ConfigDir>/operator-trust.json` exists and matches, pins it at once; otherwise the next matching bundle from the heartbeat pins.

- [ ] **Step 1:** Tests: `TestTrustShowNoPin`, `TestTrustShowPinned` (golden output), `TestTrustShowUnreadableExit2`, `TestTrustResetRequiresExpect`, `TestTrustResetPinsMatchingFile`, `TestTrustResetIgnoresMismatchedFile`, `TestTrustResetResetsHighWater`.
- [ ] **Step 2:** run → FAIL. **Step 3:** implement. **Step 4:** `cd agent && go test ./internal/agentapp/ -run Trust` → PASS.
- [ ] **Step 5:** Commit `#12257 opsign: trust show and trust reset commands`.

### Task 10: Whole-branch check and PR

- [ ] `cd agent && go vet ./... && CGO_ENABLED=0 go test -race ./...` → PASS.
- [ ] `cd packages/shared && npx vitest run src/operatorSigning` and `cd apps/api && npx vitest run src/routes/agents/schemas` → PASS.
- [ ] Compression pass over `agent/internal/opsign/` and the TS module; record it in the PR.
- [ ] Run `spec-review` against #12257 for delivery step 1.
- [ ] **Only if #12257 has a maintainer reply that accepts the approach:** push to `fork`, open PR `#12257 Operator-signed commands (step 1 of 7: formats and agent gate)` from `jeffharlan/breeze` to `LanternOps/breeze` `main`, body starting `Part of #12257`, with sections: what is gated, accepted limits (secret values, `dev_update` path, workspace data dir), tier judgement calls, compression pass.
