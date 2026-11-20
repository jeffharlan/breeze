---
issue: 12257
status: v2 approved by requester 2026-11-19 (phone-only signing; USB security keys deferred) — awaiting maintainer agreement
---

# Operator-signed commands (#12257)

## Intent

Today an agent runs any risky command the API delivers. Whoever controls the API host (database,
process, environment — including `APP_ENCRYPTION_KEY`, which unlocks the deployment signing key in
`manifest_signing_keys`) can run code on every enrolled device at once. The same deployment key also
signs update manifests, rollback directives, rebind directives and key delegations, and is pinned by
**every** agent through the heartbeat (`apps/api/src/routes/agents/heartbeat.ts:2763`), regardless
of `BINARY_SOURCE`.

**Goal:** a full compromise of the Breeze server must not, by itself, be able to make agents run
code, replace or downgrade the agent, install software, write or destroy files, change device trust
or identity, or open remote control. Those actions need a signature from an operator's own hardware
key, checked **on the agent** against keys the server cannot add, swap or remove.

**Why now:** an MSP pilot wants to expand from a test group to its whole fleet; this is the open
blocker.

## Goals

1. Under `enforce`, agents refuse Tier A actions — commands, update/rollback/upgrade paths, and
   trust-changing heartbeat fields — without a valid operator approval.
2. One operator approval can cover a bulk action (chunked by device).
3. Scheduled work (patching, scheduled scripts, software deployment, remediation) keeps running under
   **standing rules** an operator signs once.
4. Migration without downtime: `off → audit → enforce`.
5. Losing a key cannot brick a fleet: documented local recovery.

## Non-goals

- A compromised **endpoint** (local admin can already do anything).
- Confidentiality of reads (`file_read`, screenshots, logs) — phase 2 option.
- Replacing server-side RBAC, MFA or the approval inbox. They stay.
- Signing from the web browser in v1 (see §5).

## Anti-goals

- Any path where the server can add, swap or remove an operator key, lower the mode, change the
  device's pinned identity, or move the device's clock backwards in a way that revives approvals.
- A path where an operator's phone signs bytes it did not first decode and show.
- Approvals that cover "whatever the server sends next": every approval binds exact payload hashes.
- Silent automation loss: a rule that stops matching is visible in the UI.

## Threat model

| Attacker | Result under `enforce` |
|---|---|
| Full API host compromise (DB + process + env + Redis) | Cannot run any Tier A action without an operator tap on an operator phone that shows the real content. **Can still:** deny service; read server-held data; send Tier B commands (outage only); withhold rule revocations (bounded to already-approved content, ≤ 90 days); **inject input into a remote session an operator opened** (terminal/desktop traffic is relayed by the server — §6; end-to-end session keys are phase 2). |
| DB-only compromise | Strictly weaker than above. |
| Stolen operator web login | Cannot approve: approvals need the operator's phone key. |
| Stolen + unlocked operator phone | Can approve actions within that key's role; cannot change the bundle alone once threshold ≥ 2; revocable by other admins. |
| Compromised endpoint | Out of scope. |
| Server compromised **before** a device first pins trust | TOFU window. Detected by a 128-bit fingerprint the operator checks locally (§2). |

## Background (today's code)

- Command choke point: `dispatchCommand` (`agent/internal/heartbeat/handlers.go:119`), only caller
  `heartbeat.go:8207`, used by both poll and WebSocket paths. Existing payload guard at `:127`.
- **Not** through that choke point: heartbeat response fields (`heartbeat.go:6169-6391` — upgrade
  offers for agent/helper/watchdog, manifest keys, delegations, rebind directive, time-sync settings,
  network containment state `containment.go:460-480`), and the watchdog's own command channel
  (`agent/cmd/breeze-watchdog/main.go:1576`, `1644-1675`).
- Server direct-push: 15 non-test API files call `sendCommandToAgent` (terminal, desktop, tunnel,
  `tunnelHttpCore.ts` via `sendCommandToAgentAwaitResult`, `routes/remote/sessions.ts`,
  `routes/tunnels.ts`, `routes/monitors.ts`, `agentCommandRelay.ts`, …) — not only the queue.
- Updater trusts the embedded vendor key **and** pinned deployment keys (`updater.go:719-775`,
  `859-878`). Rollback has no version floor (`rollback/executor.go`). The downgrade guard lives only
  in `heartbeat/version_downgrade.go:19`.
- The mobile approver signs a server-supplied nonce string verbatim
  (`apps/mobile/src/services/approverDevice.ts:509-516`) — fine for login step-up, unsafe as an
  envelope signer.
- Prior art reused: frozen TOFU + monotonic epoch (`manifestkeys.go`, `manifestdelegation.go`);
  line-based domain-separated canonical bytes and interop golden vectors (`diagaccess_grant.go`,
  `services/diagnosticAccess/`); attested Secure Enclave / StrongBox P-256 keys
  (`apps/mobile/src/services/attestingSigner.ts`).

## Approaches considered

| Approach | Trade-off | Decision |
|---|---|---|
| A. Operator-signed per-action approvals **and** operator-signed standing rules | Most build; keeps automation; removes silent mass compromise | **Chosen** by the requester, 2026-11-19 |
| B. Per-action approvals only | Simpler; stops all scheduled automation | Rejected |
| C. Move the deployment key to a separate signer/HSM | Server can still ask it to sign anything | Rejected as the fix |
| D. Host hardening only | Lowers likelihood, not blast radius | Rejected as the fix |

**Signing channel** (decided in this design, after review): v1 signs **only** in the native mobile
app. Web/WebAuthn signing was cut — a compromised server serves the web page, can swap what any
passkey prompt signs (including a bundle change that adds its own key), platform passkeys are
cloud-synced, and the server can swap the public key at web registration.

## Design

### 1. Tiers

A static table `agent/internal/opsign/tiers.go` maps every `handlerRegistry` key to a tier; a unit
test fails on any missing key. **Unknown types are Tier A.**

- **Tier A — operator approval required under `enforce`:**
  - Code and shell: `script`, `run_script`, `task_run`, `computer_action`, `http_request`,
    `network_http_check`, `terminal_start`, `start_desktop`, `desktop_stream_start`, `tunnel_open`.
  - Software and patches: `software_install|update|uninstall`, `install_patches`,
    `rollback_patches`, `oem_update_run`, `homebrew_bootstrap`.
  - Agent self-change: `dev_update`, `agent_rollback_v1`, `set_auto_update`, `self_uninstall`.
  - Privilege and policy: `actuate_elevation`, `pam_apply_v2`, `pam_cleanup_v2`, `pam_reconcile_v2`,
    `apply_cis_remediation`, `apply_audit_policy_baseline`, `manage_startup_item`,
    `peripheral_policy_sync*`, `vault_configure`.
  - File and registry change: `file_write`, `file_copy`, `file_rename`, `file_mkdir`, `file_delete`,
    `secure_delete_file`, `encrypt_file`, `file_trash_purge`, `file_trash_restore`, `registry_set`,
    `registry_delete`, `registry_key_create`, `registry_key_delete`.
  - Restore, containment, security: `bare_metal_rebuild`, `bmr_recover`, `vm_restore_from_backup`,
    `vm_instant_boot`, `backup_restore`, `mssql_restore`, `hyperv_restore`, `hyperv_checkpoint`,
    `backup_cleanup`, `execute_containment`, `release_containment`, `security_threat_restore`,
    `encryption_rotate_key`, `system_cleanup_run`, `backup_run`, `mssql_backup`, `hyperv_backup`
    (the payload picks the destination and credentials, so they can copy files off the device),
    `security_threat_remove`, `security_threat_quarantine`, `quarantine_file`.
  - Time: `time_apply_policy`, `time_set_timezone` (the clock protects expiry — §3).
- **Tier B — unsigned in v1 (outage only):** reboot/shutdown/lock family, start/stop/restart
  service, kill process, task enable/disable, security scan (it quarantines only into the agent's own folder),
  cancel commands.
- **Tier C — unsigned:** reads and telemetry.

The plan finalizes the list by walking the registry; when unsure, Tier A.

### 2. Trust root on the agent

**Operator signing key.** A **separate** attested P-256 key in the mobile app (Secure Enclave /
StrongBox), created only for this purpose and used only through the render-then-sign flow (§5). It
is never used for login step-up and never signs a raw server string.

**Trust bundle** (partner-wide):

```
breeze-operator-trust-bundle-v1
partnerId
epoch              strictly increasing
mode               audit | enforce
threshold          signatures required to change this bundle
minAgentVersion    nothing installs below this, whoever signed it
keys               sorted: keyId, spkiB64, role (admin | approver), label
```

**Device pin** (per agent, written at pin time, never from the bundle): `deviceId`, `orgId`,
`partnerId`, local hostname. Under `enforce`, a rebind directive or identity sync that changes these
needs an operator approval (Tier A, kind `identity`).

**Rules:**

- **First pin** — only when nothing is pinned. Sources: `operator-trust.json` beside the installer
  or passed as an installer property (preferred), or the enrollment / heartbeat response (existing
  agents). The agent logs and reports a **128-bit fingerprint** (32 hex chars of SHA-256 of the
  canonical bundle). The operator's phone renders the same fingerprint from its own copy; an operator
  checks at least one device locally with `breeze-agent trust show`. A server-rendered list of
  mismatches is a convenience only, not assurance.
- **Every later change** (keys, roles, mode, threshold, `minAgentVersion`) needs `threshold`
  signatures from **admin** keys in the currently pinned bundle and a higher epoch. The server can
  relay a bundle; it cannot make one. The bundle has no expiry date (no clock dependency).
- **Threshold** defaults to 2 as soon as two admin keys exist; the UI blocks enforce with fewer
  than two admin keys.
- **Adding a key** is phone-to-phone: the new operator's phone shows a QR with its public key; an
  admin phone scans it and signs the bundle change. The server never supplies the key bytes the
  admin signs.
- **Fail closed:** a pin that exists but is unreadable or corrupt → refuse Tier A and report.
- **Recovery:** local administrator runs `breeze-agent trust reset --expect <fingerprint>`; the
  agent re-pins only a bundle matching that fingerprint. Until it lands, Tier A and every update
  are refused in every mode (`trust show`: `mode: pending`), so a server that never sends the
  bundle cannot keep the device ungated after a reset.

### 3. Approval envelopes

One canonical format, line-based like `diagaccess_grant.go` (UTF-8, LF, no trailing newline, control
characters rejected, sorted lists). Payload hashing: **the whole command payload**, canonical JSON
(RFC 8785), minus a reviewed per-type exclusion list of fields that are set at delivery and cannot
change what runs (e.g. a presigned download URL — the required SHA-256 is bound instead). New
payload fields are therefore covered by default.

**Exception, `agent_update`:** the payload hash is the lowercase hex SHA-256 of the UTF-8 bytes of
the update manifest text, exactly the bytes the manifest signature is checked over, never parsed
and re-encoded. Binding the whole signed text covers the release version and every file it lists
(agent binary, macOS `.pkg`, helpers, watchdog), so nothing it names can be swapped. Each download
response carries its own manifest and approval: today the server signs one manifest per component
with a deployment key, so one release still needs one envelope per component (step 3 decides
whether to sign one release-wide manifest instead). Shared Go/TS test vector: `agentUpdate` in
`agent/internal/opsign/testdata/operator_signing_v1_vectors.json`.

**Action approval** (one tap; per-device entries because some values, like sourced script
parameters, are resolved per device):

```
breeze-operator-approval-v1
kind=action
approvalId       random 128-bit
partnerId
commandType
entries          sorted: deviceId, hostname, payloadHash   (≤ 500 per envelope; chunk larger sets)
issuedAt
expiresAt        ≤ 24h; ≤ 2 min for session starts
keyId
```

**Standing rule:**

```
breeze-operator-approval-v1
kind=rule
ruleId
ruleEpoch        strictly increasing per ruleId; new epoch replaces old
partnerId
scope            org:<id> | devices:<sorted deviceId+hostname>
commandType
match            payloadHashes (sorted allow-list)  |  patchItems (sorted allow-list, install_patches only)
once             true | false
notAfter         ≤ 90 days
keyId
```

- Rules are allowed only for: scheduled scripts, software deployment, patching, and remediation
  scripts. **Not** for destructive file/registry types, restores, containment, uninstall, identity
  or session starts — those are action approvals only.
- `install_patches`: the agent checks each requested patch item is in the rule's list (one request
  differs per device; the allow-list does not).
- Rules signed by a key later removed from the bundle become invalid; the key-removal flow on the
  phone offers to re-sign them.
- Revocation = new epoch with an empty list.

**Signature:** ES256 over SHA-256 of the canonical bytes, made in the app (§5).

**Time.** The agent persists a **high-water time** (largest trusted time it has seen, from its own
clock and from verified `issuedAt` values). Expiry and replay pruning use the high-water mark, never
the raw clock, so rolling the clock back cannot revive anything. Server-supplied NTP settings and the
time commands are Tier A.

**Replay.** Action `approvalId`s are stored on disk until high-water time passes their expiry
(`agent_update` approvals are the exception; see §4).
Hostname in each entry is checked against the agent's own local hostname, so an approval for one
device does not run on a device the server renamed or rebound to that ID.

### 4. Agent update, rollback and upgrade paths

Enforced inside `agent/internal/updater` so every caller (heartbeat upgrade offers, rollback,
helper/watchdog upgrades, the watchdog's own channel) inherits it. Under `enforce`:

- A manifest signed only by a deployment key needs an action approval of kind `agent_update` over
  the manifest text (§3, exception). It is not single-use: it is already tied to exact bytes, this
  device and at most 24 hours, and one release needs several downloads and retries. Accepted
  limit: until it expires the server can apply it again, including to move a device back to that
  release after a newer one was installed (the watchdog's update has no downgrade check); raising
  `minAgentVersion` stops that at once. An approval expiring at or before the replay prune floor is
  still refused.
- Nothing installs below the bundle's `minAgentVersion`, whoever signed it (closes downgrade to a
  gate-less release, including via `agent_rollback_v1` and the watchdog).
- The watchdog reads the same pinned state and applies the same check.

This ships in the **first** enforce-capable agent.

### 5. Render-then-sign (mobile app)

The server sends the app the envelope **and** the full payloads. The app:

1. Parses the envelope; refuses unknown kinds or domains.
2. Recomputes every payload hash from the payloads itself; any mismatch → refuse. For
   `agent_update` it must also refuse a manifest it cannot fully decode: any field name it does not
   know, any repeated field, any file name listed twice. The agent reads manifests loosely (field
   names in any case, last repeated field wins, first matching file entry wins), and the holder of
   the deployment key writes the manifest, so the phone must never show one reading of the text
   while the agent installs another.
3. Renders the decoded action: script text, URLs + checksums, file paths, device names, rule scope,
   expiry, and for bundle changes the exact key fingerprints added/removed.
4. Only after the operator confirms with biometrics, signs with the operator signing key.

The app never signs bytes it did not parse and render.

### 6. Agent gate

New package `agent/internal/opsign`, `Check(cmd, now) Decision`, called once in `dispatchCommand`
before the handler, and by the updater/watchdog and the heartbeat-field appliers for trust-changing
fields (rebind/identity, time sync, containment state). Steps:

1. Tier lookup. Not Tier A → allow.
2. No pin → allow (mode `off`). Pin unreadable, or a `trust reset` still waiting for its bundle →
   refuse.
3. Find the `operatorApproval` field (action envelope, or rule envelope attached at delivery).
4. Verify signature against a pinned key of a role allowed for this kind (action and `agent_update`: admin or approver; rule: admin only); check partner, own
   deviceId + hostname, command type, payload hash recomputed from **this** payload, expiry against
   high-water time.
5. Action: record `approvalId`; refuse reuse. Rule: refuse older `ruleEpoch`; honor `once`.
6. `audit` → log + report, allow. `enforce` → refuse with `E_OPSIGN_*`.

The approval field is stripped before the handler runs.

**Sessions** (`terminal_start`, `start_desktop`, `desktop_stream_start`, `tunnel_open`): the
whole start payload is hashed (shell, offer/ICE servers, target host:port), expiry ≤ 2 minutes, and
the agent enforces a maximum session length and idle timeout. Data frames are accepted only for an
approved, live session. Stated limit: the server relays session traffic and can inject into an open
session; phase 2 adds an end-to-end session key bound in the envelope.

### 7. Server side

- **Tables** (partner-wide first per `docs/agents/tenancy-rls.md`; RLS in the creating migration;
  registered in cascade, merge and export lists): `operator_signing_keys` (partner_id),
  `operator_trust_bundles` (partner_id), `operator_approvals` (org_id), `operator_standing_rules`
  (partner_id XOR org_id).
- **Attachment:** one function attaches the matching approval/rule to a Tier A command. It is called
  from `prepareClaimedCommandsForDelivery` **and** from a wrapper around `sendCommandToAgent` /
  `sendCommandToAgentAwaitResult`, so direct-push paths are covered. The server never signs.
- **No-human producers** in v1 that get rules: automations/scheduled scripts, patch scheduler,
  software deployment, remediation scripts. Everything else (DR, offboarding, containment, fleet
  findings, AI/Wisp) creates a pending action approval for a human. AI/Wisp never holds a key.
- **Web UI** (management only, no signing): bundle page (keys, roles, threshold, mode, fingerprint),
  pending approvals (approve on phone), rules with "stopped matching" status, refusals from audit.

### 8. Rollout

1. Agents ship with the gate in `audit`.
2. Operators install the app, create keys, pin the first bundle; check fingerprints locally.
3. Signed bundle change sets a pilot group to `enforce`; watch refusals.
4. Fleet-wide `enforce`.

## Cut from v1

Web/WebAuthn signing; USB/NFC security keys (later: only through the mobile app or a separately
installed desktop app, which render before signing — never through the web origin); site scope; rule `notBefore`; bundle expiry; per-type canonicalizers
(replaced by whole-payload hashing + exclusions); rules for DR/offboarding/containment/AI; the
">500 devices becomes a rule" path (chunk instead).

## Builder's calls

- File layout inside `opsign` and the API service split.
- Replay/high-water store format (must survive restarts and be pruned).
- UI wording and placement (one home at partner level, per `docs/agents/settings.md`).

## Delivery order

1. **Format freeze + agent core:** canonical format with golden vectors (Go + TS), tier table,
   pin, gate, high-water time, identity pin, updater floor and watchdog check — enforce-capable,
   wired for `script` first.
2. **Mobile app:** separate signing key, render-then-sign, QR key-add, fingerprint view
   (critical path: app-store review).
3. **API:** tables, attachment on queue **and** direct-push paths; prove `enforce` on a test group.
4. Widen to all Tier A command types and heartbeat fields.
5. Standing rules + the four producers.
6. Session starts.
7. Web management UI.
