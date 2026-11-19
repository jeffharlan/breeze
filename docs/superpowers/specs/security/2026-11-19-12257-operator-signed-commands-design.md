---
issue: 12257
status: draft — awaiting second opinion and maintainer agreement
---

# Operator-signed commands (#12257)

## Intent

Today an agent runs any risky command the API delivers. Whoever controls the API host
(database, process, and its environment — including `APP_ENCRYPTION_KEY`, which unlocks the
deployment signing key in `manifest_signing_keys`) can run code on every enrolled device at once.

**Goal:** a full compromise of the Breeze server must not, by itself, be able to make agents run
code, install software, write files, open remote control, or destroy data. A risky action needs a
signature from an operator's own key, checked **on the agent** against keys the server cannot add
or change.

**Why now:** an MSP pilot wants to expand from a test group to its whole fleet; this is the open
blocker.

## Goals

1. Agents refuse Tier A commands (below) that lack a valid operator approval, once enforcement is on.
2. One operator approval can cover a bulk action (many devices).
3. Scheduled and automatic work (patching, remediation, scheduled scripts) keeps running under
   **standing approvals**: rules an operator signs once.
4. Existing fleets can migrate without downtime: `off → audit → enforce`.
5. A lost key cannot brick a fleet: there is a documented recovery path.

## Non-goals

- Protecting against a compromised **endpoint** (local admin on the device can already do anything).
- Protecting confidentiality of reads (`file_read`, screenshots, event logs) in phase 1. Listed as a
  phase 2 option.
- Replacing server-side RBAC, MFA, or the approval inbox. Those stay; this adds a check the server
  cannot fake.
- Changing the vendor-signed update path (already outside the server's reach).

## Anti-goals (would make this a failure even if it "works")

- Any path where the server can add, swap, or remove an operator key, or lower the enforcement
  mode, without an operator signature.
- Approvals that cover "whatever the server sends next" (a rule must bind exact content hashes).
- Silently dropping automation: if a standing rule stops matching, the operator must see why.
- A design LanternOps cannot maintain: one gate, one canonical format, one tier table.

## Threat model

| Attacker | In scope? | Result after this change |
|---|---|---|
| Full API host compromise (DB + process + env + Redis) | Yes — the target | Cannot run Tier A on any device without an operator's tap. Can still: deny service, read data the server already holds, send Tier B commands (reboot, restart service), replay nothing (single-use approvals), and **swap the content an operator is shown in the web UI** (see "What you see is what you sign"). |
| DB-only compromise | Yes | Same as above, strictly weaker. |
| Stolen operator login (password/session) | Yes | Cannot approve without the operator's key device. |
| Stolen operator key device + unlock | Partly | Can approve; limited by the operator's scope; revocable by another operator. |
| Compromised endpoint | No | Out of scope. |
| Server compromised **before** a device first pins trust | Partly | Trust-on-first-use window. Mitigated by fingerprint check (below). |

## Background (today's code)

- One agent choke point: `dispatchCommand` (`agent/internal/heartbeat/handlers.go:119`), reached by
  both the poll path and the WebSocket path. It already has a payload guard for diagnostic
  authorizations (`handlers.go:127`).
- Queue bypasses: terminal, desktop and tunnel frames go through `sendCommandToAgent` directly from
  `routes/terminalWs.ts`, `desktopWs.ts`, `tunnelWs.ts`, `tunnelHttpCore.ts`.
- ~164 registered command types; ~80 are risky.
- Prior art reused here:
  - Frozen TOFU + monotonic-epoch key rotation: `agent/internal/config/manifestkeys.go`,
    `manifestdelegation.go`.
  - Line-based canonical bytes with a domain string, short expiry and replay cache:
    `diagaccess_grant.go` / `services/diagnosticAccess/authorization.ts`.
  - Approver device keys: `services/approverWebAuthn.ts` (platform WebAuthn, UV required),
    `apps/mobile/src/services/attestingSigner.ts` (Secure Enclave / StrongBox P-256, attested),
    `services/mobileHwKey.ts`, `services/authenticatorAssurance.ts` (L1–L4).
- Gap in all of the above: verification happens on the **server**; the agent never sees the
  operator's signature.

## Approaches considered

| Approach | Trade-off | Decision |
|---|---|---|
| A. Operator-signed commands with per-action taps **and** operator-signed standing rules | Most build; keeps automation; the only option that removes the "silent mass compromise" | **Chosen** (by the requester, 2026-11-19) |
| B. Per-action taps only | Simpler; stops all scheduled automation | Rejected: automation is core RMM value |
| C. Move deployment key to a separate signer/HSM | Cheap; server can still ask the signer to sign anything | Rejected as the fix; may still be worth doing separately |
| D. Harden the host only | Lowers likelihood, not blast radius | Rejected as the fix |

## Design

### 1. Tiers

A static table in the agent, `agent/internal/opsign/tiers.go`, maps every registered command type
to a tier. A unit test fails if any `handlerRegistry` key is missing from the table, so a new
command cannot ship untiered. **Unknown types default to Tier A.**

- **Tier A — needs operator approval when enforcing.** Code and shell (`script`, `run_script`,
  `task_run`, `computer_action`, `http_request`, terminal/desktop/tunnel *session start*), software
  and patches (`software_install|update|uninstall`, `install_patches`, `rollback_patches`,
  `oem_update_run`, `homebrew_bootstrap`), agent self-change (`dev_update`, `set_auto_update`,
  `self_uninstall`), privilege and policy (`actuate_elevation`, `pam_apply_v2`, `pam_cleanup_v2`,
  `apply_cis_remediation`, `apply_audit_policy_baseline`, `manage_startup_item`,
  `peripheral_policy_sync*`), file and registry writes (`file_write`, `registry_set`), restore and
  containment (`bare_metal_rebuild`, `bmr_recover`, `vm_restore_from_backup`, `vm_instant_boot`,
  `backup_restore`, `mssql_restore`, `hyperv_restore`, `execute_containment`,
  `release_containment`), **and destructive data operations** (`file_delete`,
  `secure_delete_file`, `encrypt_file`, `file_trash_purge`, `registry_delete`,
  `registry_key_delete`, `encryption_rotate_key`).
- **Tier B — unsigned in phase 1.** Availability-only actions: reboot/shutdown/lock family,
  service and process control, task enable/disable, backups (create, not restore), time settings,
  quarantine/restore of threats, cleanup. Rationale: worst case is an outage, not code execution or
  data loss. Revisit in phase 2.
- **Tier C — unsigned.** Reads and telemetry. Phase 2 option for confidentiality.

The exact table is finalized in the plan by walking `handlerRegistry`; the lists above are the
intent.

### 2. Operator trust root on the agent

**Operator key.** A P-256 (ES256) key held in hardware by one operator: either a mobile-app
Secure Enclave/StrongBox key (strong channel, §5) or a WebAuthn credential (web channel). Each key
has an opaque `keyId`, a public key (SPKI), a channel (`mobile` | `webauthn`), and for WebAuthn the
`rpId` and allowed origins.

**Trust bundle.** A partner-wide document listing the operator keys and the enforcement mode:

```
breeze-operator-trust-bundle-v1
partnerId
epoch            (strictly increasing)
mode             (audit | enforce)
keys             (sorted list: keyId, alg, spkiB64, channel, rpId, origins, label)
threshold        (signatures needed to change the bundle; default 1, recommended 2)
notBefore / notAfter
```

**Pinning rules** (copied from `manifestkeys.go` / `manifestdelegation.go`, but rooted in operator
keys, not the deployment key):

- **First pin (bootstrap):** the agent accepts a bundle with no signature requirement **only** when
  it has none pinned. The bundle reaches the agent either (a) as `operator-trust.json` placed beside
  the installer / passed as an MSI/PKG property, or (b) from the enrollment response. Either way the
  agent logs and reports the bundle **fingerprint** (first 16 hex of SHA-256 of the canonical bytes).
  The operator compares that with the fingerprint shown on their own key device (mobile app renders
  it locally) — this is how a TOFU substitution gets caught.
- **Every change after that** (add/remove key, change mode, change threshold) requires `threshold`
  signatures from keys in the **currently pinned** bundle, over the new bundle's canonical bytes, and
  a strictly higher `epoch`. The server can relay a bundle; it cannot make one.
- **Mode can only go up without a signature** (`off → audit` on first pin). Going down
  (`enforce → audit`) is a bundle change and needs signatures.
- Pinned state lives in the agent config next to `pinned_manifest_pub_keys`, written under the same
  lock and file permissions.

**Existing agents (migration).** Already-enrolled agents receive the first bundle through the
heartbeat once. This is a TOFU moment: the fingerprint is reported back and shown in the UI and on
the operator's mobile app; the operator spot-checks one or more devices locally with
`breeze-agent trust show`. Accepted risk: a server already compromised at migration time could pin
its own bundle; the fingerprint check is the detection.

**Recovery.** Lost all keys → a local administrator on the device runs `breeze-agent trust reset`
(needs local admin, which is outside the threat model) and re-pins. The UI warns when a bundle has
fewer than two keys.

### 3. Approval envelopes

One canonical format, line-based like `diagaccess_grant.go`: UTF-8, LF-joined, no trailing newline,
control characters rejected, sorted lists. The envelope is what the operator signs.

**Action approval** (one tap, one action, one or more devices):

```
breeze-operator-approval-v1
kind=action
approvalId        (random 128-bit, single use per device)
partnerId
commandType
contentHash       (per-type, §4)
deviceIds         (sorted; at most 500 — larger fans out as a rule)
issuedAt
expiresAt         (≤ 24h after issuedAt; covers offline devices within one day)
keyId
```

**Standing rule** (one tap, repeated automatic use):

```
breeze-operator-approval-v1
kind=rule
ruleId
ruleEpoch         (strictly increasing per ruleId; a new epoch replaces the old)
partnerId
scope             (org:<id> | site:<id> | devices:<sorted ids>)
commandType
contentHashes     (sorted allow-list of exact §4 hashes)
notBefore / notAfter (≤ 365 days)
keyId
```

A rule never says "any script" — it lists exact content hashes. Editing the script changes the
hash, the rule stops matching, the command is refused, and the UI shows "needs re-approval".
Revoking a rule is a new epoch with an empty hash list. (A compromised server can **withhold** a
revocation; the damage is bounded to content an operator already approved.)

Signature formats:

- **Mobile channel:** ES256 over SHA-256 of the canonical bytes, directly.
- **WebAuthn channel:** the WebAuthn challenge is `SHA-256(canonical bytes)`. The agent receives
  `authenticatorData`, `clientDataJSON`, `signature` and checks: `type == "webauthn.get"`,
  `challenge` matches, `origin` is in the key's pinned origins, `rpIdHash == SHA-256(rpId)`, UP and
  UV flags set, signature valid over `authenticatorData || SHA-256(clientDataJSON)`. Sign counters
  are ignored (synced passkeys report 0).

### 4. Content hashes per command type

Each Tier A type has a canonicalizer on **both** sides (Go and TypeScript) with shared golden test
vectors (same pattern as the diagnostic-access interop test). It hashes everything that changes what
runs. Examples:

- `script` / `run_script`: language, content, runAs, timeout, raw parameters (before rendering),
  target session, and a hash of the encrypted secret envelope's **key names** (values rotate and are
  secret; names bound so a rule cannot gain new secrets).
- `software_install`: download URL, **required** SHA-256 (the agent refuses an empty checksum when
  enforcing), silent args, file type/name, detection rules, pre/post script bodies; or package
  manager + name + version.
- `file_write`: path + SHA-256 of decoded bytes.
- `install_patches`: patch source + sorted patch ids (OS-vendor patches) or the third-party
  URL+checksum list.
- Session starts (`terminal_start`, `start_desktop`, `tunnel_open`): session id, user/role, and
  for tunnels the target host:port. Data frames are accepted only for a session whose start was
  approved.

Types without a stable content (e.g. `self_uninstall`) hash a fixed type tag plus their arguments.

### 5. What you see is what you sign

A compromised server also serves the web UI. It can show "restart the print spooler" while asking
the browser to sign the hash of a malicious script. WebAuthn authenticators do not display the
challenge, so the web channel **cannot** stop this.

Therefore:

- **Strong channel (recommended default): the native mobile app.** It is distributed through the app
  stores, not served by the Breeze server. It receives the envelope **and** the full content
  (script text, URLs, paths), recomputes the content hash locally, renders the decoded action, and
  only then signs with its hardware key. A server that swaps content gets a hash mismatch.
- **Web channel (allowed, weaker):** still removes the *silent, all-devices-at-once* attack — the
  attacker must wait for an operator to approve something and can only swap within that one tap.
  The trust bundle records each key's channel; a partner can set the bundle to require
  mobile-channel keys for Tier A.

This is a known limit, stated plainly in the UI and docs.

### 6. Agent gate

`agent/internal/opsign` (new package) exposes `Check(cmd Command, now) Decision`. It is called in
`dispatchCommand` before the handler, and in the terminal/desktop/tunnel start handlers. Order:

1. Tier lookup. Not Tier A → allow.
2. No pinned bundle or mode `off` → allow.
3. Find an `operatorApproval` payload field: either an action approval or a rule reference
   (`ruleId`, plus the rule envelope and its signature attached by the server at delivery).
4. Verify signature against a key in the pinned bundle; check partner, expiry, device (own deviceId
   in list or in scope), command type, content hash recomputed from **this** payload.
5. Action approvals: record `approvalId` in a durable replay store (on disk, pruned after expiry)
   and refuse reuse.
6. Rules: check the latest pinned `ruleEpoch` for that `ruleId` (persisted; older epochs refused).
7. Mode `audit` → log and report the would-be refusal, then allow. Mode `enforce` → refuse with a
   distinct error code (`E_OPSIGN_*`) the server shows as "needs operator approval".

The approval field is stripped before the handler runs so handlers never see it.

### 7. Server side

- **Tables** (partner-wide first, per `docs/agents/tenancy-rls.md`; RLS + policies in the creating
  migration; registered in cascade, merge and export lists):
  - `operator_signing_keys` (partner_id): public key, channel, rpId/origins, owner user, status.
  - `operator_trust_bundles` (partner_id): epoch, canonical bytes, signatures.
  - `operator_approvals` (org_id): action envelopes + signatures, linked to `device_commands`.
  - `operator_standing_rules` (partner_id XOR org_id): rule envelopes + signatures, linked to the
    producer (automation, patch policy, deployment, etc.).
- **Delivery:** `prepareClaimedCommandsForDelivery` attaches the matching approval or rule to each
  Tier A command. The server never signs anything here.
- **Producers with no human present** (automations, patch scheduler, policy remediation, software
  deployment, CIS, PAM actuation, DR, offboarding, fleet findings, AI/Wisp): each looks up a
  matching standing rule; if none matches it still queues the command, and the agent's audit/refusal
  is surfaced in the UI as "needs approval" with a one-tap path to create the rule.
- **AI/Wisp:** may propose; never holds a key. A Tier A proposal becomes a pending approval for a
  human.
- **UI:** key registration (mobile + web), trust bundle page (keys, threshold, mode, fingerprint,
  devices that report a different fingerprint), approval prompts, rule list with "stopped matching"
  status.

### 8. Rollout

1. Ship agent with gate in `audit` only. Collect would-be refusals per producer.
2. Ship server signing, rules, and UI. Operators create keys and the first bundle.
3. Turn a pilot group to `enforce` via a signed bundle change. Watch refusals.
4. Fleet-wide `enforce`.

### 9. Self-hosted local update manifests

With `BINARY_SOURCE=local`, update manifests are signed by the deployment key (server-held). In
`enforce` mode the agent refuses a deployment-key-only manifest unless a standing rule of type
`agent_update` lists that binary's SHA-256. Vendor-signed manifests are unaffected.

## Open for the builder (minor, builder's call)

- File layout inside `agent/internal/opsign` and the API service split.
- Replay store format (journal file vs small bbolt), as long as it survives restarts and is pruned.
- Exact UI wording and placement (must follow `docs/agents/settings.md`: the trust bundle has one
  home, at partner level).

## Delivery (several PRs, in order)

1. Agent: tier table + test, `opsign` package, canonical format + golden vectors, gate in `audit`.
2. Agent: trust bundle pinning + `breeze-agent trust show|reset`.
3. API + migration: keys, bundles, approvals, rules tables; delivery attachment.
4. Mobile app: sign envelopes with the attested key; render content; fingerprint view.
5. Web: key registration, bundle page, approval prompt (WebAuthn), rule management.
6. Producers: rule lookup for each automatic producer.
7. Enforce mode + session-start gating for terminal/desktop/tunnel + local update manifests.
