package opsign

import (
	"crypto/sha256"
	"encoding/hex"
	"maps"
)

// PayloadKey is the command payload key that carries the approval itself; it is
// never part of what is hashed or what a handler sees.
const PayloadKey = "operatorApproval"

// payloadExclusions lists, per command type, top-level payload fields the server
// sets at delivery time that cannot change what runs. Source:
// apps/api/src/services/scriptDispatch.ts. executionId and batchId are
// per-delivery IDs; restorePoint is re-resolved at delivery (fresh requestId and
// validUntil, restorePointRequest.ts), and the whole block is excluded, its
// on/off switch included; secretEnv/secretEnvEnvelope are server-held values
// the operator never sees. Accepted limits: the server can turn off the pre-run
// restore point without a signature (ruling R8), and a script that executes a
// secret's value as code can be steered through that value. Every other field,
// including ones added later, is covered by default.
var payloadExclusions = map[string][]string{
	"script": {"executionId", "batchId", "restorePoint", "secretEnv", "secretEnvEnvelope"},
}

// PayloadHash returns the lowercase hex SHA-256 of the canonical JSON of the
// whole command payload, minus PayloadKey and the command type's exclusions.
// The caller's map is not modified.
func PayloadHash(commandType string, payload map[string]any) (string, error) {
	covered := maps.Clone(payload)
	delete(covered, PayloadKey)
	for _, key := range payloadExclusions[commandType] {
		delete(covered, key)
	}
	canonical, err := Canonicalize(covered)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// AgentUpdatePayloadHash is the payload hash of an agent_update approval: the
// lowercase hex SHA-256 of the update manifest text exactly as served, the same
// bytes its signature is checked over, never re-encoded. Binding the whole
// signed text covers the version and every file it lists (the macOS .pkg the
// updater installs included), where one artifact's hash covered one file.
func AgentUpdatePayloadHash(manifest []byte) string {
	sum := sha256.Sum256(manifest)
	return hex.EncodeToString(sum[:])
}
