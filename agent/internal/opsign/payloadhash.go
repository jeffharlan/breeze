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
// per-delivery IDs; secretEnv/secretEnvEnvelope are server-held values the
// operator never sees. Accepted limit: a script that executes a secret's value
// as code can be steered through that value. Every other field, including ones
// added later, is covered by default.
var payloadExclusions = map[string][]string{
	"script": {"executionId", "batchId", "secretEnv", "secretEnvEnvelope"},
}

// PayloadHash returns the lowercase hex SHA-256 of the canonical JSON of the
// whole command payload, minus PayloadKey and the command type's exclusions.
// The caller's map is not modified.
func PayloadHash(commandType string, payload map[string]any) (string, error) {
	covered := maps.Clone(payload)
	if covered == nil {
		covered = map[string]any{}
	}
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
