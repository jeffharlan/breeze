package opsign

import (
	"encoding/json"
	"reflect"
	"regexp"
	"testing"
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func scriptPayload() map[string]any {
	return map[string]any{
		"scriptId":                     "11111111-1111-4111-8111-111111111111",
		"executionId":                  "exec-1",
		"batchId":                      "batch-1",
		"language":                     "bash",
		"content":                      "echo hi",
		"parameters":                   map[string]any{"a": "1"},
		"secretEnv":                    map[string]any{"TOKEN": "s3cret"},
		"secretEnvEnvelope":            "sealed-1",
		"timeoutSeconds":               60.0,
		"runAs":                        "system",
		"acknowledgedSecurityPatterns": []any{"curl-pipe-sh"},
		"targetSessionId":              "sess-1",
	}
}

func mustHash(t *testing.T, commandType string, payload map[string]any) string {
	t.Helper()
	h, err := PayloadHash(commandType, payload)
	if err != nil {
		t.Fatalf("PayloadHash: %v", err)
	}
	return h
}

func TestPayloadHash(t *testing.T) {
	t.Run("format and golden value", func(t *testing.T) {
		h := mustHash(t, "file_delete", map[string]any{"b": 1.0, "a": "x"})
		if !hex64.MatchString(h) {
			t.Fatalf("not 64 lowercase hex: %q", h)
		}
		// sha256 of {"a":"x","b":1}, computed independently with sha256sum.
		if want := "cdab067e9f3beb32d1252cfd63e492592fecbf591b0d08cadb24bb17f3864246"; h != want {
			t.Fatalf("got %s want %s", h, want)
		}
	})

	t.Run("operatorApproval never affects the hash", func(t *testing.T) {
		base := map[string]any{"path": "/tmp/x"}
		with := map[string]any{"path": "/tmp/x", PayloadKey: map[string]any{"anything": "here"}}
		if mustHash(t, "file_delete", base) != mustHash(t, "file_delete", with) {
			t.Fatal("operatorApproval changed the hash")
		}
		if mustHash(t, "script", scriptPayload()) != mustHash(t, "script", withKey(scriptPayload(), PayloadKey, "x")) {
			t.Fatal("operatorApproval changed the script hash")
		}
	})

	t.Run("script delivery-time fields are excluded", func(t *testing.T) {
		base := mustHash(t, "script", scriptPayload())
		for _, key := range []string{"executionId", "batchId", "secretEnv", "secretEnvEnvelope"} {
			if got := mustHash(t, "script", withKey(scriptPayload(), key, "changed")); got != base {
				t.Errorf("changing %s changed the hash", key)
			}
			p := scriptPayload()
			delete(p, key)
			if got := mustHash(t, "script", p); got != base {
				t.Errorf("removing %s changed the hash", key)
			}
		}
	})

	t.Run("script content-bearing fields are covered", func(t *testing.T) {
		base := mustHash(t, "script", scriptPayload())
		changes := map[string]any{
			"content":                      "echo bye",
			"parameters":                   map[string]any{"a": "2"},
			"runAs":                        "user",
			"language":                     "powershell",
			"timeoutSeconds":               61.0,
			"acknowledgedSecurityPatterns": []any{},
			"targetSessionId":              "sess-2",
			"scriptId":                     "22222222-2222-4222-8222-222222222222",
			"newFutureField":               "x",
		}
		for key, val := range changes {
			if mustHash(t, "script", withKey(scriptPayload(), key, val)) == base {
				t.Errorf("changing %s did not change the hash", key)
			}
		}
		p := scriptPayload()
		delete(p, "targetSessionId")
		if mustHash(t, "script", p) == base {
			t.Error("removing targetSessionId did not change the hash")
		}
	})

	t.Run("types without an exclusion list count every key", func(t *testing.T) {
		payload := map[string]any{"path": "/tmp/x", "executionId": "e", "batchId": "b", "secretEnv": "s", "secretEnvEnvelope": "x"}
		base := mustHash(t, "file_delete", payload)
		for _, key := range []string{"path", "executionId", "batchId", "secretEnv", "secretEnvEnvelope"} {
			if mustHash(t, "file_delete", withKey(payload, key, "changed")) == base {
				t.Errorf("file_delete ignored %s", key)
			}
		}
	})

	t.Run("exclusions are per command type and top level only", func(t *testing.T) {
		p := map[string]any{"content": "x", "nested": map[string]any{"executionId": "a"}}
		q := map[string]any{"content": "x", "nested": map[string]any{"executionId": "b"}}
		if mustHash(t, "script", p) == mustHash(t, "script", q) {
			t.Fatal("nested executionId must stay covered")
		}
	})

	t.Run("the input map is not mutated", func(t *testing.T) {
		p := scriptPayload()
		p[PayloadKey] = map[string]any{"sig": "x"}
		before := deepCopy(t, p)
		mustHash(t, "script", p)
		if !reflect.DeepEqual(before, p) {
			t.Fatal("PayloadHash mutated its input")
		}
	})

	t.Run("nil and empty payloads hash like an empty object", func(t *testing.T) {
		if mustHash(t, "file_delete", nil) != mustHash(t, "file_delete", map[string]any{}) {
			t.Fatal("nil and empty differ")
		}
	})

	t.Run("canonicalization errors propagate", func(t *testing.T) {
		if _, err := PayloadHash("file_delete", map[string]any{"bad": "a\xff"}); err == nil {
			t.Fatal("expected error for invalid UTF-8")
		}
	})

	t.Run("API-side and agent-side decoding hash the same", func(t *testing.T) {
		const doc = `{"path":"/tmp/x","mode":420,"force":true,"limits":[1,2.5]}`
		var m map[string]any
		if err := json.Unmarshal([]byte(doc), &m); err != nil {
			t.Fatal(err)
		}
		// sha256 of {"force":true,"limits":[1,2.5],"mode":420,"path":"/tmp/x"}, via sha256sum.
		const want = "af119de6df47bcdcec6efb2c950118ceaf7b77745376f8a71ad06a3c7815b1e5"
		if got := mustHash(t, "file_delete", m); got != want {
			t.Fatalf("got %s want %s", got, want)
		}
	})
}

func withKey(m map[string]any, key string, val any) map[string]any {
	out := make(map[string]any, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	out[key] = val
	return out
}

func deepCopy(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
