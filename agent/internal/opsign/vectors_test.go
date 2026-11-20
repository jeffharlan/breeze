package opsign

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// The golden vectors are shared with the TypeScript twin in
// packages/shared/src/operatorSigning (interop.test.ts reads the same file), so
// the phone builds byte-identical text to what this package verifies. Private
// keys are never stored: only public keys and the signatures made with them.
const vectorsPath = "testdata/operator_signing_v1_vectors.json"

var update = flag.Bool("update", false, "rewrite "+vectorsPath+" (new keys and signatures every run)")

type vectorKey struct {
	KeyID   string `json:"keyId"`
	SPKIB64 string `json:"spkiB64"`
	Role    string `json:"role"`
	Label   string `json:"label"`
}

type vectorEntry struct {
	DeviceID    string `json:"deviceId"`
	Hostname    string `json:"hostname"`
	PayloadHash string `json:"payloadHash,omitempty"`
}

type bundleStruct struct {
	PartnerID       string      `json:"partnerId"`
	Epoch           uint64      `json:"epoch"`
	Mode            string      `json:"mode"`
	Threshold       int         `json:"threshold"`
	MinAgentVersion string      `json:"minAgentVersion"`
	Keys            []vectorKey `json:"keys"`
}

type actionStruct struct {
	ApprovalID  string        `json:"approvalId"`
	PartnerID   string        `json:"partnerId"`
	CommandType string        `json:"commandType"`
	Entries     []vectorEntry `json:"entries"`
	IssuedAt    string        `json:"issuedAt"`
	ExpiresAt   string        `json:"expiresAt"`
	KeyID       string        `json:"keyId"`
}

type ruleStruct struct {
	RuleID       string        `json:"ruleId"`
	RuleEpoch    uint64        `json:"ruleEpoch"`
	PartnerID    string        `json:"partnerId"`
	ScopeOrgID   string        `json:"scopeOrgId,omitempty"`
	ScopeDevices []vectorEntry `json:"scopeDevices,omitempty"`
	CommandType  string        `json:"commandType"`
	MatchKind    string        `json:"matchKind"`
	MatchItems   []string      `json:"matchItems"`
	Once         bool          `json:"once"`
	NotAfter     string        `json:"notAfter"`
	KeyID        string        `json:"keyId"`
}

type jcsVector struct {
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	Canonical string          `json:"canonical"`
}

type payloadHashVector struct {
	Name        string          `json:"name"`
	CommandType string          `json:"commandType"`
	Payload     json.RawMessage `json:"payload"`
	Hash        string          `json:"hash"`
}

type agentUpdateVector struct {
	Name     string `json:"name"`
	Manifest string `json:"manifest"`
	Hash     string `json:"hash"`
}

type bundleVector struct {
	Struct       bundleStruct `json:"struct"`
	CanonicalB64 string       `json:"canonicalB64"`
	Fingerprint  string       `json:"fingerprint"`
	Signatures   []BundleSig  `json:"signatures"`
}

type signedVector[S any] struct {
	Struct       S      `json:"struct"`
	CanonicalB64 string `json:"canonicalB64"`
	SignatureB64 string `json:"signatureB64"`
}

type vectorFile struct {
	JCS         []jcsVector                `json:"jcs"`
	PayloadHash []payloadHashVector        `json:"payloadHash"`
	Keys        []vectorKey                `json:"keys"`
	Bundle      bundleVector               `json:"bundle"`
	Action      signedVector[actionStruct] `json:"action"`
	Rule        signedVector[ruleStruct]   `json:"rule"`
	RuleOrg     signedVector[ruleStruct]   `json:"ruleOrg"`
	AgentUpdate []agentUpdateVector        `json:"agentUpdate"`
}

func parseVectorTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v.UTC()
}

func (s bundleStruct) bundle() Bundle {
	b := Bundle{PartnerID: s.PartnerID, Epoch: s.Epoch, Mode: Mode(s.Mode), Threshold: s.Threshold, MinAgentVersion: s.MinAgentVersion}
	for _, k := range s.Keys {
		b.Keys = append(b.Keys, BundleKey{KeyID: k.KeyID, SPKIB64: k.SPKIB64, Role: Role(k.Role), Label: k.Label})
	}
	return b
}

func entriesOf(list []vectorEntry) (out []Entry) {
	for _, e := range list {
		out = append(out, Entry{DeviceID: e.DeviceID, Hostname: e.Hostname, PayloadHash: e.PayloadHash})
	}
	return out
}

func (s actionStruct) action(t *testing.T) ActionApproval {
	return ActionApproval{
		ApprovalID: s.ApprovalID, PartnerID: s.PartnerID, CommandType: s.CommandType, Entries: entriesOf(s.Entries),
		IssuedAt: parseVectorTime(t, s.IssuedAt), ExpiresAt: parseVectorTime(t, s.ExpiresAt), KeyID: s.KeyID,
	}
}

func (s ruleStruct) rule(t *testing.T) Rule {
	return Rule{
		RuleID: s.RuleID, RuleEpoch: s.RuleEpoch, PartnerID: s.PartnerID, ScopeOrgID: s.ScopeOrgID,
		ScopeDevices: entriesOf(s.ScopeDevices), CommandType: s.CommandType, MatchKind: s.MatchKind,
		MatchItems: s.MatchItems, Once: s.Once, NotAfter: parseVectorTime(t, s.NotAfter), KeyID: s.KeyID,
	}
}

// jcsCases carry hand-written expected text, so the generator refuses to freeze
// a wrong value into the fixture. Inputs are JSON text so number spellings and
// escapes reach both decoders exactly as written.
var jcsCases = []struct{ name, input, want string }{
	{"key-order", `{"b":1,"a":"x"}`, `{"a":"x","b":1}`},
	{"nested", `{"z":[null,true,false,{}],"a":[]}`, `{"a":[],"z":[null,true,false,{}]}`},
	{"num-zero", `0`, `0`},
	{"num-negative-zero", `-0`, `0`},
	{"num-int", `1`, `1`},
	{"num-negative", `-2.5`, `-2.5`},
	{"num-1e20", `1e20`, `100000000000000000000`},
	{"num-1e21", `1e21`, `1e+21`},
	{"num-negative-1e21", `-1e21`, `-1e+21`},
	{"num-1e-6", `0.000001`, `0.000001`},
	{"num-1e-7", `1e-7`, `1e-7`},
	{"num-min-denormal", `5e-324`, `5e-324`},
	{"num-max", `1.7976931348623157e308`, `1.7976931348623157e+308`},
	{"num-2^53", `9007199254740992`, `9007199254740992`},
	{"num-2^53+1-rounds", `9007199254740993`, `9007199254740992`},
	{"num-shortest", `333333333.33333329`, `333333333.3333333`},
	{"num-spellings", `[1.50,2E-3,1E+2,-0.0]`, `[1.5,0.002,100,0]`},
	{"num-rfc-295147905179352830000", `295147905179352830000`, `295147905179352830000`},
	{"num-rfc-9.999999999999997e+22", `9.999999999999997e22`, `9.999999999999997e+22`},
	{"num-rfc-1e+23", `1e23`, `1e+23`},
	{"num-rfc-999999999999999700000", `999999999999999700000`, `999999999999999700000`},
	{"num-rfc-9.999999999999997e-7", `9.999999999999997e-7`, `9.999999999999997e-7`},
	{"num-rfc-negative-small", `-0.0000033333333333333333`, `-0.0000033333333333333333`},
	{"num-rfc-1424953923781206.2", `1424953923781206.2`, `1424953923781206.2`},
	{"str-no-html-escape", `" <&>é"`, `" <&>é"`},
	{"str-escapes", `"\n\t\"\\\b\f\r"`, `"\n\t\"\\\b\f\r"`},
	{"str-control", `"\u0001\u001f"`, `"\u0001\u001f"`},
	{"str-del-and-line-separator-raw", `"\u007f\u2028"`, "\"\x7f\u2028\""},
	{"str-astral", `"\ud83d\ude00"`, "\"\U0001F600\""},
	{"key-escaped", `{"a\"b":1}`, `{"a\"b":1}`},
	{"key-utf16-order-ascii-first", `{"é":1,"e":2,"E":3}`, `{"E":3,"e":2,"é":1}`},
	// U+FB33 is where UTF-16 order and code-point order part: UTF-16 puts the
	// surrogate pair of U+1F600 first.
	{"key-utf16-vs-codepoint-order", `{"\ufb33":1,"\ud83d\ude00":2}`, "{\"\U0001F600\":2,\"\ufb33\":1}"},
	{"key-rfc8785-section-3.2.3",
		`{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}`,
		"{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"\u00f6\":\"Latin Small Letter O With Diaeresis\"," +
			"\"\u20ac\":\"Euro Sign\",\"\U0001F600\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}"},
}

const scriptA = `{"scriptId":"11111111-1111-4111-8111-111111111111","executionId":"exec-1","batchId":"batch-1",
"restorePoint":{"requestId":"rp-1","validUntil":"2026-11-19T00:00:00Z"},"language":"bash","content":"echo \"héllo 😀\"\n",
"parameters":{"a":"1","b":2},"secretEnv":{"TOKEN":"s3cret"},"secretEnvEnvelope":"sealed-1","timeoutSeconds":60,"runAs":"system",
"acknowledgedSecurityPatterns":["curl-pipe-sh"],"targetSessionId":"sess-1",
"operatorApproval":{"v":1,"canonicalB64":"x","signatureB64":"y"}}`

var payloadCases = []struct{ name, commandType, payload string }{
	{"script-device-a", "script", scriptA},
	{"script-device-b", "script", `{"scriptId":"22222222-2222-4222-8222-222222222222","executionId":"exec-9","language":"powershell",
"content":"Get-Service | Where-Object Status -eq 'Running'","parameters":{},"timeoutSeconds":300,"runAs":"user"}`},
	// Same covered fields as script-device-a; only excluded ones differ, so the hash must match.
	{"script-device-a-excluded-fields-differ", "script", `{"scriptId":"11111111-1111-4111-8111-111111111111","executionId":"exec-2","batchId":"batch-2",
"restorePoint":{"requestId":"rp-2","validUntil":"2027-01-01T00:00:00Z"},"language":"bash","content":"echo \"héllo 😀\"\n",
"parameters":{"b":2,"a":"1"},"secretEnv":{"TOKEN":"other"},"secretEnvEnvelope":"sealed-2","timeoutSeconds":60.0,"runAs":"system",
"acknowledgedSecurityPatterns":["curl-pipe-sh"],"targetSessionId":"sess-1"}`},
	{"other-type-keeps-every-key", "file_delete", `{"path":"/tmp/x","executionId":"kept","restorePoint":{"a":1},"mode":420,"limits":[1,2.5,1e21]}`},
	{"exclusions-are-top-level-only", "script", `{"content":"x","nested":{"executionId":"a","restorePoint":"b"}}`},
	{"empty", "file_delete", `{}`},
}

// agentUpdateCases are manifest text as a server serves it, deliberately not
// canonical JSON (keys unsorted, a non-ASCII character, a trailing newline): a
// twin that re-encodes the text before hashing it gets a different hash.
var agentUpdateCases = []struct{ name, manifest string }{
	{"one-file-manifest-as-served", `{"version":"1.2.3","component":"agent","platform":"windows","arch":"amd64",` +
		`"url":"https://updates.example.invalid/releases/Général/breeze-agent-windows-amd64.exe",` +
		`"checksum":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","size":31337}` + "\n"},
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestGenerateVectors(t *testing.T) {
	if !*update {
		t.Skip("run with -update to rewrite " + vectorsPath)
	}
	var f vectorFile

	for _, c := range jcsCases {
		var in any
		if err := json.Unmarshal([]byte(c.input), &in); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got, err := Canonicalize(in)
		if err != nil || string(got) != c.want {
			t.Fatalf("%s: got %q (%v), want %q", c.name, got, err, c.want)
		}
		f.JCS = append(f.JCS, jcsVector{Name: c.name, Input: json.RawMessage(c.input), Canonical: c.want})
	}

	hashes := map[string]string{}
	for _, c := range payloadCases {
		var payload map[string]any
		if err := json.Unmarshal([]byte(c.payload), &payload); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		hash, err := PayloadHash(c.commandType, payload)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		hashes[c.name] = hash
		f.PayloadHash = append(f.PayloadHash, payloadHashVector{Name: c.name, CommandType: c.commandType, Payload: json.RawMessage(c.payload), Hash: hash})
	}
	if hashes["script-device-a"] != hashes["script-device-a-excluded-fields-differ"] {
		t.Fatal("excluded script fields changed the hash")
	}
	for _, c := range agentUpdateCases {
		f.AgentUpdate = append(f.AgentUpdate, agentUpdateVector{Name: c.name, Manifest: c.manifest, Hash: AgentUpdatePayloadHash([]byte(c.manifest))})
	}

	privs := map[string]*ecdsa.PrivateKey{}
	for _, k := range []struct {
		role  Role
		label string
	}{
		{RoleAdmin, "Jeff's iPhone"}, {RoleAdmin, "Ops lead — Pixel 🔑"}, {RoleApprover, "Dispatch"},
	} {
		priv, spki := newKey(t, elliptic.P256())
		der, err := base64.StdEncoding.DecodeString(spki)
		if err != nil {
			t.Fatal(err)
		}
		id := KeyIDFromSPKI(der)
		privs[id] = priv
		f.Keys = append(f.Keys, vectorKey{KeyID: id, SPKIB64: spki, Role: string(k.role), Label: k.label})
	}
	slices.SortFunc(f.Keys, func(a, b vectorKey) int { return strings.Compare(a.KeyID, b.KeyID) })
	var admins []string
	approver := ""
	for _, k := range f.Keys {
		if k.Role == string(RoleAdmin) {
			admins = append(admins, k.KeyID)
		} else {
			approver = k.KeyID
		}
	}

	seal := func(v canonicalizer, keyID string) (canonicalB64, sigB64 string) {
		t.Helper()
		canonical, err := v.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		return b64(canonical), signRaw(t, privs[keyID], canonical)
	}

	f.Bundle.Struct = bundleStruct{PartnerID: partnerID, Epoch: 3, Mode: "audit", Threshold: 2, MinAgentVersion: "v0.70.0", Keys: f.Keys}
	for _, id := range admins {
		var sig string
		f.Bundle.CanonicalB64, sig = seal(f.Bundle.Struct.bundle(), id)
		f.Bundle.Signatures = append(f.Bundle.Signatures, BundleSig{KeyID: id, SignatureB64: sig})
	}
	canonicalBundle, _ := base64.StdEncoding.DecodeString(f.Bundle.CanonicalB64)
	f.Bundle.Fingerprint = Fingerprint(canonicalBundle)

	f.Action.Struct = actionStruct{
		ApprovalID: approval, PartnerID: partnerID, CommandType: "script",
		Entries: []vectorEntry{
			{DeviceID: deviceA, Hostname: "srv-01", PayloadHash: hashes["script-device-a"]},
			{DeviceID: deviceB, Hostname: "srv_02.example-net.local", PayloadHash: hashes["script-device-b"]},
		},
		IssuedAt: "2026-11-19T12:00:00Z", ExpiresAt: "2026-11-19T12:30:00Z", KeyID: approver,
	}
	f.Action.CanonicalB64, f.Action.SignatureB64 = seal(f.Action.Struct.action(t), approver)

	// The first two items part UTF-16 order from byte order (see key-utf16-vs-codepoint-order).
	f.Rule.Struct = ruleStruct{
		RuleID: "5e9f1c0a7b3d4e2f8a6b0c1d2e3f4a5b", RuleEpoch: 2, PartnerID: partnerID,
		ScopeDevices: []vectorEntry{{DeviceID: deviceA, Hostname: "srv-01"}, {DeviceID: deviceB, Hostname: "srv_02.example-net.local"}},
		CommandType:  "install_patches", MatchKind: "patchItems",
		MatchItems: []string{"Cumulative Update \ufb33", "Cumulative Update \U0001F600", "KB5034441"},
		Once:       true, NotAfter: "2026-12-19T12:00:00Z", KeyID: admins[0],
	}
	f.Rule.CanonicalB64, f.Rule.SignatureB64 = seal(f.Rule.Struct.rule(t), admins[0])

	orgItems := []string{hashes["script-device-a"], hashes["script-device-b"]}
	slices.Sort(orgItems)
	f.RuleOrg.Struct = ruleStruct{
		RuleID: "a0b1c2d3e4f5061728394a5b6c7d8e9f", RuleEpoch: 5, PartnerID: partnerID, ScopeOrgID: orgID,
		CommandType: "script", MatchKind: "payloadHashes", MatchItems: orgItems,
		Once: false, NotAfter: "2026-12-19T12:00:00Z", KeyID: admins[1],
	}
	f.RuleOrg.CanonicalB64, f.RuleOrg.SignatureB64 = seal(f.RuleOrg.Struct.rule(t), admins[1])

	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vectorsPath, out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f vectorFile
	if err := dec.Decode(&f); err != nil {
		t.Fatal(err)
	}
	return f
}

func decodeVector(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVectorsVerify(t *testing.T) {
	f := readVectors(t)

	t.Run("jcs", func(t *testing.T) {
		for _, v := range f.JCS {
			var in any
			if err := json.Unmarshal(v.Input, &in); err != nil {
				t.Fatalf("%s: %v", v.Name, err)
			}
			if got, err := Canonicalize(in); err != nil || string(got) != v.Canonical {
				t.Errorf("%s: got %q (%v), want %q", v.Name, got, err, v.Canonical)
			}
		}
	})

	coveredHashes := map[string]bool{}
	t.Run("payloadHash", func(t *testing.T) {
		for _, v := range f.PayloadHash {
			var payload map[string]any
			if err := json.Unmarshal(v.Payload, &payload); err != nil {
				t.Fatalf("%s: %v", v.Name, err)
			}
			if got, err := PayloadHash(v.CommandType, payload); err != nil || got != v.Hash {
				t.Errorf("%s: got %q (%v), want %q", v.Name, got, err, v.Hash)
			}
			coveredHashes[v.Hash] = true
		}
	})

	t.Run("agentUpdate", func(t *testing.T) {
		if len(f.AgentUpdate) == 0 {
			t.Fatal("no agent_update vectors")
		}
		for _, v := range f.AgentUpdate {
			if got := AgentUpdatePayloadHash([]byte(v.Manifest)); got != v.Hash {
				t.Errorf("%s: got %s, want %s", v.Name, got, v.Hash)
			}
			var parsed map[string]any
			if err := json.Unmarshal([]byte(v.Manifest), &parsed); err != nil {
				t.Fatalf("%s: %v", v.Name, err)
			}
			if canonical, err := Canonicalize(parsed); err != nil || AgentUpdatePayloadHash(canonical) == v.Hash {
				t.Errorf("%s: hashing the re-encoded manifest must give a different hash (%v)", v.Name, err)
			}
		}
	})

	spkiOf := map[string]string{}
	t.Run("keys", func(t *testing.T) {
		for _, k := range f.Keys {
			if got := KeyIDFromSPKI(decodeVector(t, k.SPKIB64)); got != k.KeyID {
				t.Errorf("key %s: id derives to %s", k.KeyID, got)
			}
			spkiOf[k.KeyID] = k.SPKIB64
		}
		if !reflect.DeepEqual(f.Keys, f.Bundle.Struct.Keys) {
			t.Error("top-level keys differ from the bundle's keys")
		}
	})

	verifies := func(t *testing.T, keyID string, canonical []byte, sigB64 string) {
		t.Helper()
		if err := VerifyES256(spkiOf[keyID], canonical, sigB64); err != nil {
			t.Errorf("signature by %s: %v", keyID, err)
		}
	}

	t.Run("bundle", func(t *testing.T) {
		want := f.Bundle.Struct.bundle()
		canonical := decodeVector(t, f.Bundle.CanonicalB64)
		if got, err := want.CanonicalBytes(); err != nil || !bytes.Equal(got, canonical) {
			t.Fatalf("struct builds %q (%v)", got, err)
		}
		if got, err := ParseBundle(canonical); err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("parse: %+v (%v)", got, err)
		}
		if got := Fingerprint(canonical); got != f.Bundle.Fingerprint {
			t.Errorf("fingerprint %s, want %s", got, f.Bundle.Fingerprint)
		}
		if len(f.Bundle.Signatures) != want.Threshold {
			t.Errorf("%d signatures, threshold %d", len(f.Bundle.Signatures), want.Threshold)
		}
		for _, s := range f.Bundle.Signatures {
			if !slices.ContainsFunc(want.Keys, func(k BundleKey) bool { return k.KeyID == s.KeyID && k.Role == RoleAdmin }) {
				t.Errorf("%s is not an admin key", s.KeyID)
			}
			verifies(t, s.KeyID, canonical, s.SignatureB64)
		}
	})

	t.Run("action", func(t *testing.T) {
		want := f.Action.Struct.action(t)
		canonical := decodeVector(t, f.Action.CanonicalB64)
		if got, err := want.CanonicalBytes(); err != nil || !bytes.Equal(got, canonical) {
			t.Fatalf("struct builds %q (%v)", got, err)
		}
		if got, err := ParseEnvelope(canonical); err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("parse: %+v (%v)", got, err)
		}
		for _, e := range want.Entries {
			if !coveredHashes[e.PayloadHash] {
				t.Errorf("entry %s hash is not one of the payloadHash vectors", e.DeviceID)
			}
		}
		verifies(t, want.KeyID, canonical, f.Action.SignatureB64)
	})

	for name, v := range map[string]signedVector[ruleStruct]{"rule": f.Rule, "ruleOrg": f.RuleOrg} {
		t.Run(name, func(t *testing.T) {
			want := v.Struct.rule(t)
			canonical := decodeVector(t, v.CanonicalB64)
			if got, err := want.CanonicalBytes(); err != nil || !bytes.Equal(got, canonical) {
				t.Fatalf("struct builds %q (%v)", got, err)
			}
			if got, err := ParseEnvelope(canonical); err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("parse: %+v (%v)", got, err)
			}
			verifies(t, want.KeyID, canonical, v.SignatureB64)
		})
	}
}
