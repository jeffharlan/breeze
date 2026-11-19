package opsign

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// Fixed public keys (IDs sorted ascending) so the layout tests are deterministic.
var fixedKeys = [3]struct{ id, spki string }{
	{"727e77fbad8df01ea1290f0ae11d9656", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0LPTLjr/elF3te9pQzi2EuKuXbAH4CEeLikLxM4MqleDYf2hD1LcNlY/5olnH/QO+2Y9+caDxWCQkCLcESrozA=="},
	{"7477df6df8671c0241bea6217fe507af", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIk+JKH4wqIrrghDFLjEXg3XNvTmbm4t8zY/GaOwlofj3/vZU+PITJULqX4mCudnHfvJJnVaMR1adw5sn1OmPHA=="},
	{"c49757765e807c6af2e2a2a8cd90044c", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+6leV2fsaUchguvV5Oiw/NtOMscZjgqRoFyECuYm5qCxyxdL2Mj/Z+HHJ5p6aGVniFwxKRz71VyPLkmwlKkVsQ=="},
}

const (
	partnerID = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	orgID     = "11111111-2222-4333-8444-555555555555"
	deviceA   = "aaaaaaaa-0000-4000-8000-000000000001"
	deviceB   = "bbbbbbbb-0000-4000-8000-000000000002"
	deviceC   = "cccccccc-0000-4000-8000-000000000003"
	approval  = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
)

// Hashes contain letters so the uppercase-hex cases actually change them; they
// sort hashA < hashB < hashC.
var (
	hashA    = strings.Repeat("ab", 32)
	hashB    = strings.Repeat("cd", 32)
	hashC    = strings.Repeat("ef", 32)
	signerID = fixedKeys[0].id
)

var issuedAt = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

func sampleBundle() Bundle {
	return Bundle{
		PartnerID: partnerID, Epoch: 7, Mode: ModeEnforce, Threshold: 2, MinAgentVersion: "v0.70.0",
		Keys: []BundleKey{
			{KeyID: fixedKeys[0].id, SPKIB64: fixedKeys[0].spki, Role: RoleAdmin, Label: "Jeff's iPhone"},
			{KeyID: fixedKeys[1].id, SPKIB64: fixedKeys[1].spki, Role: RoleAdmin, Label: "Second admin phone"},
			{KeyID: fixedKeys[2].id, SPKIB64: fixedKeys[2].spki, Role: RoleApprover, Label: "Dispatch"},
		},
	}
}

// Entries are deliberately out of order; CanonicalBytes sorts them.
func sampleAction() ActionApproval {
	return ActionApproval{
		ApprovalID: approval, PartnerID: partnerID, CommandType: "script",
		Entries: []Entry{
			{DeviceID: deviceC, Hostname: "srv-03.example.net", PayloadHash: hashC},
			{DeviceID: deviceA, Hostname: "srv-01", PayloadHash: hashA},
			{DeviceID: deviceB, Hostname: "srv-02", PayloadHash: hashB},
		},
		IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(3 * time.Minute), KeyID: signerID,
	}
}

func sampleOrgRule() Rule {
	return Rule{
		RuleID: "0f0e0d0c0b0a09080706050403020100", RuleEpoch: 3, PartnerID: partnerID, ScopeOrgID: orgID,
		CommandType: "script", MatchKind: "payloadHashes", MatchItems: []string{hashB, hashA},
		Once: false, NotAfter: issuedAt.Add(30 * 24 * time.Hour), KeyID: signerID,
	}
}

func sampleDeviceRule() Rule {
	return Rule{
		RuleID: "0f0e0d0c0b0a09080706050403020100", RuleEpoch: 1, PartnerID: partnerID,
		ScopeDevices: []Entry{{DeviceID: deviceB, Hostname: "srv-02"}, {DeviceID: deviceA, Hostname: "srv-01"}},
		CommandType:  "install_patches", MatchKind: "patchItems", MatchItems: []string{"KB5034441", "KB5001 Cumulative Update"},
		Once: true, NotAfter: issuedAt.Add(24 * time.Hour), KeyID: signerID,
	}
}

func canonicalText(t *testing.T, v canonicalizer) string {
	t.Helper()
	b, err := v.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	return string(b)
}

func TestLayouts(t *testing.T) {
	tests := []struct {
		name string
		v    canonicalizer
		want []string
	}{
		{"bundle", sampleBundle(), []string{
			"breeze-operator-trust-bundle-v1",
			"partnerId=" + partnerID,
			"epoch=7",
			"mode=enforce",
			"threshold=2",
			"minAgentVersion=v0.70.0",
			"keys=3",
			fixedKeys[0].id + " admin " + fixedKeys[0].spki + " Jeff's iPhone",
			fixedKeys[1].id + " admin " + fixedKeys[1].spki + " Second admin phone",
			fixedKeys[2].id + " approver " + fixedKeys[2].spki + " Dispatch",
		}},
		{"action", sampleAction(), []string{
			"breeze-operator-approval-v1",
			"kind=action",
			"approvalId=" + approval,
			"partnerId=" + partnerID,
			"commandType=script",
			"entries=3",
			deviceA + " srv-01 " + hashA,
			deviceB + " srv-02 " + hashB,
			deviceC + " srv-03.example.net " + hashC,
			"issuedAt=2026-11-19T12:00:00Z",
			"expiresAt=2026-11-19T12:03:00Z",
			"keyId=" + signerID,
		}},
		{"rule scoped to an org", sampleOrgRule(), []string{
			"breeze-operator-approval-v1",
			"kind=rule",
			"ruleId=0f0e0d0c0b0a09080706050403020100",
			"ruleEpoch=3",
			"partnerId=" + partnerID,
			"scope=org:" + orgID,
			"commandType=script",
			"match=payloadHashes",
			"matchItems=2",
			hashA,
			hashB,
			"once=false",
			"notAfter=2026-12-19T12:00:00Z",
			"keyId=" + signerID,
		}},
		{"rule scoped to devices", sampleDeviceRule(), []string{
			"breeze-operator-approval-v1",
			"kind=rule",
			"ruleId=0f0e0d0c0b0a09080706050403020100",
			"ruleEpoch=1",
			"partnerId=" + partnerID,
			"scope=devices",
			"scopeDevices=2",
			deviceA + " srv-01",
			deviceB + " srv-02",
			"commandType=install_patches",
			"match=patchItems",
			"matchItems=2",
			"KB5001 Cumulative Update",
			"KB5034441",
			"once=true",
			"notAfter=2026-11-20T12:00:00Z",
			"keyId=" + signerID,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, want := canonicalText(t, tt.v), strings.Join(tt.want, "\n"); got != want {
				t.Errorf("layout drifted\n got: %q\nwant: %q", got, want)
			}
		})
	}
}

func TestBundleRoundTrip(t *testing.T) {
	want := sampleBundle()
	in := sampleBundle()
	slices.Reverse(in.Keys)

	canonical, err := in.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if want := canonicalText(t, want); string(canonical) != want {
		t.Fatalf("key order must not change the canonical bytes\n got: %q\nwant: %q", canonical, want)
	}
	got, err := ParseBundle(canonical)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parsed bundle differs\n got: %+v\nwant: %+v", got, want)
	}
	again, err := got.CanonicalBytes()
	if err != nil || !bytes.Equal(again, canonical) {
		t.Errorf("re-serialization differs: %v", err)
	}
}

func TestBundleAllowsEmptyMinAgentVersion(t *testing.T) {
	b := sampleBundle()
	b.MinAgentVersion = ""
	canonical, err := b.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseBundle(canonical)
	if err != nil || got.MinAgentVersion != "" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestActionRoundTrip(t *testing.T) {
	in := sampleAction()
	canonical, err := in.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseEnvelope(canonical)
	if err != nil {
		t.Fatalf("ParseEnvelope: %v", err)
	}
	got, ok := parsed.(ActionApproval)
	if !ok {
		t.Fatalf("ParseEnvelope returned %T, want ActionApproval", parsed)
	}
	want := in
	want.Entries = []Entry{in.Entries[1], in.Entries[2], in.Entries[0]}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parsed approval differs\n got: %+v\nwant: %+v", got, want)
	}
	again, err := got.CanonicalBytes()
	if err != nil || !bytes.Equal(again, canonical) {
		t.Errorf("re-serialization differs: %v", err)
	}
}

func TestRuleRoundTrip(t *testing.T) {
	orgRule := sampleOrgRule()
	orgRule.MatchItems = []string{hashA, hashB}
	devRule := sampleDeviceRule()
	devRule.ScopeDevices = []Entry{devRule.ScopeDevices[1], devRule.ScopeDevices[0]}
	devRule.MatchItems = []string{"KB5001 Cumulative Update", "KB5034441"}

	for name, in := range map[string]Rule{"org": orgRule, "devices": devRule} {
		t.Run(name, func(t *testing.T) {
			canonical, err := in.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseEnvelope(canonical)
			if err != nil {
				t.Fatalf("ParseEnvelope: %v", err)
			}
			got, ok := parsed.(Rule)
			if !ok {
				t.Fatalf("ParseEnvelope returned %T, want Rule", parsed)
			}
			if !reflect.DeepEqual(got, in) {
				t.Errorf("parsed rule differs\n got: %+v\nwant: %+v", got, in)
			}
			again, err := got.CanonicalBytes()
			if err != nil || !bytes.Equal(again, canonical) {
				t.Errorf("re-serialization differs: %v", err)
			}
		})
	}
}

func TestActionLifetimeLimits(t *testing.T) {
	tests := []struct {
		commandType string
		lifetime    time.Duration
		ok          bool
	}{
		{"script", 24 * time.Hour, true},
		{"script", 24*time.Hour + time.Second, false},
		{"script", time.Second, true},
		{"script", 0, false},
		{"script", -time.Minute, false},
		{"terminal_start", 2 * time.Minute, true},
		{"terminal_start", 2*time.Minute + time.Second, false},
		{"start_desktop", 3 * time.Minute, false},
		{"desktop_stream_start", 3 * time.Minute, false},
		{"tunnel_open", 3 * time.Minute, false},
		{"tunnel_open", 2 * time.Minute, true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%s", tt.commandType, tt.lifetime), func(t *testing.T) {
			a := sampleAction()
			a.CommandType = tt.commandType
			a.ExpiresAt = a.IssuedAt.Add(tt.lifetime)
			canonical, err := a.CanonicalBytes()
			if (err == nil) != tt.ok {
				t.Fatalf("CanonicalBytes err = %v, want ok=%v", err, tt.ok)
			}
			if _, err := ParseEnvelope([]byte(canonicalWithLifetime(a, tt.lifetime))); (err == nil) != tt.ok {
				t.Fatalf("ParseEnvelope err = %v, want ok=%v (canonical %q)", err, tt.ok, canonical)
			}
		})
	}
}

// canonicalWithLifetime renders the text a hostile signer could produce for any
// lifetime, bypassing CanonicalBytes's own validation.
func canonicalWithLifetime(a ActionApproval, lifetime time.Duration) string {
	return fmt.Sprintf("breeze-operator-approval-v1\nkind=action\napprovalId=%s\npartnerId=%s\ncommandType=%s\nentries=1\n%s %s %s\nissuedAt=%s\nexpiresAt=%s\nkeyId=%s",
		a.ApprovalID, a.PartnerID, a.CommandType, deviceA, "srv-01", hashA,
		a.IssuedAt.Format(timeLayout), a.IssuedAt.Add(lifetime).Format(timeLayout), a.KeyID)
}

func TestEntryCountLimit(t *testing.T) {
	text := func(n int) string {
		lines := []string{"breeze-operator-approval-v1", "kind=action", "approvalId=" + approval, "partnerId=" + partnerID,
			"commandType=script", fmt.Sprintf("entries=%d", n)}
		for i := range n {
			lines = append(lines, fmt.Sprintf("00000000-0000-4000-8000-%012x host-%d %s", i, i, hashA))
		}
		lines = append(lines, "issuedAt=2026-11-19T12:00:00Z", "expiresAt=2026-11-19T12:03:00Z", "keyId="+signerID)
		return strings.Join(lines, "\n")
	}
	if _, err := ParseEnvelope([]byte(text(500))); err != nil {
		t.Errorf("500 entries rejected: %v", err)
	}
	if _, err := ParseEnvelope([]byte(text(501))); err == nil {
		t.Error("501 entries accepted")
	}
	a := sampleAction()
	a.Entries = nil
	if _, err := a.CanonicalBytes(); err == nil {
		t.Error("0 entries accepted")
	}
}

func TestParseRejects(t *testing.T) {
	bundle := canonicalText(t, sampleBundle())
	action := canonicalText(t, sampleAction())
	ruleOrg := canonicalText(t, sampleOrgRule())
	ruleDev := canonicalText(t, sampleDeviceRule())

	sub := func(old, repl string) func(string) string {
		return func(s string) string {
			if !strings.Contains(s, old) {
				panic(fmt.Sprintf("test bug: %q not in sample", old))
			}
			return strings.Replace(s, old, repl, 1)
		}
	}
	lineEdit := func(f func(lines []string) []string) func(string) string {
		return func(s string) string { return strings.Join(f(strings.Split(s, "\n")), "\n") }
	}
	setLine := func(i int, f func(string) string) func(string) string {
		return lineEdit(func(l []string) []string { l[i] = f(l[i]); return l })
	}
	dropLine := func(i int) func(string) string {
		return lineEdit(func(l []string) []string { return slices.Delete(l, i, i+1) })
	}
	swapLines := func(i, j int) func(string) string {
		return lineEdit(func(l []string) []string { l[i], l[j] = l[j], l[i]; return l })
	}
	// Bundle lines: 0 domain, 1 partnerId, 2 epoch, 3 mode, 4 threshold, 5 minAgentVersion, 6 keys=3, 7..9 keys.
	// Action lines: 0 domain, 1 kind, 2 approvalId, 3 partnerId, 4 commandType, 5 entries=3, 6..8 entries, 9 issuedAt, 10 expiresAt, 11 keyId.
	// Org rule lines: 0 domain, 1 kind, 2 ruleId, 3 ruleEpoch, 4 partnerId, 5 scope, 6 commandType, 7 match, 8 matchItems=2, 9..10 items, 11 once, 12 notAfter, 13 keyId.
	// Device rule lines: ..., 5 scope=devices, 6 scopeDevices=2, 7..8 devices, 9 commandType, 10 match, 11 matchItems=2, 12..13 items, 14 once, 15 notAfter, 16 keyId.
	upperKeyID := func(s string) string { return strings.ToUpper(s[:32]) + s[32:] }
	appendTo := func(suffix string) func(string) string { return func(s string) string { return s + suffix } }

	bundleBad := []struct {
		name string
		edit func(string) string
	}{
		{"trailing newline", appendTo("\n")},
		{"extra trailing line", appendTo("\nextra=1")},
		{"CRLF", func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }},
		{"empty input", func(string) string { return "" }},
		{"empty line in the middle", sub("epoch=7", "epoch=7\n")},
		{"invalid UTF-8", appendTo("\xff")},
		{"wrong domain line", sub("breeze-operator-trust-bundle-v1", "breeze-operator-trust-bundle-v2")},
		{"approval domain on a bundle", sub("breeze-operator-trust-bundle-v1", "breeze-operator-approval-v1")},
		{"unsorted keys", swapLines(7, 8)},
		{"duplicate key", lineEdit(func(l []string) []string { l[8] = l[7]; return l })},
		{"key count too high", sub("keys=3", "keys=4")},
		{"key count too low", sub("keys=3", "keys=2")},
		{"keyId does not match its SPKI", setLine(7, func(s string) string { return "00000000000000000000000000000000" + s[32:] })},
		{"uppercase keyId", setLine(7, upperKeyID)},
		{"keyId truncated", setLine(7, func(s string) string { return s[1:] })},
		{"SPKI not base64", setLine(7, func(s string) string { return strings.Replace(s, fixedKeys[0].spki[:8], "!!!!!!!!", 1) })},
		{"SPKI not a P-256 key", setLine(7, func(s string) string { return fixedKeys[0].id + " admin AAAA label" })},
		{"unknown role", sub(" approver ", " owner ")},
		{"threshold 0", sub("threshold=2", "threshold=0")},
		{"threshold above the admin count", sub("threshold=2", "threshold=3")},
		{"negative threshold", sub("threshold=2", "threshold=-1")},
		{"threshold with leading zero", sub("threshold=2", "threshold=02")},
		{"epoch with leading zero", sub("epoch=7", "epoch=07")},
		{"epoch not a number", sub("epoch=7", "epoch=seven")},
		{"unknown mode off", sub("mode=enforce", "mode=off")},
		{"uppercase partnerId", sub(partnerID, strings.ToUpper(partnerID))},
		{"version without v", sub("v0.70.0", "0.70.0")},
		{"version with prerelease", sub("v0.70.0", "v0.70.0-rc1")},
		{"missing minAgentVersion line", dropLine(5)},
		{"fields out of order", swapLines(2, 3)},
		{"empty label", setLine(7, func(s string) string { return strings.TrimSuffix(s, "Jeff's iPhone") })},
		{"label missing entirely", setLine(7, func(s string) string { return strings.TrimSuffix(s, " Jeff's iPhone") })},
		{"label with leading space", sub(" Jeff's iPhone", "  Jeff's iPhone")},
		{"label with trailing space", sub("Dispatch", "Dispatch ")},
		{"control character in label", sub("Dispatch", "Dis\x01patch")},
		{"DEL in label", sub("Dispatch", "Dis\x7fpatch")},
		{"tab in label", sub("Dispatch", "Dis\tpatch")},
	}
	actionBad := []struct {
		name string
		edit func(string) string
	}{
		{"trailing newline", appendTo("\n")},
		{"extra trailing line", appendTo("\nextra=1")},
		{"CRLF", func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }},
		{"unknown kind", sub("kind=action", "kind=other")},
		{"missing kind", dropLine(1)},
		{"wrong domain line", sub("breeze-operator-approval-v1", "breeze-operator-approval-v2")},
		{"bundle domain on an approval", sub("breeze-operator-approval-v1", "breeze-operator-trust-bundle-v1")},
		{"duplicate entry", lineEdit(func(l []string) []string { l[7] = l[6]; return l })},
		{"same device twice with another hostname", setLine(7, func(string) string { return deviceA + " srv-01x " + hashB })},
		{"same device twice with another hash", setLine(7, func(string) string { return deviceA + " srv-01 " + hashB })},
		{"unsorted entries", swapLines(6, 7)},
		{"entry count too high", sub("entries=3", "entries=4")},
		{"entry count too low", sub("entries=3", "entries=2")},
		{"zero entries", lineEdit(func(l []string) []string { return slices.Concat(l[:5], []string{"entries=0"}, l[9:]) })},
		{"entry with only two fields", setLine(6, func(s string) string { return deviceA + " srv-01" })},
		{"entry with four fields", setLine(6, func(s string) string { return s + " extra" })},
		{"entry with double space", setLine(6, func(s string) string { return strings.Replace(s, " ", "  ", 1) })},
		{"uppercase approvalId", sub(approval, strings.ToUpper(approval))},
		{"short approvalId", sub(approval, approval[1:])},
		{"uppercase deviceId", sub(deviceA, strings.ToUpper(deviceA))},
		{"uppercase hostname", sub("srv-01", "SRV-01")},
		{"hostname with a slash", sub("srv-01", "srv/01")},
		{"payload hash too short", sub(hashA, hashA[1:])},
		{"uppercase payload hash", sub(hashA, strings.ToUpper(hashA))},
		{"uppercase commandType", sub("commandType=script", "commandType=Script")},
		{"empty commandType", sub("commandType=script", "commandType=")},
		{"expiry beyond 24h", sub("expiresAt=2026-11-19T12:03:00Z", "expiresAt=2026-11-20T12:00:01Z")},
		{"expiry equal to issue time", sub("expiresAt=2026-11-19T12:03:00Z", "expiresAt=2026-11-19T12:00:00Z")},
		{"expiry before issue time", sub("expiresAt=2026-11-19T12:03:00Z", "expiresAt=2026-11-19T11:00:00Z")},
		{"session type with a 3 minute expiry", sub("commandType=script", "commandType=terminal_start")},
		{"time with an offset", sub("issuedAt=2026-11-19T12:00:00Z", "issuedAt=2026-11-19T12:00:00+00:00")},
		{"time with fractional seconds", sub("issuedAt=2026-11-19T12:00:00Z", "issuedAt=2026-11-19T12:00:00.5Z")},
		{"time without seconds", sub("issuedAt=2026-11-19T12:00:00Z", "issuedAt=2026-11-19T12:00Z")},
		{"lowercase time separator", sub("issuedAt=2026-11-19T12:00:00Z", "issuedAt=2026-11-19t12:00:00Z")},
		{"uppercase keyId", sub("keyId="+signerID, "keyId="+strings.ToUpper(signerID))},
		{"missing keyId", dropLine(11)},
	}
	ruleBad := []struct {
		name string
		base string
		edit func(string) string
	}{
		{"unknown match kind", ruleOrg, sub("match=payloadHashes", "match=allowAll")},
		{"payloadHashes item is not a hash", ruleOrg, sub(hashA, "not-a-hash")},
		{"unsorted match items", ruleOrg, swapLines(9, 10)},
		{"duplicate match item", ruleOrg, lineEdit(func(l []string) []string { l[10] = l[9]; return l })},
		{"no match items", ruleOrg, lineEdit(func(l []string) []string { return slices.Concat(l[:8], []string{"matchItems=0"}, l[11:]) })},
		{"once not a boolean", ruleOrg, sub("once=false", "once=no")},
		{"once capitalised", ruleOrg, sub("once=false", "once=False")},
		{"scope without a kind", ruleOrg, sub("scope=org:"+orgID, "scope=org:")},
		{"scope with unknown kind", ruleOrg, sub("scope=org:"+orgID, "scope=partner:"+orgID)},
		{"org scope followed by device list", ruleOrg, sub("scope=org:"+orgID, "scope=org:"+orgID+"\nscopeDevices=0")},
		{"devices scope without a list", ruleDev, lineEdit(func(l []string) []string { return slices.Concat(l[:6], l[9:]) })},
		{"empty device list", ruleDev, lineEdit(func(l []string) []string { return slices.Concat(l[:6], []string{"scopeDevices=0"}, l[9:]) })},
		{"unsorted scope devices", ruleDev, swapLines(7, 8)},
		{"duplicate scope device", ruleDev, lineEdit(func(l []string) []string { l[8] = l[7]; return l })},
		{"same scope device twice with another hostname", ruleDev, setLine(8, func(string) string { return deviceA + " srv-01x" })},
		{"scope device carrying a hash", ruleDev, setLine(7, func(s string) string { return s + " " + hashA })},
		{"empty patch item", ruleDev, setLine(12, func(string) string { return "" })},
		{"patch item with a control character", ruleDev, sub("KB5034441", "KB5034\x07441")},
		{"patch item with a trailing space", ruleDev, sub("KB5034441", "KB5034441 ")},
		{"notAfter with an offset", ruleOrg, sub("notAfter=2026-12-19T12:00:00Z", "notAfter=2026-12-19T12:00:00+01:00")},
		{"rule ruleId uppercase", ruleOrg, sub("ruleId=0f0e", "ruleId=0F0E")},
		{"rule epoch not a number", ruleOrg, sub("ruleEpoch=3", "ruleEpoch=-3")},
		{"rule trailing newline", ruleOrg, appendTo("\n")},
	}

	parseBundle := func(in string) error { _, err := ParseBundle([]byte(in)); return err }
	parseEnvelope := func(in string) error { _, err := ParseEnvelope([]byte(in)); return err }

	// The unmodified samples must parse, or every rejection below proves nothing.
	for name, c := range map[string]struct {
		text  string
		parse func(string) error
	}{"bundle": {bundle, parseBundle}, "action": {action, parseEnvelope}, "org rule": {ruleOrg, parseEnvelope}, "device rule": {ruleDev, parseEnvelope}} {
		if err := c.parse(c.text); err != nil {
			t.Fatalf("sample %s does not parse: %v", name, err)
		}
	}
	for _, c := range bundleBad {
		t.Run("bundle/"+c.name, func(t *testing.T) {
			if err := parseBundle(c.edit(bundle)); err == nil {
				t.Error("accepted")
			} else {
				t.Log(err)
			}
		})
	}
	for _, c := range actionBad {
		t.Run("action/"+c.name, func(t *testing.T) {
			if err := parseEnvelope(c.edit(action)); err == nil {
				t.Error("accepted")
			} else {
				t.Log(err)
			}
		})
	}
	for _, c := range ruleBad {
		t.Run("rule/"+c.name, func(t *testing.T) {
			if err := parseEnvelope(c.edit(c.base)); err == nil {
				t.Error("accepted")
			} else {
				t.Log(err)
			}
		})
	}
	t.Run("a bundle is not an envelope and vice versa", func(t *testing.T) {
		if parseEnvelope(bundle) == nil || parseBundle(action) == nil || parseBundle(ruleOrg) == nil {
			t.Error("cross-parse accepted")
		}
	})
}

func TestCanonicalBytesRejectsInvalidStructs(t *testing.T) {
	bundleEdits := map[string]func(*Bundle){
		"duplicate keyId":        func(b *Bundle) { b.Keys[1] = b.Keys[0] },
		"newline in label":       func(b *Bundle) { b.Keys[2].Label = "a\nb" },
		"threshold above admins": func(b *Bundle) { b.Threshold = 3 },
		"no keys":                func(b *Bundle) { b.Keys = nil },
		"only approver keys": func(b *Bundle) {
			b.Keys = []BundleKey{{KeyID: fixedKeys[2].id, SPKIB64: fixedKeys[2].spki, Role: RoleApprover, Label: "x"}}
		},
		"mode off":                  func(b *Bundle) { b.Mode = "off" },
		"keyId for a different key": func(b *Bundle) { b.Keys[0].KeyID = fixedKeys[1].id },
	}
	for name, edit := range bundleEdits {
		t.Run("bundle/"+name, func(t *testing.T) {
			b := sampleBundle()
			edit(&b)
			if _, err := b.CanonicalBytes(); err == nil {
				t.Error("accepted")
			}
		})
	}
	t.Run("action with sub-second time", func(t *testing.T) {
		a := sampleAction()
		a.IssuedAt = a.IssuedAt.Add(time.Millisecond)
		if _, err := a.CanonicalBytes(); err == nil {
			t.Error("accepted")
		}
	})
	t.Run("action with a device twice", func(t *testing.T) {
		a := sampleAction()
		a.Entries = append(a.Entries, Entry{DeviceID: a.Entries[0].DeviceID, Hostname: "other-host", PayloadHash: hashB})
		if _, err := a.CanonicalBytes(); err == nil {
			t.Error("accepted")
		}
	})
	t.Run("rule with a scope device twice", func(t *testing.T) {
		r := sampleDeviceRule()
		r.ScopeDevices = append(r.ScopeDevices, Entry{DeviceID: r.ScopeDevices[0].DeviceID, Hostname: "other-host"})
		if _, err := r.CanonicalBytes(); err == nil {
			t.Error("accepted")
		}
	})
	t.Run("rule with both scopes", func(t *testing.T) {
		r := sampleDeviceRule()
		r.ScopeOrgID = orgID
		if _, err := r.CanonicalBytes(); err == nil {
			t.Error("accepted")
		}
	})
	t.Run("rule with neither scope", func(t *testing.T) {
		r := sampleOrgRule()
		r.ScopeOrgID = ""
		if _, err := r.CanonicalBytes(); err == nil {
			t.Error("accepted")
		}
	})
}

func TestNonUTCTimesSerializeAsUTC(t *testing.T) {
	a := sampleAction()
	a.IssuedAt = a.IssuedAt.In(time.FixedZone("EST", -5*3600))
	a.ExpiresAt = a.ExpiresAt.In(time.FixedZone("EST", -5*3600))
	if got, want := canonicalText(t, a), canonicalText(t, sampleAction()); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Only an ASCII space at the edge is refused; Unicode whitespace is accepted
// because the TypeScript twin cannot reproduce Go's whitespace table.
func TestLineEdgeRuleIsASCIISpaceOnly(t *testing.T) {
	for _, edge := range []string{"\u00a0", "\u0085", "\ufeff", "\u200b"} {
		b := sampleBundle()
		b.Keys[2].Label = edge + "Dispatch" + edge
		r := sampleDeviceRule()
		r.MatchItems = []string{edge + "KB1" + edge}
		for name, v := range map[string]canonicalizer{"label": b, "patch item": r} {
			canonical, err := v.CanonicalBytes()
			if err != nil {
				t.Errorf("%s edged with %+q rejected: %v", name, edge, err)
				continue
			}
			var parseErr error
			if name == "label" {
				_, parseErr = ParseBundle(canonical)
			} else {
				_, parseErr = ParseEnvelope(canonical)
			}
			if parseErr != nil {
				t.Errorf("%s edged with %+q does not parse back: %v", name, edge, parseErr)
			}
		}
	}
}
