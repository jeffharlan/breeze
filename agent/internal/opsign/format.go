package opsign

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// sessionTypes are the command types that open an interactive session; an
// approval for one lives at most maxSessionLifetime. IsSessionType reads this
// same set.
var sessionTypes = map[string]bool{
	"terminal_start":       true,
	"start_desktop":        true,
	"desktop_stream_start": true,
	"tunnel_open":          true,
}

const (
	bundleDomain   = "breeze-operator-trust-bundle-v1"
	approvalDomain = "breeze-operator-approval-v1"
	timeLayout     = "2006-01-02T15:04:05Z"

	maxEntries         = 500
	maxActionLifetime  = 24 * time.Hour
	maxSessionLifetime = 2 * time.Minute
)

type Role string
type Mode string

const (
	RoleAdmin    Role = "admin"
	RoleApprover Role = "approver"
	ModeAudit    Mode = "audit"
	ModeEnforce  Mode = "enforce"
)

type BundleKey struct {
	KeyID, SPKIB64 string
	Role           Role
	Label          string
}

type Bundle struct {
	PartnerID       string
	Epoch           uint64
	Mode            Mode
	Threshold       int
	MinAgentVersion string
	Keys            []BundleKey
}

// Entry is one device in an approval (with the hash of what it may run) or in a
// rule's device scope (PayloadHash empty).
type Entry struct{ DeviceID, Hostname, PayloadHash string }

type ActionApproval struct {
	ApprovalID, PartnerID, CommandType string
	Entries                            []Entry
	IssuedAt, ExpiresAt                time.Time
	KeyID                              string
}

type Rule struct {
	RuleID     string
	RuleEpoch  uint64
	PartnerID  string
	ScopeOrgID string
	// ScopeDevices is used instead of ScopeOrgID when the rule names devices.
	ScopeDevices []Entry
	CommandType  string
	MatchKind    string
	MatchItems   []string
	Once         bool
	NotAfter     time.Time
	KeyID        string
}

type canonicalizer interface{ CanonicalBytes() ([]byte, error) }

var (
	uuidRe        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hex32Re       = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hex64Re       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hostnameRe    = regexp.MustCompile(`^[a-z0-9._-]{1,253}$`)
	commandTypeRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	versionRe     = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
)

func check(re *regexp.Regexp, field, v string) error {
	if !re.MatchString(v) {
		return fmt.Errorf("opsign: invalid %s %q", field, v)
	}
	return nil
}

// checkLine validates free text that occupies part of one line: labels and
// patch items. Control characters (including LF) would let a value forge extra
// lines. Only an ASCII space at either edge is refused: Unicode whitespace
// tables differ between Go and JS, so a wider rule could not be mirrored exactly.
func checkLine(field, s string) error {
	isControl := func(r rune) bool { return r < 0x20 || r == 0x7f }
	if s == "" || s[0] == ' ' || s[len(s)-1] == ' ' || !utf8.ValidString(s) || strings.IndexFunc(s, isControl) >= 0 {
		return fmt.Errorf("opsign: invalid %s %q", field, s)
	}
	return nil
}

func checkWholeSecond(field string, t time.Time) error {
	if t.Nanosecond() != 0 {
		return fmt.Errorf("opsign: %s has sub-second precision", field)
	}
	return nil
}

func formatTime(t time.Time) string { return t.UTC().Format(timeLayout) }

// sortedUnique returns a sorted copy of items; two items comparing equal are an error.
func sortedUnique[T any](items []T, compare func(a, b T) int, what string) ([]T, error) {
	sorted := slices.Clone(items)
	slices.SortFunc(sorted, compare)
	for i := 1; i < len(sorted); i++ {
		if compare(sorted[i-1], sorted[i]) == 0 {
			return nil, fmt.Errorf("opsign: duplicate in %s", what)
		}
	}
	return sorted, nil
}

// sortedEntries validates a device list and returns it in canonical order. A
// device appears once, whatever its hostname or hash.
func sortedEntries(list []Entry, what string, withHash bool) ([]Entry, error) {
	if len(list) == 0 || len(list) > maxEntries {
		return nil, fmt.Errorf("opsign: %s holds %d entries, want 1 to %d", what, len(list), maxEntries)
	}
	var errs []error
	for _, e := range list {
		errs = append(errs, check(uuidRe, "deviceId", e.DeviceID), check(hostnameRe, "hostname", e.Hostname))
		if withHash {
			errs = append(errs, check(hex64Re, "payloadHash", e.PayloadHash))
		} else if e.PayloadHash != "" {
			errs = append(errs, fmt.Errorf("opsign: %s entry carries a payloadHash", what))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return sortedUnique(list, func(a, b Entry) int { return strings.Compare(a.DeviceID, b.DeviceID) }, what)
}

func (k BundleKey) validate() error {
	_, der, err := parseP256SPKI(k.SPKIB64)
	if err != nil {
		return err
	}
	if k.KeyID != KeyIDFromSPKI(der) {
		return fmt.Errorf("opsign: keyId %q does not match its public key", k.KeyID)
	}
	if k.Role != RoleAdmin && k.Role != RoleApprover {
		return fmt.Errorf("opsign: unknown role %q", k.Role)
	}
	return checkLine("label", k.Label)
}

func (b Bundle) CanonicalBytes() ([]byte, error) {
	keys, err := sortedUnique(b.Keys, func(x, y BundleKey) int { return strings.Compare(x.KeyID, y.KeyID) }, "keys")
	if err != nil {
		return nil, err
	}
	errs := []error{check(uuidRe, "partnerId", b.PartnerID)}
	admins := 0
	for _, k := range keys {
		errs = append(errs, k.validate())
		if k.Role == RoleAdmin {
			admins++
		}
	}
	if b.Mode != ModeAudit && b.Mode != ModeEnforce {
		errs = append(errs, fmt.Errorf("opsign: unknown mode %q", b.Mode))
	}
	if b.Threshold < 1 || b.Threshold > admins {
		errs = append(errs, fmt.Errorf("opsign: threshold %d must be between 1 and the %d admin keys", b.Threshold, admins))
	}
	if b.MinAgentVersion != "" {
		errs = append(errs, check(versionRe, "minAgentVersion", b.MinAgentVersion))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	lines := []string{
		bundleDomain,
		"partnerId=" + b.PartnerID,
		"epoch=" + strconv.FormatUint(b.Epoch, 10),
		"mode=" + string(b.Mode),
		"threshold=" + strconv.Itoa(b.Threshold),
		"minAgentVersion=" + b.MinAgentVersion,
		"keys=" + strconv.Itoa(len(keys)),
	}
	for _, k := range keys {
		lines = append(lines, k.KeyID+" "+string(k.Role)+" "+k.SPKIB64+" "+k.Label)
	}
	return []byte(strings.Join(lines, "\n")), nil
}

func (a ActionApproval) CanonicalBytes() ([]byte, error) {
	entries, err := sortedEntries(a.Entries, "entries", true)
	if err != nil {
		return nil, err
	}
	errs := []error{
		check(hex32Re, "approvalId", a.ApprovalID),
		check(uuidRe, "partnerId", a.PartnerID),
		check(commandTypeRe, "commandType", a.CommandType),
		check(hex32Re, "keyId", a.KeyID),
		checkWholeSecond("issuedAt", a.IssuedAt),
		checkWholeSecond("expiresAt", a.ExpiresAt),
	}
	limit := maxActionLifetime
	if sessionTypes[a.CommandType] {
		limit = maxSessionLifetime
	}
	if d := a.ExpiresAt.Sub(a.IssuedAt); d <= 0 || d > limit {
		errs = append(errs, fmt.Errorf("opsign: %s approval must expire within %s of issue, got %s", a.CommandType, limit, d))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	lines := []string{
		approvalDomain,
		"kind=action",
		"approvalId=" + a.ApprovalID,
		"partnerId=" + a.PartnerID,
		"commandType=" + a.CommandType,
		"entries=" + strconv.Itoa(len(entries)),
	}
	for _, e := range entries {
		lines = append(lines, e.DeviceID+" "+e.Hostname+" "+e.PayloadHash)
	}
	lines = append(lines, "issuedAt="+formatTime(a.IssuedAt), "expiresAt="+formatTime(a.ExpiresAt), "keyId="+a.KeyID)
	return []byte(strings.Join(lines, "\n")), nil
}

func (r Rule) CanonicalBytes() ([]byte, error) {
	errs := []error{
		check(hex32Re, "ruleId", r.RuleID),
		check(uuidRe, "partnerId", r.PartnerID),
		check(commandTypeRe, "commandType", r.CommandType),
		checkWholeSecond("notAfter", r.NotAfter),
		check(hex32Re, "keyId", r.KeyID),
	}
	var scope []string
	switch {
	case r.ScopeOrgID != "" && len(r.ScopeDevices) == 0:
		errs = append(errs, check(uuidRe, "scope org", r.ScopeOrgID))
		scope = []string{"scope=org:" + r.ScopeOrgID}
	case r.ScopeOrgID == "" && len(r.ScopeDevices) > 0:
		devices, err := sortedEntries(r.ScopeDevices, "scopeDevices", false)
		errs = append(errs, err)
		scope = []string{"scope=devices", "scopeDevices=" + strconv.Itoa(len(devices))}
		for _, d := range devices {
			scope = append(scope, d.DeviceID+" "+d.Hostname)
		}
	default:
		errs = append(errs, errors.New("opsign: a rule needs exactly one of an org scope or a device list"))
	}
	items, err := sortedUnique(r.MatchItems, strings.Compare, "matchItems")
	errs = append(errs, err)
	if len(items) == 0 {
		errs = append(errs, errors.New("opsign: a rule needs at least one match item"))
	}
	switch r.MatchKind {
	case "payloadHashes":
		for _, item := range items {
			errs = append(errs, check(hex64Re, "match item", item))
		}
	case "patchItems":
		for _, item := range items {
			errs = append(errs, checkLine("match item", item))
		}
	default:
		errs = append(errs, fmt.Errorf("opsign: unknown match kind %q", r.MatchKind))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	lines := []string{
		approvalDomain,
		"kind=rule",
		"ruleId=" + r.RuleID,
		"ruleEpoch=" + strconv.FormatUint(r.RuleEpoch, 10),
		"partnerId=" + r.PartnerID,
	}
	lines = append(lines, scope...)
	lines = append(lines, "commandType="+r.CommandType, "match="+r.MatchKind, "matchItems="+strconv.Itoa(len(items)))
	lines = append(lines, items...)
	lines = append(lines, "once="+strconv.FormatBool(r.Once), "notAfter="+formatTime(r.NotAfter), "keyId="+r.KeyID)
	return []byte(strings.Join(lines, "\n")), nil
}

// Fingerprint is what an operator compares across devices and on their phone.
func Fingerprint(canonical []byte) string { return shortDigest(canonical) }

// lineReader reads the line-based formats. The first failure sticks: later
// reads return zero values, so a parser reads straight through and checks err once.
type lineReader struct {
	lines []string
	err   error
}

func newLineReader(canonical []byte) *lineReader {
	return &lineReader{lines: strings.Split(string(canonical), "\n")}
}

func (r *lineReader) fail(format string, args ...any) {
	if r.err == nil {
		r.err = fmt.Errorf("opsign: "+format, args...)
	}
}

func (r *lineReader) next() string {
	if r.err != nil {
		return ""
	}
	if len(r.lines) == 0 {
		r.fail("truncated")
		return ""
	}
	line := r.lines[0]
	r.lines = r.lines[1:]
	return line
}

func (r *lineReader) expect(line string) {
	if r.next() != line {
		r.fail("expected line %q", line)
	}
}

func (r *lineReader) field(key string) string {
	line := r.next()
	value, ok := strings.CutPrefix(line, key+"=")
	if !ok {
		r.fail("expected %s=", key)
	}
	return value
}

func (r *lineReader) num(key string, bits int) uint64 {
	n, err := strconv.ParseUint(r.field(key), 10, bits)
	if err != nil {
		r.fail("%s is not an unsigned integer", key)
	}
	return n
}

// count reads a list length, bounded by the lines left so it cannot over-read.
func (r *lineReader) count(key string) int {
	n := r.num(key, 31)
	if n > uint64(len(r.lines)) {
		r.fail("%s=%d but only %d lines remain", key, n, len(r.lines))
		return 0
	}
	return int(n)
}

func (r *lineReader) flag(key string) bool {
	switch r.field(key) {
	case "true":
		return true
	case "false":
		return false
	}
	r.fail("%s must be true or false", key)
	return false
}

func (r *lineReader) time(key string) time.Time {
	t, err := time.Parse(time.RFC3339, r.field(key))
	if err != nil {
		r.fail("%s: %v", key, err)
	}
	return t.UTC()
}

// rows reads n lines, each split on single spaces into exactly parts fields; the
// last field keeps any further spaces.
func (r *lineReader) rows(n, parts int) [][]string {
	var out [][]string
	for range n {
		fields := strings.SplitN(r.next(), " ", parts)
		if len(fields) != parts {
			r.fail("list line has %d fields, want %d", len(fields), parts)
			break
		}
		out = append(out, fields)
	}
	return out
}

func (r *lineReader) end() {
	if len(r.lines) > 0 {
		r.fail("unexpected trailing line")
	}
}

// requireCanonical is the one rule that rejects every non-canonical spelling
// (order, case, padding, whitespace, number format): a parsed value must
// serialize back to exactly the bytes it was read from.
func requireCanonical(v canonicalizer, input []byte) error {
	out, err := v.CanonicalBytes()
	if err != nil {
		return err
	}
	if !bytes.Equal(out, input) {
		return errors.New("opsign: not in canonical form")
	}
	return nil
}

func ParseBundle(canonical []byte) (Bundle, error) {
	r := newLineReader(canonical)
	r.expect(bundleDomain)
	var b Bundle
	b.PartnerID = r.field("partnerId")
	b.Epoch = r.num("epoch", 64)
	b.Mode = Mode(r.field("mode"))
	b.Threshold = int(r.num("threshold", 31))
	b.MinAgentVersion = r.field("minAgentVersion")
	for _, f := range r.rows(r.count("keys"), 4) {
		b.Keys = append(b.Keys, BundleKey{KeyID: f[0], Role: Role(f[1]), SPKIB64: f[2], Label: f[3]})
	}
	r.end()
	if r.err != nil {
		return Bundle{}, r.err
	}
	if err := requireCanonical(b, canonical); err != nil {
		return Bundle{}, err
	}
	return b, nil
}

func parseAction(r *lineReader) ActionApproval {
	var a ActionApproval
	a.ApprovalID = r.field("approvalId")
	a.PartnerID = r.field("partnerId")
	a.CommandType = r.field("commandType")
	for _, f := range r.rows(r.count("entries"), 3) {
		a.Entries = append(a.Entries, Entry{DeviceID: f[0], Hostname: f[1], PayloadHash: f[2]})
	}
	a.IssuedAt = r.time("issuedAt")
	a.ExpiresAt = r.time("expiresAt")
	a.KeyID = r.field("keyId")
	return a
}

func parseRule(r *lineReader) Rule {
	var x Rule
	x.RuleID = r.field("ruleId")
	x.RuleEpoch = r.num("ruleEpoch", 64)
	x.PartnerID = r.field("partnerId")
	switch scope := r.field("scope"); {
	case scope == "devices":
		for _, f := range r.rows(r.count("scopeDevices"), 2) {
			x.ScopeDevices = append(x.ScopeDevices, Entry{DeviceID: f[0], Hostname: f[1]})
		}
	case strings.HasPrefix(scope, "org:"):
		x.ScopeOrgID = strings.TrimPrefix(scope, "org:")
	default:
		r.fail("unknown scope")
	}
	x.CommandType = r.field("commandType")
	x.MatchKind = r.field("match")
	for _, f := range r.rows(r.count("matchItems"), 1) {
		x.MatchItems = append(x.MatchItems, f[0])
	}
	x.Once = r.flag("once")
	x.NotAfter = r.time("notAfter")
	x.KeyID = r.field("keyId")
	return x
}

// ParseEnvelope reads an approval envelope and returns an ActionApproval or a
// Rule (by value). It does not look at the clock: callers check expiry and
// issue time against the agent's trusted time.
func ParseEnvelope(canonical []byte) (any, error) {
	r := newLineReader(canonical)
	r.expect(approvalDomain)
	var v canonicalizer
	switch kind := r.field("kind"); kind {
	case "action":
		v = parseAction(r)
	case "rule":
		v = parseRule(r)
	default:
		r.fail("unknown kind %q", kind)
	}
	r.end()
	if r.err != nil {
		return nil, r.err
	}
	if err := requireCanonical(v, canonical); err != nil {
		return nil, err
	}
	return v, nil
}
