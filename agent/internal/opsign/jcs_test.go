package opsign

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestCanonicalizeVectors(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want string
	}{
		{"key-order", map[string]any{"b": 1.0, "a": "x"}, `{"a":"x","b":1}`},
		{"nested", map[string]any{"z": []any{nil, true, false, map[string]any{}}, "a": []any{}}, `{"a":[],"z":[null,true,false,{}]}`},
		{"num-zero", 0.0, `0`},
		{"num-negative-zero", math.Copysign(0, -1), `0`},
		{"num-1e21", 1e21, `1e+21`},
		{"num-1e20", 1e20, `100000000000000000000`},
		{"num-1e-6", 0.000001, `0.000001`},
		{"num-1e-7", 1e-7, `1e-7`},
		{"num-min-denormal", 5e-324, `5e-324`},
		{"num-max", 1.7976931348623157e308, `1.7976931348623157e+308`},
		{"num-2^53", 9007199254740992.0, `9007199254740992`},
		{"num-shortest", 333333333.33333329, `333333333.3333333`},
		{"num-int", float64(1), `1`},
		{"num-negative", -2.5, `-2.5`},
		{"num-negative-exponent", -1e21, `-1e+21`},
		{"json-number", json.Number("1.50"), `1.5`},
		{"json-number-exponent", json.Number("2E-3"), `0.002`},
		{"json-number-negative-zero", json.Number("-0"), `0`},
		{"str-no-html-escape", " <&>é", `" <&>é"`},
		{"str-escapes", "\n\t\"\\\b\f\r", `"\n\t\"\\\b\f\r"`},
		{"str-control", "\x01\x1f", `"\u0001\u001f"`},
		{"str-del-and-line-separator-raw", "\x7f ", "\"\x7f \""},
		// U+20AC (0x20AC) sorts before U+1F600 (0xD83D 0xDE00) in UTF-16 and in
		// code-point order alike; U+FB33 is where the two orders part: UTF-16 puts
		// the surrogate pair first, code-point order puts U+FB33 first.
		{"key-utf16-order", map[string]any{"\U0001F600": 2.0, "€": 1.0}, "{\"€\":1,\"\U0001F600\":2}"},
		{"key-utf16-vs-codepoint-order", map[string]any{"\ufb33": 1.0, "\U0001F600": 2.0}, "{\"\U0001F600\":2,\"\ufb33\":1}"},
		{"key-rfc8785-section-3.2.3", map[string]any{
			"\u20ac": "Euro Sign", "\r": "Carriage Return", "\ufb33": "Hebrew Letter Dalet With Dagesh",
			"1": "One", "\U0001F600": "Emoji: Grinning Face", "\u0080": "Control", "\u00f6": "Latin Small Letter O With Diaeresis",
		}, "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"\u00f6\":\"Latin Small Letter O With Diaeresis\"," +
			"\"\u20ac\":\"Euro Sign\",\"\U0001F600\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}"},
		{"key-utf16-order-ascii-first", map[string]any{"é": 1.0, "e": 2.0, "E": 3.0}, `{"E":3,"e":2,"é":1}`},
		{"key-escaped", map[string]any{"a\"b": 1.0}, `{"a\"b":1}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Canonicalize(tt.in)
			if err != nil {
				t.Fatalf("Canonicalize: %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
}

// RFC 8785 Appendix B, plus the spec's cross-language boundary cases. Expected
// strings were produced by JavaScript's Number.prototype.toString.
func TestCanonicalizeRFC8785NumberTable(t *testing.T) {
	tests := []struct {
		bits uint64
		want string
	}{
		{0x0000000000000000, `0`},
		{0x8000000000000000, `0`},
		{0x0000000000000001, `5e-324`},
		{0x7fefffffffffffff, `1.7976931348623157e+308`},
		{0x4340000000000000, `9007199254740992`},
		{0x4430000000000000, `295147905179352830000`},
		{0x44b52d02c7e14af5, `9.999999999999997e+22`},
		{0x44b52d02c7e14af6, `1e+23`},
		{0x44b52d02c7e14af7, `1.0000000000000001e+23`},
		{0x444b1ae4d6e2ef4e, `999999999999999700000`},
		{0x444b1ae4d6e2ef4f, `999999999999999900000`},
		{0x444b1ae4d6e2ef50, `1e+21`},
		{0x3eb0c6f7a0b5ed8c, `9.999999999999997e-7`},
		{0x3eb0c6f7a0b5ed8d, `0.000001`},
		{0x41b3de4355555553, `333333333.3333332`},
		{0x41b3de4355555555, `333333333.3333333`},
		{0x41b3de4355555557, `333333333.33333343`},
		{0xbecbf647612f3696, `-0.0000033333333333333333`},
		{0x43143ff3c1cb0959, `1424953923781206.2`},
	}
	for _, tt := range tests {
		got, err := Canonicalize(math.Float64frombits(tt.bits))
		if err != nil {
			t.Fatalf("%#x: %v", tt.bits, err)
		}
		if string(got) != tt.want {
			t.Errorf("%#x: got %s, want %s", tt.bits, got, tt.want)
		}
	}
}

func TestCanonicalizeErrors(t *testing.T) {
	nested := func(depth int) any {
		var v any = "leaf"
		for i := 0; i < depth; i++ {
			v = []any{v}
		}
		return v
	}
	tests := []struct {
		name string
		in   any
	}{
		{"nan", math.NaN()},
		{"inf", math.Inf(1)},
		{"neg-inf", math.Inf(-1)},
		{"invalid-utf8-string", "a\xffb"},
		{"invalid-utf8-key", map[string]any{"a\xff": 1.0}},
		{"depth-33", nested(33)},
		{"nan-nested", map[string]any{"a": []any{math.NaN()}}},
		{"unsupported-int", 1},
		{"unsupported-map-type", map[string]string{"a": "b"}},
		{"unsupported-slice-type", []string{"a"}},
		{"json-number-hex", json.Number("0x10")},
		{"json-number-nan", json.Number("NaN")},
		{"json-number-out-of-range", json.Number("1e999")},
		{"json-number-empty", json.Number("")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := Canonicalize(tt.in); err == nil {
				t.Fatalf("expected error, got %s", got)
			}
		})
	}
}

func TestCanonicalizeDepthBoundary(t *testing.T) {
	var v any = "leaf"
	for i := 0; i < maxDepth; i++ {
		v = []any{v}
	}
	got, err := Canonicalize(v)
	if err != nil {
		t.Fatalf("depth %d should be allowed: %v", maxDepth, err)
	}
	want := strings.Repeat("[", maxDepth) + `"leaf"` + strings.Repeat("]", maxDepth)
	if string(got) != want {
		t.Fatalf("got %s", got)
	}
}

// The API (JS) writes 1 and the agent decodes it as float64(1); both decoding
// paths and the JS form must meet at the same bytes.
func TestCanonicalizeSameBytesFromBothDecoders(t *testing.T) {
	const doc = `{"n":1,"big":9007199254740992,"f":1.50,"e":1E+2,"s":"é","l":[1,2.0]}`
	var plain any
	if err := json.Unmarshal([]byte(doc), &plain); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(strings.NewReader(doc))
	dec.UseNumber()
	var withNumber any
	if err := dec.Decode(&withNumber); err != nil {
		t.Fatal(err)
	}
	a, err := Canonicalize(plain)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Canonicalize(withNumber)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"big":9007199254740992,"e":100,"f":1.5,"l":[1,2],"n":1,"s":"é"}`
	if string(a) != want || string(b) != want {
		t.Fatalf("plain=%s useNumber=%s want=%s", a, b, want)
	}
}
