// Package opsign verifies operator-signed approvals for sensitive commands.
package opsign

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const maxDepth = 32

var jsonNumberSyntax = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

// Canonicalize returns the RFC 8785 (JCS) form of v. It accepts only what a
// JSON decode of a command payload produces: nil, bool, float64, json.Number,
// string, []any and map[string]any. Anything else is an error, so a payload the
// API and the agent could read differently can never be hashed.
func Canonicalize(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeValue(&buf, v, 0); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeValue(buf *bytes.Buffer, v any, depth int) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(x))
	case float64:
		return writeNumber(buf, x)
	case json.Number:
		if !jsonNumberSyntax.MatchString(string(x)) {
			return fmt.Errorf("canonical json: invalid number %q", string(x))
		}
		f, err := strconv.ParseFloat(string(x), 64)
		if err != nil {
			return fmt.Errorf("canonical json: number %q: %w", string(x), err)
		}
		return writeNumber(buf, f)
	case string:
		return writeString(buf, x)
	case []any:
		if depth >= maxDepth {
			return errors.New("canonical json: nesting too deep")
		}
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeValue(buf, e, depth+1); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		if depth >= maxDepth {
			return errors.New("canonical json: nesting too deep")
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeValue(buf, x[k], depth+1); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonical json: unsupported type %T", v)
	}
	return nil
}

// lessUTF16 orders keys by UTF-16 code units, which RFC 8785 requires and which
// differs from Go's byte order once a key holds a character above U+FFFF.
func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func writeString(buf *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return errors.New("canonical json: string is not valid UTF-8")
	}
	buf.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			buf.WriteString(`\"`)
		case r == '\\':
			buf.WriteString(`\\`)
		case r == '\b':
			buf.WriteString(`\b`)
		case r == '\f':
			buf.WriteString(`\f`)
		case r == '\n':
			buf.WriteString(`\n`)
		case r == '\r':
			buf.WriteString(`\r`)
		case r == '\t':
			buf.WriteString(`\t`)
		case r < 0x20:
			fmt.Fprintf(buf, `\u%04x`, r)
		default:
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
	return nil
}

// writeNumber formats f like ECMAScript Number::toString, which RFC 8785 mandates.
func writeNumber(buf *bytes.Buffer, f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return errors.New("canonical json: NaN and Infinity are not representable")
	}
	if f == 0 {
		buf.WriteByte('0')
		return nil
	}
	if f < 0 {
		buf.WriteByte('-')
		f = -f
	}
	// 'e' format gives the shortest round-trip digits as d[.ddd]e±XX; the value
	// is then s × 10^(n-k) for k digits.
	mant, exp, _ := strings.Cut(strconv.FormatFloat(f, 'e', -1, 64), "e")
	s := strings.Replace(mant, ".", "", 1)
	e, _ := strconv.Atoi(exp)
	k, n := len(s), e+1
	switch {
	case k <= n && n <= 21:
		buf.WriteString(s + strings.Repeat("0", n-k))
	case 0 < n && n <= 21:
		buf.WriteString(s[:n] + "." + s[n:])
	case -6 < n && n <= 0:
		buf.WriteString("0." + strings.Repeat("0", -n) + s)
	default:
		buf.WriteString(s[:1])
		if k > 1 {
			buf.WriteString("." + s[1:])
		}
		if n-1 < 0 {
			buf.WriteString("e-" + strconv.Itoa(1-n))
		} else {
			buf.WriteString("e+" + strconv.Itoa(n-1))
		}
	}
	return nil
}
