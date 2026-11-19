package opsign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func newKey(t *testing.T, curve elliptic.Curve) (priv *ecdsa.PrivateKey, spkiB64 string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return priv, base64.StdEncoding.EncodeToString(der)
}

// signRaw returns the 64-byte r||s signature over SHA-256(msg), standard base64.
func signRaw(t *testing.T, priv *ecdsa.PrivateKey, msg []byte) string {
	t.Helper()
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return base64.StdEncoding.EncodeToString(raw)
}

func TestVerifyES256(t *testing.T) {
	priv, spki := newKey(t, elliptic.P256())
	_, otherSPKI := newKey(t, elliptic.P256())
	_, p384SPKI := newKey(t, elliptic.P384())
	msg := []byte("breeze-operator-approval-v1\nkind=action")
	sig := signRaw(t, priv, msg)
	rawSig, _ := base64.StdEncoding.DecodeString(sig)

	flipped := func(b []byte, i int) []byte {
		c := append([]byte(nil), b...)
		c[i] ^= 0x01
		return c
	}
	digest := sha256.Sum256(msg)
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.StdEncoding.EncodeToString

	tests := []struct {
		name string
		spki string
		msg  []byte
		sig  string
		ok   bool
	}{
		{"valid", spki, msg, sig, true},
		{"flipped message byte", spki, flipped(msg, 5), sig, false},
		{"flipped signature byte in r", spki, msg, enc(flipped(rawSig, 3)), false},
		{"flipped signature byte in s", spki, msg, enc(flipped(rawSig, 40)), false},
		{"different key", otherSPKI, msg, sig, false},
		{"DER signature", spki, msg, enc(der), false},
		{"63-byte signature", spki, msg, enc(rawSig[:63]), false},
		{"65-byte signature", spki, msg, enc(append(append([]byte(nil), rawSig...), 0)), false},
		{"empty signature", spki, msg, "", false},
		{"signature not base64", spki, msg, "!!!!", false},
		{"base64 with a newline", spki, msg, sig[:40] + "\n" + sig[40:], false},
		{"unpadded base64", spki, msg, strings.TrimRight(sig, "="), false},
		{"all-zero signature", spki, msg, enc(make([]byte, 64)), false},
		{"key not base64", "!!!!", msg, sig, false},
		{"key not an SPKI", enc([]byte("not a key")), msg, sig, false},
		{"key on the wrong curve", p384SPKI, msg, sig, false},
		{"empty key", "", msg, sig, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := VerifyES256(tt.spki, tt.msg, tt.sig); (err == nil) != tt.ok {
				t.Errorf("VerifyES256 err = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestDigestIDs(t *testing.T) {
	// SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223 b00361a3...
	const want = "ba7816bf8f01cfea414140de5dae2223"
	if got := KeyIDFromSPKI([]byte("abc")); got != want {
		t.Errorf("KeyIDFromSPKI = %s, want %s", got, want)
	}
	if got := Fingerprint([]byte("abc")); got != want {
		t.Errorf("Fingerprint = %s, want %s", got, want)
	}
}

func TestWireFieldNames(t *testing.T) {
	tests := []struct {
		name string
		v    any
		want string
	}{
		{"carrier", Carrier{V: 1, CanonicalB64: "Yw==", SignatureB64: "cw=="}, `{"v":1,"canonicalB64":"Yw==","signatureB64":"cw=="}`},
		{"signed bundle", SignedBundle{CanonicalB64: "Yw==", Signatures: []BundleSig{{KeyID: "k", SignatureB64: "cw=="}}}, `{"canonicalB64":"Yw==","signatures":[{"keyId":"k","signatureB64":"cw=="}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.v)
			if err != nil || string(got) != tt.want {
				t.Errorf("got %s (%v), want %s", got, err, tt.want)
			}
		})
	}
}
