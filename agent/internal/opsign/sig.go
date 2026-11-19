package opsign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

// Carrier is the value of a command payload's operatorApproval key: one
// operator's signature over one approval envelope.
type Carrier struct {
	V            int    `json:"v"`
	CanonicalB64 string `json:"canonicalB64"`
	SignatureB64 string `json:"signatureB64"`
}

// SignedBundle is a trust bundle plus the admin signatures over its canonical bytes.
type SignedBundle struct {
	CanonicalB64 string      `json:"canonicalB64"`
	Signatures   []BundleSig `json:"signatures"`
}

type BundleSig struct {
	KeyID        string `json:"keyId"`
	SignatureB64 string `json:"signatureB64"`
}

// shortDigest is the first 128 bits of SHA-256 as lowercase hex, the form of
// every ID an operator might compare by eye.
func shortDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}

func KeyIDFromSPKI(spkiDER []byte) string { return shortDigest(spkiDER) }

// decodeB64 accepts only the canonical standard-base64 spelling of the bytes it
// returns (padded, no newlines, no stray bits), so a value cannot have two
// encodings.
func decodeB64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil, errors.New("opsign: not canonical standard base64")
	}
	return b, nil
}

// parseP256SPKI returns the public key and its DER bytes; any other key type or
// curve is an error.
func parseP256SPKI(spkiB64 string) (*ecdsa.PublicKey, []byte, error) {
	der, err := decodeB64(spkiB64)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, nil, fmt.Errorf("opsign: public key: %w", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, nil, errors.New("opsign: public key is not ECDSA P-256")
	}
	return pub, der, nil
}

// VerifyES256 checks an ECDSA P-256 signature over SHA-256(msg). The signature
// is the raw 64-byte r||s, not DER.
func VerifyES256(spkiB64 string, msg []byte, sigB64 string) error {
	pub, _, err := parseP256SPKI(spkiB64)
	if err != nil {
		return err
	}
	sig, err := decodeB64(sigB64)
	if err != nil {
		return err
	}
	if len(sig) != 64 {
		return fmt.Errorf("opsign: signature is %d bytes, want 64 (raw r||s)", len(sig))
	}
	digest := sha256.Sum256(msg)
	if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return errors.New("opsign: signature does not verify")
	}
	return nil
}
