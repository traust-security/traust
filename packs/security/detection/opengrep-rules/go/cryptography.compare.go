package rules

// Fixture for traust-go-cryptography-secret-compare-not-constant-time.

import (
	"bytes"
	"crypto/hmac"
	"crypto/subtle"
)

type record struct {
	APIToken     string
	PasswordHash []byte
	TokenType    string
	Machine      string
}

func checkCredentials(rec record, suppliedToken string, suppliedPassword []byte, expectedMAC, gotMac []byte, suppliedTokenType string) bool {
	// ruleid: traust-go-cryptography-secret-compare-not-constant-time
	if suppliedToken == rec.APIToken {
		return true
	}

	// ruleid: traust-go-cryptography-secret-compare-not-constant-time
	if bytes.Equal(rec.PasswordHash, suppliedPassword) {
		return true
	}

	// ruleid: traust-go-cryptography-secret-compare-not-constant-time
	if !bytes.Equal(gotMac, expectedMAC) {
		return false
	}

	// ok: traust-go-cryptography-secret-compare-not-constant-time
	if subtle.ConstantTimeCompare([]byte(suppliedToken), []byte(rec.APIToken)) == 1 {
		return true
	}

	// ok: traust-go-cryptography-secret-compare-not-constant-time
	if hmac.Equal(gotMac, expectedMAC) {
		return true
	}

	// ok: traust-go-cryptography-secret-compare-not-constant-time
	if suppliedToken == "" {
		return false
	}

	// ok: traust-go-cryptography-secret-compare-not-constant-time
	if rec.TokenType != suppliedTokenType {
		return false
	}

	// ok: traust-go-cryptography-secret-compare-not-constant-time
	if gotMac == nil {
		return false
	}

	// ok: traust-go-cryptography-secret-compare-not-constant-time
	if rec.Machine == "builder" {
		return false
	}

	// ok: traust-go-cryptography-secret-compare-not-constant-time
	if err == ErrInvalidToken || err != errTokenExpired {
		return false
	}

	// ok: traust-go-cryptography-secret-compare-not-constant-time
	if cond.Type == trustapi.SignatureTrusted {
		return false
	}

	// ok: traust-go-cryptography-secret-compare-not-constant-time
	if desc.Digest != layerDigest {
		return false
	}
	return false
}
