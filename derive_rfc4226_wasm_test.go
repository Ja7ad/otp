//go:build js && wasm

package otp

import (
	"encoding/base32"
	"testing"
)

// RFC 4226 test vectors - Base32("12345678901234567890")
const hotpSecretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

var hotpExpectedCodes = []string{
	"755224",
	"287082",
	"359152",
	"969429",
	"338314",
	"254676",
	"287922",
	"162583",
	"399871",
	"520489",
}

func TestDeriveOTPWasm_HOTP_RFC4226(t *testing.T) {
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(hotpSecretBase32)
	if err != nil {
		t.Fatalf("Failed to decode secret: %v", err)
	}

	for counter, expected := range hotpExpectedCodes {
		t.Run("Counter_"+string(rune(counter)), func(t *testing.T) {
			code, err := DeriveRFC4226Wasm(secret, uint64(counter), 6, SHA1)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if code != expected {
				t.Errorf("Invalid OTP for counter %d: got %s, want %s", counter, code, expected)
			}
		})
	}
}
