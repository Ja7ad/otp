//go:build go1.18
// +build go1.18

package otp

import (
	"testing"
)

func FuzzDeriveRFC4226(f *testing.F) {
	f.Add([]byte("12345678901234567890"), uint64(0), 6, int(SHA1))
	f.Add([]byte("12345678901234567890123456789012"), uint64(1), 8, int(SHA256))
	f.Add([]byte("1234567890123456789012345678901234567890123456789012345678901234"), uint64(999), 10, int(SHA512))

	f.Fuzz(func(t *testing.T, secret []byte, counter uint64, digits int, algoInt int) {
		if len(secret) == 0 || digits < 1 || digits > 10 || algoInt < 0 || algoInt > 2 {
			t.Skip()
		}
		algo := Algorithm(algoInt)

		otp, err := deriveRFC4226(secret, counter, digits, algo)
		if err != nil {
			t.Skip()
		}

		if len(otp) != digits {
			t.Errorf("OTP length mismatch: expected %d, got %d (%s)", digits, len(otp), otp)
		}

		for i := 0; i < len(otp); i++ {
			if otp[i] < '0' || otp[i] > '9' {
				t.Errorf("Non-digit character in OTP: %q", otp[i])
			}
		}
	})
}

func FuzzDeriveRFC6287(f *testing.F) {
	f.Add(
		"OCRA-1:HOTP-SHA1-6:QN08",
		"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", // Base32 key
		[]byte("00000000"),                 // Challenge
		[]byte{},                           // Counter
		[]byte{},                           // Password
		[]byte{},                           // Session
		[]byte{},                           // Timestamp
	)

	f.Fuzz(func(t *testing.T,
		rawSuite, base32Secret string,
		challenge, counter, password, session, timestamp []byte,
	) {
		suite, err := NewRawSuite(rawSuite)
		if err != nil {
			t.Skip()
		}

		code, err := GenerateOCRA(base32Secret, suite, OCRAInput{
			Challenge:   challenge,
			Counter:     counter,
			Password:    password,
			SessionInfo: session,
			Timestamp:   timestamp,
		})
		if err != nil {
			t.Skip()
		}

		if len(code) != suite.Config().Digits {
			t.Errorf("invalid code length: want %d, got %d", suite.Config().Digits, len(code))
		}

		for i := 0; i < len(code); i++ {
			if code[i] < '0' || code[i] > '9' {
				t.Errorf("non-digit character in OTP: %q", code[i])
			}
		}
	})
}
