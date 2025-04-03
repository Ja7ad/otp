//go:build go1.18
// +build go1.18

package otp

import (
	"testing"
)

func FuzzDeriveOTP(f *testing.F) {
	f.Add([]byte("12345678901234567890"), uint64(0), 6, int(SHA1))
	f.Add([]byte("12345678901234567890123456789012"), uint64(1), 8, int(SHA256))
	f.Add([]byte("1234567890123456789012345678901234567890123456789012345678901234"), uint64(999), 10, int(SHA512))

	f.Fuzz(func(t *testing.T, secret []byte, counter uint64, digits int, algoInt int) {
		if len(secret) == 0 || digits < 1 || digits > 10 || algoInt < 0 || algoInt > 2 {
			t.Skip()
		}
		algo := Algorithm(algoInt)

		otp, err := deriveOTP(secret, counter, digits, algo)
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
