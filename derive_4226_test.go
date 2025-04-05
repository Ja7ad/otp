package otp

import (
	"encoding/base32"
	"fmt"
	"testing"
)

// HOTP test vectors from RFC 4226 — only support 6 digits here
func TestDeriveOTP_HOTP_RFC4226(t *testing.T) {
	secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")

	expected := []string{
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

	for counter, want := range expected {
		got, err := deriveRFC4226(secret, uint64(counter), 6, SHA1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != want {
			t.Errorf("HOTP RFC4226 failed at counter %d: got %s, want %s", counter, got, want)
		}
	}

	// Additional digit sizes (non-RFC test)
	for _, digits := range []int{8, 10} {
		for counter := range expected {
			got, err := deriveRFC4226(secret, uint64(counter), digits, SHA1)
			if err != nil {
				t.Fatalf("unexpected error (digits=%d): %v", digits, err)
			}
			if len(got) != digits {
				t.Errorf("HOTP with digits=%d at counter %d: got length %d", digits, counter, len(got))
			}
		}
	}
}

func TestDeriveOTP_TOTP_RFC6238(t *testing.T) {
	secrets := map[Algorithm][]byte{
		SHA1:   []byte("12345678901234567890"),
		SHA256: []byte("12345678901234567890123456789012"),
		SHA512: []byte("1234567890123456789012345678901234567890123456789012345678901234"),
	}

	tests := []struct {
		time    int64
		expects map[Algorithm]string
	}{
		{59, map[Algorithm]string{SHA1: "94287082", SHA256: "46119246", SHA512: "90693936"}},
		{1111111109, map[Algorithm]string{SHA1: "07081804", SHA256: "68084774", SHA512: "25091201"}},
		{1111111111, map[Algorithm]string{SHA1: "14050471", SHA256: "67062674", SHA512: "99943326"}},
		{1234567890, map[Algorithm]string{SHA1: "89005924", SHA256: "91819424", SHA512: "93441116"}},
		{2000000000, map[Algorithm]string{SHA1: "69279037", SHA256: "90698825", SHA512: "38618901"}},
		{20000000000, map[Algorithm]string{SHA1: "65353130", SHA256: "77737706", SHA512: "47863826"}},
	}

	for _, tt := range tests {
		counter := uint64(tt.time / 30)
		for algo, expected := range tt.expects {
			secret := secrets[algo]
			got, err := deriveRFC4226(secret, counter, 8, algo)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				continue
			}
			if got != expected {
				t.Errorf("TOTP RFC6238 failed at time %d with algo %v: got %s, want %s", tt.time, algo, got, expected)
			}
		}
	}

	// Additional digit size tests (non-RFC, for coverage)
	for _, digits := range []int{6, 10} {
		for _, tt := range tests {
			counter := uint64(tt.time / 30)
			for algo, secret := range secrets {
				got, err := deriveRFC4226(secret, counter, digits, algo)
				if err != nil {
					t.Errorf("unexpected error (digits=%d): %v", digits, err)
					continue
				}
				if len(got) != digits {
					t.Errorf("TOTP with digits=%d at time %d (algo=%v): got length %d", digits, tt.time, algo, len(got))
				}
			}
		}
	}
}

func BenchmarkDeriveOTP(b *testing.B) {
	secrets := map[Algorithm][]byte{
		SHA1:   []byte("12345678901234567890"),
		SHA256: []byte("12345678901234567890123456789012"),
		SHA512: []byte("1234567890123456789012345678901234567890123456789012345678901234"),
	}

	digitVariants := []int{6, 8, 9, 10}

	for algo, secret := range secrets {
		for _, digits := range digitVariants {
			name := fmt.Sprintf("deriveRFC4226/%v/%ddigits", algo, digits)
			b.Run(name, func(b *testing.B) {
				b.ReportAllocs()

				var counter uint64 = 0
				for i := 0; i < b.N; i++ {
					_, err := deriveRFC4226(secret, counter, digits, algo)
					if err != nil {
						b.Fatal(err)
					}
					counter++
				}
			})
		}
	}
}
