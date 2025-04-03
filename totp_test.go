package otp

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestGenerateTOTP_RFC6238(t *testing.T) {
	now := time.Now()

	algos := []Algorithm{SHA1, SHA256, SHA512}
	digits := []Digits{SixDigits, EightDigits, TenDigits}

	for _, algo := range algos {
		secret, err := RandomSecret(algo)
		if err != nil {
			t.Fatalf("RandomSecret(%s) failed: %v", algo.String(), err)
		}

		for _, digit := range digits {
			t.Run(fmt.Sprintf("%s/%d", algo.String(), digit), func(t *testing.T) {
				code, err := GenerateTOTP(secret, now, &Param{
					Digits:    digit,
					Period:    30,
					Skew:      1,
					Algorithm: algo,
				})
				if err != nil {
					t.Errorf("GenerateTOTP failed: %v", err)
				}
				if len(code) != digit.Int() {
					t.Errorf("Unexpected code length: got %d, want %d", len(code), digit)
				}
			})
		}
	}
}

func TestValidateTOTP(t *testing.T) {
	now := time.Now()

	algos := []Algorithm{SHA1, SHA256, SHA512}
	digits := []Digits{SixDigits, EightDigits, TenDigits}

	for _, algo := range algos {
		secret, err := RandomSecret(algo)
		if err != nil {
			t.Fatalf("RandomSecret(%s) failed: %v", algo.String(), err)
		}

		for _, digit := range digits {
			t.Run(fmt.Sprintf("%s/%d", algo.String(), digit), func(t *testing.T) {
				code, err := GenerateTOTP(secret, now, &Param{
					Digits:    digit,
					Period:    30,
					Skew:      1,
					Algorithm: algo,
				})
				if err != nil {
					t.Errorf("GenerateTOTP failed: %v", err)
				}
				if len(code) != digit.Int() {
					t.Errorf("Unexpected code length: got %d, want %d", len(code), digit)
				}

				valid, err := ValidateTOTP(secret, code, now, &Param{
					Digits:    digit,
					Period:    30,
					Skew:      1,
					Algorithm: algo,
				})
				if err != nil {
					t.Errorf("ValidateTOTP error: %v", err)
				}
				if !valid {
					t.Errorf("Generated code %s is not valid", code)
				}
			})
		}
	}
}

func TestGenerateTOTPURL(t *testing.T) {
	u, err := GenerateTOTPURL(URLParam{
		Issuer:      "ExampleApp",
		AccountName: "user@example.com",
		Secret:      "SECRETKEY123",
		Digits:      6,
		Period:      30,
		Algorithm:   SHA1,
	})
	if err != nil {
		t.Fatalf("GenerateTOTPURL failed: %v", err)
	}

	if u.Scheme != "otpauth" || u.Host != "totp" {
		t.Errorf("Unexpected scheme or host: %s://%s", u.Scheme, u.Host)
	}

	if !strings.Contains(u.String(), "issuer=ExampleApp") {
		t.Errorf("Issuer missing from URL")
	}

	if !strings.Contains(u.String(), "digits=6") {
		t.Errorf("Digits missing from URL")
	}

	if !strings.Contains(u.String(), "algorithm=SHA1") {
		t.Errorf("Algorithm missing from URL")
	}

	if _, err := url.Parse(u.String()); err != nil {
		t.Errorf("Invalid otpauth URL: %v", err)
	}
}
