package otp

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestGenerateHOTP(t *testing.T) {
	algos := []Algorithm{SHA1, SHA256, SHA512}
	digits := []Digits{SixDigits, EightDigits, TenDigits}
	var counter uint64 = 1234

	for _, algo := range algos {
		secret, err := RandomSecret(algo)
		if err != nil {
			t.Fatalf("RandomSecret(%s) failed: %v", algo.String(), err)
		}

		for _, digit := range digits {
			t.Run(fmt.Sprintf("%s/%d", algo.String(), digit), func(t *testing.T) {
				code, err := GenerateHOTP(secret, counter, &Param{
					Digits:    digit,
					Algorithm: algo,
				})
				if err != nil {
					t.Errorf("GenerateHOTP failed: %v", err)
				}
				if len(code) != digit.Int() {
					t.Errorf("Unexpected code length: got %d, want %d", len(code), digit)
				}
			})
		}
	}
}

func TestValidateHOTP(t *testing.T) {
	algos := []Algorithm{SHA1, SHA256, SHA512}
	digits := []Digits{SixDigits, EightDigits, TenDigits}
	var counter uint64 = 1234

	for _, algo := range algos {
		secret, err := RandomSecret(algo)
		if err != nil {
			t.Fatalf("RandomSecret(%s) failed: %v", algo.String(), err)
		}

		for _, digit := range digits {
			t.Run(fmt.Sprintf("%s/%d", algo.String(), digit), func(t *testing.T) {
				code, err := GenerateHOTP(secret, counter, &Param{
					Digits:    digit,
					Algorithm: algo,
				})
				if err != nil {
					t.Errorf("GenerateHOTP failed: %v", err)
				}
				if len(code) != digit.Int() {
					t.Errorf("Unexpected code length: got %d, want %d", len(code), digit)
				}

				valid, err := ValidateHOTP(secret, code, counter, &Param{
					Digits:    digit,
					Algorithm: algo,
				})
				if err != nil {
					t.Errorf("ValidateHOTP error: %v", err)
				}
				if !valid {
					t.Errorf("Generated code %s is not valid", code)
				}
			})
		}
	}
}

func TestGenerateHOTPURL(t *testing.T) {
	u, err := GenerateHOTPURL(URLParam{
		Issuer:      "ExampleApp",
		AccountName: "user@example.com",
		Secret:      "SECRETKEY123",
		Digits:      6,
		Algorithm:   SHA1,
	})
	if err != nil {
		t.Fatalf("GenerateHOTPURL failed: %v", err)
	}

	if u.Scheme != "otpauth" || u.Host != "hotp" {
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

	if !strings.Contains(u.String(), "counter=0") {
		t.Errorf("Counter missing from URL")
	}

	if _, err := url.Parse(u.String()); err != nil {
		t.Errorf("Invalid otpauth URL: %v", err)
	}
}
