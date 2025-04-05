package otp

import "testing"

func TestRawSuiteParsing(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		shouldPass  bool
		expectKnown bool
	}{
		{
			name:        "valid: SHA1 QN08",
			raw:         "OCRA-1:HOTP-SHA1-6:QN08",
			shouldPass:  true,
			expectKnown: true,
		},
		{
			name:        "valid: SHA256 C-QA10",
			raw:         "OCRA-1:HOTP-SHA256-8:C-QA10",
			shouldPass:  true,
			expectKnown: true,
		},
		{
			name:        "invalid: unknown suite",
			raw:         "OCRA-1:HOTP-MD5-6:QX99",
			shouldPass:  false,
			expectKnown: false,
		},
		{
			name:        "invalid: malformed string",
			raw:         "garbage-string",
			shouldPass:  false,
			expectKnown: false,
		},
		{
			name:        "invalid: empty string",
			raw:         "",
			shouldPass:  false,
			expectKnown: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isKnown := IsKnownSuite(tt.raw)
			if isKnown != tt.expectKnown {
				t.Errorf("IsKnownSuite(%q) = %v; want %v", tt.raw, isKnown, tt.expectKnown)
			}

			suite, err := NewRawSuite(tt.raw)
			if tt.shouldPass && err != nil {
				t.Errorf("NewRawSuite(%q) returned unexpected error: %v", tt.raw, err)
			}
			if !tt.shouldPass && err == nil {
				t.Errorf("NewRawSuite(%q) expected to fail, but succeeded: %v", tt.raw, suite)
			}
		})
	}
}

func TestNewSuite(t *testing.T) {
	tests := []struct {
		name       string
		cfg        SuiteConfig
		shouldPass bool
	}{
		{
			name: "valid known suite",
			cfg: SuiteConfig{
				Raw:              "OCRA-1:HOTP-SHA1-6:QN08",
				Hash:             SHA1,
				Digits:           6,
				Challenge:        ChallengeNumeric08,
				IncludeChallenge: true,
			},
			shouldPass: true,
		},
		{
			name: "invalid: suite not registered",
			cfg: SuiteConfig{
				Raw:              "OCRA-1:HOTP-SHA1-6:XYZ99",
				Hash:             SHA1,
				Digits:           6,
				Challenge:        ChallengeNone,
				IncludeChallenge: true,
			},
			shouldPass: false,
		},
		{
			name: "invalid: password input but no password hash",
			cfg: SuiteConfig{
				Raw:              "OCRA-1:HOTP-SHA1-6:QN08",
				Hash:             SHA1,
				Digits:           6,
				Challenge:        ChallengeNumeric08,
				IncludeChallenge: true,
				IncludePassword:  true,
				PasswordHash:     PasswordNone,
			},
			shouldPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite, err := NewSuite(tt.cfg)
			if tt.shouldPass && err != nil {
				t.Errorf("expected success but got error: %v", err)
			}
			if !tt.shouldPass && err == nil {
				t.Errorf("expected error but got suite: %v", suite)
			}
		})
	}
}

func TestMustRawSuitePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustRawSuite did not panic on invalid input")
		}
	}()

	_ = MustRawSuite("invalid-suite-string")
}

func TestKnownSuitesAreValid(t *testing.T) {
	for raw, cfg := range knownSuites {
		if err := cfg.Validate(); err != nil {
			t.Errorf("invalid SuiteConfig for raw=%q: %v", raw, err)
		}
	}
}
