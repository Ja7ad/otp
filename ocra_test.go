package otp

import "testing"

func TestGenerateAndValidateOCRA(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	rawSuite := "OCRA-1:HOTP-SHA1-6:QN08"

	suite := MustRawSuite(rawSuite)

	input := OCRAInput{
		Challenge: []byte("00000000"),
	}

	code, err := GenerateOCRA(secret, suite, input)
	if err != nil {
		t.Fatalf("GenerateOCRA failed: %v", err)
	}
	if code == "" {
		t.Errorf("code should not be empty")
	}
}

func TestGenerateOCRA_InvalidSecret(t *testing.T) {
	suite := MustRawSuite("OCRA-1:HOTP-SHA1-6:QN08")

	_, err := GenerateOCRA("!!INVALID_BASE32!!", suite, OCRAInput{
		Challenge: []byte("00000000"),
	})
	if err == nil {
		t.Error("expected error for invalid secret, got nil")
	}
}

func TestValidateOCRA_InvalidSecret(t *testing.T) {
	suite := MustRawSuite("OCRA-1:HOTP-SHA1-6:QN08")

	_, err := ValidateOCRA("!!INVALID_BASE32!!", "000000", suite, OCRAInput{
		Challenge: []byte("00000000"),
	})
	if err == nil {
		t.Error("expected error for invalid secret, got nil")
	}
}

func TestOCRAInputValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     SuiteConfig
		input   OCRAInput
		wantErr bool
	}{
		{
			name: "valid: only challenge QN08",
			cfg: SuiteConfig{
				IncludeChallenge: true,
				Challenge:        ChallengeNumeric08,
			},
			input: OCRAInput{
				Challenge: []byte("12345678"),
			},
			wantErr: false,
		},
		{
			name: "invalid: challenge too short",
			cfg: SuiteConfig{
				IncludeChallenge: true,
				Challenge:        ChallengeNumeric10,
			},
			input: OCRAInput{
				Challenge: []byte("short"),
			},
			wantErr: true,
		},
		{
			name: "invalid: challenge too long",
			cfg: SuiteConfig{
				IncludeChallenge: true,
				Challenge:        ChallengeNumeric08,
			},
			input: OCRAInput{
				Challenge: make([]byte, 129),
			},
			wantErr: true,
		},
		{
			name: "valid: with counter",
			cfg: SuiteConfig{
				IncludeCounter: true,
			},
			input: OCRAInput{
				Counter: make([]byte, 8),
			},
			wantErr: false,
		},
		{
			name: "invalid: counter wrong length",
			cfg: SuiteConfig{
				IncludeCounter: true,
			},
			input: OCRAInput{
				Counter: make([]byte, 5),
			},
			wantErr: true,
		},
		{
			name: "valid: with password (SHA1)",
			cfg: SuiteConfig{
				IncludePassword: true,
				PasswordHash:    PasswordSHA1,
			},
			input: OCRAInput{
				Password: make([]byte, 20),
			},
			wantErr: false,
		},
		{
			name: "invalid: password length for SHA256",
			cfg: SuiteConfig{
				IncludePassword: true,
				PasswordHash:    PasswordSHA256,
			},
			input: OCRAInput{
				Password: make([]byte, 20),
			},
			wantErr: true,
		},
		{
			name: "invalid: password missing",
			cfg: SuiteConfig{
				IncludePassword: true,
				PasswordHash:    PasswordSHA1,
			},
			input: OCRAInput{
				Password: nil,
			},
			wantErr: true,
		},
		{
			name: "valid: with session info",
			cfg: SuiteConfig{
				IncludeSession: true,
			},
			input: OCRAInput{
				SessionInfo: make([]byte, 64),
			},
			wantErr: false,
		},
		{
			name: "invalid: session info too long",
			cfg: SuiteConfig{
				IncludeSession: true,
			},
			input: OCRAInput{
				SessionInfo: make([]byte, 129),
			},
			wantErr: true,
		},
		{
			name: "valid: with timestamp",
			cfg: SuiteConfig{
				IncludeTimestamp: true,
			},
			input: OCRAInput{
				Timestamp: make([]byte, 8),
			},
			wantErr: false,
		},
		{
			name: "invalid: timestamp wrong length",
			cfg: SuiteConfig{
				IncludeTimestamp: true,
			},
			input: OCRAInput{
				Timestamp: make([]byte, 4),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.validate(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("OCRAInput.validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}
