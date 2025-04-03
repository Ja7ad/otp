package otp

import (
	"encoding/base32"
	"net/url"
	"testing"
)

func TestRandomSecret(t *testing.T) {
	tests := []struct {
		name      string
		algo      Algorithm
		wantBytes int
		wantErr   bool
	}{
		{"SHA1", SHA1, 20, false},
		{"SHA256", SHA256, 32, false},
		{"SHA512", SHA512, 64, false},
		{"InvalidAlgo", Algorithm(99), 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret, err := RandomSecret(tt.algo)

			if (err != nil) != tt.wantErr {
				t.Fatalf("unexpected error state: got error = %v, wantErr = %v", err, tt.wantErr)
			}

			if err == nil {
				decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
				if err != nil {
					t.Fatalf("failed to decode base32: %v", err)
				}
				if len(decoded) != tt.wantBytes {
					t.Errorf("unexpected decoded length: got = %d, want = %d", len(decoded), tt.wantBytes)
				}
			}

			t.Log(secret)
		})
	}
}

func TestParseOTPAuthURL(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		want    *URLParam
		wantErr bool
	}{
		{
			name:   "Valid TOTP URL with all fields",
			rawURL: "otpauth://totp/MyApp:user@example.com?secret=ABCDEF123456&issuer=MyApp&algorithm=SHA256&digits=8&period=45",
			want: &URLParam{
				Issuer:      "MyApp",
				AccountName: "user@example.com",
				Secret:      "ABCDEF123456",
				Digits:      8,
				Algorithm:   SHA256,
				Period:      45,
			},
		},
		{
			name:   "Valid HOTP URL with minimal fields",
			rawURL: "otpauth://hotp/Example:alice@domain.com?secret=XYZ987",
			want: &URLParam{
				Issuer:      "Example",
				AccountName: "alice@domain.com",
				Secret:      "XYZ987",
				Digits:      6,
				Algorithm:   SHA1,
				Period:      30,
			},
		},
		{
			name:    "Invalid scheme",
			rawURL:  "http://totp/Example:user@domain.com?secret=ABC",
			wantErr: true,
		},
		{
			name:    "Invalid host",
			rawURL:  "otpauth://foo/Example:user@domain.com?secret=ABC",
			wantErr: true,
		},
		{
			name:    "Missing label",
			rawURL:  "otpauth://totp/?secret=ABC",
			wantErr: true,
		},
		{
			name:    "Invalid digits",
			rawURL:  "otpauth://totp/Issuer:user?secret=ABC&digits=abc",
			wantErr: true,
		},
		{
			name:    "Unsupported algorithm",
			rawURL:  "otpauth://totp/Issuer:user?secret=ABC&algorithm=MD5",
			wantErr: true,
		},
		{
			name:    "Invalid period",
			rawURL:  "otpauth://totp/Issuer:user?secret=ABC&period=abc",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("failed to parse input URL: %v", err)
			}

			got, err := ParseOTPAuthURL(u)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error mismatch: got %v, wantErr %v", err, tt.wantErr)
			}

			if err == nil && tt.want != nil {
				if got.Issuer != tt.want.Issuer ||
					got.AccountName != tt.want.AccountName ||
					got.Secret != tt.want.Secret ||
					got.Digits != tt.want.Digits ||
					got.Algorithm != tt.want.Algorithm ||
					got.Period != tt.want.Period {
					t.Errorf("parsed output mismatch:\n got  %+v\n want %+v", got, tt.want)
				}
			}
		})
	}
}
