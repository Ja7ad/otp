package otp

import (
	"encoding/hex"
	"testing"
)

func TestDecodeSecret(t *testing.T) {
	tests := []struct {
		name     string
		secret   string
		expected string
		wantErr  bool
	}{
		// ✅ From RFC 4648 §10
		{"RFC 4648 - 0 chars", "", "", false},
		{"RFC 4648 - 1 char", "MY======", "66", false},                    // f
		{"RFC 4648 - 2 chars", "MZXQ====", "666f", false},                 // fo
		{"RFC 4648 - 3 chars", "MZXW6===", "666f6f", false},               // foo
		{"RFC 4648 - 4 chars", "MZXW6YQ=", "666f6f62", false},             // foob
		{"RFC 4648 - 5 chars", "MZXW6YTB", "666f6f6261", false},           // fooba
		{"RFC 4648 - 6 chars", "MZXW6YTBOI======", "666f6f626172", false}, // foobar
		{"Malformed input", "123!@#", "", true},

		// ❌ Error case
		{"Unsupported encoding", "foobar", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeSecret(tt.secret)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			expectedBytes, _ := hex.DecodeString(tt.expected)
			if string(got) != string(expectedBytes) {
				t.Errorf("decoded mismatch:\nexpected: %x\ngot:      %x", expectedBytes, got)
			}
		})
	}
}
