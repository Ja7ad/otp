package otp

import (
	"encoding/base32"
	"strings"
)

func decodeSecret(secret string) ([]byte, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(secret, " ", ""))

	// Add padding if needed
	if pad := len(normalized) % 8; pad != 0 {
		normalized += strings.Repeat("=", 8-pad)
	}

	return base32.StdEncoding.DecodeString(normalized)
}
