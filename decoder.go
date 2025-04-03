package otp

import (
	"encoding/base32"
	"strings"
)

func DecodeSecret(secret string) ([]byte, error) {
	secret = strings.TrimSpace(secret)
	if n := len(secret) % 8; n != 0 {
		secret = secret + strings.Repeat("=", 8-n)
	}

	secret = strings.ToUpper(secret)

	return base32.StdEncoding.DecodeString(secret)
}
