package otp

import (
	"crypto/subtle"
)

func validateOTP(code string, secret []byte, counter uint64, digits int, algo Algorithm) (bool, error) {
	if len(code) != digits {
		return false, ErrInvalidCodeLength
	}

	expected, err := deriveOTP(secret, counter, digits, algo)
	if err != nil {
		return false, err
	}

	// Constant-time comparison using unsafe string→[]byte conversion
	if subtle.ConstantTimeCompare([]byte(code), []byte(expected)) == 1 {
		return true, nil
	}

	return false, ErrInvalidCode
}
