package otp

import (
	"crypto/subtle"
)

func validateOTP(code string, secret []byte, counter uint64, digits Digits, algo Algorithm) (bool, error) {
	digitInt := digits.Int()

	if len(code) != digitInt {
		return false, ErrInvalidCodeLength
	}

	excepted, err := deriveOTP(secret, counter, digitInt, algo)
	if err != nil {
		return false, err
	}

	// Constant-time comparison using unsafe string→[]byte conversion
	if subtle.ConstantTimeCompare([]byte(code), []byte(excepted)) == 1 {
		return true, nil
	}

	return false, ErrInvalidCode
}
