package otp

import (
	"crypto/subtle"
)

func validateRFC4226(code string, secret []byte, counter uint64, digits Digits, algo Algorithm) (bool, error) {
	digitInt := digits.Int()

	if len(code) != digitInt {
		return false, ErrInvalidCodeLength
	}

	excepted, err := deriveRFC4226(secret, counter, digitInt, algo)
	if err != nil {
		return false, err
	}

	// Constant-time comparison using unsafe string→[]byte conversion
	if subtle.ConstantTimeCompare([]byte(code), []byte(excepted)) == 1 {
		return true, nil
	}

	return false, ErrInvalidCode
}

func validateRFC6287(code string, secret []byte, suite Suite, input OCRAInput) (bool, error) {
	cfg := suite.Config()
	expectedDigits := cfg.Digits

	if len(code) != expectedDigits {
		return false, ErrInvalidCodeLength
	}

	expected, err := deriveRFC6287(secret, suite, input)
	if err != nil {
		return false, err
	}

	if subtle.ConstantTimeCompare([]byte(code), []byte(expected)) == 1 {
		return true, nil
	}

	return false, ErrInvalidCode
}
