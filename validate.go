package otp

import (
	"crypto/subtle"
)

func validateRFC4226(code string, secret []byte, counter uint64, digits Digits, algo Algorithm) (bool, error) {
	return validate(code, digits.Int(), func() (string, error) {
		return deriveRFC4226(secret, counter, digits.Int(), algo)
	})
}

func validateRFC6287(code string, secret []byte, suite Suite, input OCRAInput) (bool, error) {
	cfg := suite.Config()
	return validate(code, cfg.Digits, func() (string, error) {
		return deriveRFC6287(secret, suite, input)
	})
}

func validate(code string, expectedLength int, deriveFn func() (string, error)) (bool, error) {
	if len(code) != expectedLength {
		return false, ErrInvalidCodeLength
	}

	expected, err := deriveFn()
	if err != nil {
		return false, err
	}

	if subtle.ConstantTimeCompare([]byte(code), []byte(expected)) == 1 {
		return true, nil
	}

	return false, ErrInvalidCode
}
