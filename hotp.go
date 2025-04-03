package otp

import (
	"net/url"
)

// DefaultHOTPParam provides a default configuration for HOTP generation and validation,
// using SHA1, 6 digits. Note: Period and Skew are not used in HOTP but included for Param compatibility.
var DefaultHOTPParam = &Param{
	Digits:    SixDigits,
	Algorithm: SHA1,
	Period:    0,
	Skew:      2,
}

// GenerateHOTP generates an HOTP code from a given secret and counter.
// If `param` is nil, DefaultHOTPParam is used.
func GenerateHOTP(secret string, counter uint64, param *Param) (string, error) {
	if param == nil {
		def := *DefaultHOTPParam
		param = &def
	}

	secretBuf, err := DecodeSecret(secret)
	if err != nil {
		return "", err
	}

	return deriveOTP(secretBuf, counter, param.Digits.Int(), param.Algorithm)
}

// GenerateHOTPURL constructs an otpauth:// URL for configuring HOTP-based authenticators.
// The URL includes the issuer, account name, secret, algorithm, digits, and counter.
//
// Example output:
// otpauth://hotp/Example:alice@domain.com?secret=BASE32ENCODEDSECRET&issuer=Example&algorithm=SHA1&digits=6&counter=0
func GenerateHOTPURL(param URLParam) (*url.URL, error) {
	return generateOTPURL("hotp", param, map[string]string{
		"counter": "0",
	})
}

// ValidateHOTP checks whether the given HOTP code is valid for the provided secret and counter.
// Returns true if valid, false otherwise. Uses constant-time comparison internally.
// If `param` is nil, DefaultHOTPParam is used.
func ValidateHOTP(secret, code string, counter uint64, param *Param) (bool, error) {
	if param == nil {
		def := *DefaultHOTPParam
		param = &def
	}

	if param.Skew > 10 {
		return false, ErrInvalidSkew
	}
	skew := int64(param.Skew)

	secretBuf, err := DecodeSecret(secret)
	if err != nil {
		return false, err
	}

	for i := -skew; i <= skew; i++ {
		var c uint64
		if i < 0 {
			if int64(counter) < -i {
				continue // prevent underflow
			}
			c = counter - uint64(-i)
		} else {
			c = counter + uint64(i)
		}

		valid, err := validateOTP(code, secretBuf, c, param.Digits, param.Algorithm)
		if err == nil && valid {
			return true, nil
		}
	}

	return false, ErrInvalidCode
}
