package otp

import (
	"fmt"
	"net/url"
)

// DefaultHOTPParam provides a default configuration for HOTP generation and validation,
// using SHA1, 6 digits. Note: Period and Skew are not used in HOTP but included for Param compatibility.
var DefaultHOTPParam = &Param{
	Digits:    SixDigits,
	Algorithm: SHA1,
	Period:    0,
	Skew:      0,
}

// GenerateHOTP generates an HOTP code from a given secret and counter.
// If `param` is nil, DefaultHOTPParam is used.
func GenerateHOTP(secret string, counter uint64, param *Param) (string, error) {
	if param == nil {
		def := *DefaultHOTPParam
		param = &def
	}

	secretBuf, err := decodeSecret(secret)
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
	if param.Issuer == "" {
		return nil, ErrIssuerRequired
	}
	if param.AccountName == "" {
		return nil, ErrAccountNameRequired
	}
	if param.Digits == 0 {
		param.Digits = Digits(6)
	}
	if param.Algorithm == 0 {
		param.Algorithm = SHA1
	}
	if param.Secret == "" {
		return nil, ErrSecretRequired
	}

	label := url.PathEscape(fmt.Sprintf("%s:%s", param.Issuer, param.AccountName))

	query := url.Values{}
	query.Set("secret", param.Secret)
	query.Set("issuer", param.Issuer)
	query.Set("algorithm", param.Algorithm.String())
	query.Set("digits", fmt.Sprintf("%d", param.Digits))
	query.Set("counter", "0") // Initial counter assumed to be 0

	return &url.URL{
		Scheme:   "otpauth",
		Host:     "hotp",
		Path:     "/" + label,
		RawQuery: query.Encode(),
	}, nil
}

// ValidateHOTP checks whether the given HOTP code is valid for the provided secret and counter.
// Returns true if valid, false otherwise. Uses constant-time comparison internally.
// If `param` is nil, DefaultHOTPParam is used.
func ValidateHOTP(secret, code string, counter uint64, param *Param) (bool, error) {
	if param == nil {
		def := *DefaultHOTPParam
		param = &def
	}

	secretBuf, err := decodeSecret(secret)
	if err != nil {
		return false, err
	}

	period := param.Period
	if period == 0 {
		period = 30
	}

	skew := param.Skew

	for i := -int64(skew); i <= int64(skew); i++ {
		valid, err := validateOTP(code, secretBuf, counter+uint64(i), param.Digits.Int(), param.Algorithm)
		if err == nil && valid {
			return true, nil
		}
	}

	return false, ErrInvalidCode
}
