package otp

import (
	"fmt"
	"net/url"
	"time"
)

// DefaultTOTPParam provides a default configuration for TOTP generation and validation,
// using SHA1, 6 digits, a 30-second period, and zero skew.
var DefaultTOTPParam = &Param{
	Digits:    SixDigits,
	Period:    30,
	Skew:      0,
	Algorithm: SHA1,
}

// GenerateTOTP generates a TOTP code based on the given secret and timestamp.
// If param is nil, DefaultTOTPParam is used.
// The secret must be encoded according to the specified algorithm's encoding (e.g., base32 for SHA1).
func GenerateTOTP(secret string, t time.Time, param *Param) (string, error) {
	if param == nil {
		_def := *DefaultTOTPParam
		param = &_def
	}

	secretBuf, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}

	return deriveOTP(secretBuf, timeCounterFunc(t, param.Period), param.Digits.Int(), param.Algorithm)
}

// GenerateTOTPURL constructs an otpauth:// URL for configuring TOTP-based authenticators (e.g., Google Authenticator).
// The URL includes the issuer, account name, secret, and TOTP parameters.
//
// Example output:
// otpauth://totp/Example:alice@domain.com?secret=BASE32ENCODEDSECRET&issuer=Example&algorithm=SHA1&digits=6&period=30
func GenerateTOTPURL(param URLParam) (*url.URL, error) {
	if param.Issuer == "" {
		return nil, ErrIssuerRequired
	}
	if param.AccountName == "" {
		return nil, ErrAccountNameRequired
	}
	if param.Digits == 0 {
		param.Digits = Digits(6)
	}
	if param.Period == 0 {
		param.Period = 30
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
	query.Set("period", fmt.Sprintf("%d", param.Period))

	return &url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + label,
		RawQuery: query.Encode(),
	}, nil
}

// ValidateTOTP checks whether the given TOTP code is valid for the specified time and secret.
// It uses constant-time comparison to avoid timing attacks.
// Returns true if the code is valid, false otherwise. If param is nil, DefaultTOTPParam is used.
func ValidateTOTP(secret, code string, t time.Time, param *Param) (bool, error) {
	if param == nil {
		_def := *DefaultTOTPParam
		param = &_def
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
	counter := timeCounterFunc(t, period)

	for i := -int64(skew); i <= int64(skew); i++ {
		valid, err := validateOTP(code, secretBuf, counter+uint64(i), param.Digits.Int(), param.Algorithm)
		if err == nil && valid {
			return true, nil
		}
	}

	return false, ErrInvalidCode
}
