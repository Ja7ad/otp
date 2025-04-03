package otp

import "errors"

var (
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")
	ErrInvalidCodeLength    = errors.New("invalid code length")
	ErrInvalidCode          = errors.New("invalid otp code")
	ErrIssuerRequired       = errors.New("issuer is required")
	ErrAccountNameRequired  = errors.New("account name is required")
	ErrSecretRequired       = errors.New("secret is required")
	ErrInvalidSkew          = errors.New("invalid skew, a larger Skew increases the chance of a brute-force hit")
)
