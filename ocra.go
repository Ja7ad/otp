package otp

// GenerateOCRA generates a one-time password (OTP) using the OCRA algorithm (RFC 6287)
// for the given secret, suite, and input parameters.
//
// The `secret` should be a base32-encoded shared key (e.g., from provisioning),
// and will be decoded into its raw binary form.
// The `suite` defines the OCRA configuration (create Suite using NewSuite or NewRawSuite).
// The `input` provides dynamic values like challenge, counter, session data, timestamp, etc.
//
// Returns the generated OTP string or an error if decoding the secret or derivation fails.
func GenerateOCRA(secret string, suite Suite, input OCRAInput) (string, error) {
	secretBuf, err := DecodeSecret(secret)
	if err != nil {
		return "", err
	}

	return deriveRFC6287(secretBuf, suite, input)
}

// ValidateOCRA checks whether a provided OTP code is valid for the given
// OCRA suite, secret, and input parameters.
//
// The `secret` should be a base32-encoded key, which is decoded before validation.
// The `code` is the OTP to validate (usually entered by the user).
// The `suite` and `input` define the expected context in which the OTP should have been generated.
//
// Returns true if the code is valid, false otherwise. An error is returned if decoding
// the secret fails or if validation encounters a critical issue.
func ValidateOCRA(secret, code string, suite Suite, input OCRAInput) (bool, error) {
	secretBuf, err := DecodeSecret(secret)
	if err != nil {
		return false, err
	}

	return validateRFC6287(code, secretBuf, suite, input)
}
