package otp

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type (
	// Algorithm defines the hashing algorithm used in the HMAC function.
	// Supported values are SHA1, SHA256, and SHA512, per RFC 6238.
	Algorithm uint8
	Digits    uint8
)

const (
	// SHA1 is the default algorithm used in TOTP/HOTP (RFC 4226, RFC 6238).
	SHA1 Algorithm = iota

	// SHA256 offers stronger security than SHA1 with better resistance to collisions.
	SHA256

	// SHA512 is the strongest hash option supported, useful in high-security environments.
	SHA512
)

const (
	SixDigits   Digits = 6
	EightDigits Digits = 8
	NineDigits  Digits = 9
	TenDigits   Digits = 10
)

func (d Digits) Int() int {
	return int(d)
}

func DigitsFromStr(digits string) Digits {
	switch digits {
	case "6":
		return SixDigits
	case "8":
		return EightDigits
	case "9":
		return NineDigits
	case "10":
		return TenDigits
	default:
		return SixDigits
	}
}

var algoStrMap = map[Algorithm]string{
	SHA1:   "SHA1",
	SHA256: "SHA256",
	SHA512: "SHA512",
}

func (algo Algorithm) String() string {
	return algoStrMap[algo]
}

func AlgorithmFromStr(algo string) Algorithm {
	switch algo {
	case "SHA1":
		return SHA1
	case "SHA256":
		return SHA256
	case "SHA512":
		return SHA512
	default:
		return SHA1
	}
}

// Param defines configuration parameters for generating and validating OTPs.
type Param struct {
	// Digits is the length of the generated OTP code (commonly 6 or 8).
	Digits Digits

	// Period is the time step in seconds for TOTP (e.g., 30 means OTP changes every 30s).
	// This is not used in HOTP.
	Period uint

	// Skew is the allowed number of time steps (forward/backward) during TOTP validation
	// to account for clock drift between client and server.
	// security: A larger Skew increases the chance of a brute-force hit, max 10.
	// default for hotp is 2
	Skew uint

	// Algorithm specifies which HMAC hashing algorithm to use (SHA1, SHA256, SHA512).
	Algorithm Algorithm
}

// TimeCounterFunc returns the TOTP counter value based on the Unix time and period.
// It performs integer division of time by the period to produce a moving counter window.
var TimeCounterFunc = func(t time.Time, period uint) uint64 {
	return uint64(t.Unix()) / uint64(period)
}

type URLParam struct {
	// Name of the issuing Organization/Company.
	Issuer string
	// Name of the User's Account (eg, email address)
	AccountName string
	// Number of seconds a TOTP hash is valid for. Defaults to 30 seconds.
	Period uint
	// Secret to store. Defaults to a randomly generated secret of SecretSize.  You should generally leave this empty.
	Secret string
	// Digits to request. Defaults to 6.
	Digits Digits
	// Algorithm to use for HMAC. Defaults to SHA1.
	Algorithm Algorithm
}

// ChallengeFormat enumerates the possible challenge formats.
type ChallengeFormat int

const (
	ChallengeNone      ChallengeFormat = iota
	ChallengeNumeric08                 // QN08 → typically 8-digit numeric
	ChallengeNumeric10                 // QN10 → typically 10-digit numeric
	ChallengeAlpha08                   // QA08 → typically 8-char alphanumeric
	ChallengeAlpha10                   // QA10 → typically 10-char alphanumeric
	ChallengeHex08                     // QH08 → typically 8-hex-digit challenge
	ChallengeHex10                     // QH10 → typically 10-hex-digit challenge
)

// PasswordHashAlgorithm enumerates the possible PIN/password hash types.
type PasswordHashAlgorithm int

const (
	PasswordNone PasswordHashAlgorithm = iota
	PasswordSHA1
	PasswordSHA256
	PasswordSHA512
)

// OCRAInput holds the raw data that will be concatenated (in the order defined
// by RFC6287) for the HMAC computation. Which fields are required or optional
// depends on the SuiteConfig (cfg).
type OCRAInput struct {
	// Counter is an 8-byte big-endian value, used if the suite has IncludeCounter=true.
	// Typically incremented for each new OCRA calculation.
	Counter []byte

	// Challenge is the raw challenge data. If the suite has IncludeChallenge=true,
	// we typically expect a certain minimum length (8 or 10 bytes) and a max of 128 bytes.
	Challenge []byte

	// Password is the hashed PIN or passphrase. If the suite has IncludePassword=true
	// and the suite's PasswordHash is e.g. PasswordSHA1, we expect the length to match
	// that hash (20 bytes for SHA-1, etc.).
	Password []byte

	// SessionInfo is optional user or system data (e.g. channel binding info), up to 128 bytes.
	// Only used if IncludeSession=true.
	SessionInfo []byte

	// Timestamp is an 8-byte big-endian representation of the time-step
	// if IncludeTimestamp=true (e.g. for T1M). Must be exactly 8 bytes.
	Timestamp []byte
}

// Validate checks that the input matches the suite's requirements.
func (in OCRAInput) Validate(cfg SuiteConfig) error {
	// Counter => 8 bytes if included
	if cfg.IncludeCounter && len(in.Counter) != 8 {
		return fmt.Errorf("expected 8-byte counter, got %d", len(in.Counter))
	}
	// Challenge => up to 128 bytes, min length depends on format
	if cfg.IncludeChallenge {
		minimum := challengeLength(cfg.Challenge)
		if len(in.Challenge) < minimum {
			return fmt.Errorf("challenge too short: expected at least %d bytes, got %d", minimum, len(in.Challenge))
		}
		if len(in.Challenge) > 128 {
			return fmt.Errorf("challenge too long: must not exceed 128 bytes, got %d", len(in.Challenge))
		}
	}
	// Password => verify length matches the declared hash
	if cfg.IncludePassword {
		if len(in.Password) == 0 {
			return fmt.Errorf("password required but not provided")
		}
		switch cfg.PasswordHash {
		case PasswordSHA1:
			if len(in.Password) != 20 {
				return fmt.Errorf("PSHA1 password must be 20 bytes, got %d", len(in.Password))
			}
		case PasswordSHA256:
			if len(in.Password) != 32 {
				return fmt.Errorf("PSHA256 password must be 32 bytes, got %d", len(in.Password))
			}
		case PasswordSHA512:
			if len(in.Password) != 64 {
				return fmt.Errorf("PSHA512 password must be 64 bytes, got %d", len(in.Password))
			}
		}
	}
	// Session => up to 128 bytes
	if cfg.IncludeSession && len(in.SessionInfo) > 128 {
		return fmt.Errorf("session info too long: max 128 bytes, got %d", len(in.SessionInfo))
	}
	// Timestamp => 8 bytes if included
	if cfg.IncludeTimestamp && len(in.Timestamp) != 8 {
		return fmt.Errorf("expected 8-byte timestamp, got %d", len(in.Timestamp))
	}
	return nil
}

func HexInputToOCRA(counter, challenge, password, sessionInfo, timestamp string) (OCRAInput, error) {
	var input OCRAInput
	var b []byte
	var err error

	if counter != "" {
		b, err = hex.DecodeString(counter)
		if err != nil {
			return OCRAInput{}, fmt.Errorf("failed to decode counter: %w", err)
		}
		input.Counter = b
	}

	if challenge != "" {
		b, err = hex.DecodeString(challenge)
		if err != nil {
			return OCRAInput{}, fmt.Errorf("failed to decode challenge: %w", err)
		}
		input.Challenge = b
	}

	if password != "" {
		b, err = hex.DecodeString(password)
		if err != nil {
			return OCRAInput{}, fmt.Errorf("failed to decode password: %w", err)
		}
		input.Password = b
	}

	if sessionInfo != "" {
		b, err = hex.DecodeString(sessionInfo)
		if err != nil {
			return OCRAInput{}, fmt.Errorf("failed to decode session info: %w", err)
		}
		input.SessionInfo = b
	}

	if timestamp != "" {
		b, err = hex.DecodeString(timestamp)
		if err != nil {
			return OCRAInput{}, fmt.Errorf("failed to decode timestamp: %w", err)
		}
		input.Timestamp = b
	}

	return input, nil
}

// challengeLength returns the minimum expected length (in bytes) for the
// given ChallengeFormat. If QN08 means 8 digits, we treat that as "at least 8 bytes."
func challengeLength(format ChallengeFormat) int {
	switch format {
	case ChallengeNumeric08, ChallengeAlpha08, ChallengeHex08:
		return 8
	case ChallengeNumeric10, ChallengeAlpha10, ChallengeHex10:
		return 10
	default:
		// For ChallengeNone or any unrecognized format, minimum is 0.
		return 0
	}
}

// RandomSecret returns a base32-encoded random secret for the given algorithm.
// The secret is of appropriate byte length for RFC-compliant HOTP/TOTP implementations.
func RandomSecret(algo Algorithm) (string, error) {
	size := 20

	switch algo {
	case SHA1:
		size = 20
	case SHA256:
		size = 32
	case SHA512:
		size = 64
	default:
		return "", ErrUnsupportedAlgorithm
	}

	secret := make([]byte, size)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("failed to generate random secret: %w", err)
	}

	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// ParseOTPAuthURL parses an otpauth:// URL (TOTP or HOTP) and converts it into a URLParam struct.
// Supported format: otpauth://TYPE/LABEL?secret=...&issuer=...&digits=...&algorithm=...&period=...
func ParseOTPAuthURL(u *url.URL) (*URLParam, error) {
	if u == nil {
		return nil, fmt.Errorf("nil URL provided")
	}
	if u.Scheme != "otpauth" {
		return nil, fmt.Errorf("invalid URL scheme: %s", u.Scheme)
	}

	otpType := strings.ToLower(u.Host)
	if otpType != "totp" && otpType != "hotp" {
		return nil, fmt.Errorf("unsupported OTP type: %s", otpType)
	}

	// Parse label
	parts := strings.SplitN(strings.TrimPrefix(u.Path, "/"), ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid label format, expected Issuer:AccountName")
	}
	issuer, accountName := parts[0], parts[1]

	query := u.Query()

	param := &URLParam{
		Issuer:      issuer,
		AccountName: accountName,
		Secret:      query.Get("secret"),
		Digits:      SixDigits,
		Algorithm:   SHA1,
		Period:      30,
	}

	if digitsStr := query.Get("digits"); digitsStr != "" {
		if digitsInt, err := strconv.Atoi(digitsStr); err == nil {
			param.Digits = Digits(digitsInt)
		} else {
			return nil, fmt.Errorf("invalid digits value: %s", digitsStr)
		}
	}

	if algStr := query.Get("algorithm"); algStr != "" {
		switch strings.ToUpper(algStr) {
		case "SHA1":
			param.Algorithm = SHA1
		case "SHA256":
			param.Algorithm = SHA256
		case "SHA512":
			param.Algorithm = SHA512
		default:
			return nil, fmt.Errorf("unsupported algorithm: %s", algStr)
		}
	}

	if periodStr := query.Get("period"); periodStr != "" {
		if p, err := strconv.Atoi(periodStr); err == nil {
			param.Period = uint(p)
		} else {
			return nil, fmt.Errorf("invalid period value: %s", periodStr)
		}
	}

	return param, nil
}

func generateOTPURL(kind string, param URLParam, extraParams map[string]string) (*url.URL, error) {
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

	// Add type-specific values
	for k, v := range extraParams {
		query.Set(k, v)
	}

	return &url.URL{
		Scheme:   "otpauth",
		Host:     kind, // "totp" or "hotp"
		Path:     "/" + label,
		RawQuery: query.Encode(),
	}, nil
}
