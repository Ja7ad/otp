package otp

import (
	"crypto/rand"
	"encoding/base32"
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

var algoStrMap = map[Algorithm]string{
	SHA1:   "SHA1",
	SHA256: "SHA256",
	SHA512: "SHA512",
}

func (algo Algorithm) String() string {
	return algoStrMap[algo]
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
	Skew uint

	// Algorithm specifies which HMAC hashing algorithm to use (SHA1, SHA256, SHA512).
	Algorithm Algorithm
}

// timeCounterFunc returns the TOTP counter value based on the Unix time and period.
// It performs integer division of time by the period to produce a moving counter window.
var timeCounterFunc = func(t time.Time, period uint) uint64 {
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
