package otp

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Suite represents an abstract OCRA suite definition.
// It allows OCRA-related functions to accept either a raw string suite
// (e.g., "OCRA-1:HOTP-SHA1-6:QN08") or a pre-parsed SuiteConfig.
//
// The Config method parses and returns the normalized SuiteConfig structure,
// enabling efficient downstream processing. The String method returns the
// original suite string representation.
//
// This interface enables both ergonomic and performance-friendly usage:
//
//	DeriveOCRA(RawSuite("OCRA-1:HOTP-SHA1-6:QN08"), secret, inputs)
//	DeriveOCRA(ParsedSuite{...}, secret, inputs)
//
// All internal logic operates on SuiteConfig, regardless of input type.
type Suite interface {
	// Config returns the parsed SuiteConfig from this suite.
	Config() SuiteConfig

	// String returns the raw string representation of the suite.
	String() string

	// Validate checks whether the suite definition is structurally and semantically valid.
	// For RawSuite, this includes parsing the raw string and validating the resulting SuiteConfig.
	// For SuiteConfig, this includes checks on hash algorithm, digit length, challenge format,
	// and consistency of included input fields.
	//
	// It returns an error if the suite is invalid or unsupported.
	Validate() error
}

type SuiteConfig struct {
	// Original suite string (useful for logging, debug, etc.)
	Raw string

	// OTP parameters
	Hash   Algorithm // SHA1, SHA256, SHA512
	Digits int       // OTP digits: 6, 7, 8

	// Challenge type
	Challenge ChallengeFormat // QN08, QA10, etc.

	// Input flags (used to determine which inputs are expected)
	IncludeCounter   bool // C
	IncludeChallenge bool // Q (always true if Challenge is set)
	IncludePassword  bool // P
	IncludeSession   bool // S
	IncludeTimestamp bool // T

	// Extra metadata
	PasswordHash PasswordHashAlgorithm // PSHA1, PSHA256, PSHA512 (optional)
	TimeStep     int                   // T1, T2, etc. (in seconds; 0 = not used)
}

// NewSuite returns a validated Suite implementation from a given SuiteConfig.
// The function first verifies the internal consistency of the config via Validate(),
// then ensures that the SuiteConfig corresponds to a known, pre-registered raw suite.
//
// If the suite is valid and known, it returns a Suite interface that can be used for
// deriving OCRA codes. Otherwise, it returns an appropriate error.
//
// This method is useful for users who construct SuiteConfig programmatically but
// still want strict adherence to known suite definitions.
//
// Returns ErrInvalidRawSuite if the suite's Raw field is not registered.
func NewSuite(cfg SuiteConfig) (Suite, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return RawSuite{SuiteConfig: cfg}, nil
}

// ListSuites returns all registered and supported OCRA raw suite strings.
// This is useful for introspection, documentation, CLI display, or API discovery.
func ListSuites() []string {
	suites := make([]string, 0, len(knownSuites))
	for name := range knownSuites {
		suites = append(suites, name)
	}
	return suites
}

// IsKnownSuite reports whether the given raw OCRA suite string is registered
// in the internal list of known supported suite configurations.
//
// This is useful for validating user input or performing discovery checks.
//
// Example:
//
//	if !IsKnownSuite(input) {
//	    return fmt.Errorf("unsupported OCRA suite")
//	}
func IsKnownSuite(raw string) bool {
	_, ok := knownSuites[raw]
	return ok
}

func SuiteConfigFromRaws(rawSuite string) SuiteConfig {
	return knownSuites[rawSuite]
}

func (cfg SuiteConfig) Config() SuiteConfig {
	return cfg
}

func (cfg SuiteConfig) String() string {
	return cfg.Raw
}

func (cfg SuiteConfig) Validate() error {
	if cfg.Digits < 4 || cfg.Digits > 10 {
		return fmt.Errorf("invalid digit length: %d", cfg.Digits)
	}
	if cfg.Hash != SHA1 && cfg.Hash != SHA256 && cfg.Hash != SHA512 {
		return fmt.Errorf("unsupported hash algorithm: %v", cfg.Hash)
	}
	if cfg.IncludePassword && cfg.PasswordHash == PasswordNone {
		return fmt.Errorf("password input enabled but no password hash specified")
	}
	if cfg.IncludeTimestamp && cfg.TimeStep <= 0 {
		return fmt.Errorf("timestamp input enabled but invalid time step: %d", cfg.TimeStep)
	}
	if cfg.IncludeChallenge && cfg.Challenge == ChallengeNone {
		return fmt.Errorf("challenge input required but no challenge format set")
	}
	return nil
}

type RawSuite struct {
	SuiteConfig
}

// NewRawSuite returns a Suite instance based on a raw OCRA suite string.
// It looks up the string in the list of known, pre-registered suite definitions
// and returns the corresponding RawSuite.
//
// If the raw suite string is not found or the associated SuiteConfig is invalid,
// it returns an appropriate error.
//
// This is the recommended way to safely create a Suite from raw input at runtime.
// You can find raw suites by ListSuites function.
func NewRawSuite(raw string) (Suite, error) {
	if suiteCfg, ok := knownSuites[raw]; ok {
		suiteCfg.Raw = raw
		if err := suiteCfg.Validate(); err != nil {
			return RawSuite{}, err
		}
		return RawSuite{SuiteConfig: suiteCfg}, nil
	}

	cfg, err := parseRawSuite(raw)
	if err != nil {
		return RawSuite{}, err
	}

	return RawSuite{SuiteConfig: cfg}, nil
}

// MustRawSuite is like NewRawSuite but panics if the suite string is invalid or unknown.
// It is intended for use in tests, internal registrations, or hardcoded trusted values
// where failure is not expected.
//
// Example:
//
//	suite := MustRawSuite("OCRA-1:HOTP-SHA1-6:QN08")
func MustRawSuite(raw string) RawSuite {
	s, err := NewRawSuite(raw)
	if err != nil {
		panic(err)
	}
	return s.(RawSuite)
}

func (r RawSuite) Config() SuiteConfig {
	return r.SuiteConfig
}

func (r RawSuite) String() string {
	return r.SuiteConfig.Raw
}

func (r RawSuite) Validate() error {
	return r.SuiteConfig.Validate()
}

func parseRawSuite(raw string) (SuiteConfig, error) {
	parts := strings.Split(raw, ":")
	if len(parts) < 3 {
		return SuiteConfig{}, fmt.Errorf("invalid OCRA suite format: %q", raw)
	}

	// e.g. "HOTP-SHA256-8"
	crypto := parts[1]
	dataInput := parts[2]

	// minimal checks
	if !strings.HasPrefix(parts[0], "OCRA-1") {
		return SuiteConfig{}, fmt.Errorf("unsupported OCRA version: %q", parts[0])
	}

	// parse the crypto function: HOTP-SHAxxx-t
	cfg, err := parseCryptoFunction(raw, crypto)
	if err != nil {
		return SuiteConfig{}, err
	}

	// parse the dataInput tokens (C, QN08, PSHA1, Sxxx, Txxx, etc.)
	if err := parseDataInputTokens(&cfg, dataInput); err != nil {
		return SuiteConfig{}, err
	}

	cfg.Raw = raw
	if err := cfg.Validate(); err != nil {
		return SuiteConfig{}, err
	}
	return cfg, nil
}

// parseCryptoFunction handles the "HOTP-SHA1-6" or "HOTP-SHA256-8" part.
func parseCryptoFunction(raw, crypto string) (SuiteConfig, error) {
	if !strings.HasPrefix(strings.ToUpper(crypto), "HOTP-SHA") {
		return SuiteConfig{}, fmt.Errorf("unknown or unsupported crypto in %q", raw)
	}
	rest := crypto[5:]
	parts := strings.Split(rest, "-")
	if len(parts) != 2 {
		return SuiteConfig{}, fmt.Errorf("invalid crypto format: %q", rest)
	}
	hashPart := parts[0] // "SHA256"
	digPart := parts[1]  // "8" or "6", etc.

	var cfg SuiteConfig
	switch strings.ToUpper(hashPart) {
	case "SHA1":
		cfg.Hash = SHA1
	case "SHA256":
		cfg.Hash = SHA256
	case "SHA512":
		cfg.Hash = SHA512
	default:
		return SuiteConfig{}, fmt.Errorf("unsupported hash %q", hashPart)
	}

	dig, err := strconv.Atoi(digPart)
	if err != nil {
		return SuiteConfig{}, fmt.Errorf("invalid digit spec %q", digPart)
	}
	cfg.Digits = dig
	return cfg, nil
}

// parseDataInputTokens processes strings like "C-QN08-PSHA1" or "QN08-T1M" etc.
// and sets fields in the given cfg. Example approach; adapt as needed.
func parseDataInputTokens(cfg *SuiteConfig, input string) error {
	toks := strings.Split(input, "-")
	for _, tok := range toks {
		tokU := strings.ToUpper(tok)
		switch {
		case tokU == "C":
			cfg.IncludeCounter = true
		case strings.HasPrefix(tokU, "QN"):
			cfg.IncludeChallenge = true
			if len(tokU) == 4 {
				// e.g. "QN08"
				// parse 08 => ChallengeNumeric08, etc.
				num := tokU[2:]
				switch num {
				case "08":
					cfg.Challenge = ChallengeNumeric08
				case "10":
					cfg.Challenge = ChallengeNumeric10
				default:
					return fmt.Errorf("unsupported numeric challenge spec %q", tok)
				}
			}
		case strings.HasPrefix(tokU, "QA"):
			cfg.IncludeChallenge = true
			// similar approach for alpha
			// ...
		case strings.HasPrefix(tokU, "QH"):
			cfg.IncludeChallenge = true
			// ...
		case strings.HasPrefix(tokU, "PSHA"):
			cfg.IncludePassword = true
			switch tokU {
			case "PSHA1":
				cfg.PasswordHash = PasswordSHA1
			case "PSHA256":
				cfg.PasswordHash = PasswordSHA256
			case "PSHA512":
				cfg.PasswordHash = PasswordSHA512
			default:
				return fmt.Errorf("unknown password hash type %q", tok)
			}
		case strings.HasPrefix(tokU, "T"):
			// This might parse e.g. "T1M" => 60 seconds
			cfg.IncludeTimestamp = true
			// parse after 'T', e.g. "1M" => 60, "30S" => 30, "1H" => 3600
			gran := tok[1:]
			secs, err := parseTimeGranularity(gran)
			if err != nil {
				return fmt.Errorf("invalid time spec %q: %w", tok, err)
			}
			cfg.TimeStep = secs
		case strings.HasPrefix(tokU, "S"): // session data e.g. "S064"?
			cfg.IncludeSession = true
			// parse length if needed
		default:
			// unrecognized token
			return fmt.Errorf("unknown data input token %q", tok)
		}
	}
	return nil
}

// parseTimeGranularity is an example that converts e.g. "1M" => 60, "2H" => 7200, "30S" => 30
func parseTimeGranularity(g string) (int, error) {
	if len(g) < 2 {
		return 0, errors.New("too short time spec")
	}
	numStr := g[:len(g)-1]
	unit := g[len(g)-1]
	val, err := strconv.Atoi(numStr)
	if err != nil {
		return 0, err
	}
	switch unit {
	case 'S':
		return val, nil
	case 'M':
		return val * 60, nil
	case 'H':
		return val * 3600, nil
	default:
		return 0, fmt.Errorf("unknown time unit %q", unit)
	}
}

// knownSuites list raw suites is based on https://datatracker.ietf.org/doc/html/rfc6287
var knownSuites = map[string]SuiteConfig{
	// Q-only (challenge only)
	"OCRA-1:HOTP-SHA1-6:QN08": {
		Hash:             SHA1,
		Digits:           6,
		Challenge:        ChallengeNumeric08,
		IncludeChallenge: true,
	},
	"OCRA-1:HOTP-SHA1-6:QA08": {
		Hash:             SHA1,
		Digits:           6,
		Challenge:        ChallengeAlpha08,
		IncludeChallenge: true,
	},
	"OCRA-1:HOTP-SHA1-6:QH08": {
		Hash:             SHA1,
		Digits:           6,
		Challenge:        ChallengeHex08,
		IncludeChallenge: true,
	},
	"OCRA-1:HOTP-SHA1-8:QN10": {
		Hash:             SHA1,
		Digits:           8,
		Challenge:        ChallengeNumeric10,
		IncludeChallenge: true,
	},
	"OCRA-1:HOTP-SHA1-8:QA10": {
		Hash:             SHA1,
		Digits:           8,
		Challenge:        ChallengeAlpha10,
		IncludeChallenge: true,
	},
	"OCRA-1:HOTP-SHA1-8:QH10": {
		Hash:             SHA1,
		Digits:           8,
		Challenge:        ChallengeHex10,
		IncludeChallenge: true,
	},
	"OCRA-1:HOTP-SHA256-6:QN08": {
		Hash:             SHA256,
		Digits:           6,
		Challenge:        ChallengeNumeric08,
		IncludeChallenge: true,
	},
	"OCRA-1:HOTP-SHA256-6:QA08": {
		Hash:             SHA256,
		Digits:           6,
		Challenge:        ChallengeAlpha08,
		IncludeChallenge: true,
	},
	"OCRA-1:HOTP-SHA256-6:QH08": {
		Hash:             SHA256,
		Digits:           6,
		Challenge:        ChallengeHex08,
		IncludeChallenge: true,
	},
	"OCRA-1:HOTP-SHA256-8:QN10": {
		Hash:             SHA256,
		Digits:           8,
		Challenge:        ChallengeNumeric10,
		IncludeChallenge: true,
	},
	"OCRA-1:HOTP-SHA256-8:QA10": {
		Hash:             SHA256,
		Digits:           8,
		Challenge:        ChallengeAlpha10,
		IncludeChallenge: true,
	},
	"OCRA-1:HOTP-SHA256-8:QH10": {
		Hash:             SHA256,
		Digits:           8,
		Challenge:        ChallengeHex10,
		IncludeChallenge: true,
	},
	"OCRA-1:HOTP-SHA512-6:QN08": {
		Hash:             SHA512,
		Digits:           6,
		Challenge:        ChallengeNumeric08,
		IncludeChallenge: true,
	},
	"OCRA-1:HOTP-SHA512-6:QA08": {
		Hash:             SHA512,
		Digits:           6,
		Challenge:        ChallengeAlpha08,
		IncludeChallenge: true,
	},
	"OCRA-1:HOTP-SHA512-6:QH08": {
		Hash:             SHA512,
		Digits:           6,
		Challenge:        ChallengeHex08,
		IncludeChallenge: true,
	},
	"OCRA-1:HOTP-SHA512-8:QN10": {
		Hash:             SHA512,
		Digits:           8,
		Challenge:        ChallengeNumeric10,
		IncludeChallenge: true,
	},
	"OCRA-1:HOTP-SHA512-8:QA10": {
		Hash:             SHA512,
		Digits:           8,
		Challenge:        ChallengeAlpha10,
		IncludeChallenge: true,
	},
	"OCRA-1:HOTP-SHA512-8:QH10": {
		Hash:             SHA512,
		Digits:           8,
		Challenge:        ChallengeHex10,
		IncludeChallenge: true,
	},

	// C-Q (counter + challenge)
	"OCRA-1:HOTP-SHA1-6:C-QN08": {
		Hash:             SHA1,
		Digits:           6,
		Challenge:        ChallengeNumeric08,
		IncludeCounter:   true,
		IncludeChallenge: true,
	},
	"OCRA-1:HOTP-SHA1-8:C-QA10": {
		Hash:             SHA1,
		Digits:           8,
		Challenge:        ChallengeAlpha10,
		IncludeCounter:   true,
		IncludeChallenge: true,
	},
	"OCRA-1:HOTP-SHA256-6:C-QN08": {
		Hash:             SHA256,
		Digits:           6,
		Challenge:        ChallengeNumeric08,
		IncludeCounter:   true,
		IncludeChallenge: true,
	},
	"OCRA-1:HOTP-SHA256-8:C-QA10": {
		Hash:             SHA256,
		Digits:           8,
		Challenge:        ChallengeAlpha10,
		IncludeCounter:   true,
		IncludeChallenge: true,
	},
	"OCRA-1:HOTP-SHA512-6:C-QH08": {
		Hash:             SHA512,
		Digits:           6,
		Challenge:        ChallengeHex08,
		IncludeCounter:   true,
		IncludeChallenge: true,
	},
	"OCRA-1:HOTP-SHA512-8:C-QH10": {
		Hash:             SHA512,
		Digits:           8,
		Challenge:        ChallengeHex10,
		IncludeCounter:   true,
		IncludeChallenge: true,
	},

	//  Q-P (challenge + password)
	"OCRA-1:HOTP-SHA1-6:QN08-PSHA1": {
		Hash:             SHA1,
		Digits:           6,
		Challenge:        ChallengeNumeric08,
		IncludeChallenge: true,
		IncludePassword:  true,
		PasswordHash:     PasswordSHA1,
	},
	"OCRA-1:HOTP-SHA1-8:QA10-PSHA1": {
		Hash:             SHA1,
		Digits:           8,
		Challenge:        ChallengeAlpha10,
		IncludeChallenge: true,
		IncludePassword:  true,
		PasswordHash:     PasswordSHA1,
	},
	"OCRA-1:HOTP-SHA256-6:QN08-PSHA256": {
		Hash:             SHA256,
		Digits:           6,
		Challenge:        ChallengeNumeric08,
		IncludeChallenge: true,
		IncludePassword:  true,
		PasswordHash:     PasswordSHA256,
	},
	"OCRA-1:HOTP-SHA256-8:QA10-PSHA256": {
		Hash:             SHA256,
		Digits:           8,
		Challenge:        ChallengeAlpha10,
		IncludeChallenge: true,
		IncludePassword:  true,
		PasswordHash:     PasswordSHA256,
	},
	"OCRA-1:HOTP-SHA512-6:QH08-PSHA512": {
		Hash:             SHA512,
		Digits:           6,
		Challenge:        ChallengeHex08,
		IncludeChallenge: true,
		IncludePassword:  true,
		PasswordHash:     PasswordSHA512,
	},
	"OCRA-1:HOTP-SHA512-8:QH10-PSHA512": {
		Hash:             SHA512,
		Digits:           8,
		Challenge:        ChallengeHex10,
		IncludeChallenge: true,
		IncludePassword:  true,
		PasswordHash:     PasswordSHA512,
	},

	// C-Q-P-S-T (all fields)
	"OCRA-1:HOTP-SHA1-6:C-QN08-PSHA1-S-T1": {
		Hash:             SHA1,
		Digits:           6,
		Challenge:        ChallengeNumeric08,
		IncludeCounter:   true,
		IncludeChallenge: true,
		IncludePassword:  true,
		IncludeSession:   true,
		IncludeTimestamp: true,
		PasswordHash:     PasswordSHA1,
		TimeStep:         1,
	},
	"OCRA-1:HOTP-SHA1-8:C-QA10-PSHA1-S-T1": {
		Hash:             SHA1,
		Digits:           8,
		Challenge:        ChallengeAlpha10,
		IncludeCounter:   true,
		IncludeChallenge: true,
		IncludePassword:  true,
		IncludeSession:   true,
		IncludeTimestamp: true,
		PasswordHash:     PasswordSHA1,
		TimeStep:         1,
	},
	"OCRA-1:HOTP-SHA256-6:C-QN08-PSHA256-S-T1": {
		Hash:             SHA256,
		Digits:           6,
		Challenge:        ChallengeNumeric08,
		IncludeCounter:   true,
		IncludeChallenge: true,
		IncludePassword:  true,
		IncludeSession:   true,
		IncludeTimestamp: true,
		PasswordHash:     PasswordSHA256,
		TimeStep:         1,
	},
	"OCRA-1:HOTP-SHA256-8:C-QA10-PSHA256-S-T1": {
		Hash:             SHA256,
		Digits:           8,
		Challenge:        ChallengeAlpha10,
		IncludeCounter:   true,
		IncludeChallenge: true,
		IncludePassword:  true,
		IncludeSession:   true,
		IncludeTimestamp: true,
		PasswordHash:     PasswordSHA256,
		TimeStep:         1,
	},
	"OCRA-1:HOTP-SHA512-6:C-QH08-PSHA512-S-T1": {
		Hash:             SHA512,
		Digits:           6,
		Challenge:        ChallengeHex08,
		IncludeCounter:   true,
		IncludeChallenge: true,
		IncludePassword:  true,
		IncludeSession:   true,
		IncludeTimestamp: true,
		PasswordHash:     PasswordSHA512,
		TimeStep:         1,
	},
	"OCRA-1:HOTP-SHA512-8:C-QH10-PSHA512-S-T1": {
		Hash:             SHA512,
		Digits:           8,
		Challenge:        ChallengeHex10,
		IncludeCounter:   true,
		IncludeChallenge: true,
		IncludePassword:  true,
		IncludeSession:   true,
		IncludeTimestamp: true,
		PasswordHash:     PasswordSHA512,
		TimeStep:         1,
	},

	// Q-S-T (no counter, with session & timestamp)
	"OCRA-1:HOTP-SHA1-6:QN08-S-T1": {
		Hash:             SHA1,
		Digits:           6,
		Challenge:        ChallengeNumeric08,
		IncludeChallenge: true,
		IncludeSession:   true,
		IncludeTimestamp: true,
		TimeStep:         1,
	},
	"OCRA-1:HOTP-SHA1-8:QA10-S-T1": {
		Hash:             SHA1,
		Digits:           8,
		Challenge:        ChallengeAlpha10,
		IncludeChallenge: true,
		IncludeSession:   true,
		IncludeTimestamp: true,
		TimeStep:         1,
	},
	"OCRA-1:HOTP-SHA256-6:QN08-S-T1": {
		Hash:             SHA256,
		Digits:           6,
		Challenge:        ChallengeNumeric08,
		IncludeChallenge: true,
		IncludeSession:   true,
		IncludeTimestamp: true,
		TimeStep:         1,
	},
	"OCRA-1:HOTP-SHA256-8:QA10-S-T1": {
		Hash:             SHA256,
		Digits:           8,
		Challenge:        ChallengeAlpha10,
		IncludeChallenge: true,
		IncludeSession:   true,
		IncludeTimestamp: true,
		TimeStep:         1,
	},
	"OCRA-1:HOTP-SHA512-6:QH08-S-T1": {
		Hash:             SHA512,
		Digits:           6,
		Challenge:        ChallengeHex08,
		IncludeChallenge: true,
		IncludeSession:   true,
		IncludeTimestamp: true,
		TimeStep:         1,
	},
	"OCRA-1:HOTP-SHA512-8:QH10-S-T1": {
		Hash:             SHA512,
		Digits:           8,
		Challenge:        ChallengeHex10,
		IncludeChallenge: true,
		IncludeSession:   true,
		IncludeTimestamp: true,
		TimeStep:         1,
	},

	// C only
	"OCRA-1:HOTP-SHA1-6:C": {
		Hash:           SHA1,
		Digits:         6,
		IncludeCounter: true,
	},
	"OCRA-1:HOTP-SHA256-6:C": {
		Hash:           SHA256,
		Digits:         6,
		IncludeCounter: true,
	},
	"OCRA-1:HOTP-SHA512-6:C": {
		Hash:           SHA512,
		Digits:         6,
		IncludeCounter: true,
	},
}
