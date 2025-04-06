package api

import (
	"errors"
	"github.com/Ja7ad/otp"
	"strings"
)

type otpGenerateReq struct {
	Secret    string `json:"secret" binding:"required"`
	Timestamp int64  `json:"timestamp,omitempty" example:"1743879194"`
	Counter   uint64 `json:"counter,omitempty" example:"0"`
	Digits    string `json:"digits,omitempty" example:"6"`
	Period    uint   `json:"period,omitempty" example:"30"`
	Algorithm string `json:"algorithm,omitempty" example:"SHA1"`
}

func (t *otpGenerateReq) validate() error {
	if strings.TrimSpace(t.Secret) == "" {
		return errors.New("missing required field: secret")
	}

	return nil
}

type otpGenerateResp struct {
	Code      string `json:"code"`
	TimeStamp int64  `json:"timestamp,omitempty"`
	Counter   uint64 `json:"counter,omitempty"`
	Suite     string `json:"suite,omitempty"`
}

type otpValidateReq struct {
	Secret    string `json:"secret" binding:"required"`                // repeated for clarity
	Timestamp int64  `json:"timestamp,omitempty" example:"1743879194"` // Unix timestamp to verify against
	Counter   uint64 `json:"counter,omitempty" example:"0"`
	Code      string `json:"code" binding:"required" example:"123456"` // TOTP code to validate
	Digits    string `json:"digits,omitempty" example:"6"`
	Period    uint   `json:"period,omitempty" example:"30"`
	Skew      uint   `json:"skew,omitempty" example:"10"` // number of valid time steps in either direction
	Algorithm string `json:"algorithm,omitempty" example:"SHA1"`
}

func (t *otpValidateReq) validate() error {
	if strings.TrimSpace(t.Secret) == "" {
		return errors.New("missing required field: secret")
	}

	if strings.TrimSpace(t.Code) == "" {
		return errors.New("missing required field: code")
	}

	return nil
}

type otpValidateResp struct {
	Valid bool `json:"valid"`
}

type generateRandomSecretResp struct {
	Secret    string `json:"secret"`
	Algorithm string `json:"algorithm"`
}

type otpURLGenerateReq struct {
	Type        string `json:"type" enums:"totp,hotp" binding:"required"`
	Secret      string `json:"secret" binding:"required"`
	Issuer      string `json:"issuer" binding:"required"`
	AccountName string `json:"account_name" binding:"required"`
	Period      uint   `json:"period,omitempty" example:"30"`
	Digits      string `json:"digits,omitempty" example:"6"`
	Algorithm   string `json:"algorithm,omitempty" example:"SHA1"`
}

func (t *otpURLGenerateReq) validate() error {
	if strings.TrimSpace(t.Type) == "" {
		return errors.New("missing required field: type (totp or hotp)")
	}

	if strings.TrimSpace(t.Secret) == "" {
		return errors.New("missing required field: secret")
	}

	if strings.TrimSpace(t.Issuer) == "" {
		return errors.New("missing required field: issuer")
	}

	if strings.TrimSpace(t.AccountName) == "" {
		return errors.New("missing required field: account_name")
	}

	return nil
}

type otpURLGenerateResp struct {
	URL string `json:"url"`
}

type ocraGenerateReq struct {
	Secret   string       `json:"secret"  binding:"required"`
	RawSuite string       `json:"raw_suite,omitempty" example:"OCRA-1:HOTP-SHA1-6:QN08"`
	Suite    *suiteConfig `json:"suite,omitempty"`
	Input    *ocraInput   `json:"input"`
}

func (t *ocraGenerateReq) validate() error {
	if strings.TrimSpace(t.Secret) == "" {
		return errors.New("missing required field: secret")
	}

	if strings.TrimSpace(t.RawSuite) == "" && t.Suite == nil {
		return errors.New("missing required field: raw_suite or suite")
	}

	if strings.TrimSpace(t.RawSuite) != "" && !otp.IsKnownSuite(t.RawSuite) {
		return errors.New("unknown suite: " + t.RawSuite)
	}

	if t.Input == nil {
		return errors.New("missing required field: input")
	}

	return nil
}

type ocraValidateReq struct {
	Secret   string       `json:"secret"  binding:"required"`
	Code     string       `json:"code"  binding:"required" example:"123456"`
	RawSuite string       `json:"raw_suite,omitempty" example:"OCRA-1:HOTP-SHA1-6:QN08"`
	Suite    *suiteConfig `json:"suite,omitempty"`
	Input    *ocraInput   `json:"input"`
}

func (t *ocraValidateReq) validate() error {
	if strings.TrimSpace(t.Secret) == "" {
		return errors.New("missing required field: secret")
	}

	if strings.TrimSpace(t.Code) == "" {
		return errors.New("missing required field: code")
	}

	if strings.TrimSpace(t.RawSuite) == "" && t.Suite == nil {
		return errors.New("missing required field: raw_suite or suite")
	}

	if strings.TrimSpace(t.RawSuite) != "" && !otp.IsKnownSuite(t.RawSuite) {
		return errors.New("unknown suite: " + t.RawSuite)
	}

	if t.Input == nil {
		return errors.New("missing required field: input")
	}

	return nil
}

type ocraInput struct {
	CounterHex     string `json:"counter_hex,omitempty"`
	ChallengeHex   string `json:"challenge_hex,omitempty"`
	PasswordHex    string `json:"password_hex,omitempty"`
	SessionInfoHex string `json:"session_info_hex,omitempty"`
	TimestampHex   string `json:"timestamp_hex,omitempty"`
}

type listOCRASuiteResp struct {
	Suites []string `json:"suites"`
}

type suiteConfigReq struct {
	RawSuite string `json:"raw_suite"  binding:"required" example:"OCRA-1:HOTP-SHA1-6:QN08"`
}

func (t *suiteConfigReq) validate() error {
	if strings.TrimSpace(t.RawSuite) == "" {
		return errors.New("missing required field: raw_suite")
	}

	if !otp.IsKnownSuite(t.RawSuite) {
		return errors.New("unknown suite: " + t.RawSuite)
	}

	return nil
}

type suiteConfigResp struct {
	Raw    string      `json:"raw"`
	Config suiteConfig `json:"config"`
}

type errResp struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

type homeResp struct {
	App         string `json:"app"`
	Description string `json:"description"`
	Version     string `json:"version"`
	Docs        string `json:"docs"`
	Status      string `json:"status"`
}

type suiteConfig struct {
	HashFunction     string `json:"hash_function" enums:"SHA1,SHA256,SHA512" example:"SHA1"`
	CodeDigits       int    `json:"code_digits" example:"6"`
	ChallengeFormat  int    `json:"challenge_format" enums:"1,2,3,4,5,6" example:"1"`
	IncludeCounter   bool   `json:"include_counter"`
	IncludeChallenge bool   `json:"include_challenge"`
	IncludePassword  bool   `json:"include_password"`
	IncludeSession   bool   `json:"include_session"`
	IncludeTimestamp bool   `json:"include_timestamp"`
	PasswordHash     int    `json:"password_hash,omitempty" enums:"1,2,3" example:"1"`
	Timestep         int    `json:"timestep,omitempty" example:"30"`
}
