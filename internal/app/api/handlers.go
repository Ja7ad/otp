package api

import (
	"encoding/json"
	"github.com/Ja7ad/otp"
	"github.com/Ja7ad/otp/internal/app/version"
	"github.com/valyala/fasthttp"
	"strings"
	"time"
)

// totpGeneration generates a TOTP code.
//
//	@Summary		Generate TOTP code
//	@Description	Generates a TOTP token using the given parameters.
//	@Tags			totp
//	@Accept			json
//	@Produce		json
//	@Param			request	body		otpGenerateReq	true	"TOTP generation payload"
//	@Success		200		{object}	otpGenerateResp
//	@Failure		400		{object}	errResp
//	@Failure		405		{object}	errResp
//	@Failure		500		{object}	errResp
//	@Router			/totp/generate [post]
func totpGeneration() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		if !ctx.IsPost() {
			writeError(ctx, fasthttp.StatusMethodNotAllowed, "method not allowed", map[string]any{
				"allowed_method": fasthttp.MethodPost,
			})
			return
		}

		var req otpGenerateReq
		if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
			writeError(ctx, fasthttp.StatusBadRequest, "failed to decode body", map[string]any{
				"error": err.Error(),
			})
			return
		}

		if err := req.validate(); err != nil {
			writeError(ctx, fasthttp.StatusBadRequest, err.Error(), nil)
			return
		}

		algo := otp.AlgorithmFromStr(req.Algorithm)
		digits := otp.DigitsFromStr(req.Digits)

		if req.Period == 0 {
			req.Period = 30
		}

		var t time.Time
		if req.Timestamp > 0 {
			t = time.Unix(req.Timestamp, 0)
		} else {
			t = time.Now()
		}

		code, err := otp.GenerateTOTP(strings.TrimSpace(req.Secret), t, &otp.Param{
			Algorithm: algo,
			Digits:    digits,
			Period:    req.Period,
		})
		if err != nil {
			writeError(ctx, fasthttp.StatusInternalServerError, "totp generation failed", map[string]any{
				"error": err.Error(),
			})
			return
		}

		resp := otpGenerateResp{
			Code:      code,
			TimeStamp: t.Unix(),
		}

		data, err := json.Marshal(resp)
		if err != nil {
			writeError(ctx, fasthttp.StatusInternalServerError, "failed to marshal response", map[string]any{
				"error": err.Error(),
			})
			return
		}

		ctx.SetContentType("application/json")
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBody(data)
	}
}

// totpValidation validates a TOTP code.
//
//	@Summary		Validate TOTP code
//	@Description	Validates a TOTP token against the provided secret and timestamp.
//	@Tags			totp
//	@Accept			json
//	@Produce		json
//	@Param			request	body		otpValidateReq	true	"TOTP validation payload"
//	@Success		200		{object}	otpValidateResp
//	@Failure		400		{object}	errResp
//	@Failure		405		{object}	errResp
//	@Failure		500		{object}	errResp
//	@Router			/totp/validate [post]
func totpValidation() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		if !ctx.IsPost() {
			writeError(ctx, fasthttp.StatusMethodNotAllowed, "method not allowed", map[string]any{
				"allowed_method": fasthttp.MethodPost,
			})
			return
		}

		var req otpValidateReq
		if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
			writeError(ctx, fasthttp.StatusBadRequest, "failed to decode body", map[string]any{
				"error": err.Error(),
			})
			return
		}

		if err := req.validate(); err != nil {
			writeError(ctx, fasthttp.StatusBadRequest, err.Error(), nil)
			return
		}

		algo := otp.AlgorithmFromStr(req.Algorithm)
		digits := otp.DigitsFromStr(req.Digits)

		var t time.Time
		if req.Timestamp > 0 {
			t = time.Unix(req.Timestamp, 0)
		} else {
			t = time.Now()
		}

		ok, _ := otp.ValidateTOTP(strings.TrimSpace(req.Secret), req.Code, t, &otp.Param{
			Algorithm: algo,
			Digits:    digits,
			Period:    req.Period,
			Skew:      req.Skew,
		})

		resp := otpValidateResp{Valid: ok}

		data, err := json.Marshal(resp)
		if err != nil {
			writeError(ctx, fasthttp.StatusInternalServerError, "failed to marshal response", map[string]any{
				"error": err.Error(),
			})
			return
		}

		ctx.SetContentType("application/json")
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBody(data)
	}
}

// hotpGeneration generates a new HOTP code.
//
//	@Summary		Generate HOTP code
//	@Description	Generates an HOTP token using the provided secret and counter.
//	@Tags			hotp
//	@Accept			json
//	@Produce		json
//	@Param			request	body		otpGenerateReq	true	"HOTP generation payload"
//	@Success		200		{object}	otpGenerateResp
//	@Failure		400		{object}	errResp
//	@Failure		405		{object}	errResp
//	@Failure		500		{object}	errResp
//	@Router			/hotp/generate [post]
func hotpGeneration() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		if !ctx.IsPost() {
			writeError(ctx, fasthttp.StatusMethodNotAllowed, "method not allowed", map[string]any{
				"allowed_method": fasthttp.MethodPost,
			})
			return
		}

		var req otpGenerateReq
		if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
			writeError(ctx, fasthttp.StatusBadRequest, "failed to decode body", map[string]any{
				"error": err.Error(),
			})
			return
		}

		if err := req.validate(); err != nil {
			writeError(ctx, fasthttp.StatusBadRequest, err.Error(), nil)
			return
		}

		algo := otp.AlgorithmFromStr(req.Algorithm)
		digits := otp.DigitsFromStr(req.Digits)

		code, err := otp.GenerateHOTP(req.Secret, req.Counter, &otp.Param{
			Algorithm: algo,
			Digits:    digits,
		})
		if err != nil {
			writeError(ctx, fasthttp.StatusInternalServerError, "hotp generation failed", map[string]any{
				"error": err,
			})
			return
		}

		resp := otpGenerateResp{
			Code:    code,
			Counter: req.Counter,
		}

		data, err := json.Marshal(resp)
		if err != nil {
			writeError(ctx, fasthttp.StatusInternalServerError, "failed to marshal response", map[string]any{
				"error": err.Error(),
			})
			return
		}

		ctx.SetContentType("application/json")
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBody(data)
	}
}

// hotpValidation validates a user-provided HOTP code.
//
//	@Summary		Validate HOTP code
//	@Description	Validates a given HOTP code against a secret and counter.
//	@Tags			hotp
//	@Accept			json
//	@Produce		json
//	@Param			request	body		otpValidateReq	true	"HOTP validation payload"
//	@Success		200		{object}	otpValidateResp
//	@Failure		400		{object}	errResp
//	@Failure		405		{object}	errResp
//	@Failure		500		{object}	errResp
//	@Router			/hotp/validate [post]
func hotpValidation() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		if !ctx.IsPost() {
			writeError(ctx, fasthttp.StatusMethodNotAllowed, "method not allowed", map[string]any{
				"allowed_method": fasthttp.MethodPost,
			})
			return
		}

		var req otpValidateReq
		if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
			writeError(ctx, fasthttp.StatusBadRequest, "failed to decode body", map[string]any{
				"error": err.Error(),
			})
			return
		}

		if err := req.validate(); err != nil {
			writeError(ctx, fasthttp.StatusBadRequest, err.Error(), nil)
			return
		}

		algo := otp.AlgorithmFromStr(req.Algorithm)
		digits := otp.DigitsFromStr(req.Digits)

		ok, _ := otp.ValidateHOTP(req.Secret, req.Code, req.Counter, &otp.Param{
			Algorithm: algo,
			Digits:    digits,
			Skew:      req.Skew,
		})

		resp := otpValidateResp{
			Valid: ok,
		}

		data, err := json.Marshal(resp)
		if err != nil {
			writeError(ctx, fasthttp.StatusInternalServerError, "failed to marshal response", map[string]any{
				"error": err.Error(),
			})
			return
		}

		ctx.SetContentType("application/json")
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBody(data)
	}
}

// otpURLGeneration generates an otpauth:// URL for TOTP or HOTP setup.
//
//	@Summary		Generate OTP URL
//	@Description	Returns a QR-compatible otpauth:// URL for TOTP or HOTP configuration.
//	@Tags			otp
//	@Accept			json
//	@Produce		json
//	@Param			request	body		otpURLGenerateReq	true	"OTP URL generation payload"
//	@Success		200		{object}	otpURLGenerateResp
//	@Failure		400		{object}	errResp
//	@Failure		405		{object}	errResp
//	@Failure		500		{object}	errResp
//	@Router			/otp/url [post]
func otpURLGeneration() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		if !ctx.IsPost() {
			writeError(ctx, fasthttp.StatusMethodNotAllowed, "method not allowed", map[string]any{
				"allowed_method": fasthttp.MethodPost,
			})
			return
		}

		var req otpURLGenerateReq
		if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
			writeError(ctx, fasthttp.StatusBadRequest, "failed to decode body", map[string]any{
				"error": err.Error(),
			})
			return
		}

		if err := req.validate(); err != nil {
			writeError(ctx, fasthttp.StatusBadRequest, err.Error(), nil)
			return
		}

		algo := otp.AlgorithmFromStr(req.Algorithm)
		digits := otp.DigitsFromStr(req.Digits)

		var resp otpURLGenerateResp

		switch req.Type {
		case "totp":
			url, err := otp.GenerateTOTPURL(otp.URLParam{
				Issuer:      req.Issuer,
				Secret:      req.Secret,
				Period:      req.Period,
				Digits:      digits,
				Algorithm:   algo,
				AccountName: req.AccountName,
			})
			if err != nil {
				writeError(ctx, fasthttp.StatusInternalServerError, "otp generation failed", map[string]any{
					"error": err.Error(),
				})
				return
			}
			resp.URL = url.String()
		case "hotp":
			url, err := otp.GenerateHOTPURL(otp.URLParam{
				Issuer:      req.Issuer,
				Secret:      req.Secret,
				Period:      req.Period,
				Digits:      digits,
				Algorithm:   algo,
				AccountName: req.AccountName,
			})
			if err != nil {
				writeError(ctx, fasthttp.StatusInternalServerError, "otp generation failed", map[string]any{
					"error": err.Error(),
				})
				return
			}
			resp.URL = url.String()
		default:
			writeError(ctx, fasthttp.StatusBadRequest, "invalid otp type", map[string]any{
				"invalid_type": req.Type,
			})
			return
		}

		data, err := json.Marshal(resp)
		if err != nil {
			writeError(ctx, fasthttp.StatusInternalServerError, "failed to marshal response", map[string]any{
				"error": err.Error(),
			})
			return
		}

		ctx.SetContentType("application/json")
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBody(data)
	}
}

// generateRandomSecret returns a randomly generated secret for the specified algorithm.
//
//	@Summary		Generate random OTP secret
//	@Description	Generates a base32-encoded secret for a given algorithm (default is SHA1 if omitted).
//	@Tags			otp
//	@Accept			json
//	@Produce		json
//	@Param			algorithm	query		string	false	"Algorithm (SHA1, SHA256, SHA512)"
//	@Success		200			{object}	generateRandomSecretResp
//	@Failure		400			{object}	errResp
//	@Failure		405			{object}	errResp
//	@Failure		500			{object}	errResp
//	@Router			/otp/secret [get]
func generateRandomSecret() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		if !ctx.IsGet() {
			writeError(ctx, fasthttp.StatusMethodNotAllowed, "method not allowed", map[string]any{
				"allowed_method": fasthttp.MethodGet,
			})
			return
		}

		algo := otp.AlgorithmFromStr(string(ctx.QueryArgs().Peek("algorithm")))

		secret, err := otp.RandomSecret(algo)
		if err != nil {
			writeError(ctx, fasthttp.StatusInternalServerError, "failed to generate secret", map[string]any{
				"error": err.Error(),
			})
			return
		}

		resp := generateRandomSecretResp{
			Secret:    secret,
			Algorithm: algo.String(),
		}

		data, err := json.Marshal(resp)
		if err != nil {
			writeError(ctx, fasthttp.StatusInternalServerError, "failed to marshal response", map[string]any{
				"error": err.Error(),
			})
			return
		}

		ctx.SetContentType("application/json")
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBody(data)
	}
}

// ocraGeneration generates an OCRA code based on the provided suite and input.
//
//	@Summary		Generate OCRA code
//	@Description	Generates an OCRA one-time password using a shared secret, suite, and input values.
//
// Field        | Type   | Description
// ------------ | ------ | ----------------------------------------------
// challenge_format | int | 1=ChallengeNumeric08, 2=ChallengeNumeric10, 3=ChallengeAlpha08, 4=ChallengeAlpha10, 5=ChallengeHex08, 6=ChallengeHex10
// password_hash    | int | 1=PasswordSHA1, 2=PasswordSHA256, 3=PasswordSHA512
//
//	@Tags			ocra
//	@Accept			json
//	@Produce		json
//	@Param			request	body		ocraGenerateReq	true	"OCRA generation request"
//	@Success		200		{object}	otpGenerateResp
//	@Failure		400		{object}	errResp
//	@Failure		405		{object}	errResp
//	@Failure		500		{object}	errResp
//	@Router			/ocra/generate [post]
func ocraGeneration() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		if !ctx.IsPost() {
			writeError(ctx, fasthttp.StatusMethodNotAllowed, "method not allowed", map[string]any{
				"allowed_method": fasthttp.MethodPost,
			})
			return
		}

		var req ocraGenerateReq
		if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
			writeError(ctx, fasthttp.StatusBadRequest, "failed to decode body", map[string]any{
				"error": err.Error(),
			})
			return
		}

		if err := req.validate(); err != nil {
			writeError(ctx, fasthttp.StatusBadRequest, err.Error(), nil)
			return
		}

		var suite otp.Suite
		if req.Suite != nil {
			s, err := otp.NewSuite(otp.SuiteConfig{
				Hash:             otp.AlgorithmFromStr(req.Suite.HashFunction),
				Digits:           req.Suite.CodeDigits,
				Challenge:        otp.ChallengeFormat(req.Suite.ChallengeFormat),
				IncludeCounter:   req.Suite.IncludeCounter,
				IncludeChallenge: req.Suite.IncludeChallenge,
				IncludePassword:  req.Suite.IncludePassword,
				IncludeSession:   req.Suite.IncludeSession,
				IncludeTimestamp: req.Suite.IncludeTimestamp,
				PasswordHash:     otp.PasswordHashAlgorithm(req.Suite.PasswordHash),
				TimeStep:         req.Suite.Timestep,
			})
			if err != nil {
				writeError(ctx, fasthttp.StatusBadRequest, "failed to create suite", map[string]any{
					"error": err.Error(),
				})
				return
			}
			suite = s
		}
		if req.RawSuite != "" {
			suite = otp.MustRawSuite(req.RawSuite)
		}

		input, err := otp.HexInputToOCRA(
			req.Input.CounterHex,
			req.Input.ChallengeHex,
			req.Input.PasswordHex,
			req.Input.SessionInfoHex,
			req.Input.TimestampHex,
		)
		if err != nil {
			writeError(ctx, fasthttp.StatusBadRequest, "failed to parse ocra input", map[string]any{
				"error": err.Error(),
			})
			return
		}

		code, err := otp.GenerateOCRA(req.Secret, suite, input)
		if err != nil {
			writeError(ctx, fasthttp.StatusInternalServerError, "failed to generate ocra code", map[string]any{
				"error": err.Error(),
			})
			return
		}

		resp := otpGenerateResp{
			Code:  code,
			Suite: suite.String(),
		}

		data, err := json.Marshal(resp)
		if err != nil {
			writeError(ctx, fasthttp.StatusInternalServerError, "failed to marshal response", map[string]any{
				"error": err.Error(),
			})
			return
		}

		ctx.SetContentType("application/json")
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBody(data)
	}
}

// ocraValidation validates an OCRA code based on the provided suite and input.
//
//	@Summary		Validate OCRA code
//	@Description	Validates an OCRA response against a secret, suite, and input parameters.
//	@Tags			ocra
//	@Accept			json
//	@Produce		json
//	@Param			request	body		ocraValidateReq	true	"OCRA validation request"
//	@Success		200		{object}	otpValidateResp
//	@Failure		400		{object}	errResp
//	@Failure		405		{object}	errResp
//	@Router			/ocra/validate [post]
func ocraValidation() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		if !ctx.IsPost() {
			writeError(ctx, fasthttp.StatusMethodNotAllowed, "method not allowed", map[string]any{
				"allowed_method": fasthttp.MethodPost,
			})
			return
		}

		var req ocraValidateReq
		if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
			writeError(ctx, fasthttp.StatusBadRequest, "failed to decode body", map[string]any{
				"error": err.Error(),
			})
			return
		}

		if err := req.validate(); err != nil {
			writeError(ctx, fasthttp.StatusBadRequest, err.Error(), nil)
			return
		}

		var suite otp.Suite
		if req.Suite != nil {
			s, err := otp.NewSuite(otp.SuiteConfig{
				Hash:             otp.AlgorithmFromStr(req.Suite.HashFunction),
				Digits:           req.Suite.CodeDigits,
				Challenge:        otp.ChallengeFormat(req.Suite.ChallengeFormat),
				IncludeCounter:   req.Suite.IncludeCounter,
				IncludeChallenge: req.Suite.IncludeChallenge,
				IncludePassword:  req.Suite.IncludePassword,
				IncludeSession:   req.Suite.IncludeSession,
				IncludeTimestamp: req.Suite.IncludeTimestamp,
				PasswordHash:     otp.PasswordHashAlgorithm(req.Suite.PasswordHash),
				TimeStep:         req.Suite.Timestep,
			})
			if err != nil {
				writeError(ctx, fasthttp.StatusBadRequest, "failed to create suite", map[string]any{
					"error": err.Error(),
				})
				return
			}
			suite = s
		}
		if req.RawSuite != "" {
			suite = otp.MustRawSuite(req.RawSuite)
		}

		input, err := otp.HexInputToOCRA(
			req.Input.CounterHex,
			req.Input.ChallengeHex,
			req.Input.PasswordHex,
			req.Input.SessionInfoHex,
			req.Input.TimestampHex,
		)
		if err != nil {
			writeError(ctx, fasthttp.StatusBadRequest, "failed to parse ocra input", map[string]any{
				"error": err.Error(),
			})
			return
		}

		ok, _ := otp.ValidateOCRA(req.Secret, req.Code, suite, input)

		resp := otpValidateResp{
			Valid: ok,
		}

		data, err := json.Marshal(resp)
		if err != nil {
			writeError(ctx, fasthttp.StatusInternalServerError, "failed to marshal response", map[string]any{
				"error": err.Error(),
			})
			return
		}

		ctx.SetContentType("application/json")
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBody(data)
	}
}

// listOCRASuites returns a list of known OCRA suite identifiers.
//
//	@Summary		List available OCRA suites
//	@Description	Returns a list of supported OCRA suite strings.
//	@Tags			ocra
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	listOCRASuiteResp
//	@Failure		405	{object}	errResp
//	@Router			/ocra/suites [get]
func listOCRASuites() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		if !ctx.IsGet() {
			writeError(ctx, fasthttp.StatusMethodNotAllowed, "method not allowed", map[string]any{
				"allowed_method": fasthttp.MethodGet,
			})
			return
		}

		resp := listOCRASuiteResp{
			Suites: otp.ListSuites(),
		}

		data, err := json.Marshal(resp)
		if err != nil {
			writeError(ctx, fasthttp.StatusInternalServerError, "failed to marshal response", map[string]any{
				"error": err.Error(),
			})
			return
		}

		ctx.SetContentType("application/json")
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBody(data)
	}
}

// ocraSuiteConfig returns the parsed configuration of a given OCRA suite.
//
//	@Summary		Get OCRA suite configuration
//	@Description	Parses a raw OCRA suite string and returns its configuration details.
//	@Tags			ocra
//	@Accept			json
//	@Produce		json
//	@Param			request	body		suiteConfigReq	true	"OCRA suite config request"
//	@Success		200		{object}	suiteConfigResp
//	@Failure		400		{object}	errResp
//	@Failure		405		{object}	errResp
//	@Failure		500		{object}	errResp
//	@Router			/ocra/suite [post]
func ocraSuiteConfig() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		if !ctx.IsPost() {
			writeError(ctx, fasthttp.StatusMethodNotAllowed, "method not allowed", map[string]any{
				"allowed_method": fasthttp.MethodPost,
			})
			return
		}

		var req suiteConfigReq
		if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
			writeError(ctx, fasthttp.StatusBadRequest, "failed to decode body", map[string]any{
				"error": err,
			})
			return
		}

		if err := req.validate(); err != nil {
			writeError(ctx, fasthttp.StatusBadRequest, err.Error(), nil)
			return
		}

		cfg := otp.SuiteConfigFromRaws(req.RawSuite)

		resp := suiteConfigResp{
			Raw: req.RawSuite,
			Config: suiteConfig{
				HashFunction:     cfg.Hash.String(),
				CodeDigits:       cfg.Digits,
				ChallengeFormat:  int(cfg.Challenge),
				IncludeCounter:   cfg.IncludeCounter,
				IncludeChallenge: cfg.IncludeChallenge,
				IncludePassword:  cfg.IncludePassword,
				IncludeSession:   cfg.IncludeSession,
				IncludeTimestamp: cfg.IncludeTimestamp,
				PasswordHash:     int(cfg.PasswordHash),
				Timestep:         cfg.TimeStep,
			},
		}

		data, err := json.Marshal(resp)
		if err != nil {
			writeError(ctx, fasthttp.StatusInternalServerError, "failed to marshal response", map[string]any{
				"error": err.Error(),
			})
			return
		}

		ctx.SetContentType("application/json")
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBody(data)
	}
}

func home() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		if !ctx.IsGet() {
			writeError(ctx, fasthttp.StatusMethodNotAllowed, "method not allowed", map[string]any{
				"allowed_method": fasthttp.MethodGet,
			})
			return
		}

		resp := homeResp{
			App:         _appName,
			Description: _description,
			Docs:        docPath,
			Status:      "ok",
		}

		data, err := json.Marshal(resp)
		if err != nil {
			writeError(ctx, fasthttp.StatusInternalServerError, "failed to marshal response", map[string]any{
				"error": err.Error(),
			})
			return
		}

		ctx.SetContentType("application/json")
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBody(data)
	}
}
