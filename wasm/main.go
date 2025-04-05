//go:build js && wasm

package main

import (
	"fmt"
	"net/url"
	"syscall/js"
	"time"

	"github.com/Ja7ad/otp"
)

// log prints a message to the JavaScript console for debugging.
func log(msg string) {
	println(fmt.Sprintf("Go: %s", msg))
}

// generateHOTP generates an HOTP code and exposes it to JavaScript.
// It expects 4 arguments: secret (string), counter (int), digits (string), algo (string).
func generateHOTP(_ js.Value, args []js.Value) any {
	log("generateHOTP called")
	result, err := parseArgsAndGenerate(args, "HOTP")
	if err != nil {
		log(err.Error())
		return js.ValueOf(fmt.Sprintf("error: %s", err))
	}
	log(fmt.Sprintf("HOTP generated: %s", result))
	return js.ValueOf(result)
}

// generateOTPURL constructs an otpauth:// URL for HOTP or TOTP using the provided parameters
// and returns it to JavaScript as a string.
//
// JavaScript expects 6 arguments:
// - otp:          string ("totp" or "hotp")
// - issuer:       string (e.g., "GitHub")
// - accountName:  string (e.g., "user@example.com")
// - secret:       string (Base32 encoded)
// - digits:       string ("6", "8", etc.)
// - algorithm:    string ("SHA1", "SHA256", or "SHA512")
//
// Returns: string URL or "error: ..." message
func generateOTPURL(_ js.Value, args []js.Value) any {
	log("generateOTPURL called")

	if len(args) != 6 {
		err := fmt.Errorf("expected 6 arguments (otp, issuer, accountName, secret, digits, algorithm), got %d", len(args))
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}

	otpType, err := parseStringArg(args[0], "otp")
	if err != nil {
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}

	issuer, err := parseStringArg(args[1], "issuer")
	if err != nil {
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}

	accountName, err := parseStringArg(args[2], "accountName")
	if err != nil {
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}

	secret, err := parseStringArg(args[3], "secret")
	if err != nil {
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}

	digitsRaw, err := parseStringArg(args[4], "digits")
	if err != nil {
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}
	digits := otp.DigitsFromStr(digitsRaw)

	algoRaw, err := parseStringArg(args[5], "algorithm")
	if err != nil {
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}
	algo := otp.AlgorithmFromStr(algoRaw)

	// Construct the URL param object
	param := otp.URLParam{
		Issuer:      issuer,
		AccountName: accountName,
		Secret:      secret,
		Digits:      digits,
		Algorithm:   algo,
	}

	var urlObj *url.URL

	switch otpType {
	case "totp":
		urlObj, err = otp.GenerateTOTPURL(param)
	case "hotp":
		urlObj, err = otp.GenerateHOTPURL(param)
	default:
		err = fmt.Errorf("invalid otp type: %s (must be 'totp' or 'hotp')", otpType)
	}

	if err != nil {
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}

	if urlObj == nil {
		return js.ValueOf("error: url not generated")
	}

	urlStr := urlObj.String()
	log("OTP URL generated: " + urlStr)
	return js.ValueOf(urlStr)
}

// validateHOTP validates an HOTP code within a given skew window.
// Args: [secret: string, code: string, counter: number, digits: string, algo: string, skew: number]
func validateHOTP(_ js.Value, args []js.Value) any {
	log("validateHOTP called")

	if len(args) != 6 {
		err := fmt.Errorf("expected 6 arguments: secret, code, counter, digits, algo, skew; got %d", len(args))
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}

	// Parse arguments
	secretStr, err := parseStringArg(args[0], "secret")
	if err != nil {
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}

	code, err := parseStringArg(args[1], "code")
	if err != nil {
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}

	counter, err := parseIntArg(args[2], "counter")
	if err != nil {
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}

	digitsStr, err := parseStringArg(args[3], "digits")
	if err != nil {
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}

	algoStr, err := parseStringArg(args[4], "algo")
	if err != nil {
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}

	skew, err := parseIntArg(args[5], "skew")
	if err != nil {
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}

	if skew < 0 || skew > 10 {
		return js.ValueOf("error: skew must be in range [0,10]")
	}

	// Normalize
	digits := otp.DigitsFromStr(digitsStr)
	algo := otp.AlgorithmFromStr(algoStr)

	// Decode secret
	secretBuf, err := otp.DecodeSecret(secretStr)
	if err != nil {
		log("invalid secret - " + err.Error())
		return js.ValueOf("error: invalid secret - " + err.Error())
	}

	for i := -skew; i <= skew; i++ {
		currCounter := int64(counter) + int64(i)
		if currCounter < 0 {
			continue
		}

		valid, err := otp.ValidateOTPWasm(code, secretBuf, uint64(counter), digits, algo)
		if err == nil && valid {
			log(fmt.Sprintf("Code %s is valid at counter %d", code, counter))
			return js.ValueOf(true)
		}
	}

	log("Code is invalid")
	return js.ValueOf(false)
}

// generateTOTP generates a TOTP code and exposes it to JavaScript.
// It expects 5 arguments: secret (string), timestamp (int), digits (string), algo (string), period (int).
func generateTOTP(_ js.Value, args []js.Value) any {
	log("generateTOTP called")

	if len(args) != 5 {
		err := fmt.Errorf("expected 5 arguments for TOTP (secret, timestamp, digits, algo, period), got %d", len(args))
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}

	secret, err := parseStringArg(args[0], "secret")
	if err != nil {
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}

	timestamp, err := parseIntArg(args[1], "timestamp")
	if err != nil {
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}

	digitsRaw, err := parseStringArg(args[2], "digits")
	if err != nil {
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}

	algoRaw, err := parseStringArg(args[3], "algo")
	if err != nil {
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}

	period, err := parseIntArg(args[4], "period")
	if err != nil {
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}
	if period <= 0 || period > 3600 {
		err := fmt.Errorf("period must be between 1 and 3600 seconds, got %d", period)
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}

	// Transform arguments
	digits := otp.DigitsFromStr(digitsRaw)
	algo := otp.AlgorithmFromStr(algoRaw)
	t := time.Unix(int64(timestamp), 0)

	// Generate counter from time and period
	counter := otp.TimeCounterFunc(t, uint(period))

	// Generate OTP
	code, err := generateOTP(secret, counter, digits, algo)
	if err != nil {
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}

	log(fmt.Sprintf("TOTP generated: %s", code))
	return js.ValueOf(code)
}

// validateTOTP validates a TOTP code at a given timestamp with optional skew and period.
// Args: [secret: string, code: string, timestamp: number, digits: string, algo: string, skew: number, period: number]
func validateTOTP(_ js.Value, args []js.Value) any {
	log("validateTOTP called")

	if len(args) != 7 {
		err := fmt.Errorf("expected 7 arguments: secret, code, timestamp, digits, algo, skew, period; got %d", len(args))
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}

	// Parse and validate inputs
	secretStr, err := parseStringArg(args[0], "secret")
	if err != nil {
		return js.ValueOf("error: " + err.Error())
	}

	code, err := parseStringArg(args[1], "code")
	if err != nil {
		return js.ValueOf("error: " + err.Error())
	}

	timestamp, err := parseIntArg(args[2], "timestamp")
	if err != nil {
		return js.ValueOf("error: " + err.Error())
	}
	if timestamp < 0 {
		return js.ValueOf("error: timestamp must be non-negative")
	}

	digitsStr, err := parseStringArg(args[3], "digits")
	if err != nil {
		return js.ValueOf("error: " + err.Error())
	}

	algoStr, err := parseStringArg(args[4], "algo")
	if err != nil {
		return js.ValueOf("error: " + err.Error())
	}

	skew, err := parseIntArg(args[5], "skew")
	if err != nil {
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}
	if skew < 0 || skew > 10 {
		err := fmt.Errorf("skew must be in range [0,10]")
		log(err.Error())
		return js.ValueOf("error: " + err.Error())
	}

	period, err := parseIntArg(args[6], "period")
	if err != nil {
		return js.ValueOf("error: " + err.Error())
	}
	if period <= 0 {
		return js.ValueOf("error: period must be > 0")
	}

	// Normalize
	digits := otp.DigitsFromStr(digitsStr)
	algo := otp.AlgorithmFromStr(algoStr)
	secretBuf, err := otp.DecodeSecret(secretStr)
	if err != nil {
		return js.ValueOf("error: invalid secret - " + err.Error())
	}

	t := time.Unix(int64(timestamp), 0)

	counter := otp.TimeCounterFunc(t, uint(period))

	for i := -int64(skew); i <= int64(skew); i++ {
		valid, err := otp.ValidateOTPWasm(code, secretBuf, counter+uint64(i), digits, algo)
		if err == nil && valid {
			log(fmt.Sprintf("Code %s is valid at counter %d", code, timestamp))
			return js.ValueOf(true)
		}
	}

	log("TOTP invalid")
	return js.ValueOf(false)
}

// parseArgsAndGenerate parses arguments and generates an OTP code.
// It handles both HOTP and TOTP based on the otpType parameter.
func parseArgsAndGenerate(args []js.Value, otpType string) (string, error) {
	if len(args) != 4 {
		return "", fmt.Errorf("expected 4 arguments for %s (secret, %s, digits, algo), got %d",
			otpType, map[string]string{"HOTP": "counter", "TOTP": "timestamp"}[otpType], len(args))
	}

	secret, err := parseStringArg(args[0], "secret")
	if err != nil {
		return "", err
	}
	counter, err := parseIntArg(args[1], map[string]string{"HOTP": "counter", "TOTP": "timestamp"}[otpType])
	if err != nil {
		return "", err
	}
	digitsRaw, err := parseStringArg(args[2], "digits")
	if err != nil {
		return "", err
	}
	algoRaw, err := parseStringArg(args[3], "algo")
	if err != nil {
		return "", err
	}

	digits := otp.DigitsFromStr(digitsRaw)
	algo := otp.AlgorithmFromStr(algoRaw)

	return generateOTP(secret, uint64(counter), digits, algo)
}

// parseStringArg extracts a string from a js.Value and validates it’s not empty.
func parseStringArg(arg js.Value, name string) (string, error) {
	if arg.Type() != js.TypeString {
		return "", fmt.Errorf("%s must be a string, got %s", name, arg.Type())
	}
	value := arg.String()
	if value == "" {
		return "", fmt.Errorf("%s cannot be empty", name)
	}
	return value, nil
}

// parseIntArg extracts an integer from a js.Value and validates it’s non-negative.
func parseIntArg(arg js.Value, name string) (int, error) {
	if arg.Type() != js.TypeNumber {
		return 0, fmt.Errorf("%s must be a number, got %s", name, arg.Type())
	}
	value := arg.Int()
	if value < 0 {
		return 0, fmt.Errorf("%s must be non-negative, got %d", name, value)
	}
	return value, nil
}

// generateOTP generates an OTP code using the provided parameters.
func generateOTP(secret string, counter uint64, digits otp.Digits, algo otp.Algorithm) (string, error) {
	secBuf, err := otp.DecodeSecret(secret)
	if err != nil {
		return "", fmt.Errorf("invalid secret - %s", err)
	}

	code, err := otp.DeriveRFC4226Wasm(secBuf, counter, digits.Int(), algo)
	if err != nil {
		return "", fmt.Errorf("failed to generate OTP - %s", err)
	}

	return code, nil
}

// registerFunctions registers all Go functions with JavaScript.
func registerFunctions() {
	log("Registering functions with JavaScript")
	js.Global().Set("generateHOTP", js.FuncOf(generateHOTP))
	js.Global().Set("generateTOTP", js.FuncOf(generateTOTP))
	js.Global().Set("validateHOTP", js.FuncOf(validateHOTP))
	js.Global().Set("validateTOTP", js.FuncOf(validateTOTP))
	js.Global().Set("generateOTPURL", js.FuncOf(generateOTPURL))
}

func main() {
	log("WASM module loaded")
	registerFunctions()
	log("WASM module initialized, entering infinite loop")
	select {} // Keep the runtime alive
}
