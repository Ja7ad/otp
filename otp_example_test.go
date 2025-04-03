package otp

import (
	"fmt"
	"time"
)

func ExampleGenerateTOTP() {
	secret, err := RandomSecret(SHA1)
	if err != nil {
		panic(err)
	}

	code, err := GenerateTOTP(secret, time.Now(), DefaultTOTPParam)
	if err != nil {
		panic(err)
	}

	fmt.Println(code)
}

func ExampleGenerateHOTP() {
	secret, err := RandomSecret(SHA1)
	if err != nil {
		panic(err)
	}

	code, err := GenerateHOTP(secret, 1, DefaultHOTPParam)
	if err != nil {
		panic(err)
	}

	fmt.Println(code)
}

func ExampleValidateTOTP() {
	secret, err := RandomSecret(SHA1)
	if err != nil {
		panic(err)
	}

	t := time.Now()

	code, err := GenerateTOTP(secret, t, DefaultTOTPParam)
	if err != nil {
		panic(err)
	}

	fmt.Println(code)

	ok, err := ValidateTOTP(secret, code, t, DefaultTOTPParam)
	if err != nil {
		panic(err)
	}

	fmt.Println(ok)
}

func ExampleValidateHOTP() {
	secret, err := RandomSecret(SHA1)
	if err != nil {
		panic(err)
	}

	counter := uint64(1)

	code, err := GenerateHOTP(secret, counter, DefaultHOTPParam)
	if err != nil {
		panic(err)
	}

	fmt.Println(code)

	ok, err := ValidateHOTP(secret, code, counter, DefaultTOTPParam)
	if err != nil {
		panic(err)
	}

	fmt.Println(ok)
}

func ExampleGenerateTOTPURL() {
	secret, err := RandomSecret(SHA1)
	if err != nil {
		panic(err)
	}

	url, err := GenerateTOTPURL(URLParam{
		Issuer:      "https://example.com",
		Secret:      secret,
		AccountName: "foobar",
		Period:      DefaultTOTPParam.Period,
		Digits:      DefaultTOTPParam.Digits,
		Algorithm:   DefaultTOTPParam.Algorithm,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(url.String())
}

func ExampleGenerateHOTPURL() {
	secret, err := RandomSecret(SHA1)
	if err != nil {
		panic(err)
	}

	url, err := GenerateHOTPURL(URLParam{
		Issuer:      "https://example.com",
		Secret:      secret,
		AccountName: "foobar",
		Period:      DefaultHOTPParam.Period,
		Digits:      DefaultHOTPParam.Digits,
		Algorithm:   DefaultHOTPParam.Algorithm,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(url.String())
}
