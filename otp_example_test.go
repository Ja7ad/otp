package otp_test

import (
	"fmt"
	"github.com/ja7ad/otp"
	"time"
)

func ExampleGenerateTOTP() {
	secret, err := otp.RandomSecret(otp.SHA1)
	if err != nil {
		panic(err)
	}

	code, err := otp.GenerateTOTP(secret, time.Now(), otp.DefaultTOTPParam)
	if err != nil {
		panic(err)
	}

	fmt.Println(code)
}

func ExampleGenerateHOTP() {
	secret, err := otp.RandomSecret(otp.SHA1)
	if err != nil {
		panic(err)
	}

	code, err := otp.GenerateHOTP(secret, 1, otp.DefaultHOTPParam)
	if err != nil {
		panic(err)
	}

	fmt.Println(code)
}

func ExampleGenerateOCRA() {
	secret, err := otp.RandomSecret(otp.SHA1)
	if err != nil {
		panic(err)
	}

	suite := otp.MustRawSuite("OCRA-1:HOTP-SHA1-6:QN08")

	code, err := otp.GenerateOCRA(secret, suite, otp.OCRAInput{
		Challenge: []byte("12345678"),
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(code)
}

func ExampleValidateOCRA() {
	secret, err := otp.RandomSecret(otp.SHA1)
	if err != nil {
		panic(err)
	}

	suite := otp.MustRawSuite("OCRA-1:HOTP-SHA1-6:QN08")

	code, err := otp.GenerateOCRA(secret, suite, otp.OCRAInput{
		Challenge: []byte("12345678"),
	})
	if err != nil {
		panic(err)
	}

	ok, err := otp.ValidateOCRA(code, secret, suite, otp.OCRAInput{
		Challenge: []byte("12345678"),
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(ok)
}

func ExampleValidateTOTP() {
	secret, err := otp.RandomSecret(otp.SHA1)
	if err != nil {
		panic(err)
	}

	t := time.Now()

	code, err := otp.GenerateTOTP(secret, t, otp.DefaultTOTPParam)
	if err != nil {
		panic(err)
	}

	fmt.Println(code)

	ok, err := otp.ValidateTOTP(secret, code, t, otp.DefaultTOTPParam)
	if err != nil {
		panic(err)
	}

	fmt.Println(ok)
}

func ExampleValidateHOTP() {
	secret, err := otp.RandomSecret(otp.SHA1)
	if err != nil {
		panic(err)
	}

	counter := uint64(1)

	code, err := otp.GenerateHOTP(secret, counter, otp.DefaultHOTPParam)
	if err != nil {
		panic(err)
	}

	fmt.Println(code)

	ok, err := otp.ValidateHOTP(secret, code, counter, otp.DefaultTOTPParam)
	if err != nil {
		panic(err)
	}

	fmt.Println(ok)
}

func ExampleGenerateTOTPURL() {
	secret, err := otp.RandomSecret(otp.SHA1)
	if err != nil {
		panic(err)
	}

	url, err := otp.GenerateTOTPURL(otp.URLParam{
		Issuer:      "https://example.com",
		Secret:      secret,
		AccountName: "foobar",
		Period:      otp.DefaultTOTPParam.Period,
		Digits:      otp.DefaultTOTPParam.Digits,
		Algorithm:   otp.DefaultTOTPParam.Algorithm,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(url.String())
}

func ExampleGenerateHOTPURL() {
	secret, err := otp.RandomSecret(otp.SHA1)
	if err != nil {
		panic(err)
	}

	url, err := otp.GenerateHOTPURL(otp.URLParam{
		Issuer:      "https://example.com",
		Secret:      secret,
		AccountName: "foobar",
		Period:      otp.DefaultHOTPParam.Period,
		Digits:      otp.DefaultHOTPParam.Digits,
		Algorithm:   otp.DefaultHOTPParam.Algorithm,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(url.String())
}
