package main

import (
	"fmt"
	"log"

	"github.com/Ja7ad/otp"
)

func main() {
	secret, err := otp.RandomSecret(otp.SHA1)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("secret: %s\n", secret)

	counter := uint64(1)

	code, err := otp.GenerateHOTP(secret, counter, otp.DefaultHOTPParam)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(code)

	ok, err := otp.ValidateHOTP(secret, code, counter, otp.DefaultHOTPParam)
	if err != nil {
		log.Fatal(err)
	}

	if !ok {
		log.Fatal("Invalid OTP")
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
		log.Fatal(err)
	}

	fmt.Println(url.String())
}
