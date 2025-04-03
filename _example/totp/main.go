package main

import (
	"fmt"
	"github.com/Ja7ad/otp"
	"log"
	"time"
)

func main() {
	secret, err := otp.RandomSecret(otp.SHA1)
	if err != nil {
		log.Fatal(err)
	}

	t := time.Now()

	code, err := otp.GenerateTOTP(secret, t, otp.DefaultTOTPParam)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(code)

	ok, err := otp.ValidateTOTP(secret, code, t, otp.DefaultTOTPParam)
	if err != nil {
		log.Fatal(err)
	}

	if !ok {
		log.Fatal("Invalid OTP")
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
		log.Fatal(err)
	}

	fmt.Println(url.String())
}
