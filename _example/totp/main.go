package main

import (
	"fmt"
	"log"
	"time"

	"github.com/Ja7ad/otp"
)

func main() {
	secret, err := otp.RandomSecret(otp.SHA1)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("secret: %s\n", secret)

	t := time.Now()

	code, err := otp.GenerateTOTP(secret, t, &otp.Param{
		Digits:    otp.EightDigits,
		Algorithm: otp.SHA512,
		Period:    60,
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(code)

	ok, err := otp.ValidateTOTP(secret, code, t, &otp.Param{
		Digits:    otp.EightDigits,
		Algorithm: otp.SHA512,
		Period:    60,
	})
	if err != nil {
		log.Fatal(err)
	}

	if !ok {
		log.Fatal("Invalid OTP")
	}

	url, err := otp.GenerateTOTPURL(otp.URLParam{
		Issuer:      "App",
		Secret:      secret,
		AccountName: "foobar",
		Period:      60,
		Digits:      otp.EightDigits,
		Algorithm:   otp.SHA512,
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(url.String())
}
