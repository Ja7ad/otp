package main

import (
	"fmt"
	"github.com/Ja7ad/otp"
)

func main() {
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

	ok, err := otp.ValidateOCRA(secret, code, suite, otp.OCRAInput{
		Challenge: []byte("12345678"),
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(ok)
}
