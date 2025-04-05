![otp](.github/otp.svg)
[![codecov](https://codecov.io/gh/Ja7ad/otp/branch/main/graph/badge.svg?token=8N6N60D5UI)](https://codecov.io/gh/Ja7ad/otp)
[![Go Report Card](https://goreportcard.com/badge/github.com/Ja7ad/otp)](https://goreportcard.com/report/github.com/Ja7ad/otp)
[![Go Reference](https://pkg.go.dev/badge/github.com/Ja7ad/otp.svg)](https://pkg.go.dev/github.com/Ja7ad/otp)

# 🔐 OTP

A high-performance, zero-dependency Go package for generating and validating TOTP, HOTP and OCRA one-time passwords — RFC [4226](https://datatracker.ietf.org/doc/html/rfc4226), RFC [6238](https://datatracker.ietf.org/doc/html/rfc6238) and RFC [6287](https://datatracker.ietf.org/doc/html/rfc6287) compliant.


- [Feature](#-features)
- [Installation](#installation-go-124-)
- [Performance Comparison](#-performance-comparison)
- [Proof algorthim](#-algorithm-rfc)
- [Example](#example)
- [Contributing](#-contributing)
- [Reference](#-references)

## ✨ Features

- Zero dependencies – fully self-contained, no external packages  
- High performance with low allocations
- Supports HOTP (RFC [4226](https://datatracker.ietf.org/doc/html/rfc4226)), TOTP (RFC [6238](https://datatracker.ietf.org/doc/html/rfc6238)) and OCRA (RFC [6287](https://datatracker.ietf.org/doc/html/rfc6287)) algorithms  
- Configurable OTP digit lengths: 6, 8, or 10  
- Supports SHA1, SHA256, and SHA512 HMAC algorithms  
- Constant-time OTP validation to prevent timing attacks  
- Clock skew tolerance for TOTP validation  
- Generates `otpauth://` URLs for Google Authenticator and compatible apps  
- Parses `otpauth://` URLs into configuration structs  
- Secure random secret generation (base32 encoded)  
- Thoroughly tested against official RFC test vectors  
- Includes fuzz tests, benchmark coverage, and solid algorithm validation

## 📦 Installation (Go >= 1.24)

```shell
go get -u github.com/Ja7ad/otp
```

> Binding nodejs is available [here](./otp-js).

## 🚀 Performance Comparison

This comparison is for `Ja7ad/otp` vs `pquerna/otp`

| Algorithm | Digits | Library        | `ns/op` | `B/op` | `allocs/op` | `N` (runs/sec) |
|-----------|--------|----------------|---------|--------|--------------|----------------|
| SHA1      | 6      | **Ja7ad/otp**  | **834.7**   | **480**   | **7**         | **1,452,314**  |
| SHA1      | 6      | pquerna/otp    | 1420    | 592    | 13           | 785,282        |
| SHA1      | 8      | **Ja7ad/otp**  | **825.3**   | **480**   | **7**         | **1,455,498**  |
| SHA1      | 8      | pquerna/otp    | 1415    | 592    | 13           | 806,175        |
| SHA256    | 6      | **Ja7ad/otp**  | **736.0**   | **520**   | **7**         | **1,620,219**  |
| SHA256    | 6      | pquerna/otp    | 1495    | 728    | 13           | 801,048        |
| SHA256    | 8      | **Ja7ad/otp**  | **746.1**   | **520**   | **7**         | **1,596,862**  |
| SHA256    | 8      | pquerna/otp    | 1477    | 728    | 13           | 833,773        |
| SHA512    | 6      | **Ja7ad/otp**  | **1398**    | **872**   | **7**         | **807,380**    |
| SHA512    | 6      | pquerna/otp    | 2350    | 1224   | 13           | 432,844        |
| SHA512    | 8      | **Ja7ad/otp**  | **1408**    | **872**   | **7**         | **728,832**    |
| SHA512    | 8      | pquerna/otp    | 2359    | 1224   | 13           | 466,941        |


| Metric            | Ja7ad/otp           | pquerna/otp        | ✅ Winner |
|------------------|---------------------|---------------------|----------|
| **Execution time** (`ns/op`) | **~2x faster** across all algorithms and digit sizes | Slower in all cases | ✅ **Ja7ad/otp** |
| **Memory usage** (`B/op`) | **~30–50% less** memory allocated | Higher allocations | ✅ **Ja7ad/otp** |
| **Allocations** (`allocs/op`) | **7** allocations | **13** allocations | ✅ **Ja7ad/otp** |
| **Dependencies**  | **Zero** external deps | Relies on stdlib + extras | ✅ **Ja7ad/otp** |

### 🔥 Example: SHA256, 6 digits
- `Ja7ad/otp`: **736 ns**, **520 B**, **7 allocs**
- `pquerna/otp`: **1495 ns**, **728 B**, **13 allocs**

## 📑 Algorithm (RFC)

- [RFC 4226 / 6238](docs/rfc4226.md) proof algorithm
- [RFC 6287](docs/rfc6287.md) proof algorithm

## 📚 Usage


<details><summary>TOTP example</summary>

```go
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
```

</details>

<details><summary>HOTP example code</summary>

```go
package main

import (
	"fmt"
	"github.com/Ja7ad/otp"
	"log"
)

func main() {
	secret, err := otp.RandomSecret(otp.SHA1)
	if err != nil {
		log.Fatal(err)
	}

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
```

</details>

<details><summary>OCRA example code</summary>

```go
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
```

</details>

## 🤝 Contributing

We welcome contributions of all kinds — from fixing bugs and improving documentation to implementing new RFCs.

Please read our [Contributing Guide](CONTRIBUTING.md) to get started. It includes setup instructions, coding standards, and development workflows.

Whether you're filing an issue, submitting a pull request, or suggesting an improvement — thank you for helping make this library better! 🙌



## 📖 References

- [RFC 6287 - OCRA](https://datatracker.ietf.org/doc/html/rfc6287)
- [RFC 4226 - HOTP](https://datatracker.ietf.org/doc/html/rfc4226)
- [RFC 6238 - TOTP](https://datatracker.ietf.org/doc/html/rfc6238)
