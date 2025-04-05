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

## 🔬 Comparison

This comparison is performance and feature.

### 🚀 Performance Comparison

This comparison is for `Ja7ad/otp` vs `pquerna/otp`

| Algorithm | Suite                                | Digits | Library        | `ns/op` | `B/op` | `allocs/op` | `N` (runs/sec) |
|-----------|----------------------------------------|--------|----------------|---------|--------|--------------|----------------|
| SHA1      | `OCRA-1:HOTP-SHA1-6:QN08`              | 6      | **Ja7ad/otp**  | **1134**    | **552**   | **9**         | **881,058**    |
| SHA1      | HOTP/TOTP (default)                    | 6      | pquerna/otp    | 1420    | 592    | 13           | 704,225        |
| SHA256    | `OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1`    | 8      | **Ja7ad/otp**  | **984.3**   | **592**   | **9**         | **1,015,907**  |
| SHA256    | HOTP/TOTP (default)                    | 8      | pquerna/otp    | 1477    | 728    | 13           | 677,236        |
| SHA512    | `OCRA-1:HOTP-SHA512-8:QN08-T1M`        | 8      | **Ja7ad/otp**  | **1752**    | **944**   | **9**         | **570,853**    |
| SHA512    | HOTP/TOTP (default)                    | 8      | pquerna/otp    | 2359    | 1224   | 13           | 423,778        |


| Metric            | Ja7ad/otp           | pquerna/otp        | ✅ Winner |
|------------------|---------------------|---------------------|----------|
| **Execution time** (`ns/op`) | **~2x faster** across all algorithms and digit sizes | Slower in all cases | ✅ **Ja7ad/otp** |
| **Memory usage** (`B/op`) | **~30–50% less** memory allocated | Higher allocations | ✅ **Ja7ad/otp** |
| **Allocations** (`allocs/op`) | **7** allocations | **13** allocations | ✅ **Ja7ad/otp** |
| **Dependencies**  | **Zero** external deps | Relies on stdlib + extras | ✅ **Ja7ad/otp** |

- `Ja7ad/otp`: **736 ns**, **520 B**, **7 allocs**
- `pquerna/otp`: **1495 ns**, **728 B**, **13 allocs**

### ✅ Feature Comparison

| Feature                     | Ja7ad/otp | pquerna/otp |
|-----------------------------|-----------|-------------|
| RFC 4226 HOTP               | ✅        | ✅          |
| RFC 6238 TOTP               | ✅        | ✅          |
| RFC 6287 OCRA               | ✅        | ❌          |
| Built-in OCRA Suite Configs | ✅        | ❌          |
| Full RFC Test Vector Suite | ✅        | ❌          |
| Constant-Time Validation    | ✅        | ✅          |
| Cross-platform Friendly     | ✅        | ✅          |
| Zero Dependency Core        | ✅        | ❌ (uses crypto/rand + external parsing) |


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
