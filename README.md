A high-performance, zero-dependency Go package for generating and validating TOTP and HOTP one-time passwords — RFC [4226](https://datatracker.ietf.org/doc/html/rfc4226) and RFC [6238](https://datatracker.ietf.org/doc/html/rfc6238) compliant.

- [Feature](#-features)
- [Installation](#installation-go-124-)
- [Performance Comparison](#-performance-comparison)
- [Proof](#-otp-algorithm-proof-rfc-4226--6238)
- [Example](#example)
- [Reference](#-references)

## ✨ Features

- Zero dependencies – fully self-contained, no external packages  
- High performance with low allocations
- Supports HOTP (RFC [4226](https://datatracker.ietf.org/doc/html/rfc4226)) and TOTP (RFC [6238](https://datatracker.ietf.org/doc/html/rfc6238)) algorithms  
- Configurable OTP digit lengths: 6, 8, or 10  
- Supports SHA1, SHA256, and SHA512 HMAC algorithms  
- Constant-time OTP validation to prevent timing attacks  
- Clock skew tolerance for TOTP validation  
- Generates `otpauth://` URLs for Google Authenticator and compatible apps  
- Parses `otpauth://` URLs into configuration structs  
- Secure random secret generation (base32 encoded)  
- Thoroughly tested against official RFC test vectors  
- Includes fuzz tests, benchmark coverage, and solid algorithm validation

## Installation (Go 1.24 >=)

```shell
go get -u github.com/Ja7ad/otp
```

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

## 🔢 OTP Algorithm Proof (RFC 4226 / 6238)

The OTP is derived using the following steps:

1. Calculate the HMAC of the secret key and the counter:

$$
\text{HMAC} = \text{HMAC-SHA1}(\text{secret}, \text{counter})
$$

2. Apply **dynamic truncation**:

Let:
- $ \text{offset} = \text{HMAC}[19] \& 0x0F $
- Then extract 4 bytes starting from offset:

$$
\text{binary\_code} = (\text{HMAC}[o] \& 0x7F) \ll 24 \,|\, (\text{HMAC}[o+1] \& 0xFF) \ll 16 \,|\, (\text{HMAC}[o+2] \& 0xFF) \ll 8 \,|\, (\text{HMAC}[o+3] \& 0xFF)
$$

3. Modulo the result to get the final OTP code:

$$
\text{OTP} = \text{binary\_code} \mod 10^{\text{digits}}
$$

---

## Example

TOTP generation example

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

HOTP example code

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

### 📖 References

- [RFC 4226 - HOTP](https://datatracker.ietf.org/doc/html/rfc4226)
- [RFC 6238 - TOTP](https://datatracker.ietf.org/doc/html/rfc6238)
