A high-performance, zero-dependency Go package for generating and validating TOTP and HOTP one-time passwords — RFC [4226](https://datatracker.ietf.org/doc/html/rfc4226) and RFC [6238](https://datatracker.ietf.org/doc/html/rfc6238) compliant.

- [Feature](#-features)
- [Installation](#installation-go-124-)
- [Proof](#-otp-algorithm-proof-rfc-4226--6238)
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
