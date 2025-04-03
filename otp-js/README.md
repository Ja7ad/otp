# 🔐 otp-js

> WebAssembly-powered One-Time Password (OTP) library with blazing-fast HOTP & TOTP generation and validation using Go — fully accessible from [javascript](https://www.npmjs.com/package/@ja7ad/otp-js).

## ✨ Features

- ✅ TOTP & HOTP code generation
- 🔐 RFC 4226 / 6238 compliant
- ⚡️ High performance with Go + WebAssembly
- 🧪 Fully unit tested with Jest
- 🔄 Time skew support for validation
- 📦 Generates `otpauth://` URLs for authenticator apps (Google Authenticator, Authy, etc.)
- 💻 Works in Node.js (browser support via bundler)

---

## 📦 Installation

```bash
npm i @ja7ad/otp-js
```

---

## 🚀 Usage

### 1. Initialize the WASM runtime

```js
const initWasm = require("otp-js");

(async () => {
  const otp = await initWasm();

  const code = otp.generateTOTP("JBSWY3DPEHPK3PXP", Math.floor(Date.now() / 1000), "6", "SHA1", 30);
  console.log("TOTP:", code);
})();
```

---

## 📚 API Reference

### `generateHOTP(secret, counter, digits, algorithm)`

Generate a counter-based HOTP code.

- `secret` *(string)* – Base32-encoded secret key
- `counter` *(number)* – Counter value (int64)
- `digits` *(string)* – OTP length: `"6"`, `"8"`, etc.
- `algorithm` *(string)* – Hash algorithm: `"SHA1"`, `"SHA256"`, or `"SHA512"`

---

### `generateTOTP(secret, timestamp, digits, algorithm, period)`

Generate a time-based TOTP code.

- `secret` *(string)* – Base32-encoded secret
- `timestamp` *(number)* – UNIX timestamp
- `digits` *(string)* – OTP length
- `algorithm` *(string)* – Algorithm name
- `period` *(number)* – Time step in seconds (default: 30)

---

### `validateHOTP(secret, code, counter, digits, algorithm, skew)`

Validate an HOTP code with optional skew.

- `code` – The OTP to validate
- `skew` *(number)* – Max allowed counter window (+/-)

Returns: `true`, `false`, or `"error: ..."`

---

### `validateTOTP(secret, code, timestamp, digits, algorithm, period, skew)`

Validate a TOTP code.

- `timestamp` – Current UNIX time
- `skew` – Allowed time step window (±skew * period)

Returns: `true`, `false`, or `"error: ..."`

---

### `generateOTPURL(otpType, issuer, accountName, secret, digits, algorithm)`

Generates a TOTP or HOTP `otpauth://` URL.

Example:
```js
const url = otp.generateOTPURL(
  "totp",
  "GitHub",
  "user@example.com",
  "JBSWY3DPEHPK3PXP",
  "6",
  "SHA1"
);
console.log(url); // otpauth://totp/GitHub:user@example.com?...
```

---

## 🧪 Running Tests

```bash
npm test
```

## 🛠️ Build the WASM (Go 1.21+)

```bash
GOOS=js GOARCH=wasm go build -o lib/otp.wasm ./go/main.go
```
