 Welcome, and thank you for your interest in contributing to `otp` — a high-performance, zero-dependency Golang implementation of HOTP, TOTP, and related standards.

We value clean code, security, and performance. Whether you're fixing bugs, implementing new RFCs, writing benchmarks, or improving documentation — you're in the right place!

---

## ⚙️ Development Setup

### 1. Clone the Repository

```bash
git clone https://github.com/Ja7ad/otp.git
cd otp
```

### 2. Run Tests

```bash
go test ./...
```

---

## 📏 Code Guidelines

- Follow [Effective Go](https://golang.org/doc/effective_go.html).
- Favor **zero allocations** and **constant-time comparisons** for security.
- Ensure full test coverage.
- Include **benchmarks** if adding cryptographic primitives or performance-sensitive code.
- Use Go’s standard formatting:

```bash
make check
```

---

## 🧪 Adding a New RFC Implementation

If you're implementing a new OTP-related RFC (e.g., OCRA, HOTP extensions):

1. Create a dedicated test file with comprehensive coverage.
2. Update `README.md` if it affects public functionality.
3. Add benchmark functions using `testing.B`.

---

## 💬 Contributing Tips

- ✅ **Before submitting a PR**, run:
  ```bash
  go test ./... && go vet ./...
  ```
- 🔍 Keep PRs focused and descriptive.
- 🧪 Ensure tests pass on the latest Go versions.
- 🧹 Avoid introducing third-party dependencies unless absolutely necessary.
- 🧾 Add doc-comments for all public functions/types.

---

## 🤝 Support & Feedback

- Open a GitHub [Issue](https://github.com/Ja7ad/otp/issues)
- Submit a [Pull Request](https://github.com/Ja7ad/otp/pulls)
- Tag with `enhancement`, `bug`, or `security` as appropriate

---

## 📜 License

All contributions are subject to the [MIT License](LICENSE).

By contributing, you agree your code will be licensed under the project's license.

---

Thanks again for helping improve `otp`. Your contributions secure millions of authentications — and we appreciate it! 💚
