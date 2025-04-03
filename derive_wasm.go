//go:build js && wasm

package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"strconv"
)

// DeriveOTPWasm generates a HOTP code (used by both HOTP/TOTP) safely for WebAssembly (js/wasm).
func DeriveOTPWasm(secret []byte, counter uint64, digits int, algo Algorithm) (string, error) {
	var h func() hash.Hash
	switch algo {
	case SHA1:
		h = sha1.New
	case SHA256:
		h = sha256.New
	case SHA512:
		h = sha512.New
	default:
		return "", ErrUnsupportedAlgorithm
	}

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(h, secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & maskOffset
	bin := (uint32(sum[offset]) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	code := bin & mask31BitInt

	var mod uint64
	if digits >= 1 && digits <= 9 {
		mod = mod10[digits]
	} else {
		mod = pow10Wasm(digits)
	}

	otp := uint64(code) % mod

	s := strconv.FormatUint(otp, 10)
	if len(s) < digits {
		padding := make([]byte, digits-len(s))
		for i := range padding {
			padding[i] = '0'
		}
		s = string(padding) + s
	}

	return s, nil
}

func pow10Wasm(n int) uint64 {
	var result uint64 = 1
	for i := 0; i < n; i++ {
		result *= 10
	}
	return result
}
