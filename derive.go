package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"sync"
	"unsafe"
)

const (
	maskOffset   = 0x0F
	mask31BitInt = 0x7FFFFFFF
	separator    = 0x00
)

type hashPool struct {
	pool *sync.Pool
	new  func(key []byte) hash.Hash
}

var (
	rfc4226BufPool = sync.Pool{
		New: func() any {
			var b [8]byte
			return &b
		},
	}
	rfc6287BufPool = sync.Pool{
		New: func() any {
			buf := make([]byte, 0, 256)
			return &buf
		},
	}
	hmacPools = [...]hashPool{
		{
			pool: &sync.Pool{},
			new: func(key []byte) hash.Hash {
				return hmac.New(sha1.New, key)
			},
		},
		{
			pool: &sync.Pool{},
			new: func(key []byte) hash.Hash {
				return hmac.New(sha256.New, key)
			},
		},
		{
			pool: &sync.Pool{},
			new: func(key []byte) hash.Hash {
				return hmac.New(sha512.New, key)
			},
		},
	}
	mod10 = [...]uint64{
		0, 10, 100, 1000, 10000, 100000, 1000000,
		10000000, 100000000, 1000000000, 1000000000,
	}
)

func shortDigit(otp uint32, digits int) string {
	var pad [8]byte
	i := digits - 1
	for otp > 0 && i >= 0 {
		pad[i] = '0' + byte(otp%10)
		otp /= 10
		i--
	}
	for ; i >= 0; i-- {
		pad[i] = '0'
	}
	return unsafeString(pad[:digits])
}

func longDigit(otp uint32, digits int) string {
	out := make([]byte, digits)
	for i := digits - 1; i >= 0; i-- {
		out[i] = '0' + byte(otp%10)
		otp /= 10
	}
	return string(out)
}

//go:nocheckptr
func unsafeString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

func padBytes(input []byte, length int) []byte {
	if len(input) >= length {
		return input[:length]
	}
	out := make([]byte, length)
	copy(out, input)
	return out
}

func formatDecimal(val uint32, digits int) string {
	out := make([]byte, digits)
	for i := digits - 1; i >= 0; i-- {
		out[i] = byte('0' + (val % 10))
		val /= 10
	}
	return string(out)
}

func truncate(sum []byte, mod uint64) uint32 {
	offset := sum[len(sum)-1] & maskOffset
	bin := (uint32(sum[offset]) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	code := bin & mask31BitInt

	return uint32(uint64(code) % mod)
}
