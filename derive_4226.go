package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"sync"
	"unsafe"
)

const (
	maskOffset   = 0x0F
	mask31BitInt = 0x7FFFFFFF
)

type hashPool struct {
	pool *sync.Pool
	new  func(key []byte) hash.Hash
}

var (
	bufPool = sync.Pool{
		New: func() any {
			var b [8]byte
			return &b
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

func deriveRFC4226(secret []byte, counter uint64, digits int, algo Algorithm) (string, error) {
	if int(algo) < 0 || int(algo) >= len(hmacPools) {
		return "", ErrUnsupportedAlgorithm
	}

	hp := &hmacPools[algo]
	buf := bufPool.Get().(*[8]byte)
	binary.BigEndian.PutUint64(buf[:], counter)
	defer bufPool.Put(buf)

	// Always create a new HMAC because Go doesn't support resetting the key.
	mac := hp.new(secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// Dynamic truncation
	offset := sum[len(sum)-1] & maskOffset
	bin := (uint32(sum[offset]) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	code := bin & mask31BitInt
	mod := mod10[digits]
	otp := uint32(uint64(code) % mod)

	if digits <= 8 {
		return shortDigit(otp, digits), nil
	}

	return longDigit(otp, digits), nil
}

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
