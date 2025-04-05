package otp

import (
	"encoding/binary"
)

func deriveRFC4226(secret []byte, counter uint64, digits int, algo Algorithm) (string, error) {
	if int(algo) < 0 || int(algo) >= len(hmacPools) {
		return "", ErrUnsupportedAlgorithm
	}

	hp := &hmacPools[algo]
	buf := rfc4226BufPool.Get().(*[8]byte)
	binary.BigEndian.PutUint64(buf[:], counter)
	defer rfc4226BufPool.Put(buf)

	// Always create a new HMAC because Go doesn't support resetting the key.
	mac := hp.new(secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// Dynamic truncation
	otp := truncate(sum, digits)

	if digits <= 8 {
		return shortDigit(otp, digits), nil
	}

	return longDigit(otp, digits), nil
}
