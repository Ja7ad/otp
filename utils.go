package otp

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// ParseDecimalToBigEndian8 converts a decimal string to an 8-byte big-endian representation.
// It interprets the input string as a base-10 unsigned integer, then returns an 8-byte slice
// where the most-significant byte is at index 0. This is useful for encoding counters or similar values.
func ParseDecimalToBigEndian8(s string) ([]byte, error) {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		out[i] = byte(v & 0xFF)
		v >>= 8
	}
	return out, nil
}

// LeftPadHex returns the input hex string left-padded with '0' characters until it reaches totalLen characters.
// If the input string is longer than or equal to totalLen, it returns the rightmost totalLen characters.
func LeftPadHex(s string, totalLen int) string {
	if len(s) >= totalLen {
		return s[len(s)-totalLen:]
	}
	return strings.Repeat("0", totalLen-len(s)) + s
}

// MustHexPadLeft decodes a hex string after left-padding it to the desired byte length.
// The size parameter specifies the desired number of bytes; the function left-pads the hex string
// to size*2 characters. It panics if the hex decoding fails.
func MustHexPadLeft(hexStr string, size int) []byte {
	padded := LeftPadHex(hexStr, size*2)
	b, err := hex.DecodeString(padded)
	if err != nil {
		panic(err)
	}
	return b
}

// ParseDecimal64BigEndian is similar to ParseDecimalToBigEndian8.
// It converts a decimal string to an 8-byte big-endian slice by parsing the string as a uint64.
func ParseDecimal64BigEndian(decStr string) ([]byte, error) {
	v, err := strconv.ParseUint(decStr, 10, 64)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		out[i] = byte(v & 0xFF)
		v >>= 8
	}
	return out, nil
}

// ParseHexTimestamp converts a hex-encoded timestamp string to an 8-byte slice.
// It left-pads the input string with '0' characters until it is 16 hex digits long (i.e. 8 bytes),
// then decodes the padded string.
func ParseHexTimestamp(ts string) ([]byte, error) {
	for len(ts) < 16 {
		ts = "0" + ts
	}
	return hex.DecodeString(ts)
}

// ParseDecimalChallengeRFC6287 converts a decimal challenge string to a 128-byte value as required by RFC 6287.
// The conversion process is as follows:
//  1. Parse the input as a decimal number into a big.Int.
//  2. Convert the number to an uppercase hexadecimal string.
//  3. Right-pad the hex string with '0's until its length is 256 characters (which corresponds to 128 bytes).
//  4. Decode the padded hex string into a byte slice.
func ParseDecimalChallengeRFC6287(s string) ([]byte, error) {
	decVal, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("invalid decimal %q", s)
	}
	hx := strings.ToUpper(decVal.Text(16))
	for len(hx) < 256 {
		hx += "0"
	}
	return hex.DecodeString(hx)
}

// To8ByteBigEndian converts a uint64 value into an 8-byte big-endian slice.
// This is a convenience function for encoding counters or time values.
func To8ByteBigEndian(v uint64) []byte {
	out := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		out[i] = byte(v & 0xFF)
		v >>= 8
	}
	return out
}
