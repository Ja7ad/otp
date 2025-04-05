package otp

import (
	"encoding/hex"
	"testing"
)

func TestPadBytes(t *testing.T) {
	tests := []struct {
		input    []byte
		length   int
		expected []byte
	}{
		{[]byte("abc"), 5, []byte("abc\x00\x00")},
		{[]byte("abcdef"), 3, []byte("abc")},
		{[]byte{}, 4, []byte{0, 0, 0, 0}},
		{[]byte("xyz"), 3, []byte("xyz")},
	}

	for _, tt := range tests {
		got := padBytes(tt.input, tt.length)
		if string(got) != string(tt.expected) {
			t.Errorf("padBytes(%q, %d) = %q, want %q", tt.input, tt.length, got, tt.expected)
		}
	}
}

func TestFormatDecimal(t *testing.T) {
	tests := []struct {
		value    uint32
		digits   int
		expected string
	}{
		{123456, 6, "123456"},
		{42, 6, "000042"},
		{0, 8, "00000000"},
		{99999999, 8, "99999999"},
	}

	for _, tt := range tests {
		got := formatDecimal(tt.value, tt.digits)
		if got != tt.expected {
			t.Errorf("formatDecimal(%d, %d) = %q, want %q", tt.value, tt.digits, got, tt.expected)
		}
	}
}

func TestTruncate(t *testing.T) {

	hmacBytes, _ := hex.DecodeString("1f8698690e02ca16618550ef7f19da8e945b555a")

	code := truncate(hmacBytes, 6)
	expected := uint32(872921)
	if code != expected {
		t.Errorf("truncate() = %d, want %d", code, expected)
	}
}
