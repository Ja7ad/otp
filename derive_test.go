package otp

import (
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
	tests := []struct {
		name     string
		hmac     []byte
		mod      uint64
		expected uint32
	}{
		{
			name: "simple_case",
			hmac: []byte{
				0x00, 0x00, 0x00, 0x00, // this will be extracted
				// filler to reach len=20
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, // len=20, last byte = 0x00
			},
			mod:      1000000,
			expected: 0, // 0 mod 10^6 = 0
		},
		{
			name: "non-zero HMAC",
			hmac: []byte{
				0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
				0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01,
				0x12, 0x34, 0x56, 0x78, // offset = 0x78 & 0x0F = 0x08
			},
			mod:      1000000,
			expected: uint32((uint64(((0x99 & 0x7F) << 24) | (0xAA << 16) | (0xBB << 8) | 0xCC)) & mask31BitInt % 1000000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncate(tt.hmac, tt.mod)
			if got != tt.expected {
				t.Errorf("truncate() = %d, want %d", got, tt.expected)
			}
		})
	}
}
