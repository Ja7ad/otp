package otp

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestParseDecimalToBigEndian8(t *testing.T) {
	input := "12345678"
	expected := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0xBC, 0x61, 0x4E}
	got, err := ParseDecimalToBigEndian8(input)
	if err != nil {
		t.Fatalf("ParseDecimalToBigEndian8(%q) returned error: %v", input, err)
	}
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("ParseDecimalToBigEndian8(%q) = %v, want %v", input, got, expected)
	}
}

func TestLeftPadHex(t *testing.T) {
	tests := []struct {
		input    string
		totalLen int
		expected string
	}{
		{"ABC", 6, "000ABC"},
		{"123456", 4, "3456"},
		{"DEAD", 4, "DEAD"},
	}
	for _, tt := range tests {
		got := LeftPadHex(tt.input, tt.totalLen)
		if got != tt.expected {
			t.Errorf("LeftPadHex(%q, %d) = %q, want %q", tt.input, tt.totalLen, got, tt.expected)
		}
	}
}

func TestMustHexPadLeft(t *testing.T) {
	input := "ABC"
	expectedBytes, _ := hex.DecodeString("00000ABC")
	got := MustHexPadLeft(input, 4)
	if !reflect.DeepEqual(got, expectedBytes) {
		t.Errorf("MustHexPadLeft(%q, 4) = %v, want %v", input, got, expectedBytes)
	}
}

func TestParseDecimal64BigEndian(t *testing.T) {
	input := "12345678"
	expected := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0xBC, 0x61, 0x4E}
	got, err := ParseDecimal64BigEndian(input)
	if err != nil {
		t.Fatalf("ParseDecimal64BigEndian(%q) returned error: %v", input, err)
	}
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("ParseDecimal64BigEndian(%q) = %v, want %v", input, got, expected)
	}
}

func TestParseHexTimestamp(t *testing.T) {
	input := "132D0B6"
	expected, _ := hex.DecodeString("000000000132D0B6")
	got, err := ParseHexTimestamp(input)
	if err != nil {
		t.Fatalf("ParseHexTimestamp(%q) returned error: %v", input, err)
	}
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("ParseHexTimestamp(%q) = %v, want %v", input, got, expected)
	}
}

func TestParseDecimalChallengeRFC6287(t *testing.T) {
	input := "11111111"
	got, err := ParseDecimalChallengeRFC6287(input)
	if err != nil {
		t.Fatalf("ParseDecimalChallengeRFC6287(%q) error: %v", input, err)
	}
	if len(got) != 128 {
		t.Errorf("ParseDecimalChallengeRFC6287(%q) length = %d, want 128", input, len(got))
	}
	expectedPrefix := []byte{0xA9, 0x8A, 0xC7}
	if !reflect.DeepEqual(got[:3], expectedPrefix) {
		t.Errorf("ParseDecimalChallengeRFC6287(%q) prefix = % X, want % X", input, got[:3], expectedPrefix)
	}
}

func TestTo8ByteBigEndian(t *testing.T) {
	var input uint64 = 12345678
	expected := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0xBC, 0x61, 0x4E}
	got := To8ByteBigEndian(input)
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("To8ByteBigEndian(%d) = %v, want %v", input, got, expected)
	}
}
