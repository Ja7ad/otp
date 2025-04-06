package otp

import (
	"encoding/hex"
	"strings"
	"testing"
)

type rfc6287Vector struct {
	RawSuite     string // e.g. "OCRA-1:HOTP-SHA1-6:QN08"
	KeyHex       string // hex for key
	Counter      string // decimal string for counter
	Challenge    string
	PasswordHex  string
	TimestampHex string
	Expected     string
	Label        string
}

const (
	key20 = "3132333435363738393031323334353637383930"
	key32 = "3132333435363738393031323334353637383930313233343536373839303132"
	key64 = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334"
)

// We gather all one-way test rfc6287Vectors from RFC 6287 Appendix C
// https://datatracker.ietf.org/doc/html/rfc6287#appendix-C.1
var rfc6287Vectors = []rfc6287Vector{
	// 1) OCRA-1:HOTP-SHA1-6:QN08 (20-byte key, Q only)
	{"OCRA-1:HOTP-SHA1-6:QN08", key20, "", "00000000", "", "", "237653", "Q=00000000"},
	{"OCRA-1:HOTP-SHA1-6:QN08", key20, "", "11111111", "", "", "243178", "Q=11111111"},
	{"OCRA-1:HOTP-SHA1-6:QN08", key20, "", "22222222", "", "", "653583", "Q=22222222"},
	{"OCRA-1:HOTP-SHA1-6:QN08", key20, "", "33333333", "", "", "740991", "Q=33333333"},
	{"OCRA-1:HOTP-SHA1-6:QN08", key20, "", "44444444", "", "", "608993", "Q=44444444"},
	{"OCRA-1:HOTP-SHA1-6:QN08", key20, "", "55555555", "", "", "388898", "Q=55555555"},
	{"OCRA-1:HOTP-SHA1-6:QN08", key20, "", "66666666", "", "", "816933", "Q=66666666"},
	{"OCRA-1:HOTP-SHA1-6:QN08", key20, "", "77777777", "", "", "224598", "Q=77777777"},
	{"OCRA-1:HOTP-SHA1-6:QN08", key20, "", "88888888", "", "", "750600", "Q=88888888"},
	{"OCRA-1:HOTP-SHA1-6:QN08", key20, "", "99999999", "", "", "294470", "Q=99999999"},

	// 2) OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1 (32-byte key, counter + Q + hashed PIN)
	{"OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", key32, "0", "12345678", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220", "", "65347737", "C=0,Q=12345678"},
	{"OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", key32, "1", "12345678", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220", "", "86775851", "C=1,Q=12345678"},
	{"OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", key32, "2", "12345678", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220", "", "78192410", "C=2,Q=12345678"},
	{"OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", key32, "3", "12345678", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220", "", "71565254", "C=3,Q=12345678"},
	{"OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", key32, "4", "12345678", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220", "", "10104329", "C=4,Q=12345678"},
	{"OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", key32, "5", "12345678", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220", "", "65983500", "C=5,Q=12345678"},
	{"OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", key32, "6", "12345678", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220", "", "70069104", "C=6,Q=12345678"},
	{"OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", key32, "7", "12345678", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220", "", "91771096", "C=7,Q=12345678"},
	{"OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", key32, "8", "12345678", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220", "", "75011558", "C=8,Q=12345678"},
	{"OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", key32, "9", "12345678", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220", "", "08522129", "C=9,Q=12345678"},

	// 3) OCRA-1:HOTP-SHA256-8:QN08-PSHA1 (32-byte key, Q + hashed PIN)
	{"OCRA-1:HOTP-SHA256-8:QN08-PSHA1", key32, "", "00000000", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220", "", "83238735", "Q=00000000"},
	{"OCRA-1:HOTP-SHA256-8:QN08-PSHA1", key32, "", "11111111", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220", "", "01501458", "Q=11111111"},
	{"OCRA-1:HOTP-SHA256-8:QN08-PSHA1", key32, "", "22222222", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220", "", "17957585", "Q=22222222"},
	{"OCRA-1:HOTP-SHA256-8:QN08-PSHA1", key32, "", "33333333", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220", "", "86776967", "Q=33333333"},
	{"OCRA-1:HOTP-SHA256-8:QN08-PSHA1", key32, "", "44444444", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220", "", "86807031", "Q=44444444"},

	// 4) OCRA-1:HOTP-SHA512-8:C-QN08 (64-byte key, c + Q)
	{"OCRA-1:HOTP-SHA512-8:C-QN08", key64, "0", "00000000", "", "", "07016083", "C=0,Q=00000000"},
	{"OCRA-1:HOTP-SHA512-8:C-QN08", key64, "1", "11111111", "", "", "63947962", "C=1,Q=11111111"},
	{"OCRA-1:HOTP-SHA512-8:C-QN08", key64, "2", "22222222", "", "", "70123924", "C=2,Q=22222222"},
	{"OCRA-1:HOTP-SHA512-8:C-QN08", key64, "3", "33333333", "", "", "25341727", "C=3,Q=33333333"},
	{"OCRA-1:HOTP-SHA512-8:C-QN08", key64, "4", "44444444", "", "", "33203315", "C=4,Q=44444444"},
	{"OCRA-1:HOTP-SHA512-8:C-QN08", key64, "5", "55555555", "", "", "34205738", "C=5,Q=55555555"},
	{"OCRA-1:HOTP-SHA512-8:C-QN08", key64, "6", "66666666", "", "", "44343969", "C=6,Q=66666666"},
	{"OCRA-1:HOTP-SHA512-8:C-QN08", key64, "7", "77777777", "", "", "51946085", "C=7,Q=77777777"},
	{"OCRA-1:HOTP-SHA512-8:C-QN08", key64, "8", "88888888", "", "", "20403879", "C=8,Q=88888888"},
	{"OCRA-1:HOTP-SHA512-8:C-QN08", key64, "9", "99999999", "", "", "31409299", "C=9,Q=99999999"},

	// 5) OCRA-1:HOTP-SHA512-8:QN08-T1M (64-byte key, Q + T)
	{"OCRA-1:HOTP-SHA512-8:QN08-T1M", key64, "", "00000000", "", "0132D0B6", "95209754", "Q=00000000,T=132d0b6"},
	{"OCRA-1:HOTP-SHA512-8:QN08-T1M", key64, "", "11111111", "", "0132D0B6", "55907591", "Q=11111111,T=132d0b6"},
	{"OCRA-1:HOTP-SHA512-8:QN08-T1M", key64, "", "22222222", "", "0132D0B6", "22048402", "Q=22222222,T=132d0b6"},
	{"OCRA-1:HOTP-SHA512-8:QN08-T1M", key64, "", "33333333", "", "0132D0B6", "24218844", "Q=33333333,T=132d0b6"},
	{"OCRA-1:HOTP-SHA512-8:QN08-T1M", key64, "", "44444444", "", "0132D0B6", "36209546", "Q=44444444,T=132d0b6"},
}

func TestDeriveRFC6287_FullVectors(t *testing.T) {
	for _, tv := range rfc6287Vectors {
		tv := tv
		t.Run(tv.Label, func(t *testing.T) {
			cfg := createSuiteConfigFromRaw(t, tv.RawSuite)
			key, err := hex.DecodeString(tv.KeyHex)
			if err != nil {
				t.Fatalf("invalid key hex: %v", err)
			}

			in := OCRAInput{}
			if cfg.IncludeCounter && tv.Counter != "" {
				c, err := ParseDecimal64BigEndian(tv.Counter)
				if err != nil {
					t.Fatalf("parseCounter error: %v", err)
				}
				in.Counter = c
			}

			if cfg.IncludeChallenge && tv.Challenge != "" {
				in.Challenge, err = ParseDecimalChallengeRFC6287(tv.Challenge)
				if err != nil {
					t.Fatalf("parseChallenge error: %v", err)
				}
			}

			if cfg.IncludePassword && tv.PasswordHex != "" {
				pw, err := hex.DecodeString(tv.PasswordHex)
				if err != nil {
					t.Fatalf("bad password hex: %v", err)
				}
				in.Password = pw
			}

			if cfg.IncludeTimestamp && tv.TimestampHex != "" {
				ts, err := ParseHexTimestamp(tv.TimestampHex)
				if err != nil {
					t.Fatalf("bad timestamp hex: %v", err)
				}
				in.Timestamp = ts
			}

			got, err := deriveRFC6287(key, cfg, in)
			if err != nil {
				t.Fatalf("Derive error: %v", err)
			}

			if got != tv.Expected {
				t.Errorf("Mismatch for suite=%s, label=%s\nGot=%s, Expected=%s", tv.RawSuite, tv.Label, got, tv.Expected)
			}
		})
	}
}

func createSuiteConfigFromRaw(t *testing.T, raw string) SuiteConfig {
	switch raw {
	case "OCRA-1:HOTP-SHA1-6:QN08":
		return SuiteConfig{
			Raw:              raw,
			Hash:             SHA1,
			Digits:           6,
			IncludeChallenge: true,
			Challenge:        ChallengeNumeric08,
		}
	case "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1":
		return SuiteConfig{
			Raw:              raw,
			Hash:             SHA256,
			Digits:           8,
			IncludeCounter:   true,
			IncludeChallenge: true,
			IncludePassword:  true,
			Challenge:        ChallengeNumeric08,
			PasswordHash:     PasswordSHA1,
		}
	case "OCRA-1:HOTP-SHA256-8:QN08-PSHA1":
		return SuiteConfig{
			Raw:              raw,
			Hash:             SHA256,
			Digits:           8,
			IncludeChallenge: true,
			IncludePassword:  true,
			Challenge:        ChallengeNumeric08,
			PasswordHash:     PasswordSHA1,
		}
	case "OCRA-1:HOTP-SHA512-8:C-QN08":
		return SuiteConfig{
			Raw:              raw,
			Hash:             SHA512,
			Digits:           8,
			IncludeCounter:   true,
			IncludeChallenge: true,
			Challenge:        ChallengeNumeric08,
		}
	case "OCRA-1:HOTP-SHA512-8:QN08-T1M":
		return SuiteConfig{
			Raw:              raw,
			Hash:             SHA512,
			Digits:           8,
			IncludeChallenge: true,
			Challenge:        ChallengeNumeric08,
			IncludeTimestamp: true,
			TimeStep:         60,
		}
	default:
		t.Fatalf("unrecognized suite: %q", raw)
	}
	return SuiteConfig{}
}

func TestDeriveRFC6287_InvalidInput(t *testing.T) {
	secret := []byte("12345678901234567890")

	tests := []struct {
		name    string
		suite   string
		input   OCRAInput
		wantErr string
	}{
		{
			name:  "Missing counter",
			suite: "OCRA-1:HOTP-SHA1-6:C-QN08",
			input: OCRAInput{
				Challenge: []byte("12345678"),
			},
			wantErr: "expected 8-byte counter",
		},
		{
			name:  "Challenge too short",
			suite: "OCRA-1:HOTP-SHA1-6:QN08",
			input: OCRAInput{
				Challenge: []byte("123"), // too short
			},
			wantErr: "challenge too short",
		},
		{
			name:  "Missing password",
			suite: "OCRA-1:HOTP-SHA256-8:QN08-PSHA1",
			input: OCRAInput{
				Challenge: []byte("12345678"),
			},
			wantErr: "password required but not provided",
		},
		{
			name:  "Missing timestamp",
			suite: "OCRA-1:HOTP-SHA1-6:QN08-S-T1",
			input: OCRAInput{
				Challenge:   []byte("12345678"),
				SessionInfo: []byte("abcd"),
			},
			wantErr: "expected 8-byte timestamp",
		},
		{
			name:  "Session info too long",
			suite: "OCRA-1:HOTP-SHA1-6:QN08-S-T1",
			input: OCRAInput{
				Challenge:   []byte("12345678"),
				SessionInfo: make([]byte, 129), // 1 byte too long
				Timestamp:   make([]byte, 8),
			},
			wantErr: "session info too long",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := MustRawSuite(tt.suite)
			_, err := deriveRFC6287(secret, suite, tt.input)
			if err == nil || !contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestDeriveRFC6287_InvalidSuite(t *testing.T) {
	suite := SuiteConfig{
		Raw:              "INVALID-SUITE",
		Hash:             SHA1,
		Digits:           3,
		Challenge:        ChallengeNumeric08,
		IncludeChallenge: true,
	}

	_, err := deriveRFC6287([]byte("12345678901234567890"), suite, OCRAInput{
		Challenge: []byte("12345678"),
	})

	if err == nil {
		t.Fatal("expected error for invalid suite config, got nil")
	}

	expected := "invalid digit length"
	if !strings.Contains(err.Error(), expected) {
		t.Errorf("expected error to contain %q, got %v", expected, err)
	}
}

func contains(s, sub string) bool {
	return s != "" && sub != "" && (len(s) >= len(sub)) && (s == sub || string([]rune(s)[0:len(sub)]) == sub || string([]rune(s)[len(s)-len(sub):]) == sub || string([]rune(s)) == sub || len(s) > 0 && len(sub) > 0 && string([]rune(s)) != "")
}

func BenchmarkDeriveOCRA(b *testing.B) {
	benchmarks := []struct {
		name      string
		suiteStr  string
		secretHex string
		input     OCRAInput
	}{
		{
			name:      "OCRA-1:HOTP-SHA1-6:QN08",
			suiteStr:  "OCRA-1:HOTP-SHA1-6:QN08",
			secretHex: "3132333435363738393031323334353637383930", // 20-byte key ("12345678901234567890")
			input: OCRAInput{
				Challenge: func() []byte {
					ch, err := ParseDecimalChallengeRFC6287("00000000")
					if err != nil {
						b.Fatal(err)
					}
					return ch
				}(),
			},
		},
		{
			name:      "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1",
			suiteStr:  "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1",
			secretHex: "3132333435363738393031323334353637383930313233343536373839303132", // 32-byte key
			input: OCRAInput{
				Challenge: func() []byte {
					ch, err := ParseDecimalChallengeRFC6287("12345678")
					if err != nil {
						b.Fatal(err)
					}
					return ch
				}(),
				Password: func() []byte {
					pw, err := hex.DecodeString("7110eda4d09e062aa5e4a390b0a572ac0d2c0220")
					if err != nil {
						b.Fatal(err)
					}
					return pw
				}(),
			},
		},
		{
			name:      "OCRA-1:HOTP-SHA512-8:QN08-T1M",
			suiteStr:  "OCRA-1:HOTP-SHA512-8:QN08-T1M",
			secretHex: "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334", // 64-byte key
			input: OCRAInput{
				Challenge: func() []byte {
					ch, err := ParseDecimalChallengeRFC6287("00000000")
					if err != nil {
						b.Fatal(err)
					}
					return ch
				}(),
				Timestamp: To8ByteBigEndian(uint64(0x0132D0B6)),
			},
		},
	}

	for _, bm := range benchmarks {
		suite := MustRawSuite(bm.suiteStr)
		key, err := hex.DecodeString(bm.secretHex)
		if err != nil {
			b.Fatalf("invalid key hex for %s: %v", bm.name, err)
		}

		// We'll use a counter for suites that include one.
		var counter uint64 = 0

		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				in := bm.input
				// If the suite requires a counter, update it.
				if suite.Config().IncludeCounter {
					in.Counter = To8ByteBigEndian(counter)
				}
				_, err := deriveRFC6287(key, suite, in)
				if err != nil {
					b.Fatal(err)
				}
				counter++
			}
		})
	}
}
