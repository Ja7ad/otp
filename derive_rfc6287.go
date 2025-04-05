package otp

// deriveRFC6287 is based on https://datatracker.ietf.org/doc/html/rfc6287
func deriveRFC6287(secret []byte, s Suite, input OCRAInput) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	cfg := s.Config()

	if err := input.validate(cfg); err != nil {
		return "", err
	}

	msgBuf := rfc6287BufPool.Get().(*[]byte)
	defer rfc6287BufPool.Put(msgBuf)

	msg := (*msgBuf)[:0]

	msg = append(msg, []byte(cfg.Raw)...)
	msg = append(msg, separator)

	if cfg.IncludeCounter {
		msg = append(msg, padBytes(input.Counter, 8)...) // 8 bytes
	}
	if cfg.IncludeChallenge {
		msg = append(msg, padBytes(input.Challenge, 128)...) // 128 bytes
	}
	if cfg.IncludePassword {
		msg = append(msg, input.Password...) // exact length (20,32,64)
	}
	if cfg.IncludeSession {
		// For demo, we do pad up to 128, but you can adapt for S064, S128, etc.
		msg = append(msg, padBytes(input.SessionInfo, 128)...)
	}
	if cfg.IncludeTimestamp {
		msg = append(msg, padBytes(input.Timestamp, 8)...) // 8 bytes
	}

	hp := &hmacPools[cfg.Hash]
	mac := hp.new(secret)
	mac.Write(msg)
	sum := mac.Sum(nil)
	otp := truncate(sum, cfg.Digits)

	return formatDecimal(otp, cfg.Digits), nil
}
