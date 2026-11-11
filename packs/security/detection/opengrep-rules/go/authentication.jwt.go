package rules

// Fixture for traust-go-authentication-jwt-signature-unverified. The
// stand-ins mirror a JWT library's call shapes so the fixture stays
// dependency-free; the rule matches call shapes, not imports.

type Claims struct{ Subject string }

type parserShim struct{}

func (parserShim) ParseUnverified(s string, c interface{}) (interface{}, []string, error) {
	return nil, nil, nil
}

func unverified(raw string, parser parserShim, testMode bool, key []byte) {
	if testMode {
		// ruleid: traust-go-authentication-jwt-signature-unverified
		parser.ParseUnverified(raw, &Claims{})
	}

	// ruleid: traust-go-authentication-jwt-signature-unverified
	jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
		return nil, nil
	})

	jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
		// ruleid: traust-go-authentication-jwt-signature-unverified
		return jwt.UnsafeAllowNoneSignatureType, nil
	})

	// ruleid: traust-go-authentication-jwt-signature-unverified
	opt := jwt.WithValidMethods([]string{"RS256", "none"})
	_ = opt

	// ok: traust-go-authentication-jwt-signature-unverified
	jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
		return key, nil
	}, jwt.WithValidMethods([]string{"RS256"}))

	// ok: traust-go-authentication-jwt-signature-unverified
	jwt.ParseWithClaims(raw, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return key, nil
	})
}
