package rules

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"math/rand"
)

func tlsConfig() {
	// ruleid: traust-go-cryptography-tls-skip-verify
	cfg := &tls.Config{InsecureSkipVerify: true}

	// ruleid: traust-go-cryptography-tls-skip-verify
	cfg.InsecureSkipVerify = true

	// ok: traust-go-cryptography-tls-skip-verify
	safe := &tls.Config{MinVersion: tls.VersionTLS12}
	_ = safe
}

func hashes(data []byte) {
	// ruleid: traust-go-cryptography-weak-hash
	md5.Sum(data)

	// ruleid: traust-go-cryptography-weak-hash
	h := sha1.New()
	_ = h

	// ok: traust-go-cryptography-weak-hash
	sha256.Sum256(data)
}

func randomness() {
	// ruleid: traust-go-cryptography-math-rand-secret
	sessionToken := rand.Intn(1 << 30)
	_ = sessionToken

	// ok: traust-go-cryptography-math-rand-secret
	jitterMillis := rand.Intn(500)
	_ = jitterMillis
}

func dsn() {
	// ruleid: traust-go-cryptography-insecure-dsn-transport
	pg := "host=db user=app dbname=app sslmode=disable"
	_ = pg

	// ruleid: traust-go-cryptography-insecure-dsn-transport
	pgURL := "postgres://app@db.svc:5432/app?sslmode=prefer"
	_ = pgURL

	// ruleid: traust-go-cryptography-insecure-dsn-transport
	my := "app@tcp(db:3306)/app?tls=skip-verify"
	_ = my

	// ok: traust-go-cryptography-insecure-dsn-transport
	safe := "postgres://app@db.svc:5432/app?sslmode=verify-full"
	_ = safe

	// ok: traust-go-cryptography-insecure-dsn-transport
	mySafe := "app@tcp(db:3306)/app?tls=true"
	_ = mySafe
}

// --- traust-go-cryptography-cosign-classical-signing fixtures ---

// ruleid: traust-go-cryptography-cosign-classical-signing
// import "github.com/sigstore/cosign/v2/pkg/cosign"

// ok: traust-go-cryptography-cosign-classical-signing
// We discussed sigstore and cosign in the design doc prose.
