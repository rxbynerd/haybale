// Command mint-e2e-jwt is a throwaway acceptance-harness helper for
// scripts/e2e-github.sh — NOT part of the haybale binary, which is a
// verifier and mints nothing. It generates a fresh ES256 keypair, writes
// the public half as a JWKS document (for haybale's per-issuer jwksFile),
// and prints a signed, short-lived JWT for the requested subject/issuer/
// audience to stdout. The private key never leaves this process; only the
// public JWKS is persisted.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
)

func main() {
	sub := flag.String("sub", "", "token subject (the run identity), required")
	iss := flag.String("iss", "", "token issuer, must match haybale's configured issuer, required")
	aud := flag.String("aud", "", "token audience, must match haybale's configured audience, required")
	jwksOut := flag.String("jwks-out", "", "path to write the public JWKS document to, required")
	ttl := flag.Duration("ttl", time.Hour, "token lifetime")
	flag.Parse()

	if *sub == "" || *iss == "" || *aud == "" || *jwksOut == "" {
		fmt.Fprintln(os.Stderr, "mint-e2e-jwt: --sub, --iss, --aud, and --jwks-out are all required")
		os.Exit(2)
	}

	if err := run(*sub, *iss, *aud, *jwksOut, *ttl); err != nil {
		fmt.Fprintf(os.Stderr, "mint-e2e-jwt: %v\n", err)
		os.Exit(1)
	}
}

func run(sub, iss, aud, jwksOut string, ttl time.Duration) error {
	const kid = "e2e-mint-key"

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	jwk, err := jwkset.NewJWKFromKey(key.Public(), jwkset.JWKOptions{
		Metadata: jwkset.JWKMetadataOptions{KID: kid, ALG: jwkset.AlgES256, USE: jwkset.UseSig},
	})
	if err != nil {
		return fmt.Errorf("build jwk: %w", err)
	}
	store := jwkset.NewMemoryStorage()
	if err := store.KeyWrite(context.Background(), jwk); err != nil {
		return fmt.Errorf("write jwk: %w", err)
	}
	raw, err := store.JSONPublic(context.Background())
	if err != nil {
		return fmt.Errorf("marshal jwks: %w", err)
	}
	if err := os.WriteFile(jwksOut, raw, 0o600); err != nil {
		return fmt.Errorf("write jwks file: %w", err)
	}

	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": iss,
		"aud": aud,
		"sub": sub,
		"jti": sub + "-jti",
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	})
	tok.Header["kid"] = kid
	tok.Header["typ"] = "at+jwt"
	signed, err := tok.SignedString(key)
	if err != nil {
		return fmt.Errorf("sign token: %w", err)
	}

	fmt.Println(signed)
	return nil
}
