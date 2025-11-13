package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

type TokenGenerator struct {
	size int
}

func NewTokenGenerator(size int) *TokenGenerator {
	if size <= 0 {
		size = 32
	}
	return &TokenGenerator{size: size}
}

func (g *TokenGenerator) Generate() (token string, hash string, err error) {
	buf := make([]byte, g.size)
	if _, err = rand.Read(buf); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(buf)
	hash = HashToken(token)
	return token, hash, nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
