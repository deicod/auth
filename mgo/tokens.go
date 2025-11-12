package mgo

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
)

type tokenGenerator struct {
    size int
}

func newTokenGenerator(size int) tokenGenerator {
    if size <= 0 {
        size = 32
    }
    return tokenGenerator{size: size}
}

func (g tokenGenerator) Generate() (token string, hash string, err error) {
    buf := make([]byte, g.size)
    if _, err = rand.Read(buf); err != nil {
        return "", "", err
    }
    token = base64.RawURLEncoding.EncodeToString(buf)
    hash = hashToken(token)
    return token, hash, nil
}

func hashToken(token string) string {
    sum := sha256.Sum256([]byte(token))
    return hex.EncodeToString(sum[:])
}
