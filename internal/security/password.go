package security

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/deicod/auth/config"
	"golang.org/x/crypto/argon2"
)

type PasswordHasher struct {
	cfg config.Argon2
}

func NewPasswordHasher(cfg config.Argon2) *PasswordHasher {
	return &PasswordHasher{cfg: cfg}
}

func (h *PasswordHasher) Hash(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, h.cfg.Time, h.cfg.Memory, h.cfg.Threads, h.cfg.KeyLen)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf("argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", h.cfg.Memory, h.cfg.Time, h.cfg.Threads, b64Salt, b64Hash)
	return encoded, nil
}

func (h *PasswordHasher) Verify(encoded, password string) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 {
		return errors.New("invalid hash format")
	}

	params := strings.Split(parts[2], ",")
	if len(params) != 3 {
		return errors.New("invalid hash params")
	}

	var memory uint32
	var timeCost uint32
	var threads uint8
	for _, param := range params {
		if strings.HasPrefix(param, "m=") {
			fmt.Sscanf(param, "m=%d", &memory)
		} else if strings.HasPrefix(param, "t=") {
			fmt.Sscanf(param, "t=%d", &timeCost)
		} else if strings.HasPrefix(param, "p=") {
			var p uint32
			fmt.Sscanf(param, "p=%d", &p)
			threads = uint8(p)
		}
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return err
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return err
	}

	computed := argon2.IDKey([]byte(password), salt, timeCost, memory, threads, uint32(len(hash)))
	if !compareBytes(hash, computed) {
		return errors.New("password mismatch")
	}
	return nil
}

func compareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
