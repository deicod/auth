package security

import (
	"crypto/rand"
	"crypto/subtle"
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
			if _, err := fmt.Sscanf(param, "m=%d", &memory); err != nil {
				return fmt.Errorf("invalid memory param: %w", err)
			}
		} else if strings.HasPrefix(param, "t=") {
			if _, err := fmt.Sscanf(param, "t=%d", &timeCost); err != nil {
				return fmt.Errorf("invalid time param: %w", err)
			}
		} else if strings.HasPrefix(param, "p=") {
			var p uint32
			if _, err := fmt.Sscanf(param, "p=%d", &p); err != nil {
				return fmt.Errorf("invalid threads param: %w", err)
			}
			threads = uint8(p)
		} else {
			return errors.New("invalid hash params")
		}
	}
	if memory == 0 || timeCost == 0 || threads == 0 {
		return errors.New("invalid hash params")
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
	if subtle.ConstantTimeCompare(hash, computed) != 1 {
		return errors.New("password mismatch")
	}
	return nil
}
