package config

import "time"

type Session struct {
	Length time.Duration
}

type Tokens struct {
	VerificationTTL time.Duration
	ResetTTL        time.Duration
	EmailChangeTTL  time.Duration
}

type Argon2 struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
}

type Password struct {
	MinLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireNumber    bool
	RequireSpecial   bool
}

func DefaultSession() Session {
	return Session{Length: 30 * 24 * time.Hour}
}

func DefaultTokens() Tokens {
	return Tokens{
		VerificationTTL: 48 * time.Hour,
		ResetTTL:        1 * time.Hour,
		EmailChangeTTL:  24 * time.Hour,
	}
}

func DefaultArgon2() Argon2 {
	return Argon2{
		Time:    3,
		Memory:  64 * 1024,
		Threads: 2,
		KeyLen:  32,
	}
}

func DefaultPassword() Password {
	return Password{
		MinLength:        8,
		RequireUppercase: false,
		RequireLowercase: false,
		RequireNumber:    false,
		RequireSpecial:   false,
	}
}
