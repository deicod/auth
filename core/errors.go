package core

import "errors"

// MaxTokenLength bounds every accepted token (session, verification, reset,
// email-change). It is enforced before hashing or DB work to prevent hash/DB
// DoS from oversized inputs, and before parsing raw Authorization headers.
const MaxTokenLength = 1024

var (
	ErrEmailExists        = errors.New("email already registered")
	ErrUsernameExists     = errors.New("username already registered")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrTokenNotFound      = errors.New("token not found")
	ErrTokenExpired       = errors.New("token expired")
	ErrTokenConsumed      = errors.New("token already used")
	ErrTokenGeneration    = errors.New("token generation failed")
	ErrSessionNotFound    = errors.New("session not found")
	ErrEmailNotVerified   = errors.New("email not verified")
	ErrInvalidInput       = errors.New("invalid input")
	ErrDeadline           = errors.New("operation timed out")
)
