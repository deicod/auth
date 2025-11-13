package core

import "errors"

var (
	ErrEmailExists        = errors.New("email already registered")
	ErrUsernameExists     = errors.New("username already registered")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrTokenNotFound      = errors.New("token not found")
	ErrTokenExpired       = errors.New("token expired")
	ErrTokenConsumed      = errors.New("token already used")
	ErrSessionNotFound    = errors.New("session not found")
	ErrEmailNotVerified   = errors.New("email not verified")
	ErrInvalidInput       = errors.New("invalid input")
	ErrDeadline           = errors.New("operation timed out")
)
