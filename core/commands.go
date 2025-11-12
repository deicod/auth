package core

import "context"

// CommandContext is implemented by command structs that embed a context-aware
// base struct. It provides an optional hook for middleware to supply
// request-scoped data without threading it manually through every call.
type CommandContext interface {
	Context() context.Context
}

type RegisterCommand struct {
	Email     string
	Username  string
	Password  string
	UserAgent string
	IP        string
}

type LoginCommand struct {
	Email     string
	Password  string
	UserAgent string
	IP        string
}

type VerifyEmailCommand struct {
	Token string
}

type ForgotPasswordCommand struct {
	Email string
}

type ResetPasswordCommand struct {
	Token       string
	NewPassword string
}

type ChangeEmailCommand struct {
	UserID   ID
	Password string
	NewEmail string
}

type ConfirmEmailChangeCommand struct {
	Token string
}
