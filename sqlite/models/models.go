package models

import "time"

// User represents a user record in the SQLite database.
type User struct {
	ID           string
	Email        string
	Username     string
	PasswordHash string
	Role         string
	IsVerified   bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
	VerifiedAt   *time.Time
	LastLoginAt  *time.Time
}

// Session represents a user session in the SQLite database.
type Session struct {
	ID        string
	UserID    string
	TokenHash string
	UserAgent string
	IP        string
	ExpiresAt time.Time
	CreatedAt time.Time
	Revoked   bool
}

// VerificationToken represents an email verification token.
type VerificationToken struct {
	ID         string
	UserID     string
	TokenHash  string
	ExpiresAt  time.Time
	CreatedAt  time.Time
	ConsumedAt *time.Time
}

// PasswordReset represents a password reset token.
type PasswordReset struct {
	ID         string
	UserID     string
	TokenHash  string
	ExpiresAt  time.Time
	CreatedAt  time.Time
	ConsumedAt *time.Time
}

// EmailChange represents an email change request.
type EmailChange struct {
	ID         string
	UserID     string
	NewEmail   string
	TokenHash  string
	ExpiresAt  time.Time
	CreatedAt  time.Time
	ConsumedAt *time.Time
}
