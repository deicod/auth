package core

import "time"

// ID represents an opaque identifier that can be backed by ObjectIDs, UUIDs, etc.
type ID string

// Role defines the authorization level of a user.
type Role string

const (
	// RoleUser is the default role for registered users.
	RoleUser Role = "user"
	// RoleAdmin grants administrative privileges.
	RoleAdmin Role = "admin"
)

// User represents a registered identity in the system.
type User struct {
	ID           ID
	Email        string
	Username     string
	PasswordHash string
	Role         Role
	IsVerified   bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
	// VerifiedAt is nil if the user has not verified their email.
	VerifiedAt *time.Time
	// LastLoginAt is updated on successful login.
	LastLoginAt *time.Time
}

// Session represents an active user session.
type Session struct {
	ID     ID
	UserID ID
	// TokenHash is the secure hash of the bearer token.
	TokenHash string
	UserAgent string
	IP        string
	ExpiresAt time.Time
	CreatedAt time.Time
	// Revoked is true if the session was explicitly killed (e.g. at logout).
	Revoked bool
}

// VerificationToken tracks email verification attempts.
type VerificationToken struct {
	ID        ID
	UserID    ID
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
	// ConsumedAt is set when the token is successfully used.
	ConsumedAt *time.Time
}

// PasswordResetToken tracks forgotten password flows.
type PasswordResetToken struct {
	ID        ID
	UserID    ID
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
	// ConsumedAt prevents replay attacks.
	ConsumedAt *time.Time
}

// EmailChangeRequest tracks the two-step email change process.
type EmailChangeRequest struct {
	ID        ID
	UserID    ID
	NewEmail  string
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
	// ConsumedAt prevents double confirmations.
	ConsumedAt *time.Time
}
