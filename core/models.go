package core

import "time"

// ID represents an opaque identifier that can be backed by ObjectIDs, UUIDs, etc.
type ID string

type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

type User struct {
	ID           ID
	Email        string
	Username     string
	PasswordHash string
	Role         Role
	IsVerified   bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
	VerifiedAt   *time.Time
	LastLoginAt  *time.Time
}

type Session struct {
	ID        ID
	UserID    ID
	TokenHash string
	UserAgent string
	IP        string
	ExpiresAt time.Time
	CreatedAt time.Time
	Revoked   bool
}

type VerificationToken struct {
	ID         ID
	UserID     ID
	TokenHash  string
	ExpiresAt  time.Time
	CreatedAt  time.Time
	ConsumedAt *time.Time
}

type PasswordResetToken struct {
	ID         ID
	UserID     ID
	TokenHash  string
	ExpiresAt  time.Time
	CreatedAt  time.Time
	ConsumedAt *time.Time
}

type EmailChangeRequest struct {
	ID         ID
	UserID     ID
	NewEmail   string
	TokenHash  string
	ExpiresAt  time.Time
	CreatedAt  time.Time
	ConsumedAt *time.Time
}
