package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID           uuid.UUID
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

type Session struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash string
	UserAgent string
	IP        string
	ExpiresAt time.Time
	CreatedAt time.Time
	Revoked   bool
}

type VerificationToken struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TokenHash  string
	ExpiresAt  time.Time
	CreatedAt  time.Time
	ConsumedAt *time.Time
}

type PasswordReset struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TokenHash  string
	ExpiresAt  time.Time
	CreatedAt  time.Time
	ConsumedAt *time.Time
}

type EmailChange struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	NewEmail   string
	TokenHash  string
	ExpiresAt  time.Time
	CreatedAt  time.Time
	ConsumedAt *time.Time
}
