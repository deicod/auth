package services

import (
	"context"
	"time"

	"github.com/deicod/auth/config"
	"github.com/deicod/auth/core"
	"github.com/deicod/auth/email"
)

type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(encoded, password string) error
}

type TokenGenerator interface {
	Generate() (token string, hash string, err error)
}

type Stores struct {
	Users          UserStore
	Sessions       SessionStore
	Verifications  VerificationStore
	PasswordResets PasswordResetStore
	EmailChanges   EmailChangeStore
}

type Dependencies struct {
	Stores         Stores
	Hasher         PasswordHasher
	SessionTokens  TokenGenerator
	TokenGenerator TokenGenerator
	SessionCfg     config.Session
	TokenCfg       config.Tokens
	PasswordCfg    config.Password
	Mailer         email.Sender
}

type CreateUserParams struct {
	Email        string
	Username     string
	PasswordHash string
	Role         core.Role
	IsVerified   bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type CreateSessionParams struct {
	UserID    core.ID
	TokenHash string
	UserAgent string
	IP        string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type CreateVerificationParams struct {
	UserID    core.ID
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type CreatePasswordResetParams struct {
	UserID    core.ID
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type CreateEmailChangeParams struct {
	UserID    core.ID
	NewEmail  string
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type UserStore interface {
	Create(ctx context.Context, params CreateUserParams) (core.User, error)
	DeleteByID(ctx context.Context, id core.ID) error
	FindByEmail(ctx context.Context, email string) (core.User, error)
	FindByUsername(ctx context.Context, username string) (core.User, error)
	FindByID(ctx context.Context, id core.ID) (core.User, error)
	UpdateFields(ctx context.Context, id core.ID, fields map[string]interface{}) error
}

type SessionStore interface {
	Create(ctx context.Context, params CreateSessionParams) (core.Session, error)
	FindByTokenHash(ctx context.Context, hash string) (core.Session, error)
	Revoke(ctx context.Context, id core.ID) error
	RevokeByUser(ctx context.Context, userID core.ID) error
}

type VerificationStore interface {
	Create(ctx context.Context, params CreateVerificationParams) (core.VerificationToken, error)
	FindByHash(ctx context.Context, hash string) (core.VerificationToken, error)
	DeleteByID(ctx context.Context, id core.ID) error
	Consume(ctx context.Context, id core.ID, consumedAt time.Time) error
}

type PasswordResetStore interface {
	Create(ctx context.Context, params CreatePasswordResetParams) (core.PasswordResetToken, error)
	FindByHash(ctx context.Context, hash string) (core.PasswordResetToken, error)
	Consume(ctx context.Context, id core.ID, consumedAt time.Time) error
}

type EmailChangeStore interface {
	Create(ctx context.Context, params CreateEmailChangeParams) (core.EmailChangeRequest, error)
	FindByHash(ctx context.Context, hash string) (core.EmailChangeRequest, error)
	Consume(ctx context.Context, id core.ID, consumedAt time.Time) error
}
