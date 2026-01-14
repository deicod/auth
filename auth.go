// Package auth is the main entry point for the authentication service.
// It defines the Service interface, configuration, and factory methods
// to instantiate the service with different backends (Mongo, Postgres, SQLite).
package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/deicod/auth/config"
	"github.com/deicod/auth/core"
	"github.com/deicod/auth/mgo"
	pgxbackend "github.com/deicod/auth/pgx"
	sqlitebackend "github.com/deicod/auth/sqlite"
)

// Service defines the core authentication and user management operations.
// It is the primary entry point for the auth package and is implementation
// agnostic, supported by various backends (Mongo, Postgres, SQLite).
type Service interface {
	// Register creates a new user account, a session, and returns an access token.
	// It returns ErrEmailExists or ErrUsernameExists if logic fails.
	Register(ctx context.Context, cmd core.RegisterCommand) (core.AuthResult, error)

	// Login authenticates a user by email and password, returning a new session.
	// It returns ErrInvalidCredentials if authentication fails.
	Login(ctx context.Context, cmd core.LoginCommand) (core.AuthResult, error)

	// VerifyEmail validates a verification token and marks the user as verified.
	// It returns ErrTokenExpired or ErrTokenInvalid if the token is not valid.
	VerifyEmail(ctx context.Context, cmd core.VerifyEmailCommand) (core.VerifyEmailResult, error)

	// ForgotPassword initiates the password reset flow by sending an email (if configured).
	// It returns nil even if the email is not found to prevent user enumeration.
	ForgotPassword(ctx context.Context, cmd core.ForgotPasswordCommand) error

	// ResetPassword completes the password reset flow using a valid token.
	// It invalidates all existing sessions for the user.
	ResetPassword(ctx context.Context, cmd core.ResetPasswordCommand) (core.UserPublic, error)

	// InitiateEmailChange starts the process of changing a user's email address.
	// It requires the current password for security and sends a confirmation email.
	InitiateEmailChange(ctx context.Context, cmd core.ChangeEmailCommand) error

	// ConfirmEmailChange finalizes the email change using a token sent to the new address.
	ConfirmEmailChange(ctx context.Context, cmd core.ConfirmEmailChangeCommand) (core.ChangeEmailResult, error)

	// AuthenticateSession validates a bearer token and returns the associated user and session.
	// It returns ErrSessionNotFound or ErrSessionExpired if valid.
	AuthenticateSession(ctx context.Context, token string) (core.UserPublic, core.SessionPublic, error)

	// Logout invalidates the session associated with the given token.
	Logout(ctx context.Context, token string) error
}

// Backend identifies the persistence layer implementation.
type Backend string

const (
	// BackendMongo uses the official MongoDB driver.
	BackendMongo Backend = "mongo"
	// BackendPostgres uses pgx with a connection pool.
	BackendPostgres Backend = "postgres"
	// BackendSQLite uses go-sqlite3 with CGO.
	BackendSQLite Backend = "sqlite"
)

// Config holds all configuration for the auth service.
// It aggregates backend-specific configs and common policies like session length.
type Config struct {
	// Backend selects the database implementation to use.
	Backend Backend

	// Mongo configuration (required if Backend is BackendMongo).
	Mongo *mgo.Config
	// Pgx configuration (required if Backend is BackendPostgres).
	Pgx *pgxbackend.Config
	// Sqlite configuration (required if Backend is BackendSQLite).
	Sqlite *sqlitebackend.Config

	// Session policy (lifetime, etc.).
	Session config.Session
	// Tokens policy (TTLs for verification/reset tokens).
	Tokens config.Tokens
	// Argon2 hashing parameters.
	Argon2 config.Argon2
	// Email transport configuration.
	Email config.Mail
}

// DefaultConfig returns a configuration with sensible defaults.
// Be sure to set the specific backend config (e.g. Mongo.URI or Pgx.DSN).
func DefaultConfig() Config {
	return Config{
		Backend: BackendMongo,
		Mongo:   func() *mgo.Config { cfg := mgo.DefaultConfig(); return &cfg }(),
		Pgx:     func() *pgxbackend.Config { cfg := pgxbackend.DefaultConfig(); return &cfg }(),
		Sqlite:  func() *sqlitebackend.Config { cfg := sqlitebackend.DefaultConfig(); return &cfg }(),
		Session: config.DefaultSession(),
		Tokens:  config.DefaultTokens(),
		Argon2:  config.DefaultArgon2(),
		Email:   config.DefaultMail(),
	}
}

// NewService initializes the auth service with the chosen backend and configuration.
// It returns an error if the selected backend's config is missing.
func NewService(ctx context.Context, cfg Config) (Service, error) {
	switch cfg.Backend {
	case BackendMongo:
		if cfg.Mongo == nil {
			return nil, errors.New("mongo config is required")
		}
		return mgo.NewService(ctx, mgo.ServiceConfig{
			Mongo:   *cfg.Mongo,
			Session: cfg.Session,
			Tokens:  cfg.Tokens,
			Argon2:  cfg.Argon2,
			Email:   cfg.Email,
		})
	case BackendPostgres:
		if cfg.Pgx == nil {
			return nil, errors.New("pgx config is required")
		}
		return pgxbackend.NewService(ctx, pgxbackend.ServiceConfig{
			Pgx:     *cfg.Pgx,
			Session: cfg.Session,
			Tokens:  cfg.Tokens,
			Argon2:  cfg.Argon2,
			Email:   cfg.Email,
		})
	case BackendSQLite:
		if cfg.Sqlite == nil {
			return nil, errors.New("sqlite config is required")
		}
		return sqlitebackend.NewService(ctx, sqlitebackend.ServiceConfig{
			Sqlite:  *cfg.Sqlite,
			Session: cfg.Session,
			Tokens:  cfg.Tokens,
			Argon2:  cfg.Argon2,
			Email:   cfg.Email,
		})
	default:
		return nil, fmt.Errorf("unsupported backend %q", cfg.Backend)
	}
}
