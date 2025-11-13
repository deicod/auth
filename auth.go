package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/deicod/auth/config"
	"github.com/deicod/auth/core"
	"github.com/deicod/auth/mgo"
	pgxbackend "github.com/deicod/auth/pgx"
)

type Service interface {
	Register(ctx context.Context, cmd core.RegisterCommand) (core.AuthResult, error)
	Login(ctx context.Context, cmd core.LoginCommand) (core.AuthResult, error)
	VerifyEmail(ctx context.Context, cmd core.VerifyEmailCommand) (core.VerifyEmailResult, error)
	ForgotPassword(ctx context.Context, cmd core.ForgotPasswordCommand) error
	ResetPassword(ctx context.Context, cmd core.ResetPasswordCommand) (core.UserPublic, error)
	InitiateEmailChange(ctx context.Context, cmd core.ChangeEmailCommand) error
	ConfirmEmailChange(ctx context.Context, cmd core.ConfirmEmailChangeCommand) (core.ChangeEmailResult, error)
}

type Backend string

const (
	BackendMongo    Backend = "mongo"
	BackendPostgres Backend = "postgres"
)

type Config struct {
	Backend Backend
	Mongo   *mgo.Config
	Pgx     *pgxbackend.Config
	Session config.Session
	Tokens  config.Tokens
	Argon2  config.Argon2
	Email   config.Mail
}

func DefaultConfig() Config {
	return Config{
		Backend: BackendMongo,
		Mongo:   func() *mgo.Config { cfg := mgo.DefaultConfig(); return &cfg }(),
		Pgx:     func() *pgxbackend.Config { cfg := pgxbackend.DefaultConfig(); return &cfg }(),
		Session: config.DefaultSession(),
		Tokens:  config.DefaultTokens(),
		Argon2:  config.DefaultArgon2(),
		Email:   config.DefaultMail(),
	}
}

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
	default:
		return nil, fmt.Errorf("unsupported backend %q", cfg.Backend)
	}
}
