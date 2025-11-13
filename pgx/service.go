package pgx

import (
	"context"
	"errors"
	"time"

	"github.com/deicod/auth/config"
	"github.com/deicod/auth/core/services"
	"github.com/deicod/auth/email"
	"github.com/deicod/auth/internal/security"
	"github.com/deicod/auth/pgx/repos"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Service struct {
	pool *pgxpool.Pool
	*services.AuthService
}

func NewService(ctx context.Context, cfg ServiceConfig) (*Service, error) {
	if cfg.Pgx.DSN == "" {
		return nil, errors.New("pgx DSN is required")
	}

	poolCfg, err := pgxpool.ParseConfig(cfg.Pgx.DSN)
	if err != nil {
		return nil, err
	}
	if cfg.Pgx.MaxConns > 0 {
		poolCfg.MaxConns = cfg.Pgx.MaxConns
	}
	if cfg.Pgx.MinConns > 0 {
		poolCfg.MinConns = cfg.Pgx.MinConns
	}
	if cfg.Pgx.HealthCheckInterval > 0 {
		poolCfg.HealthCheckPeriod = cfg.Pgx.HealthCheckInterval
	}
	if cfg.Pgx.MaxConnLifetime > 0 {
		poolCfg.MaxConnLifetime = cfg.Pgx.MaxConnLifetime
	}
	if cfg.Pgx.MaxConnIdleTime > 0 {
		poolCfg.MaxConnIdleTime = cfg.Pgx.MaxConnIdleTime
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	if err := applyMigrations(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}

	sessionCfg := cfg.Session
	if sessionCfg.Length <= 0 {
		sessionCfg.Length = 30 * 24 * time.Hour
	}

	tokenCfg := cfg.Tokens
	if tokenCfg.VerificationTTL <= 0 {
		tokenCfg.VerificationTTL = 48 * time.Hour
	}
	if tokenCfg.ResetTTL <= 0 {
		tokenCfg.ResetTTL = time.Hour
	}
	if tokenCfg.EmailChangeTTL <= 0 {
		tokenCfg.EmailChangeTTL = 24 * time.Hour
	}

	argonCfg := cfg.Argon2
	defaultArgon := config.DefaultArgon2()
	if argonCfg.Time == 0 {
		argonCfg.Time = defaultArgon.Time
	}
	if argonCfg.Memory == 0 {
		argonCfg.Memory = defaultArgon.Memory
	}
	if argonCfg.Threads == 0 {
		argonCfg.Threads = defaultArgon.Threads
	}
	if argonCfg.KeyLen == 0 {
		argonCfg.KeyLen = defaultArgon.KeyLen
	}

	timeout := cfg.Pgx.OperationTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	mailer := email.Sender(email.NopSender{})
	if cfg.Email.Host != "" {
		mailer = email.NewMailer(cfg.Email)
	}

	usersRepo := repos.NewUserRepository(pool, timeout)
	sessionsRepo := repos.NewSessionRepository(pool, timeout)
	verificationsRepo := repos.NewVerificationRepository(pool, timeout)
	resetsRepo := repos.NewPasswordResetRepository(pool, timeout)
	emailChangesRepo := repos.NewEmailChangeRepository(pool, timeout)

	stores := services.Stores{
		Users:          newUserStore(usersRepo),
		Sessions:       newSessionStore(sessionsRepo),
		Verifications:  newVerificationStore(verificationsRepo),
		PasswordResets: newPasswordResetStore(resetsRepo),
		EmailChanges:   newEmailChangeStore(emailChangesRepo),
	}

	logic, err := services.New(services.Dependencies{
		Stores:         stores,
		Hasher:         security.NewPasswordHasher(argonCfg),
		SessionTokens:  security.NewTokenGenerator(48),
		TokenGenerator: security.NewTokenGenerator(32),
		SessionCfg:     sessionCfg,
		TokenCfg:       tokenCfg,
		Mailer:         mailer,
	})
	if err != nil {
		pool.Close()
		return nil, err
	}

	return &Service{pool: pool, AuthService: logic}, nil
}

func (s *Service) Close(context.Context) error {
	if s.pool != nil {
		s.pool.Close()
	}
	return nil
}
