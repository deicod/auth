package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"github.com/deicod/auth/config"
	"github.com/deicod/auth/core/services"
	"github.com/deicod/auth/email"
	"github.com/deicod/auth/internal/security"
	"github.com/deicod/auth/sqlite/repos"
	_ "modernc.org/sqlite"
)

// Service wraps an AuthService with a SQLite database connection.
type Service struct {
	db *sql.DB
	*services.AuthService
}

// NewService creates a new SQLite-backed auth service.
func NewService(ctx context.Context, cfg ServiceConfig) (*Service, error) {
	if cfg.Sqlite.DSN == "" {
		return nil, errors.New("sqlite DSN is required")
	}

	db, err := sql.Open("sqlite", cfg.Sqlite.DSN)
	if err != nil {
		return nil, err
	}

	// Configure connection pool
	if cfg.Sqlite.MaxOpenConns > 0 {
		db.SetMaxOpenConns(cfg.Sqlite.MaxOpenConns)
	}
	if cfg.Sqlite.MaxIdleConns > 0 {
		db.SetMaxIdleConns(cfg.Sqlite.MaxIdleConns)
	}
	if cfg.Sqlite.ConnMaxLifetime > 0 {
		db.SetConnMaxLifetime(cfg.Sqlite.ConnMaxLifetime)
	}

	// Verify connection
	if err := db.PingContext(ctx); err != nil {
		closeErr := db.Close()
		if closeErr != nil {
			return nil, errors.Join(err, closeErr)
		}
		return nil, err
	}

	// Apply migrations
	if err := applyMigrations(ctx, db); err != nil {
		closeErr := db.Close()
		if closeErr != nil {
			return nil, errors.Join(err, closeErr)
		}
		return nil, err
	}

	// Set default session config
	sessionCfg := cfg.Session
	if sessionCfg.Length <= 0 {
		sessionCfg.Length = DefaultSessionLength
	}

	// Set default token config
	tokenCfg := cfg.Tokens
	if tokenCfg.VerificationTTL <= 0 {
		tokenCfg.VerificationTTL = DefaultVerificationTTL
	}
	if tokenCfg.ResetTTL <= 0 {
		tokenCfg.ResetTTL = DefaultResetTTL
	}
	if tokenCfg.EmailChangeTTL <= 0 {
		tokenCfg.EmailChangeTTL = DefaultEmailChangeTTL
	}

	// Set default Argon2 config
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

	timeout := cfg.Sqlite.OperationTimeout
	if timeout <= 0 {
		timeout = DefaultOperationTimeout
	}

	// Create mailer
	mailer := email.Sender(email.NopSender{})
	if cfg.Email.Host != "" {
		mailer = email.NewMailer(cfg.Email)
	}

	// Create repositories
	usersRepo := repos.NewUserRepository(db, timeout)
	sessionsRepo := repos.NewSessionRepository(db, timeout)
	verificationsRepo := repos.NewVerificationRepository(db, timeout)
	resetsRepo := repos.NewPasswordResetRepository(db, timeout)
	emailChangesRepo := repos.NewEmailChangeRepository(db, timeout)

	// Create stores
	stores := services.Stores{
		Users:          newUserStore(usersRepo),
		Sessions:       newSessionStore(sessionsRepo),
		Verifications:  newVerificationStore(verificationsRepo),
		PasswordResets: newPasswordResetStore(resetsRepo),
		EmailChanges:   newEmailChangeStore(emailChangesRepo),
	}

	// Create auth service
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
		closeErr := db.Close()
		if closeErr != nil {
			return nil, errors.Join(err, closeErr)
		}
		return nil, err
	}

	return &Service{db: db, AuthService: logic}, nil
}

// Close closes the database connection.
func (s *Service) Close(context.Context) error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
