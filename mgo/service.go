package mgo

import (
	"context"
	"errors"
	"time"

	"github.com/deicod/auth/config"
	"github.com/deicod/auth/core/services"
	"github.com/deicod/auth/email"
	"github.com/deicod/auth/internal/security"
	"github.com/deicod/auth/mgo/repos"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type Service struct {
	client *mongo.Client
	*services.AuthService
	*services.ManagementService
	mongoCfg Config
}

func NewService(ctx context.Context, cfg ServiceConfig) (*Service, error) {
	return NewServiceWithMailer(ctx, cfg, nil)
}

// NewServiceWithMailer creates a service using mailer when non-nil. A nil mailer
// preserves the built-in SMTP/NopSender behavior configured through cfg.Email.
func NewServiceWithMailer(ctx context.Context, cfg ServiceConfig, mailer email.Sender) (*Service, error) {
	if cfg.Mongo.URI == "" {
		return nil, errors.New("mongo URI is required")
	}
	if cfg.Mongo.Database == "" {
		return nil, errors.New("mongo database is required")
	}

	client, err := mongo.Connect(options.Client().ApplyURI(cfg.Mongo.URI))
	if err != nil {
		return nil, err
	}

	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(ctx)
		return nil, err
	}

	timeout := cfg.Mongo.OperationTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
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

	mongoCfg := cfg.Mongo
	if mongoCfg.UsersCollection == "" {
		mongoCfg.UsersCollection = "users"
	}
	if mongoCfg.SessionsCollection == "" {
		mongoCfg.SessionsCollection = "sessions"
	}
	if mongoCfg.VerificationCollection == "" {
		mongoCfg.VerificationCollection = "email_verifications"
	}
	if mongoCfg.PasswordResetCollection == "" {
		mongoCfg.PasswordResetCollection = "password_resets"
	}
	if mongoCfg.EmailChangeCollection == "" {
		mongoCfg.EmailChangeCollection = "email_changes"
	}

	db := client.Database(mongoCfg.Database)
	if err := ensureIndexes(ctx, db, mongoCfg); err != nil {
		_ = client.Disconnect(ctx)
		return nil, err
	}

	if mailer == nil {
		mailer = email.Sender(email.NopSender{})
		if cfg.Email.Host != "" {
			mailer = email.NewMailer(cfg.Email)
		}
	}

	mongoCfg.OperationTimeout = timeout
	stores := newStores(db, mongoCfg)

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
		_ = client.Disconnect(ctx)
		return nil, err
	}

	return &Service{client: client, AuthService: logic, ManagementService: services.NewManagementService(logic), mongoCfg: mongoCfg}, nil
}

func newStores(db *mongo.Database, cfg Config) services.Stores {
	return services.Stores{
		Users:          newUserStore(repos.NewUserRepository(db.Collection(cfg.UsersCollection), cfg.OperationTimeout)),
		Sessions:       newSessionStore(repos.NewSessionRepository(db.Collection(cfg.SessionsCollection), cfg.OperationTimeout)),
		Verifications:  newVerificationStore(repos.NewVerificationRepository(db.Collection(cfg.VerificationCollection), cfg.OperationTimeout)),
		PasswordResets: newPasswordResetStore(repos.NewPasswordResetRepository(db.Collection(cfg.PasswordResetCollection), cfg.OperationTimeout)),
		EmailChanges:   newEmailChangeStore(repos.NewEmailChangeRepository(db.Collection(cfg.EmailChangeCollection), cfg.OperationTimeout)),
	}
}

func (s *Service) Close(ctx context.Context) error {
	if s.client == nil {
		return nil
	}
	return s.client.Disconnect(ctx)
}
