package auth

import (
	"context"
	"fmt"

	"github.com/deicod/auth/core"
	"github.com/deicod/auth/email"
	"github.com/deicod/auth/mgo"
	pgxbackend "github.com/deicod/auth/pgx"
	sqlitebackend "github.com/deicod/auth/sqlite"
)

// ManagementService adds optional capabilities without extending Service or
// requiring changes to existing external implementations and mocks. Management
// operations do not authorize the caller; applications enforce their own policy.
// For native transactions, use the backend service's WithTx/InTx API.
type ManagementService interface {
	Service
	VerifyPassword(ctx context.Context, userID core.ID, password string) error
	RevokeSessionsByUser(ctx context.Context, userID core.ID) error
	UpdateUsername(ctx context.Context, userID core.ID, username string) (core.UserPublic, error)
	UpdateRole(ctx context.Context, userID core.ID, role core.Role) (core.UserPublic, error)
	Close(context.Context) error
}

var (
	_ ManagementService = (*mgo.Service)(nil)
	_ ManagementService = (*pgxbackend.Service)(nil)
	_ ManagementService = (*sqlitebackend.Service)(nil)
)

// NewManagementService creates a service with additive management operations.
func NewManagementService(ctx context.Context, cfg Config) (ManagementService, error) {
	return NewManagementServiceWithMailer(ctx, cfg, nil)
}

// NewManagementServiceWithMailer also uses the supplied email sender. A nil
// sender preserves the built-in SMTP/NopSender behavior.
func NewManagementServiceWithMailer(ctx context.Context, cfg Config, mailer email.Sender) (ManagementService, error) {
	if cfg.Backend != BackendMongo && cfg.Backend != BackendPostgres && cfg.Backend != BackendSQLite {
		return nil, fmt.Errorf("%w: unsupported management backend %q", core.ErrInvalidInput, cfg.Backend)
	}
	svc, err := newService(ctx, cfg, mailer)
	if err != nil {
		return nil, err
	}
	return svc.(ManagementService), nil
}
