package pgx

import (
	"context"
	"fmt"
	"time"

	"github.com/deicod/auth/core"
	"github.com/deicod/auth/core/services"
	"github.com/deicod/auth/pgx/repos"
	"github.com/jackc/pgx/v5"
)

// Transaction exposes management and policy-checked token completion operations
// bound to a pgx.Tx. It reuses the service's crypto configuration.
type Transaction = services.Transaction

// WithTx binds auth to an already-started transaction in the migrated auth
// database/schema. The caller owns commit/rollback and must roll back on any
// operation error. The returned operations must not outlive tx.
func (s *Service) WithTx(ctx context.Context, tx pgx.Tx) (*Transaction, error) {
	if tx == nil {
		return nil, fmt.Errorf("%w: transaction is required", core.ErrInvalidInput)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return services.NewTransaction(s.AuthService, newStores(tx, s.timeout)), nil
}

// InTx runs fn with auth and consumer SQL on the same transaction. An error or
// panic rolls back; success commits. fn must not commit, roll back or retain tx.
// The callback is never automatically retried.
func (s *Service) InTx(ctx context.Context, fn func(pgx.Tx, *Transaction) error) error {
	if fn == nil {
		return fmt.Errorf("%w: transaction callback is required", core.ErrInvalidInput)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(rollbackCtx)
	}()
	bound, err := s.WithTx(ctx, tx)
	if err != nil {
		return err
	}
	if err := fn(tx, bound); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func newStores(db repos.DBTX, timeout time.Duration) services.Stores {
	return services.Stores{
		Users:          newUserStore(repos.NewUserRepositoryWithDB(db, timeout)),
		Sessions:       newSessionStore(repos.NewSessionRepositoryWithDB(db, timeout)),
		Verifications:  newVerificationStore(repos.NewVerificationRepositoryWithDB(db, timeout)),
		PasswordResets: newPasswordResetStore(repos.NewPasswordResetRepositoryWithDB(db, timeout)),
		EmailChanges:   newEmailChangeStore(repos.NewEmailChangeRepositoryWithDB(db, timeout)),
	}
}
