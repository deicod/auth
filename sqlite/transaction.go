package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/deicod/auth/core"
	"github.com/deicod/auth/core/services"
	"github.com/deicod/auth/sqlite/repos"
)

// Transaction exposes management and policy-checked token completion operations
// bound to a *sql.Tx. It reuses the service's crypto configuration.
type Transaction = services.Transaction

// WithTx binds auth to an already-started transaction in the migrated auth
// database. It reserves SQLite's writer before auth reads or policy checks using
// a zero-row write. Binding a stale read transaction may fail with SQLITE_BUSY
// or SQLITE_BUSY_SNAPSHOT; retry the entire transaction, never just the operation.
// The caller owns commit/rollback and must roll back on any operation error.
func (s *Service) WithTx(ctx context.Context, tx *sql.Tx) (*Transaction, error) {
	if tx == nil {
		return nil, fmt.Errorf("%w: transaction is required", core.ErrInvalidInput)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET id = id WHERE 0`); err != nil {
		return nil, err
	}
	return services.NewTransaction(s.AuthService, newStores(tx, s.timeout)), nil
}

// InTx runs fn with auth and consumer SQL on the same transaction. An error or
// panic rolls back; success commits. fn must not commit, roll back or retain tx.
// The callback is never automatically retried. Configure a SQLite busy timeout
// to allow contending writers to wait for the preceding unit of work.
func (s *Service) InTx(ctx context.Context, fn func(*sql.Tx, *Transaction) error) error {
	if fn == nil {
		return fmt.Errorf("%w: transaction callback is required", core.ErrInvalidInput)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	bound, err := s.WithTx(ctx, tx)
	if err != nil {
		return err
	}
	if err := fn(tx, bound); err != nil {
		return err
	}
	return tx.Commit()
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
