package mgo

import (
	"context"
	"fmt"
	"time"

	"github.com/deicod/auth/core"
	"github.com/deicod/auth/core/services"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readconcern"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
)

// Transaction exposes synchronous auth operations in one native Mongo session
// transaction. Every call requires that session's active context. Create a new
// binding for every transaction attempt; do not retain or use it concurrently.
type Transaction struct {
	session *mongo.Session
	bound   *services.Transaction
}

// WithTx binds auth to the active session in ctx. The MongoDB v2 driver represents
// SessionContext as context.Context; use mongo.NewSessionContext or the context
// supplied by Session.WithTransaction. The session may belong to another client
// connected to the same migrated deployment. The caller owns commit/abort.
// Standalone servers return core.ErrTransactionsUnsupported, never a fallback.
func (s *Service) WithTx(ctx context.Context) (*Transaction, error) {
	session := mongo.SessionFromContext(ctx)
	if session == nil || !session.TransactionRunning() {
		return nil, core.ErrTransactionRequired
	}
	if err := checkTransactions(ctx, session.Client()); err != nil {
		return nil, err
	}
	db := session.Client().Database(s.mongoCfg.Database)
	return &Transaction{session: session, bound: services.NewTransaction(s.AuthService, newStores(db, s.mongoCfg))}, nil
}

// InTx uses native WithTransaction to commit or abort auth and consumer writes
// together. Both fn and any policies may be retried on transient errors. Use the
// callback context for ALL Mongo operations, propagate errors, and avoid external
// side effects. A panic aborts the transaction and is rethrown. Nested sessions
// are rejected. fn must not commit, abort or retain the session. Options override
// the snapshot/majority defaults.
func (s *Service) InTx(ctx context.Context, fn func(context.Context, *Transaction) error, opts ...options.Lister[options.TransactionOptions]) error {
	if fn == nil {
		return fmt.Errorf("%w: transaction callback is required", core.ErrInvalidInput)
	}
	if mongo.SessionFromContext(ctx) != nil {
		return fmt.Errorf("%w: InTx cannot replace an existing session", core.ErrTransactionRequired)
	}
	if err := checkTransactions(ctx, s.client); err != nil {
		return err
	}
	session, err := s.client.StartSession()
	if err != nil {
		return err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		session.EndSession(cleanupCtx) // Also aborts an active transaction on panic.
	}()
	defaults := options.Transaction().SetReadConcern(readconcern.Snapshot()).SetWriteConcern(writeconcern.Majority())
	transactionOpts := append([]options.Lister[options.TransactionOptions]{defaults}, opts...)
	_, err = session.WithTransaction(ctx, func(txCtx context.Context) (any, error) {
		// Preflight ran before the session started. Each retry gets a fresh
		// binding, with no additional crypto or out-of-transaction DB work.
		bound := &Transaction{session: session, bound: services.NewTransaction(s.AuthService, newStores(s.client.Database(s.mongoCfg.Database), s.mongoCfg))}
		if err := fn(txCtx, bound); err != nil {
			return nil, err
		}
		return nil, bound.check(txCtx)
	}, transactionOpts...)
	return err
}

func checkTransactions(ctx context.Context, client *mongo.Client) error {
	var hello struct {
		SetName        string `bson:"setName"`
		Msg            string `bson:"msg"`
		MaxWireVersion int32  `bson:"maxWireVersion"`
		SessionTimeout *int64 `bson:"logicalSessionTimeoutMinutes"`
	}
	// hello is a topology check, explicitly outside any caller transaction.
	if err := client.Database("admin").RunCommand(mongo.NewSessionContext(ctx, nil), bson.D{{Key: "hello", Value: 1}}).Decode(&hello); err != nil {
		return err
	}
	if hello.SessionTimeout == nil || (hello.SetName == "" && hello.Msg != "isdbgrid") || hello.MaxWireVersion < 7 || (hello.Msg == "isdbgrid" && hello.MaxWireVersion < 8) {
		return core.ErrTransactionsUnsupported
	}
	return nil
}

func (t *Transaction) check(ctx context.Context) error {
	if t.session == nil || mongo.SessionFromContext(ctx) != t.session || !t.session.TransactionRunning() {
		return core.ErrTransactionRequired
	}
	return ctx.Err()
}

// A policy can execute native session operations. Recheck its transaction before
// returning to core so an accidental abort cannot turn the following writes into
// non-transactional operations on that session.
func (t *Transaction) checkedPolicy(policy core.MutationPolicy) core.MutationPolicy {
	return func(ctx context.Context, mutation core.Mutation) error {
		if policy != nil {
			if err := policy(ctx, mutation); err != nil {
				return err
			}
		}
		return t.check(ctx)
	}
}

// VerifyPassword checks the password without creating a session or writing timestamps.
func (t *Transaction) VerifyPassword(ctx context.Context, userID core.ID, password string) error {
	if err := t.check(ctx); err != nil {
		return err
	}
	return t.bound.VerifyPassword(ctx, userID, password)
}

// RevokeSessionsByUser idempotently revokes the user's sessions in this transaction.
func (t *Transaction) RevokeSessionsByUser(ctx context.Context, userID core.ID) error {
	if err := t.check(ctx); err != nil {
		return err
	}
	return t.bound.RevokeSessionsByUser(ctx, userID)
}

// UpdateUsername applies the shared registration rules and database race guard.
func (t *Transaction) UpdateUsername(ctx context.Context, userID core.ID, username string) (core.UserPublic, error) {
	if err := t.check(ctx); err != nil {
		return core.UserPublic{}, err
	}
	return t.bound.UpdateUsername(ctx, userID, username)
}

// UpdateRole changes an auth role; the caller enforces application authorization.
func (t *Transaction) UpdateRole(ctx context.Context, userID core.ID, role core.Role) (core.UserPublic, error) {
	if err := t.check(ctx); err != nil {
		return core.UserPublic{}, err
	}
	return t.bound.UpdateRole(ctx, userID, role)
}

// VerifyEmail checks policy before verification or token consumption. nil permits it.
func (t *Transaction) VerifyEmail(ctx context.Context, cmd core.VerifyEmailCommand, policy core.MutationPolicy) (core.VerifyEmailResult, error) {
	if err := t.check(ctx); err != nil {
		return core.VerifyEmailResult{}, err
	}
	return t.bound.VerifyEmail(ctx, cmd, t.checkedPolicy(policy))
}

// ResetPassword checks policy before password, session or token changes. nil permits it.
func (t *Transaction) ResetPassword(ctx context.Context, cmd core.ResetPasswordCommand, policy core.MutationPolicy) (core.UserPublic, error) {
	if err := t.check(ctx); err != nil {
		return core.UserPublic{}, err
	}
	return t.bound.ResetPassword(ctx, cmd, t.checkedPolicy(policy))
}

// ConfirmEmailChange checks policy before email or token changes. nil permits it.
func (t *Transaction) ConfirmEmailChange(ctx context.Context, cmd core.ConfirmEmailChangeCommand, policy core.MutationPolicy) (core.ChangeEmailResult, error) {
	if err := t.check(ctx); err != nil {
		return core.ChangeEmailResult{}, err
	}
	return t.bound.ConfirmEmailChange(ctx, cmd, t.checkedPolicy(policy))
}
