package mgo

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deicod/auth/config"
	"github.com/deicod/auth/core"
	"github.com/deicod/auth/core/services"
	"github.com/deicod/auth/internal/security"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// Coordinate completed real Mongo reads, without simulating database results.
// Both callers must observe the same unused token before either can proceed.
type resetReadBarrier struct {
	services.PasswordResetStore
	reads atomic.Int32
	ready chan struct{}
}

func (s *resetReadBarrier) FindByHash(ctx context.Context, hash string) (core.PasswordResetToken, error) {
	token, err := s.PasswordResetStore.FindByHash(ctx, hash)
	if err != nil || token.ConsumedAt != nil {
		return token, err
	}
	if s.reads.Add(1) == 2 {
		close(s.ready)
	}
	select {
	case <-s.ready:
		return token, nil
	case <-ctx.Done():
		return core.PasswordResetToken{}, ctx.Err()
	}
}

type resetUserWrites struct {
	services.UserStore
	passwords atomic.Int32
}

func (s *resetUserWrites) UpdateFields(ctx context.Context, id core.ID, fields map[string]interface{}) error {
	if _, ok := fields["password_hash"]; ok {
		s.passwords.Add(1)
	}
	return s.UserStore.UpdateFields(ctx, id, fields)
}

type resetSessionWrites struct {
	services.SessionStore
	revocations atomic.Int32
}

func (s *resetSessionWrites) RevokeByUser(ctx context.Context, id core.ID) error {
	s.revocations.Add(1)
	return s.SessionStore.RevokeByUser(ctx, id)
}

func TestMongoOrdinaryPasswordResetRace(t *testing.T) {
	for _, env := range []string{"AUTH_TEST_MONGO_URI", "AUTH_TEST_MONGO_STANDALONE_URI"} {
		t.Run(env, func(t *testing.T) {
			f := newMongoFixture(t, env)
			user, other := f.register(t), f.register(t)
			_, err := f.svc.Login(f.ctx, core.LoginCommand{Email: user.User.Email, Password: mongoPassword})
			mongoMust(t, err)
			token := f.seedToken(t, core.MutationResetPassword, user.User.ID)
			before, otherBefore := f.snapshot(t, f.ctx, user.User.ID), f.snapshot(t, f.ctx, other.User.ID)

			// Instrument real repositories so scheduling cannot hide a losing
			// caller's transient credential write behind the winner's final write.
			stores := newStores(f.db, f.cfg)
			reads := &resetReadBarrier{PasswordResetStore: stores.PasswordResets, ready: make(chan struct{})}
			users := &resetUserWrites{UserStore: stores.Users}
			sessions := &resetSessionWrites{SessionStore: stores.Sessions}
			stores.PasswordResets, stores.Users, stores.Sessions = reads, users, sessions
			logic, err := services.New(services.Dependencies{
				Stores:         stores,
				Hasher:         security.NewPasswordHasher(config.Argon2{Time: 1, Memory: 1024, Threads: 1, KeyLen: 32}),
				SessionTokens:  security.NewTokenGenerator(48),
				TokenGenerator: security.NewTokenGenerator(32),
			})
			mongoMust(t, err)
			f.svc.AuthService, f.svc.ManagementService = logic, services.NewManagementService(logic)

			ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
			defer cancel()
			passwords := []string{"first-new-password-123", "second-new-password-456"}
			type result struct {
				index int
				user  core.UserPublic
				err   error
			}
			results := make(chan result, 2)
			for i, password := range passwords {
				go func() {
					updated, err := f.svc.ResetPassword(ctx, core.ResetPasswordCommand{Token: token.raw, NewPassword: password})
					results <- result{index: i, user: updated, err: err}
				}()
			}
			a, b := <-results, <-results
			assertMongoRace(t, a.err, b.err, core.ErrTokenConsumed)
			if a.err != nil {
				a, b = b, a
			}
			if a.user.ID != user.User.ID || users.passwords.Load() != 1 || sessions.revocations.Load() != 1 {
				t.Fatalf("loser performed mutation: password writes=%d revocations=%d", users.passwords.Load(), sessions.revocations.Load())
			}
			mongoMust(t, f.svc.VerifyPassword(f.ctx, user.User.ID, passwords[a.index]))
			for _, password := range []string{passwords[b.index], mongoPassword} {
				if err := f.svc.VerifyPassword(f.ctx, user.User.ID, password); !errors.Is(err, core.ErrInvalidCredentials) {
					t.Fatalf("losing/old password accepted: %v", err)
				}
			}
			after := f.snapshot(t, f.ctx, user.User.ID)
			if after.ActiveSessions != 0 || after.Sessions != before.Sessions || !reflect.DeepEqual(after.User.LastLoginAt, before.User.LastLoginAt) {
				t.Fatal("reset did not revoke existing sessions without creating sessions or changing last login")
			}
			assertMongoSnapshot(t, otherBefore, f.snapshot(t, f.ctx, other.User.ID))
			tokenAfter := f.tokenDocument(t, f.ctx, token)
			if tokenAfter["consumed_at"] == nil {
				t.Fatal("winning reset did not consume token")
			}
			_, err = f.svc.ResetPassword(f.ctx, core.ResetPasswordCommand{Token: token.raw, NewPassword: "replayed-password-789"})
			if !errors.Is(err, core.ErrTokenConsumed) {
				t.Fatalf("replay: %v", err)
			}
			assertMongoSnapshot(t, after, f.snapshot(t, f.ctx, user.User.ID))
			f.assertTokenUnchanged(t, f.ctx, token, tokenAfter)
		})
	}
}

func setMongoValidator(t *testing.T, f *mongoFixture, collection string, validator bson.M) {
	t.Helper()
	mongoMust(t, f.db.RunCommand(f.ctx, bson.D{
		{Key: "collMod", Value: collection}, {Key: "validator", Value: validator},
		{Key: "validationLevel", Value: "strict"}, {Key: "validationAction", Value: "error"},
	}).Err())
}

func assertMongoValidationError(t *testing.T, err error) {
	t.Helper()
	var writeErr mongo.WriteException
	if !errors.As(err, &writeErr) || !writeErr.HasErrorCode(121) {
		t.Fatalf("expected real Mongo document validation failure, got %v", err)
	}
}

func TestMongoOrdinaryResetFailureBoundary(t *testing.T) {
	for _, env := range []string{"AUTH_TEST_MONGO_URI", "AUTH_TEST_MONGO_STANDALONE_URI"} {
		for _, reject := range []string{"consume", "password"} {
			t.Run(env+"/"+reject, func(t *testing.T) {
				f := newMongoFixture(t, env)
				user := f.register(t)
				token := f.seedToken(t, core.MutationResetPassword, user.User.ID)
				before, tokenBefore := f.snapshot(t, f.ctx, user.User.ID), f.tokenDocument(t, f.ctx, token)
				if reject == "consume" {
					setMongoValidator(t, f, token.coll, bson.M{"consumed_at": bson.M{"$exists": false}})
				} else {
					setMongoValidator(t, f, f.cfg.UsersCollection, bson.M{"password_hash": before.User.PasswordHash})
				}
				_, err := f.svc.ResetPassword(f.ctx, core.ResetPasswordCommand{Token: token.raw, NewPassword: mongoNewPassword})
				assertMongoValidationError(t, err)
				assertMongoSnapshot(t, before, f.snapshot(t, f.ctx, user.User.ID))
				if reject == "consume" {
					f.assertTokenUnchanged(t, f.ctx, token, tokenBefore)
					return
				}
				// Outside a transaction, failure after a successful claim is
				// fail-closed: do not make the spent token reusable.
				if f.tokenDocument(t, f.ctx, token)["consumed_at"] == nil {
					t.Fatal("credential failure released the already-claimed token")
				}
				_, err = f.svc.ResetPassword(f.ctx, core.ResetPasswordCommand{Token: token.raw, NewPassword: mongoNewPassword})
				if !errors.Is(err, core.ErrTokenConsumed) {
					t.Fatalf("failed reset token could be reused: %v", err)
				}
			})
		}
	}
}

func TestMongoResetCredentialFailureRollsBackClaim(t *testing.T) {
	f := newMongoFixture(t, "AUTH_TEST_MONGO_URI")
	user := f.register(t)
	token := f.seedToken(t, core.MutationResetPassword, user.User.ID)
	before, tokenBefore := f.snapshot(t, f.ctx, user.User.ID), f.tokenDocument(t, f.ctx, token)
	mongoMust(t, f.db.CreateCollection(f.ctx, "consumer"))
	setMongoValidator(t, f, f.cfg.UsersCollection, bson.M{"password_hash": before.User.PasswordHash})
	err := f.svc.InTx(f.ctx, func(ctx context.Context, tx *Transaction) error {
		if err := f.insertConsumer(ctx, user.User.ID); err != nil {
			return err
		}
		_, err := tx.ResetPassword(ctx, core.ResetPasswordCommand{Token: token.raw, NewPassword: mongoNewPassword}, nil)
		return err
	})
	assertMongoValidationError(t, err)
	assertMongoSnapshot(t, before, f.snapshot(t, f.ctx, user.User.ID))
	f.assertTokenUnchanged(t, f.ctx, token, tokenBefore)
	if f.consumerCount(t, "consumer", user.User.ID) != 0 {
		t.Fatal("consumer write survived the failed reset transaction")
	}
	setMongoValidator(t, f, f.cfg.UsersCollection, bson.M{})
	mongoMust(t, f.svc.InTx(f.ctx, func(ctx context.Context, tx *Transaction) error {
		_, err := tx.ResetPassword(ctx, core.ResetPasswordCommand{Token: token.raw, NewPassword: mongoNewPassword}, nil)
		return err
	}))
	f.assertCompleted(t, user, token, before)
}
