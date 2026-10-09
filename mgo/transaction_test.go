package mgo

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deicod/auth/core"
	"github.com/deicod/auth/internal/security"
	"github.com/deicod/auth/mgo/models"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

var mongoMutationKinds = []core.MutationKind{core.MutationVerifyEmail, core.MutationResetPassword, core.MutationConfirmEmailChange}

const mongoNewPassword = "changed-password-456"

type mongoToken struct {
	kind             core.MutationKind
	id               bson.ObjectID
	userID           core.ID
	raw, coll, email string
}

func (f *mongoFixture) seedToken(t *testing.T, kind core.MutationKind, userID core.ID) mongoToken {
	t.Helper()
	raw, hash, err := security.NewTokenGenerator(32).Generate()
	mongoMust(t, err)
	token := mongoToken{kind: kind, id: bson.NewObjectID(), userID: userID, raw: raw, email: bson.NewObjectID().Hex() + "@example.com"}
	oid, now := mongoID(t, userID), time.Now().UTC()
	var document any
	switch kind {
	case core.MutationVerifyEmail:
		token.coll = f.cfg.VerificationCollection
		document = models.VerificationToken{ID: token.id, UserID: oid, TokenHash: hash, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	case core.MutationResetPassword:
		token.coll = f.cfg.PasswordResetCollection
		document = models.PasswordReset{ID: token.id, UserID: oid, TokenHash: hash, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	case core.MutationConfirmEmailChange:
		token.coll = f.cfg.EmailChangeCollection
		document = models.EmailChange{ID: token.id, UserID: oid, TokenHash: hash, NewEmail: token.email, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	default:
		t.Fatalf("unexpected mutation %q", kind)
	}
	_, err = f.db.Collection(token.coll).InsertOne(f.ctx, document)
	mongoMust(t, err)
	return token
}

func (token mongoToken) complete(ctx context.Context, tx *Transaction, policy core.MutationPolicy) (core.UserPublic, error) {
	switch token.kind {
	case core.MutationVerifyEmail:
		result, err := tx.VerifyEmail(ctx, core.VerifyEmailCommand{Token: token.raw}, policy)
		return result.User, err
	case core.MutationResetPassword:
		return tx.ResetPassword(ctx, core.ResetPasswordCommand{Token: token.raw, NewPassword: mongoNewPassword}, policy)
	default:
		result, err := tx.ConfirmEmailChange(ctx, core.ConfirmEmailChangeCommand{Token: token.raw}, policy)
		return result.User, err
	}
}

func (f *mongoFixture) tokenDocument(t *testing.T, ctx context.Context, token mongoToken) bson.M {
	t.Helper()
	var doc bson.M
	mongoMust(t, f.database(ctx).Collection(token.coll).FindOne(ctx, bson.M{"_id": token.id}).Decode(&doc))
	return doc
}

func (f *mongoFixture) assertTokenUnchanged(t *testing.T, ctx context.Context, token mongoToken, before bson.M) {
	t.Helper()
	if !reflect.DeepEqual(before, f.tokenDocument(t, ctx, token)) {
		t.Fatal("token changed before authorization or survived rollback")
	}
}

func TestMongoTokenTransactionPolicyAndAtomicity(t *testing.T) {
	f := newMongoFixture(t, "AUTH_TEST_MONGO_URI")
	mongoMust(t, f.db.CreateCollection(f.ctx, "consumer"))
	mongoMust(t, f.db.CreateCollection(f.ctx, "controls"))
	for _, kind := range mongoMutationKinds {
		t.Run(string(kind), func(t *testing.T) {
			user := f.register(t)
			token := f.seedToken(t, kind, user.User.ID)
			before, tokenBefore := f.snapshot(t, f.ctx, user.User.ID), f.tokenDocument(t, f.ctx, token)
			_, err := f.db.Collection("controls").InsertOne(f.ctx, bson.M{"_id": mongoID(t, user.User.ID), "revision": 0})
			mongoMust(t, err)
			denied, aborted := errors.New("consumer policy denied"), errors.New("later consumer failure")
			for _, outcome := range []string{"deny", "rollback", "commit"} {
				t.Run(outcome, func(t *testing.T) {
					called := 0
					err := f.svc.InTx(f.ctx, func(ctx context.Context, tx *Transaction) error {
						if err := f.insertConsumer(ctx, user.User.ID); err != nil {
							return err
						}
						policy := func(policyCtx context.Context, mutation core.Mutation) error {
							called++
							if mongo.SessionFromContext(policyCtx) != mongo.SessionFromContext(ctx) || mutation != (core.Mutation{Kind: kind, UserID: user.User.ID}) {
								t.Fatal("policy did not receive identified user and native transaction context")
							}
							// Inspect within the same transaction: a later rollback must
							// not disguise credential/session/token writes before policy.
							assertMongoSnapshot(t, before, f.snapshot(t, policyCtx, user.User.ID))
							f.assertTokenUnchanged(t, policyCtx, token, tokenBefore)
							var control bson.M
							err := f.database(policyCtx).Collection("controls").FindOneAndUpdate(policyCtx,
								bson.M{"_id": mongoID(t, mutation.UserID)}, bson.M{"$inc": bson.M{"revision": 1}}).Decode(&control)
							if err != nil {
								return err
							}
							if outcome == "deny" {
								return denied
							}
							return nil
						}
						result, err := token.complete(ctx, tx, policy)
						if err != nil {
							return err
						}
						if result.ID != user.User.ID {
							t.Fatal("wrong result user")
						}
						if outcome == "rollback" {
							return aborted
						}
						return nil
					})
					if called != 1 {
						t.Fatalf("policy called %d times", called)
					}
					var control struct{ Revision int }
					mongoMust(t, f.db.Collection("controls").FindOne(f.ctx, bson.M{"_id": mongoID(t, user.User.ID)}).Decode(&control))
					if outcome == "commit" {
						mongoMust(t, err)
						f.assertCompleted(t, user, token, before)
						if control.Revision != 1 || f.consumerCount(t, "consumer", user.User.ID) != 1 {
							t.Fatal("consumer policy and data did not commit with auth")
						}
						return
					}
					want := denied
					if outcome == "rollback" {
						want = aborted
					}
					if !errors.Is(err, want) {
						t.Fatalf("expected %v, got %v", want, err)
					}
					assertMongoSnapshot(t, before, f.snapshot(t, f.ctx, user.User.ID))
					f.assertTokenUnchanged(t, f.ctx, token, tokenBefore)
					if control.Revision != 0 || f.consumerCount(t, "consumer", user.User.ID) != 0 {
						t.Fatal("consumer policy/data survived denial or callback error")
					}
				})
			}
			// A replay is rejected before a consumer policy can run.
			err = f.svc.InTx(f.ctx, func(ctx context.Context, tx *Transaction) error {
				_, err := token.complete(ctx, tx, func(context.Context, core.Mutation) error {
					t.Fatal("policy ran for consumed token")
					return nil
				})
				return err
			})
			if !errors.Is(err, core.ErrTokenConsumed) {
				t.Fatalf("replay: %v", err)
			}
		})
	}
}

func (f *mongoFixture) assertCompleted(t *testing.T, user core.AuthResult, token mongoToken, before mongoSnapshot) {
	t.Helper()
	after := f.snapshot(t, f.ctx, user.User.ID)
	if f.tokenDocument(t, f.ctx, token)["consumed_at"] == nil {
		t.Fatal("token was not consumed")
	}
	if !reflect.DeepEqual(after.User.LastLoginAt, before.User.LastLoginAt) || after.Sessions != before.Sessions {
		t.Fatal("token completion changed login timestamp or created a session")
	}
	switch token.kind {
	case core.MutationResetPassword:
		if after.ActiveSessions != 0 || after.User.PasswordHash == before.User.PasswordHash {
			t.Fatal("reset did not update password and revoke sessions")
		}
		mongoMust(t, f.svc.VerifyPassword(f.ctx, user.User.ID, mongoNewPassword))
		if err := f.svc.VerifyPassword(f.ctx, user.User.ID, mongoPassword); !errors.Is(err, core.ErrInvalidCredentials) {
			t.Fatalf("old password accepted after reset: %v", err)
		}
	default:
		if !after.User.IsVerified || after.User.VerifiedAt == nil || after.ActiveSessions != before.ActiveSessions || after.User.PasswordHash != before.User.PasswordHash {
			t.Fatal("verification/email mutation has wrong effects")
		}
		if token.kind == core.MutationConfirmEmailChange && after.User.Email != token.email {
			t.Fatal("email not updated")
		}
	}
}

func TestMongoConcurrentTokenConsumption(t *testing.T) {
	f := newMongoFixture(t, "AUTH_TEST_MONGO_URI")
	for _, kind := range mongoMutationKinds {
		t.Run(string(kind), func(t *testing.T) {
			user := f.register(t)
			token := f.seedToken(t, kind, user.User.ID)
			before := f.snapshot(t, f.ctx, user.User.ID)
			var arrivals, attempts atomic.Int32
			ready, results := make(chan struct{}), make(chan error, 2)
			for range 2 {
				go func() {
					results <- f.svc.InTx(f.ctx, func(ctx context.Context, tx *Transaction) error {
						attempts.Add(1)
						_, err := token.complete(ctx, tx, func(ctx context.Context, _ core.Mutation) error {
							// Both transactions have read the unused token before either
							// writes. A write conflict must retry the whole callback.
							if arrivals.Add(1) == 2 {
								close(ready)
							}
							select {
							case <-ready:
								return nil
							case <-ctx.Done():
								return ctx.Err()
							}
						})
						return err
					})
				}()
			}
			assertMongoRace(t, <-results, <-results, core.ErrTokenConsumed)
			if attempts.Load() < 3 {
				t.Fatal("native WithTransaction did not retry the write conflict")
			}
			f.assertCompleted(t, user, token, before)
		})
	}
}

func TestMongoInvalidTokensDoNotRunPolicy(t *testing.T) {
	f := newMongoFixture(t, "AUTH_TEST_MONGO_URI")
	// Keep expired fixtures available for assertions instead of racing Mongo's
	// asynchronous TTL monitor. Production TTL indexes are tested on startup.
	for coll, index := range map[string]string{
		f.cfg.VerificationCollection:  "verifications_expires_ttl",
		f.cfg.PasswordResetCollection: "password_resets_expires_ttl",
		f.cfg.EmailChangeCollection:   "email_changes_expires_ttl",
	} {
		mongoMust(t, f.db.Collection(coll).Indexes().DropOne(f.ctx, index))
	}
	for _, kind := range mongoMutationKinds {
		t.Run(string(kind), func(t *testing.T) {
			user := f.register(t)
			token := f.seedToken(t, kind, user.User.ID)
			_, err := f.db.Collection(token.coll).UpdateByID(f.ctx, token.id, bson.M{"$set": bson.M{"expires_at": time.Now().Add(-time.Minute)}})
			mongoMust(t, err)
			before, tokenBefore := f.snapshot(t, f.ctx, user.User.ID), f.tokenDocument(t, f.ctx, token)
			for _, tc := range []struct {
				raw  string
				want error
			}{{"missing-token", core.ErrTokenNotFound}, {strings.Repeat("x", core.MaxTokenLength+1), core.ErrTokenNotFound}, {token.raw, core.ErrTokenExpired}} {
				tokenCopy := token
				tokenCopy.raw = tc.raw
				err := f.svc.InTx(f.ctx, func(ctx context.Context, tx *Transaction) error {
					_, err := tokenCopy.complete(ctx, tx, func(context.Context, core.Mutation) error {
						t.Fatal("invalid token reached policy")
						return nil
					})
					return err
				})
				if !errors.Is(err, tc.want) {
					t.Fatalf("invalid token: %v, want %v", err, tc.want)
				}
			}
			assertMongoSnapshot(t, before, f.snapshot(t, f.ctx, user.User.ID))
			f.assertTokenUnchanged(t, f.ctx, token, tokenBefore)
		})
	}
}

func TestMongoTransactionContextRequired(t *testing.T) {
	f := newMongoFixture(t, "AUTH_TEST_MONGO_URI")
	user := f.register(t)
	before := f.snapshot(t, f.ctx, user.User.ID)
	session, err := f.client.StartSession()
	mongoMust(t, err)
	defer session.EndSession(f.ctx)
	for _, ctx := range []context.Context{f.ctx, mongo.NewSessionContext(f.ctx, session)} {
		if _, err := f.svc.WithTx(ctx); !errors.Is(err, core.ErrTransactionRequired) {
			t.Fatalf("bound an absent/inactive transaction: %v", err)
		}
	}
	if err := f.svc.InTx(f.ctx, nil); !errors.Is(err, core.ErrInvalidInput) {
		t.Fatalf("nil callback: %v", err)
	}
	var bound *Transaction
	var savedCtx context.Context
	mongoMust(t, f.svc.InTx(f.ctx, func(ctx context.Context, tx *Transaction) error {
		bound, savedCtx = tx, ctx
		if err := f.svc.InTx(ctx, func(context.Context, *Transaction) error { t.Fatal("nested callback ran"); return nil }); !errors.Is(err, core.ErrTransactionRequired) {
			t.Fatalf("nested transaction: %v", err)
		}
		mongoMust(t, session.StartTransaction())
		otherCtx := mongo.NewSessionContext(f.ctx, session)
		for _, wrongCtx := range []context.Context{f.ctx, otherCtx} {
			policy := func(context.Context, core.Mutation) error {
				t.Fatal("policy ran outside bound transaction")
				return nil
			}
			operationErrors := []error{tx.VerifyPassword(wrongCtx, user.User.ID, mongoPassword), tx.RevokeSessionsByUser(wrongCtx, user.User.ID)}
			_, err := tx.UpdateUsername(wrongCtx, user.User.ID, "wrong_context")
			operationErrors = append(operationErrors, err)
			_, err = tx.UpdateRole(wrongCtx, user.User.ID, core.RoleAdmin)
			operationErrors = append(operationErrors, err)
			_, err = tx.VerifyEmail(wrongCtx, core.VerifyEmailCommand{}, policy)
			operationErrors = append(operationErrors, err)
			_, err = tx.ResetPassword(wrongCtx, core.ResetPasswordCommand{}, policy)
			operationErrors = append(operationErrors, err)
			_, err = tx.ConfirmEmailChange(wrongCtx, core.ConfirmEmailChangeCommand{}, policy)
			operationErrors = append(operationErrors, err)
			for _, err := range operationErrors {
				if err != core.ErrTransactionRequired {
					t.Fatalf("wrong context: %v", err)
				}
			}
		}
		mongoMust(t, session.AbortTransaction(otherCtx))
		derivedCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		return tx.VerifyPassword(derivedCtx, user.User.ID, mongoPassword)
	}))
	if err := bound.VerifyPassword(savedCtx, user.User.ID, mongoPassword); !errors.Is(err, core.ErrTransactionRequired) {
		t.Fatalf("used binding after commit: %v", err)
	}
	assertMongoSnapshot(t, before, f.snapshot(t, f.ctx, user.User.ID))
}

func TestMongoCallbackCannotReportAbortedTransactionAsCommitted(t *testing.T) {
	f := newMongoFixture(t, "AUTH_TEST_MONGO_URI")
	user := f.register(t)
	before := f.snapshot(t, f.ctx, user.User.ID)
	err := f.svc.InTx(f.ctx, func(ctx context.Context, tx *Transaction) error {
		if _, err := tx.UpdateRole(ctx, user.User.ID, core.RoleAdmin); err != nil {
			return err
		}
		return mongo.SessionFromContext(ctx).AbortTransaction(ctx)
	})
	if !errors.Is(err, core.ErrTransactionRequired) {
		t.Fatalf("callback aborted but InTx reported success: %v", err)
	}
	assertMongoSnapshot(t, before, f.snapshot(t, f.ctx, user.User.ID))
}

func TestMongoPolicyCannotAbortAndFallBack(t *testing.T) {
	f := newMongoFixture(t, "AUTH_TEST_MONGO_URI")
	for _, kind := range mongoMutationKinds {
		t.Run(string(kind), func(t *testing.T) {
			user := f.register(t)
			token := f.seedToken(t, kind, user.User.ID)
			before, tokenBefore := f.snapshot(t, f.ctx, user.User.ID), f.tokenDocument(t, f.ctx, token)
			err := f.svc.InTx(f.ctx, func(ctx context.Context, tx *Transaction) error {
				_, err := token.complete(ctx, tx, func(ctx context.Context, _ core.Mutation) error {
					return mongo.SessionFromContext(ctx).AbortTransaction(ctx)
				})
				return err
			})
			if !errors.Is(err, core.ErrTransactionRequired) {
				t.Fatalf("policy ended transaction without rejecting further mutation: %v", err)
			}
			assertMongoSnapshot(t, before, f.snapshot(t, f.ctx, user.User.ID))
			f.assertTokenUnchanged(t, f.ctx, token, tokenBefore)
		})
	}
}

func TestMongoLegacyTokenCompletion(t *testing.T) {
	f := newMongoFixture(t, "AUTH_TEST_MONGO_STANDALONE_URI")
	for _, kind := range mongoMutationKinds {
		t.Run(string(kind), func(t *testing.T) {
			user := f.register(t)
			token := f.seedToken(t, kind, user.User.ID)
			before := f.snapshot(t, f.ctx, user.User.ID)
			var err error
			switch kind {
			case core.MutationVerifyEmail:
				_, err = f.svc.VerifyEmail(f.ctx, core.VerifyEmailCommand{Token: token.raw})
			case core.MutationResetPassword:
				_, err = f.svc.ResetPassword(f.ctx, core.ResetPasswordCommand{Token: token.raw, NewPassword: mongoNewPassword})
			default:
				_, err = f.svc.ConfirmEmailChange(f.ctx, core.ConfirmEmailChangeCommand{Token: token.raw})
			}
			mongoMust(t, err)
			f.assertCompleted(t, user, token, before)
		})
	}
}

func TestMongoConditionalTokenConsume(t *testing.T) {
	f := newMongoFixture(t, "AUTH_TEST_MONGO_STANDALONE_URI")
	for _, kind := range mongoMutationKinds {
		t.Run(string(kind), func(t *testing.T) {
			user := f.register(t)
			token := f.seedToken(t, kind, user.User.ID)
			stores := newStores(f.db, f.cfg)
			var consume func(context.Context, core.ID, time.Time) error
			switch kind {
			case core.MutationVerifyEmail:
				consume = stores.Verifications.Consume
			case core.MutationResetPassword:
				consume = stores.PasswordResets.Consume
			default:
				consume = stores.EmailChanges.Consume
			}
			mongoMust(t, consume(f.ctx, core.ID(token.id.Hex()), time.Now().UTC()))
			before := f.tokenDocument(t, f.ctx, token)
			if err := consume(f.ctx, core.ID(token.id.Hex()), time.Now().Add(time.Minute)); !errors.Is(err, core.ErrTokenConsumed) {
				t.Fatalf("consume overwrote a used token: %v", err)
			}
			f.assertTokenUnchanged(t, f.ctx, token, before)
		})
	}
}
