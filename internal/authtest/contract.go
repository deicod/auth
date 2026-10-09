// Package authtest contains the shared SQL backend integration contract.
package authtest

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/deicod/auth/core"
	"github.com/deicod/auth/core/services"
	"github.com/deicod/auth/internal/security"
	"github.com/google/uuid"
)

// Service is the public capability exercised by both SQL backends.
type Service interface {
	Register(context.Context, core.RegisterCommand) (core.AuthResult, error)
	Login(context.Context, core.LoginCommand) (core.AuthResult, error)
	AuthenticateSession(context.Context, string) (core.UserPublic, core.SessionPublic, error)
	VerifyPassword(context.Context, core.ID, string) error
	RevokeSessionsByUser(context.Context, core.ID) error
	UpdateUsername(context.Context, core.ID, string) (core.UserPublic, error)
	UpdateRole(context.Context, core.ID, core.Role) (core.UserPublic, error)
}

type Scanner interface{ Scan(...any) error }

// DB adapts test SQL with ? placeholders to a backend's native database API.
type DB struct {
	Exec     func(context.Context, string, ...any) error
	QueryRow func(context.Context, string, ...any) Scanner
}

// Tx is an externally owned native transaction with auth bound to it.
type Tx struct {
	DB
	Auth     *services.Transaction
	Commit   func() error
	Rollback func() error
}

type Backend struct {
	Service Service
	DB
	InTx      func(context.Context, func(DB, *services.Transaction) error) error
	Begin     func(context.Context) (*Tx, error)
	UpdateRaw func(context.Context, core.ID, string) error
	CreateRaw func(context.Context, string, string) error
	ForUpdate string
}

const password = "correct-password-123"

func Run(t *testing.T, b Backend) {
	t.Helper()
	ctx := context.Background()
	must(t, b.Exec(ctx, `CREATE TABLE auth_test_controls (user_id TEXT PRIMARY KEY, state TEXT NOT NULL)`))
	must(t, b.Exec(ctx, `CREATE TABLE auth_test_events (user_id TEXT NOT NULL, kind TEXT NOT NULL)`))
	register := func(t *testing.T) core.AuthResult {
		t.Helper()
		name := "user_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:20]
		res, err := b.Service.Register(ctx, core.RegisterCommand{Email: name + "@example.com", Username: name, Password: password})
		must(t, err)
		return res
	}

	t.Run("sessionless_password_verification", func(t *testing.T) {
		user := register(t)
		for _, loggedIn := range []bool{false, true} {
			if loggedIn {
				_, err := b.Service.Login(ctx, core.LoginCommand{Email: user.User.Email, Password: password})
				must(t, err)
			}
			before := snapshot(t, b.DB, user.User.ID)
			for _, tc := range []struct {
				id   core.ID
				pw   string
				want error
			}{
				{user.User.ID, password, nil},
				{user.User.ID, "wrong", core.ErrInvalidCredentials},
				{core.ID(uuid.NewString()), password, core.ErrInvalidCredentials},
				{"malformed-id", password, core.ErrInvalidCredentials},
				{user.User.ID, strings.Repeat("x", 1025), core.ErrInvalidCredentials},
			} {
				if err := b.Service.VerifyPassword(ctx, tc.id, tc.pw); !errors.Is(err, tc.want) {
					t.Fatalf("VerifyPassword = %v, want %v", err, tc.want)
				}
			}
			assertSnapshot(t, before, snapshot(t, b.DB, user.User.ID))
		}
	})

	t.Run("user_session_revocation_is_idempotent", func(t *testing.T) {
		user, other := register(t), register(t)
		_, err := b.Service.Login(ctx, core.LoginCommand{Email: user.User.Email, Password: password})
		must(t, err)
		must(t, b.Service.RevokeSessionsByUser(ctx, user.User.ID))
		must(t, b.Service.RevokeSessionsByUser(ctx, user.User.ID))
		must(t, b.Service.RevokeSessionsByUser(ctx, core.ID(uuid.NewString())))
		if n := count(t, b.DB, `SELECT COUNT(*) FROM sessions WHERE user_id = ? AND revoked = false`, string(user.User.ID)); n != 0 {
			t.Fatalf("%d sessions remained active", n)
		}
		_, _, err = b.Service.AuthenticateSession(ctx, user.Token)
		if !errors.Is(err, core.ErrSessionNotFound) {
			t.Fatalf("revoked session accepted: %v", err)
		}
		_, _, err = b.Service.AuthenticateSession(ctx, other.Token)
		must(t, err)
	})

	t.Run("username_validation_and_availability", func(t *testing.T) {
		user, other := register(t), register(t)
		for _, username := range []string{"", " \t", "ab", strings.Repeat("a", 31), "space name", "has.dot", "Äbc", "line\nbreak"} {
			_, err := b.Service.UpdateUsername(ctx, user.User.ID, username)
			if !errors.Is(err, core.ErrInvalidInput) {
				t.Fatalf("UpdateUsername(%q) = %v", username, err)
			}
			_, err = b.Service.Register(ctx, core.RegisterCommand{Email: uuid.NewString() + "@example.com", Username: username, Password: password})
			if !errors.Is(err, core.ErrInvalidInput) {
				t.Fatalf("Register(%q) = %v", username, err)
			}
		}
		for _, name := range []string{user.User.Username, strings.ToUpper(user.User.Username), " \tAbc_-19\n", strings.Repeat("a", 30)} {
			updated, err := b.Service.UpdateUsername(ctx, user.User.ID, name)
			must(t, err)
			if updated.Username != strings.TrimSpace(name) {
				t.Fatalf("unexpected normalized username %q", updated.Username)
			}
		}
		_, err := b.Service.UpdateUsername(ctx, user.User.ID, strings.ToUpper(other.User.Username))
		if !errors.Is(err, core.ErrUsernameExists) {
			t.Fatalf("case-insensitive conflict: %v", err)
		}
		_, err = b.Service.Register(ctx, core.RegisterCommand{Email: uuid.NewString() + "@example.com", Username: strings.ToUpper(other.User.Username), Password: password})
		if !errors.Is(err, core.ErrUsernameExists) {
			t.Fatalf("registration case-insensitive conflict: %v", err)
		}
		_, err = b.Service.UpdateUsername(ctx, core.ID(uuid.NewString()), "valid_name")
		if !errors.Is(err, core.ErrUserNotFound) {
			t.Fatalf("missing user: %v", err)
		}
		// Bypass the optimistic availability query to exercise the final DB guard
		// and its error mapping for both repository creation and updates.
		if err := b.UpdateRaw(ctx, user.User.ID, strings.ToUpper(other.User.Username)); !errors.Is(err, core.ErrUsernameExists) {
			t.Fatalf("update uniqueness mapping: %v", err)
		}
		if err := b.CreateRaw(ctx, uuid.NewString()+"@example.com", strings.ToUpper(other.User.Username)); !errors.Is(err, core.ErrUsernameExists) {
			t.Fatalf("create uniqueness mapping: %v", err)
		}
		if err := b.CreateRaw(ctx, other.User.Email, "new_available_name"); !errors.Is(err, core.ErrEmailExists) {
			t.Fatalf("email uniqueness mapping: %v", err)
		}
	})

	for _, transactional := range []bool{false, true} {
		name := "concurrent_username_updates"
		if transactional {
			name += "_in_transaction"
		}
		t.Run(name, func(t *testing.T) {
			users := []core.AuthResult{register(t), register(t)}
			start, result := make(chan struct{}), make(chan error, 2)
			baseName := "race_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:20]
			for i, user := range users {
				go func() {
					<-start
					name := baseName
					if i == 1 {
						name = strings.ToUpper(name)
					}
					if transactional {
						result <- b.InTx(ctx, func(_ DB, auth *services.Transaction) error {
							_, err := auth.UpdateUsername(ctx, user.User.ID, name)
							return err
						})
						return
					}
					_, err := b.Service.UpdateUsername(ctx, user.User.ID, name)
					result <- err
				}()
			}
			close(start)
			assertOneConflict(t, <-result, <-result)
			if n := count(t, b.DB, `SELECT COUNT(*) FROM users WHERE LOWER(username) = LOWER(?)`, baseName); n != 1 {
				t.Fatalf("expected one username owner, got %d", n)
			}
		})
	}

	t.Run("database_race_guard", func(t *testing.T) {
		users := []core.AuthResult{register(t), register(t)}
		start, result := make(chan struct{}), make(chan error, 2)
		for i, user := range users {
			go func() {
				<-start
				name := "race_guard"
				if i == 1 {
					name = strings.ToUpper(name)
				}
				result <- b.UpdateRaw(ctx, user.User.ID, name)
			}()
		}
		close(start)
		assertOneConflict(t, <-result, <-result)
	})

	t.Run("management_and_consumer_changes_commit_or_rollback_together", func(t *testing.T) {
		for _, commit := range []bool{false, true} {
			user := register(t)
			before := snapshot(t, b.DB, user.User.ID)
			aborted := errors.New("consumer operation failed")
			err := b.InTx(ctx, func(db DB, auth *services.Transaction) error {
				if _, err := auth.UpdateUsername(ctx, user.User.ID, "upd_"+user.User.Username); err != nil {
					return err
				}
				if _, err := auth.UpdateRole(ctx, user.User.ID, core.RoleAdmin); err != nil {
					return err
				}
				if err := auth.VerifyPassword(ctx, user.User.ID, password); err != nil {
					return err
				}
				if err := auth.RevokeSessionsByUser(ctx, user.User.ID); err != nil {
					return err
				}
				if err := db.Exec(ctx, `INSERT INTO auth_test_events (user_id, kind) VALUES (?, ?)`, string(user.User.ID), "management"); err != nil {
					return err
				}
				if !commit {
					return aborted
				}
				return nil
			})
			if !commit {
				if !errors.Is(err, aborted) {
					t.Fatalf("rollback error: %v", err)
				}
				assertSnapshot(t, before, snapshot(t, b.DB, user.User.ID))
				if n := count(t, b.DB, `SELECT COUNT(*) FROM auth_test_events WHERE user_id = ?`, string(user.User.ID)); n != 0 {
					t.Fatal("consumer row survived rollback")
				}
			} else {
				must(t, err)
				after := snapshot(t, b.DB, user.User.ID)
				if after.Username != "upd_"+user.User.Username || after.Role != "admin" || after.ActiveSessions != 0 {
					t.Fatalf("auth changes did not commit: %+v", after)
				}
				if n := count(t, b.DB, `SELECT COUNT(*) FROM auth_test_events WHERE user_id = ?`, string(user.User.ID)); n != 1 {
					t.Fatal("consumer row did not commit")
				}
			}
		}
	})

	t.Run("caller_owned_transaction", func(t *testing.T) {
		for _, commit := range []bool{false, true} {
			user := register(t)
			tx, err := b.Begin(ctx)
			must(t, err)
			defer func() { _ = tx.Rollback() }()
			_, err = tx.Auth.UpdateRole(ctx, user.User.ID, core.RoleAdmin)
			must(t, err)
			must(t, tx.Exec(ctx, `INSERT INTO auth_test_events (user_id, kind) VALUES (?, ?)`, string(user.User.ID), "external"))
			if commit {
				must(t, tx.Commit())
			} else {
				must(t, tx.Rollback())
			}
			role, rows := "user", 0
			if commit {
				role, rows = "admin", 1
			}
			if got := snapshot(t, b.DB, user.User.ID).Role; got != role {
				t.Fatalf("role = %q, want %q", got, role)
			}
			if n := count(t, b.DB, `SELECT COUNT(*) FROM auth_test_events WHERE user_id = ?`, string(user.User.ID)); n != rows {
				t.Fatal("consumer data and auth data diverged")
			}
		}
	})

	t.Run("panic_rolls_back", func(t *testing.T) {
		user := register(t)
		func() {
			defer func() {
				if got := recover(); got != "stop" {
					t.Fatalf("unexpected panic: %v", got)
				}
			}()
			_ = b.InTx(ctx, func(db DB, auth *services.Transaction) error {
				_, err := auth.UpdateRole(ctx, user.User.ID, core.RoleAdmin)
				must(t, err)
				must(t, db.Exec(ctx, `INSERT INTO auth_test_events (user_id, kind) VALUES (?, ?)`, string(user.User.ID), "panic"))
				panic("stop")
			})
		}()
		if snapshot(t, b.DB, user.User.ID).Role != "user" || count(t, b.DB, `SELECT COUNT(*) FROM auth_test_events WHERE user_id = ?`, string(user.User.ID)) != 0 {
			t.Fatal("panic did not roll back both schemas")
		}
	})

	t.Run("invalid_role", func(t *testing.T) {
		user := register(t)
		_, err := b.Service.UpdateRole(ctx, user.User.ID, "unknown")
		if !errors.Is(err, core.ErrInvalidInput) || snapshot(t, b.DB, user.User.ID).Role != "user" {
			t.Fatalf("invalid role accepted: %v", err)
		}
	})

	for _, kind := range []core.MutationKind{core.MutationVerifyEmail, core.MutationResetPassword, core.MutationConfirmEmailChange} {
		t.Run(string(kind)+"_invalid_or_expired_token_skips_policy", func(t *testing.T) {
			user := register(t)
			token, table := seedToken(t, b.DB, user.User.ID, kind)
			must(t, b.Exec(ctx, "UPDATE "+table+" SET expires_at = ? WHERE token_hash = ?", time.Now().UTC().Add(-time.Hour), security.HashToken(token)))
			for _, tc := range []struct {
				token string
				want  error
			}{
				{"missing-token", core.ErrTokenNotFound},
				{strings.Repeat("x", core.MaxTokenLength+1), core.ErrTokenNotFound},
				{token, core.ErrTokenExpired},
			} {
				err := b.InTx(ctx, func(_ DB, auth *services.Transaction) error {
					return complete(ctx, auth, kind, tc.token, func(context.Context, core.Mutation) error {
						t.Fatal("policy invoked for an invalid or expired token")
						return nil
					})
				})
				if !errors.Is(err, tc.want) {
					t.Fatalf("invalid token result: %v, want %v", err, tc.want)
				}
			}
			assertUnused(t, b.DB, table, token)
		})
		t.Run(string(kind)+"_concurrent_consumption", func(t *testing.T) {
			user := register(t)
			token, _ := seedToken(t, b.DB, user.User.ID, kind)
			start, results := make(chan struct{}), make(chan error, 2)
			for range 2 {
				go func() {
					<-start
					results <- b.InTx(ctx, func(_ DB, auth *services.Transaction) error {
						return complete(ctx, auth, kind, token, nil)
					})
				}()
			}
			close(start)
			a, c := <-results, <-results
			assertOneSuccess(t, a, c, core.ErrTokenConsumed)
		})
		t.Run(string(kind)+"_policy_and_atomicity", func(t *testing.T) {
			user := register(t)
			// Seed a token as an existing database row. This exercises completion
			// independently of mail delivery/background scheduling.
			token, table := seedToken(t, b.DB, user.User.ID, kind)
			before := snapshot(t, b.DB, user.User.ID)
			must(t, b.Exec(ctx, `INSERT INTO auth_test_controls (user_id, state) VALUES (?, ?)`, string(user.User.ID), "denied"))
			denied := errors.New("account policy denied")
			for _, phase := range []string{"deny", "rollback", "commit"} {
				if phase == "rollback" {
					must(t, b.Exec(ctx, `UPDATE auth_test_controls SET state = ? WHERE user_id = ?`, "active", string(user.User.ID)))
				}
				calls := 0
				aborted := errors.New("consumer failure after auth mutation")
				err := b.InTx(ctx, func(db DB, auth *services.Transaction) error {
					policy := func(policyCtx context.Context, mutation core.Mutation) error {
						calls++
						if mutation.Kind != kind || mutation.UserID != user.User.ID {
							t.Fatalf("wrong policy identity: %+v", mutation)
						}
						var state string
						if err := db.QueryRow(policyCtx, `SELECT state FROM auth_test_controls WHERE user_id = ?`+b.ForUpdate, string(mutation.UserID)).Scan(&state); err != nil {
							return err
						}
						if state != "active" {
							return denied
						}
						return nil
					}
					err := complete(ctx, auth, kind, token, policy)
					if phase == "deny" {
						if !errors.Is(err, denied) {
							t.Fatalf("policy denial: %v", err)
						}
						// Inspect INSIDE the transaction: rollback must not hide an
						// early credential write, session revocation or token consume.
						assertSnapshot(t, before, snapshot(t, db, user.User.ID))
						assertUnused(t, db, table, token)
						return err
					}
					if err != nil {
						return err
					}
					if err := db.Exec(ctx, `UPDATE auth_test_controls SET state = ? WHERE user_id = ?`, "changed", string(user.User.ID)); err != nil {
						return err
					}
					if phase == "rollback" {
						return aborted
					}
					return nil
				})
				if calls != 1 {
					t.Fatalf("policy called %d times", calls)
				}
				if phase == "commit" {
					must(t, err)
					continue
				}
				want := denied
				if phase == "rollback" {
					want = aborted
				}
				if !errors.Is(err, want) {
					t.Fatalf("%s error: %v", phase, err)
				}
				assertSnapshot(t, before, snapshot(t, b.DB, user.User.ID))
				assertUnused(t, b.DB, table, token)
				var state string
				must(t, b.QueryRow(ctx, `SELECT state FROM auth_test_controls WHERE user_id = ?`, string(user.User.ID)).Scan(&state))
				if phase == "rollback" && state != "active" {
					t.Fatal("consumer change survived rollback")
				}
			}
			after := snapshot(t, b.DB, user.User.ID)
			switch kind {
			case core.MutationVerifyEmail:
				if !after.Verified || after.VerifiedAt == nil {
					t.Fatal("verification did not commit")
				}
			case core.MutationResetPassword:
				must(t, b.Service.VerifyPassword(ctx, user.User.ID, "new-password-123"))
				if after.ActiveSessions != 0 {
					t.Fatal("password reset did not revoke sessions")
				}
			case core.MutationConfirmEmailChange:
				if after.Email != "changed-"+string(user.User.ID)+"@example.com" || !after.Verified {
					t.Fatal("email change did not commit")
				}
			}
			err := b.InTx(ctx, func(_ DB, auth *services.Transaction) error {
				return complete(ctx, auth, kind, token, func(context.Context, core.Mutation) error {
					t.Fatal("policy invoked for consumed token")
					return nil
				})
			})
			if !errors.Is(err, core.ErrTokenConsumed) {
				t.Fatalf("token replay = %v", err)
			}
		})
	}
}

type userSnapshot struct {
	Email, Username, Role, Hash        string
	Verified                           bool
	UpdatedAt, LastLoginAt, VerifiedAt any
	Sessions, ActiveSessions           int
}

func snapshot(t *testing.T, db DB, id core.ID) userSnapshot {
	t.Helper()
	var s userSnapshot
	must(t, db.QueryRow(context.Background(), `SELECT email, username, role, password_hash, is_verified, updated_at, last_login_at, verified_at FROM users WHERE id = ?`, string(id)).Scan(&s.Email, &s.Username, &s.Role, &s.Hash, &s.Verified, &s.UpdatedAt, &s.LastLoginAt, &s.VerifiedAt))
	s.Sessions = count(t, db, `SELECT COUNT(*) FROM sessions WHERE user_id = ?`, string(id))
	s.ActiveSessions = count(t, db, `SELECT COUNT(*) FROM sessions WHERE user_id = ? AND revoked = false`, string(id))
	return s
}

func assertSnapshot(t *testing.T, want, got userSnapshot) {
	t.Helper()
	if !reflect.DeepEqual(want, got) {
		t.Fatal("user credentials, timestamps or sessions unexpectedly changed")
	}
}

func count(t *testing.T, db DB, query string, args ...any) int {
	t.Helper()
	var n int
	must(t, db.QueryRow(context.Background(), query, args...).Scan(&n))
	return n
}

func assertOneConflict(t *testing.T, a, b error) {
	t.Helper()
	assertOneSuccess(t, a, b, core.ErrUsernameExists)
}

func assertOneSuccess(t *testing.T, a, b, conflict error) {
	t.Helper()
	if a == nil && errors.Is(b, conflict) {
		return
	}
	if b == nil && errors.Is(a, conflict) {
		return
	}
	t.Fatalf("expected one success and one %v, got %v / %v", conflict, a, b)
}

func seedToken(t *testing.T, db DB, userID core.ID, kind core.MutationKind) (string, string) {
	t.Helper()
	token, hash, err := security.NewTokenGenerator(32).Generate()
	must(t, err)
	table := tokenTable(kind)
	columns, placeholders := "id, user_id, token_hash, expires_at, created_at", "?, ?, ?, ?, ?"
	now := time.Now().UTC()
	args := []any{uuid.NewString(), string(userID), hash, now.Add(time.Hour), now}
	if kind == core.MutationConfirmEmailChange {
		columns += ", new_email"
		placeholders += ", ?"
		args = append(args, "changed-"+string(userID)+"@example.com")
	}
	must(t, db.Exec(context.Background(), fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", table, columns, placeholders), args...))
	return token, table
}

func tokenTable(kind core.MutationKind) string {
	switch kind {
	case core.MutationVerifyEmail:
		return "verification_tokens"
	case core.MutationResetPassword:
		return "password_reset_tokens"
	case core.MutationConfirmEmailChange:
		return "email_change_requests"
	default:
		panic("unknown mutation")
	}
}

func assertUnused(t *testing.T, db DB, table, token string) {
	t.Helper()
	var consumed any
	must(t, db.QueryRow(context.Background(), "SELECT consumed_at FROM "+table+" WHERE token_hash = ?", security.HashToken(token)).Scan(&consumed))
	if consumed != nil {
		t.Fatal("token consumed before policy or despite rollback")
	}
}

func complete(ctx context.Context, auth *services.Transaction, kind core.MutationKind, token string, policy core.MutationPolicy) error {
	switch kind {
	case core.MutationVerifyEmail:
		_, err := auth.VerifyEmail(ctx, core.VerifyEmailCommand{Token: token}, policy)
		return err
	case core.MutationResetPassword:
		_, err := auth.ResetPassword(ctx, core.ResetPasswordCommand{Token: token, NewPassword: "new-password-123"}, policy)
		return err
	case core.MutationConfirmEmailChange:
		_, err := auth.ConfirmEmailChange(ctx, core.ConfirmEmailChangeCommand{Token: token}, policy)
		return err
	default:
		panic("unknown mutation")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
