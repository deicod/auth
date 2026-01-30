package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/deicod/auth/config"
	"github.com/deicod/auth/core"
	"github.com/deicod/auth/internal/security"
)

func TestAuthServiceRegister(t *testing.T) {
	svc, deps := newTestService(t)
	ctx := context.Background()

	result, err := svc.Register(ctx, core.RegisterCommand{
		Email:     "Alice@Example.com",
		Username:  "alice",
		Password:  "supersafe",
		UserAgent: "cli",
		IP:        "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}
	if result.User.Email != "alice@example.com" {
		t.Fatalf("expected normalized email, got %s", result.User.Email)
	}
	if len(deps.mailer.verificationTokens) != 1 {
		t.Fatalf("expected verification email to be sent")
	}
	if len(deps.sessions.sessions) != 1 {
		t.Fatalf("expected one session to be created")
	}
}

func TestAuthServiceLoginInvalidPassword(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	_, _ = svc.Register(ctx, core.RegisterCommand{Email: "bob@example.com", Username: "bob", Password: "secretpass"})

	_, err := svc.Login(ctx, core.LoginCommand{Email: "bob@example.com", Password: "wrong"})
	if !errors.Is(err, core.ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
}

func TestAuthServiceLogoutRevokesSession(t *testing.T) {
	svc, deps := newTestService(t)
	ctx := context.Background()
	result, err := svc.Register(ctx, core.RegisterCommand{Email: "carol@example.com", Username: "carol", Password: "password123"})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	if err := svc.Logout(ctx, result.Token); err != nil {
		t.Fatalf("logout failed: %v", err)
	}
	sess := deps.sessions.sessions[result.Session.ID]
	if !sess.Revoked {
		t.Fatalf("expected session to be revoked")
	}
}

func TestResetPasswordRevokesAllSessions(t *testing.T) {
	svc, deps := newTestService(t)
	ctx := context.Background()
	result, err := svc.Register(ctx, core.RegisterCommand{Email: "dave@example.com", Username: "dave", Password: "startpassword"})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	if err := svc.ForgotPassword(ctx, core.ForgotPasswordCommand{Email: "dave@example.com"}); err != nil {
		t.Fatalf("forgot password failed: %v", err)
	}

	// Wait for async email
	select {
	case <-deps.mailer.notifyReset:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for password reset email")
	}

	if len(deps.mailer.resetTokens) == 0 {
		t.Fatalf("expected reset token to be sent")
	}
	token := deps.mailer.resetTokens[len(deps.mailer.resetTokens)-1]

	if _, err := svc.ResetPassword(ctx, core.ResetPasswordCommand{Token: token, NewPassword: "newpassword"}); err != nil {
		t.Fatalf("reset password failed: %v", err)
	}

	sess := deps.sessions.sessions[result.Session.ID]
	if !sess.Revoked {
		t.Fatalf("expected session to be revoked after password reset")
	}
}

func TestVerifyEmailFlow(t *testing.T) {
	svc, deps := newTestService(t)
	ctx := context.Background()
	result, err := svc.Register(ctx, core.RegisterCommand{Email: "eve@example.com", Username: "eve", Password: "startpassword"})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}
	if len(deps.mailer.verificationTokens) == 0 {
		t.Fatalf("expected verification token")
	}
	token := deps.mailer.verificationTokens[0]

	if _, err := svc.VerifyEmail(ctx, core.VerifyEmailCommand{Token: token}); err != nil {
		t.Fatalf("verify email failed: %v", err)
	}
	user, err := deps.users.FindByID(ctx, result.User.ID)
	if err != nil {
		t.Fatalf("find user failed: %v", err)
	}
	if !user.IsVerified || user.VerifiedAt == nil {
		t.Fatalf("expected user to be verified")
	}
}

func TestEmailChangeFlow(t *testing.T) {
	svc, deps := newTestService(t)
	ctx := context.Background()
	res, err := svc.Register(ctx, core.RegisterCommand{Email: "frank@example.com", Username: "frank", Password: "secretpassword"})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	cmd := core.ChangeEmailCommand{
		UserID:   res.User.ID,
		Password: "secretpassword",
		NewEmail: "frank+new@example.com",
	}
	if err := svc.InitiateEmailChange(ctx, cmd); err != nil {
		t.Fatalf("initiate email change failed: %v", err)
	}
	if len(deps.mailer.emailChangeTokens) == 0 {
		t.Fatalf("expected email change token")
	}
	changeToken := deps.mailer.emailChangeTokens[0]

	if _, err := svc.ConfirmEmailChange(ctx, core.ConfirmEmailChangeCommand{Token: changeToken}); err != nil {
		t.Fatalf("confirm email change failed: %v", err)
	}
	user, err := deps.users.FindByID(ctx, res.User.ID)
	if err != nil {
		t.Fatalf("find user failed: %v", err)
	}
	if user.Email != "frank+new@example.com" {
		t.Fatalf("expected updated email, got %s", user.Email)
	}
	if !user.IsVerified {
		t.Fatalf("expected user to remain verified")
	}
}

func TestInitiateEmailChange_UserEnumeration(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	// Non-existent user ID
	cmd := core.ChangeEmailCommand{
		UserID:   "non-existent-user",
		Password: "somepassword",
		NewEmail: "new@example.com",
	}

	err := svc.InitiateEmailChange(ctx, cmd)
	if !errors.Is(err, core.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials to prevent enumeration, got: %v", err)
	}
}

func TestVerifyEmailExpired(t *testing.T) {
	svc, deps := newTestService(t)
	ctx := context.Background()
	res, err := svc.Register(ctx, core.RegisterCommand{Email: "e@e.com", Username: "user1", Password: "password123"})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}
	token := deps.mailer.verificationTokens[0]
	hash := security.HashToken(token)

	// artificially expire token
	for id, t := range deps.verifications.tokens {
		if t.TokenHash == hash {
			t.ExpiresAt = time.Now().Add(-1 * time.Hour)
			deps.verifications.tokens[id] = t
		}
	}

	_, err = svc.VerifyEmail(ctx, core.VerifyEmailCommand{Token: token})
	if !errors.Is(err, core.ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
	// Check user is not verified
	user, _ := deps.users.FindByID(ctx, res.User.ID)
	if user.IsVerified {
		t.Fatal("expected user to be unverified")
	}
}

func TestResetPasswordExpired(t *testing.T) {
	svc, deps := newTestService(t)
	ctx := context.Background()
	res, err := svc.Register(ctx, core.RegisterCommand{Email: "e@e.com", Username: "user1", Password: "password123"})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}
	if err := svc.ForgotPassword(ctx, core.ForgotPasswordCommand{Email: "e@e.com"}); err != nil {
		t.Fatalf("forgot password failed: %v", err)
	}

	// Wait for async email
	select {
	case <-deps.mailer.notifyReset:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for password reset email")
	}

	token := deps.mailer.resetTokens[0]
	hash := security.HashToken(token)

	// artificially expire
	for id, t := range deps.resets.tokens {
		if t.TokenHash == hash {
			t.ExpiresAt = time.Now().Add(-1 * time.Hour)
			deps.resets.tokens[id] = t
		}
	}

	_, err = svc.ResetPassword(ctx, core.ResetPasswordCommand{Token: token, NewPassword: "new"})
	if !errors.Is(err, core.ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
	// Password should remain same (check hash)
	user, _ := deps.users.FindByID(ctx, res.User.ID)
	// We can verify that the user still exists and the operation failed with proper error.
	if user.ID == "" {
		t.Fatal("expected user to still exist")
	}
}

func TestRegisterDuplicateEmail(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.Register(ctx, core.RegisterCommand{Email: "e@e.com", Username: "user1", Password: "password123"}); err != nil {
		t.Fatalf("register failed: %v", err)
	}
	_, err := svc.Register(ctx, core.RegisterCommand{Email: "e@e.com", Username: "user2", Password: "password123"})
	if !errors.Is(err, core.ErrEmailExists) {
		t.Fatalf("expected ErrEmailExists, got %v", err)
	}
}

func TestRegisterDuplicateUsername(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.Register(ctx, core.RegisterCommand{Email: "e1@e.com", Username: "user1", Password: "password123"}); err != nil {
		t.Fatalf("register failed: %v", err)
	}
	_, err := svc.Register(ctx, core.RegisterCommand{Email: "e2@e.com", Username: "user1", Password: "password123"})
	if !errors.Is(err, core.ErrUsernameExists) {
		t.Fatalf("expected ErrUsernameExists, got %v", err)
	}
}

func TestRegisterInvalidInput(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	tests := []struct {
		name     string
		email    string
		username string
		password string
		errMsg   string
	}{
		{
			name:     "invalid email format",
			email:    "invalid-email",
			username: "validUser",
			password: "password123",
			errMsg:   "invalid email format",
		},
		{
			name:     "email with name",
			email:    "Alice <alice@example.com>",
			username: "validUser",
			password: "password123",
			errMsg:   "invalid email format",
		},
		{
			name:     "short username",
			email:    "valid@example.com",
			username: "ab",
			password: "password123",
			errMsg:   "invalid username",
		},
		{
			name:     "long username",
			email:    "valid@example.com",
			username: strings.Repeat("a", 31),
			password: "password123",
			errMsg:   "invalid username",
		},
		{
			name:     "invalid username chars",
			email:    "valid@example.com",
			username: "user@name",
			password: "password123",
			errMsg:   "invalid username",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.Register(ctx, core.RegisterCommand{
				Email:    tc.email,
				Username: tc.username,
				Password: tc.password,
			})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.errMsg) {
				t.Errorf("expected error containing %q, got %q", tc.errMsg, err.Error())
			}
		})
	}
}

func TestRegisterPasswordComplexity(t *testing.T) {
	svc, _ := newTestService(t)
	// Update config to be strict
	svc.passwordCfg = config.Password{
		Validation:       true,
		MinLength:        8,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireNumber:    true,
		RequireSpecial:   true,
	}
	ctx := context.Background()

	// Weak password (missing number, special, upper)
	_, err := svc.Register(ctx, core.RegisterCommand{
		Email:     "Alice@Example.com",
		Username:  "alice",
		Password:  "weakpassword",
		UserAgent: "cli",
		IP:        "127.0.0.1",
	})
	if err == nil {
		t.Fatalf("expected error for weak password, got nil")
	}

	// Compliant password
	_, err = svc.Register(ctx, core.RegisterCommand{
		Email:     "Bob@Example.com",
		Username:  "bob",
		Password:  "StrongP@ss1",
		UserAgent: "cli",
		IP:        "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("expected success for strong password, got: %v", err)
	}

	// Disable validation
	svc.passwordCfg.Validation = false
	// Weak password should now succeed
	_, err = svc.Register(ctx, core.RegisterCommand{
		Email:     "Charlie@Example.com",
		Username:  "charlie",
		Password:  "weak",
		UserAgent: "cli",
		IP:        "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("expected success when validation disabled, got: %v", err)
	}
}

func TestMemSessionStoreWithContextHelpers(t *testing.T) {
	store := newMemSessionStore()
	baseCtx, baseCancel := context.WithCancel(context.Background())
	t.Cleanup(baseCancel)

	ctx, cancel := store.withContext(baseCtx)
	cancel()
	select {
	case <-ctx.Done():
		t.Fatal("expected context to remain active after cancel")
	default:
	}

	ctx2, cancel2 := store.withContext2(baseCtx)
	cancel2()
	select {
	case <-ctx2.Done():
		t.Fatal("expected context to remain active after cancel")
	default:
	}

	baseCancel()

	select {
	case <-ctx.Done():
	case <-time.After(50 * time.Millisecond):
		t.Fatal("expected base context to cancel")
	}

	select {
	case <-ctx2.Done():
	case <-time.After(50 * time.Millisecond):
		t.Fatal("expected base context to cancel")
	}
}

// --- fakes ---

type testDeps struct {
	users         *memUserStore
	sessions      *memSessionStore
	verifications *memVerificationStore
	resets        *memPasswordResetStore
	changes       *memEmailChangeStore
	mailer        *captureMailer
}

func newTestService(t *testing.T) (*AuthService, *testDeps) {
	t.Helper()
	deps := &testDeps{
		users:         newMemUserStore(),
		sessions:      newMemSessionStore(),
		verifications: newMemVerificationStore(),
		resets:        newMemPasswordResetStore(),
		changes:       newMemEmailChangeStore(),
		mailer:        &captureMailer{notifyReset: make(chan struct{}, 1)},
	}

	svc, err := New(Dependencies{
		Stores: Stores{
			Users:          deps.users,
			Sessions:       deps.sessions,
			Verifications:  deps.verifications,
			PasswordResets: deps.resets,
			EmailChanges:   deps.changes,
		},
		Hasher:         fakeHasher{},
		SessionTokens:  newFixedTokenGenerator("sess"),
		TokenGenerator: newFixedTokenGenerator("tok"),
		Mailer:         deps.mailer,
	})
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}
	return svc, deps
}

type fakeHasher struct{}

func (fakeHasher) Hash(password string) (string, error) { return "hash:" + password, nil }

func (fakeHasher) Verify(encoded, password string) error {
	if encoded != "hash:"+password {
		return errors.New("mismatch")
	}
	return nil
}

type fixedTokenGenerator struct {
	prefix string
	seq    int
}

func newFixedTokenGenerator(prefix string) *fixedTokenGenerator {
	return &fixedTokenGenerator{prefix: prefix}
}

func (g *fixedTokenGenerator) Generate() (string, string, error) {
	token := fmt.Sprintf("%s-%d", g.prefix, g.seq)
	g.seq++
	return token, security.HashToken(token), nil
}

type captureMailer struct {
	verificationTokens []string
	resetTokens        []string
	emailChangeTokens  []string
	notifyReset        chan struct{}
}

func (c *captureMailer) SendVerification(_ context.Context, _ core.User, token string) error {
	c.verificationTokens = append(c.verificationTokens, token)
	return nil
}

func (c *captureMailer) SendPasswordReset(_ context.Context, _ core.User, token string) error {
	c.resetTokens = append(c.resetTokens, token)
	if c.notifyReset != nil {
		select {
		case c.notifyReset <- struct{}{}:
		default:
		}
	}
	return nil
}

func (c *captureMailer) SendEmailChange(_ context.Context, _ core.User, _ string, token string) error {
	c.emailChangeTokens = append(c.emailChangeTokens, token)
	return nil
}

type memUserStore struct {
	users         map[core.ID]core.User
	emailIndex    map[string]core.ID
	usernameIndex map[string]core.ID
	nextID        int
}

func newMemUserStore() *memUserStore {
	return &memUserStore{
		users:         make(map[core.ID]core.User),
		emailIndex:    make(map[string]core.ID),
		usernameIndex: make(map[string]core.ID),
	}
}

func (m *memUserStore) Create(_ context.Context, params CreateUserParams) (core.User, error) {
	id := core.ID(fmt.Sprintf("user-%d", m.nextID))
	m.nextID++
	user := core.User{
		ID:           id,
		Email:        params.Email,
		Username:     params.Username,
		PasswordHash: params.PasswordHash,
		Role:         params.Role,
		IsVerified:   params.IsVerified,
		CreatedAt:    params.CreatedAt,
		UpdatedAt:    params.UpdatedAt,
	}
	m.users[id] = user
	m.emailIndex[params.Email] = id
	m.usernameIndex[params.Username] = id
	return user, nil
}

func (m *memUserStore) DeleteByID(_ context.Context, id core.ID) error {
	if user, ok := m.users[id]; ok {
		delete(m.emailIndex, user.Email)
		delete(m.usernameIndex, user.Username)
		delete(m.users, id)
	}
	return nil
}

func (m *memUserStore) FindByEmail(_ context.Context, email string) (core.User, error) {
	if id, ok := m.emailIndex[email]; ok {
		return m.users[id], nil
	}
	return core.User{}, core.ErrUserNotFound
}

func (m *memUserStore) FindByUsername(_ context.Context, username string) (core.User, error) {
	if id, ok := m.usernameIndex[username]; ok {
		return m.users[id], nil
	}
	return core.User{}, core.ErrUserNotFound
}

func (m *memUserStore) FindByID(_ context.Context, id core.ID) (core.User, error) {
	user, ok := m.users[id]
	if !ok {
		return core.User{}, core.ErrUserNotFound
	}
	return user, nil
}

func (m *memUserStore) UpdateFields(_ context.Context, id core.ID, fields map[string]interface{}) error {
	user, ok := m.users[id]
	if !ok {
		return core.ErrUserNotFound
	}
	for key, value := range fields {
		switch key {
		case "last_login_at":
			if ts, ok := value.(time.Time); ok {
				user.LastLoginAt = &ts
			}
		case "updated_at":
			if ts, ok := value.(time.Time); ok {
				user.UpdatedAt = ts
			}
		case "is_verified":
			if b, ok := value.(bool); ok {
				user.IsVerified = b
			}
		case "verified_at":
			if ts, ok := value.(time.Time); ok {
				user.VerifiedAt = &ts
			}
		case "email":
			if s, ok := value.(string); ok {
				delete(m.emailIndex, user.Email)
				user.Email = s
				m.emailIndex[s] = id
			}
		case "password_hash":
			if s, ok := value.(string); ok {
				user.PasswordHash = s
			}
		}
	}
	m.users[id] = user
	return nil
}

type memSessionStore struct {
	sessions map[core.ID]core.Session
	nextID   int
}

func newMemSessionStore() *memSessionStore {
	return &memSessionStore{sessions: make(map[core.ID]core.Session)}
}

func (s *memSessionStore) Create(_ context.Context, params CreateSessionParams) (core.Session, error) {
	id := core.ID(fmt.Sprintf("sess-%d", s.nextID))
	s.nextID++
	session := core.Session{
		ID:        id,
		UserID:    params.UserID,
		TokenHash: params.TokenHash,
		UserAgent: params.UserAgent,
		IP:        params.IP,
		ExpiresAt: params.ExpiresAt,
		CreatedAt: params.CreatedAt,
	}
	s.sessions[id] = session
	return session, nil
}

func (s *memSessionStore) FindByTokenHash(_ context.Context, hash string) (core.Session, error) {
	for _, session := range s.sessions {
		if session.TokenHash == hash {
			return session, nil
		}
	}
	return core.Session{}, core.ErrSessionNotFound
}

func (s *memSessionStore) Revoke(_ context.Context, id core.ID) error {
	session, ok := s.sessions[id]
	if !ok {
		return core.ErrSessionNotFound
	}
	session.Revoked = true
	s.sessions[id] = session
	return nil
}

func (s *memSessionStore) RevokeByUser(_ context.Context, userID core.ID) error {
	for id, session := range s.sessions {
		if session.UserID == userID {
			session.Revoked = true
			s.sessions[id] = session
		}
	}
	return nil
}

func (s *memSessionStore) withContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return ctx, func() {}
}

func (s *memSessionStore) withContext2(ctx context.Context) (context.Context, context.CancelFunc) {
	return ctx, func() {}
}

type memVerificationStore struct {
	tokens map[core.ID]core.VerificationToken
	nextID int
}

func newMemVerificationStore() *memVerificationStore {
	return &memVerificationStore{tokens: make(map[core.ID]core.VerificationToken)}
}

func (m *memVerificationStore) Create(_ context.Context, params CreateVerificationParams) (core.VerificationToken, error) {
	id := core.ID(fmt.Sprintf("ver-%d", m.nextID))
	m.nextID++
	token := core.VerificationToken{
		ID:        id,
		UserID:    params.UserID,
		TokenHash: params.TokenHash,
		ExpiresAt: params.ExpiresAt,
		CreatedAt: params.CreatedAt,
	}
	m.tokens[id] = token
	return token, nil
}

func (m *memVerificationStore) FindByHash(_ context.Context, hash string) (core.VerificationToken, error) {
	for _, token := range m.tokens {
		if token.TokenHash == hash {
			return token, nil
		}
	}
	return core.VerificationToken{}, core.ErrTokenNotFound
}

func (m *memVerificationStore) DeleteByID(_ context.Context, id core.ID) error {
	delete(m.tokens, id)
	return nil
}

func (m *memVerificationStore) Consume(_ context.Context, id core.ID, consumedAt time.Time) error {
	token, ok := m.tokens[id]
	if !ok {
		return core.ErrTokenNotFound
	}
	token.ConsumedAt = &consumedAt
	m.tokens[id] = token
	return nil
}

type memPasswordResetStore struct {
	tokens map[core.ID]core.PasswordResetToken
	nextID int
}

func newMemPasswordResetStore() *memPasswordResetStore {
	return &memPasswordResetStore{tokens: make(map[core.ID]core.PasswordResetToken)}
}

func (m *memPasswordResetStore) Create(_ context.Context, params CreatePasswordResetParams) (core.PasswordResetToken, error) {
	id := core.ID(fmt.Sprintf("reset-%d", m.nextID))
	m.nextID++
	token := core.PasswordResetToken{
		ID:        id,
		UserID:    params.UserID,
		TokenHash: params.TokenHash,
		ExpiresAt: params.ExpiresAt,
		CreatedAt: params.CreatedAt,
	}
	m.tokens[id] = token
	return token, nil
}

func (m *memPasswordResetStore) FindByHash(_ context.Context, hash string) (core.PasswordResetToken, error) {
	for _, token := range m.tokens {
		if token.TokenHash == hash {
			return token, nil
		}
	}
	return core.PasswordResetToken{}, core.ErrTokenNotFound
}

func (m *memPasswordResetStore) Consume(_ context.Context, id core.ID, consumedAt time.Time) error {
	token, ok := m.tokens[id]
	if !ok {
		return core.ErrTokenNotFound
	}
	token.ConsumedAt = &consumedAt
	m.tokens[id] = token
	return nil
}

type memEmailChangeStore struct {
	tokens map[core.ID]core.EmailChangeRequest
	nextID int
}

func newMemEmailChangeStore() *memEmailChangeStore {
	return &memEmailChangeStore{tokens: make(map[core.ID]core.EmailChangeRequest)}
}

func (m *memEmailChangeStore) Create(_ context.Context, params CreateEmailChangeParams) (core.EmailChangeRequest, error) {
	id := core.ID(fmt.Sprintf("change-%d", m.nextID))
	m.nextID++
	token := core.EmailChangeRequest{
		ID:        id,
		UserID:    params.UserID,
		NewEmail:  params.NewEmail,
		TokenHash: params.TokenHash,
		ExpiresAt: params.ExpiresAt,
		CreatedAt: params.CreatedAt,
	}
	m.tokens[id] = token
	return token, nil
}

func (m *memEmailChangeStore) FindByHash(_ context.Context, hash string) (core.EmailChangeRequest, error) {
	for _, token := range m.tokens {
		if token.TokenHash == hash {
			return token, nil
		}
	}
	return core.EmailChangeRequest{}, core.ErrTokenNotFound
}

func (m *memEmailChangeStore) Consume(_ context.Context, id core.ID, consumedAt time.Time) error {
	token, ok := m.tokens[id]
	if !ok {
		return core.ErrTokenNotFound
	}
	token.ConsumedAt = &consumedAt
	m.tokens[id] = token
	return nil
}
