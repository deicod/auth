package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/deicod/auth/config"
	"github.com/deicod/auth/core"
	"github.com/deicod/auth/email"
	"github.com/deicod/auth/internal/security"
)

type AuthService struct {
	stores         Stores
	hasher         PasswordHasher
	sessionTokens  TokenGenerator
	tokenGenerator TokenGenerator
	sessionCfg     config.Session
	tokenCfg       config.Tokens
	passwordCfg    config.Password
	mailer         email.Sender
	dummyHash      string
}

const (
	maxPasswordLength = 1024
	maxEmailLength    = 254
)

func New(deps Dependencies) (*AuthService, error) {
	if deps.Stores.Users == nil || deps.Stores.Sessions == nil || deps.Stores.Verifications == nil || deps.Stores.PasswordResets == nil || deps.Stores.EmailChanges == nil {
		return nil, errors.New("all stores are required")
	}
	if deps.Hasher == nil || deps.SessionTokens == nil || deps.TokenGenerator == nil {
		return nil, errors.New("crypto dependencies are required")
	}

	sessionCfg := deps.SessionCfg
	if sessionCfg.Length <= 0 {
		sessionCfg = config.DefaultSession()
	}

	tokenCfg := deps.TokenCfg
	defaults := config.DefaultTokens()
	if tokenCfg.VerificationTTL <= 0 {
		tokenCfg.VerificationTTL = defaults.VerificationTTL
	}
	if tokenCfg.ResetTTL <= 0 {
		tokenCfg.ResetTTL = defaults.ResetTTL
	}
	if tokenCfg.EmailChangeTTL <= 0 {
		tokenCfg.EmailChangeTTL = defaults.EmailChangeTTL
	}

	passwordCfg := deps.PasswordCfg
	if passwordCfg.MinLength <= 0 {
		passwordCfg = config.DefaultPassword()
	}

	mailer := deps.Mailer
	if mailer == nil {
		mailer = email.NopSender{}
	}

	// Generate a dummy hash for timing attack protection
	dummy, err := deps.Hasher.Hash("dummy_password_for_timing_protection")
	if err != nil {
		return nil, fmt.Errorf("failed to generate dummy hash: %w", err)
	}

	svc := &AuthService{
		stores:         deps.Stores,
		hasher:         deps.Hasher,
		sessionTokens:  deps.SessionTokens,
		tokenGenerator: deps.TokenGenerator,
		sessionCfg:     sessionCfg,
		tokenCfg:       tokenCfg,
		passwordCfg:    passwordCfg,
		mailer:         mailer,
		dummyHash:      dummy,
	}
	return svc, nil
}

func (s *AuthService) Register(ctx context.Context, cmd core.RegisterCommand) (core.AuthResult, error) {
	if len(cmd.Email) > maxEmailLength {
		return core.AuthResult{}, fmt.Errorf("%w: email too long", core.ErrInvalidInput)
	}
	email := normalizeEmail(cmd.Email)
	if !isValidEmail(email) {
		return core.AuthResult{}, fmt.Errorf("%w: invalid email format", core.ErrInvalidInput)
	}

	username := strings.TrimSpace(cmd.Username)
	if !isValidUsername(username) {
		return core.AuthResult{}, fmt.Errorf("%w: invalid username (must be 3-30 chars, alphanumeric, underscore, or hyphen)", core.ErrInvalidInput)
	}

	if err := s.ensureEmailAvailable(ctx, email, ""); err != nil {
		return core.AuthResult{}, err
	}
	if err := s.ensureUsernameAvailable(ctx, username); err != nil {
		return core.AuthResult{}, err
	}
	if len(cmd.Password) > maxPasswordLength {
		return core.AuthResult{}, fmt.Errorf("%w: password too long", core.ErrInvalidInput)
	}
	if len(cmd.Password) < s.passwordCfg.MinLength {
		return core.AuthResult{}, fmt.Errorf("%w: password must be at least %d characters", core.ErrInvalidInput, s.passwordCfg.MinLength)
	}

	hashed, err := s.hasher.Hash(cmd.Password)
	if err != nil {
		return core.AuthResult{}, err
	}

	now := time.Now().UTC()
	user, err := s.stores.Users.Create(ctx, CreateUserParams{
		Email:        email,
		Username:     username,
		PasswordHash: hashed,
		Role:         core.RoleUser,
		IsVerified:   false,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		return core.AuthResult{}, err
	}

	token, verificationID, err := s.issueVerification(ctx, user)
	if err != nil {
		_ = s.stores.Users.DeleteByID(ctx, user.ID)
		return core.AuthResult{}, err
	}
	if err := s.mailer.SendVerification(ctx, user, token); err != nil {
		_ = s.stores.Verifications.DeleteByID(ctx, verificationID)
		_ = s.stores.Users.DeleteByID(ctx, user.ID)
		return core.AuthResult{}, err
	}

	session, sessionToken, err := s.createSession(ctx, user.ID, cmd.UserAgent, cmd.IP)
	if err != nil {
		_ = s.stores.Verifications.DeleteByID(ctx, verificationID)
		_ = s.stores.Users.DeleteByID(ctx, user.ID)
		return core.AuthResult{}, err
	}

	result := core.AuthResult{
		User:    core.NewUserPublic(user),
		Session: core.NewSessionPublic(session),
		Token:   sessionToken,
	}
	return result, nil
}

func (s *AuthService) Login(ctx context.Context, cmd core.LoginCommand) (core.AuthResult, error) {
	if len(cmd.Password) > maxPasswordLength {
		return core.AuthResult{}, core.ErrInvalidCredentials
	}

	email := normalizeEmail(cmd.Email)
	user, err := s.stores.Users.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, core.ErrUserNotFound) {
			// Simulate password verification to prevent timing attacks (username enumeration)
			_ = s.hasher.Verify(s.dummyHash, cmd.Password)
			return core.AuthResult{}, core.ErrInvalidCredentials
		}
		return core.AuthResult{}, err
	}

	if err := s.hasher.Verify(user.PasswordHash, cmd.Password); err != nil {
		return core.AuthResult{}, core.ErrInvalidCredentials
	}

	now := time.Now().UTC()
	updates := map[string]interface{}{
		"last_login_at": now,
		"updated_at":    now,
	}
	_ = s.stores.Users.UpdateFields(ctx, user.ID, updates)

	session, token, err := s.createSession(ctx, user.ID, cmd.UserAgent, cmd.IP)
	if err != nil {
		return core.AuthResult{}, err
	}

	user.LastLoginAt = &now
	return core.AuthResult{
		User:    core.NewUserPublic(user),
		Session: core.NewSessionPublic(session),
		Token:   token,
	}, nil
}

func (s *AuthService) VerifyEmail(ctx context.Context, cmd core.VerifyEmailCommand) (core.VerifyEmailResult, error) {
	hash := security.HashToken(cmd.Token)
	token, err := s.stores.Verifications.FindByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, core.ErrTokenNotFound) {
			return core.VerifyEmailResult{}, core.ErrTokenNotFound
		}
		return core.VerifyEmailResult{}, err
	}

	if token.ConsumedAt != nil {
		return core.VerifyEmailResult{}, core.ErrTokenConsumed
	}
	if time.Now().UTC().After(token.ExpiresAt) {
		return core.VerifyEmailResult{}, core.ErrTokenExpired
	}

	now := time.Now().UTC()
	updates := map[string]interface{}{
		"is_verified": true,
		"verified_at": now,
		"updated_at":  now,
	}
	if err := s.stores.Users.UpdateFields(ctx, token.UserID, updates); err != nil {
		return core.VerifyEmailResult{}, err
	}
	if err := s.stores.Verifications.Consume(ctx, token.ID, now); err != nil {
		return core.VerifyEmailResult{}, err
	}

	user, err := s.stores.Users.FindByID(ctx, token.UserID)
	if err != nil {
		return core.VerifyEmailResult{}, err
	}
	return core.VerifyEmailResult{User: core.NewUserPublic(user)}, nil
}

func (s *AuthService) ForgotPassword(ctx context.Context, cmd core.ForgotPasswordCommand) error {
	email := normalizeEmail(cmd.Email)
	user, err := s.stores.Users.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, core.ErrUserNotFound) {
			return nil
		}
		return err
	}

	// Generate token and send email asynchronously to prevent timing attacks (username enumeration).
	// We must move BOTH the DB write and the email sending to the background goroutine.
	// If the DB write remains synchronous, an attacker can distinguish "User Found" (slow DB write)
	// from "User Not Found" (fast return) by measuring response latency.
	go func() {
		// Use a detached context for the background operation
		ctx := context.Background()

		token, err := s.issuePasswordReset(ctx, user)
		if err != nil {
			log.Printf("failed to issue password reset token for user %s: %v", user.ID, err)
			return
		}

		if err := s.mailer.SendPasswordReset(ctx, user, token); err != nil {
			log.Printf("failed to send password reset email to user %s: %v", user.ID, err)
		}
	}()

	return nil
}

func (s *AuthService) ResetPassword(ctx context.Context, cmd core.ResetPasswordCommand) (core.UserPublic, error) {
	hash := security.HashToken(cmd.Token)
	token, err := s.stores.PasswordResets.FindByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, core.ErrTokenNotFound) {
			return core.UserPublic{}, core.ErrTokenNotFound
		}
		return core.UserPublic{}, err
	}

	if token.ConsumedAt != nil {
		return core.UserPublic{}, core.ErrTokenConsumed
	}
	if time.Now().UTC().After(token.ExpiresAt) {
		return core.UserPublic{}, core.ErrTokenExpired
	}
	if len(cmd.NewPassword) > maxPasswordLength {
		return core.UserPublic{}, fmt.Errorf("%w: password too long", core.ErrInvalidInput)
	}
	if len(cmd.NewPassword) < s.passwordCfg.MinLength {
		return core.UserPublic{}, fmt.Errorf("%w: password must be at least %d characters", core.ErrInvalidInput, s.passwordCfg.MinLength)
	}

	hashed, err := s.hasher.Hash(cmd.NewPassword)
	if err != nil {
		return core.UserPublic{}, err
	}

	now := time.Now().UTC()
	if err := s.stores.Users.UpdateFields(ctx, token.UserID, map[string]interface{}{
		"password_hash": hashed,
		"updated_at":    now,
	}); err != nil {
		return core.UserPublic{}, err
	}
	if err := s.stores.PasswordResets.Consume(ctx, token.ID, now); err != nil {
		return core.UserPublic{}, err
	}
	if err := s.stores.Sessions.RevokeByUser(ctx, token.UserID); err != nil {
		return core.UserPublic{}, err
	}

	user, err := s.stores.Users.FindByID(ctx, token.UserID)
	if err != nil {
		return core.UserPublic{}, err
	}
	return core.NewUserPublic(user), nil
}

func (s *AuthService) InitiateEmailChange(ctx context.Context, cmd core.ChangeEmailCommand) error {
	user, err := s.stores.Users.FindByID(ctx, cmd.UserID)
	if err != nil {
		return err
	}

	if len(cmd.Password) > maxPasswordLength {
		return core.ErrInvalidCredentials
	}
	if err := s.hasher.Verify(user.PasswordHash, cmd.Password); err != nil {
		return core.ErrInvalidCredentials
	}

	if len(cmd.NewEmail) > maxEmailLength {
		return fmt.Errorf("%w: email too long", core.ErrInvalidInput)
	}
	newEmail := normalizeEmail(cmd.NewEmail)
	if err := s.ensureEmailAvailable(ctx, newEmail, user.ID); err != nil {
		return err
	}

	token, err := s.issueEmailChange(ctx, user, newEmail)
	if err != nil {
		return err
	}
	return s.mailer.SendEmailChange(ctx, user, newEmail, token)
}

func (s *AuthService) ConfirmEmailChange(ctx context.Context, cmd core.ConfirmEmailChangeCommand) (core.ChangeEmailResult, error) {
	hash := security.HashToken(cmd.Token)
	req, err := s.stores.EmailChanges.FindByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, core.ErrTokenNotFound) {
			return core.ChangeEmailResult{}, core.ErrTokenNotFound
		}
		return core.ChangeEmailResult{}, err
	}

	if req.ConsumedAt != nil {
		return core.ChangeEmailResult{}, core.ErrTokenConsumed
	}
	if time.Now().UTC().After(req.ExpiresAt) {
		return core.ChangeEmailResult{}, core.ErrTokenExpired
	}

	now := time.Now().UTC()
	updates := map[string]interface{}{
		"email":       req.NewEmail,
		"updated_at":  now,
		"is_verified": true,
		"verified_at": now,
	}
	if err := s.stores.Users.UpdateFields(ctx, req.UserID, updates); err != nil {
		return core.ChangeEmailResult{}, err
	}
	if err := s.stores.EmailChanges.Consume(ctx, req.ID, now); err != nil {
		return core.ChangeEmailResult{}, err
	}

	user, err := s.stores.Users.FindByID(ctx, req.UserID)
	if err != nil {
		return core.ChangeEmailResult{}, err
	}
	return core.ChangeEmailResult{User: core.NewUserPublic(user)}, nil
}

func (s *AuthService) AuthenticateSession(ctx context.Context, token string) (core.UserPublic, core.SessionPublic, error) {
	if strings.TrimSpace(token) == "" {
		return core.UserPublic{}, core.SessionPublic{}, core.ErrSessionNotFound
	}
	hash := security.HashToken(token)
	session, err := s.stores.Sessions.FindByTokenHash(ctx, hash)
	if err != nil {
		if errors.Is(err, core.ErrSessionNotFound) {
			return core.UserPublic{}, core.SessionPublic{}, core.ErrSessionNotFound
		}
		return core.UserPublic{}, core.SessionPublic{}, err
	}

	now := time.Now().UTC()
	if session.Revoked || now.After(session.ExpiresAt) {
		_ = s.stores.Sessions.Revoke(ctx, session.ID)
		return core.UserPublic{}, core.SessionPublic{}, core.ErrSessionNotFound
	}

	user, err := s.stores.Users.FindByID(ctx, session.UserID)
	if err != nil {
		return core.UserPublic{}, core.SessionPublic{}, err
	}
	return core.NewUserPublic(user), core.NewSessionPublic(session), nil
}

func (s *AuthService) Logout(ctx context.Context, token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return core.ErrSessionNotFound
	}
	hash := security.HashToken(token)
	session, err := s.stores.Sessions.FindByTokenHash(ctx, hash)
	if err != nil {
		if errors.Is(err, core.ErrSessionNotFound) {
			return core.ErrSessionNotFound
		}
		return err
	}

	now := time.Now().UTC()
	if session.Revoked || now.After(session.ExpiresAt) {
		_ = s.stores.Sessions.Revoke(ctx, session.ID)
		return core.ErrSessionNotFound
	}

	return s.stores.Sessions.Revoke(ctx, session.ID)
}

func (s *AuthService) createSession(ctx context.Context, userID core.ID, userAgent, ip string) (core.Session, string, error) {
	token, hash, err := s.sessionTokens.Generate()
	if err != nil {
		return core.Session{}, "", err
	}

	now := time.Now().UTC()
	session, err := s.stores.Sessions.Create(ctx, CreateSessionParams{
		UserID:    userID,
		TokenHash: hash,
		UserAgent: userAgent,
		IP:        ip,
		ExpiresAt: now.Add(s.sessionCfg.Length),
		CreatedAt: now,
	})
	if err != nil {
		return core.Session{}, "", err
	}
	return session, token, nil
}

func (s *AuthService) issueVerification(ctx context.Context, user core.User) (string, core.ID, error) {
	token, hash, err := s.tokenGenerator.Generate()
	if err != nil {
		return "", "", err
	}
	now := time.Now().UTC()
	record, err := s.stores.Verifications.Create(ctx, CreateVerificationParams{
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: now.Add(s.tokenCfg.VerificationTTL),
		CreatedAt: now,
	})
	if err != nil {
		return "", "", err
	}
	return token, record.ID, nil
}

func (s *AuthService) issuePasswordReset(ctx context.Context, user core.User) (string, error) {
	token, hash, err := s.tokenGenerator.Generate()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	if _, err := s.stores.PasswordResets.Create(ctx, CreatePasswordResetParams{
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: now.Add(s.tokenCfg.ResetTTL),
		CreatedAt: now,
	}); err != nil {
		return "", err
	}
	return token, nil
}

func (s *AuthService) issueEmailChange(ctx context.Context, user core.User, newEmail string) (string, error) {
	token, hash, err := s.tokenGenerator.Generate()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	if _, err := s.stores.EmailChanges.Create(ctx, CreateEmailChangeParams{
		UserID:    user.ID,
		NewEmail:  newEmail,
		TokenHash: hash,
		ExpiresAt: now.Add(s.tokenCfg.EmailChangeTTL),
		CreatedAt: now,
	}); err != nil {
		return "", err
	}
	return token, nil
}

func (s *AuthService) ensureEmailAvailable(ctx context.Context, email string, exclude core.ID) error {
	if email == "" {
		return fmt.Errorf("%w: email is required", core.ErrInvalidInput)
	}
	user, err := s.stores.Users.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, core.ErrUserNotFound) {
			return nil
		}
		return err
	}
	if exclude != "" && user.ID == exclude {
		return nil
	}
	return core.ErrEmailExists
}

func (s *AuthService) ensureUsernameAvailable(ctx context.Context, username string) error {
	if username == "" {
		return fmt.Errorf("%w: username is required", core.ErrInvalidInput)
	}
	_, err := s.stores.Users.FindByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, core.ErrUserNotFound) {
			return nil
		}
		return err
	}
	return core.ErrUsernameExists
}

func normalizeEmail(email string) string {
	return strings.TrimSpace(strings.ToLower(email))
}

func isValidEmail(email string) bool {
	// basic structure check
	if !strings.Contains(email, "@") {
		return false
	}
	// ParseAddress follows RFC 5322, which is generous.
	// We want to ensure it parses correctly at minimum.
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}
	// Ensure the parsed address matches the input (disallow "Alice <alice@example.com>")
	return addr.Address == email
}

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{3,30}$`)

func isValidUsername(username string) bool {
	return usernameRegex.MatchString(username)
}
