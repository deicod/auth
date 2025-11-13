package pgx

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/deicod/auth/config"
	"github.com/deicod/auth/core"
	"github.com/deicod/auth/email"
	pgxmodels "github.com/deicod/auth/pgx/models"
	"github.com/deicod/auth/pgx/repos"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Service struct {
	pool          *pgxpool.Pool
	users         *repos.UserRepository
	sessions      *repos.SessionRepository
	verifications *repos.VerificationRepository
	resets        *repos.PasswordResetRepository
	emailChanges  *repos.EmailChangeRepository
	hasher        passwordHasher
	sessionGen    tokenGenerator
	tokenGen      tokenGenerator
	sessionCfg    config.Session
	tokenCfg      config.Tokens
	mailer        email.Sender
	timeout       time.Duration
}

func NewService(ctx context.Context, cfg ServiceConfig) (*Service, error) {
	if cfg.Pgx.DSN == "" {
		return nil, errors.New("pgx DSN is required")
	}
	poolCfg, err := pgxpool.ParseConfig(cfg.Pgx.DSN)
	if err != nil {
		return nil, err
	}
	if cfg.Pgx.MaxConns > 0 {
		poolCfg.MaxConns = cfg.Pgx.MaxConns
	}
	if cfg.Pgx.MinConns > 0 {
		poolCfg.MinConns = cfg.Pgx.MinConns
	}
	if cfg.Pgx.HealthCheckInterval > 0 {
		poolCfg.HealthCheckPeriod = cfg.Pgx.HealthCheckInterval
	}
	if cfg.Pgx.MaxConnLifetime > 0 {
		poolCfg.MaxConnLifetime = cfg.Pgx.MaxConnLifetime
	}
	if cfg.Pgx.MaxConnIdleTime > 0 {
		poolCfg.MaxConnIdleTime = cfg.Pgx.MaxConnIdleTime
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	if err := applyMigrations(ctx, pool); err != nil {
		pool.Close()
		return nil, err
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

	timeout := cfg.Pgx.OperationTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	mailer := email.Sender(email.NopSender{})
	if cfg.Email.Host != "" {
		mailer = email.NewMailer(cfg.Email)
	}

	svc := &Service{
		pool:          pool,
		users:         repos.NewUserRepository(pool, timeout),
		sessions:      repos.NewSessionRepository(pool, timeout),
		verifications: repos.NewVerificationRepository(pool, timeout),
		resets:        repos.NewPasswordResetRepository(pool, timeout),
		emailChanges:  repos.NewEmailChangeRepository(pool, timeout),
		hasher:        newPasswordHasher(argonCfg),
		sessionGen:    newTokenGenerator(48),
		tokenGen:      newTokenGenerator(32),
		sessionCfg:    sessionCfg,
		tokenCfg:      tokenCfg,
		mailer:        mailer,
		timeout:       timeout,
	}
	return svc, nil
}

func (s *Service) Close(context.Context) error {
	if s.pool != nil {
		s.pool.Close()
	}
	return nil
}

func (s *Service) Register(ctx context.Context, cmd core.RegisterCommand) (core.AuthResult, error) {
	email := normalizeEmail(cmd.Email)
	username := strings.TrimSpace(cmd.Username)

	if err := s.ensureEmailAvailable(ctx, email, uuid.Nil); err != nil {
		return core.AuthResult{}, err
	}
	if err := s.ensureUsernameAvailable(ctx, username); err != nil {
		return core.AuthResult{}, err
	}
	if cmd.Password == "" {
		return core.AuthResult{}, fmt.Errorf("%w: password is required", core.ErrInvalidInput)
	}

	hashed, err := s.hasher.Hash(cmd.Password)
	if err != nil {
		return core.AuthResult{}, err
	}

	now := time.Now().UTC()
	userModel := pgxmodels.User{
		Email:        email,
		Username:     username,
		PasswordHash: hashed,
		Role:         string(core.RoleUser),
		IsVerified:   false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	created, err := s.users.Create(ctx, userModel)
	if err != nil {
		return core.AuthResult{}, err
	}

	token, tokenID, err := s.issueVerification(ctx, created)
	if err != nil {
		_ = s.users.DeleteByID(ctx, created.ID)
		return core.AuthResult{}, err
	}
	if err := s.mailer.SendVerification(ctx, pgxmodels.UserToCore(created), token); err != nil {
		_ = s.verifications.DeleteByID(ctx, tokenID)
		_ = s.users.DeleteByID(ctx, created.ID)
		return core.AuthResult{}, err
	}

	session, sessionToken, err := s.createSession(ctx, created.ID, cmd.UserAgent, cmd.IP)
	if err != nil {
		_ = s.verifications.DeleteByID(ctx, tokenID)
		_ = s.users.DeleteByID(ctx, created.ID)
		return core.AuthResult{}, err
	}

	publicUser := core.NewUserPublic(pgxmodels.UserToCore(created))
	result := core.AuthResult{
		User:    publicUser,
		Session: core.NewSessionPublic(session),
		Token:   sessionToken,
	}
	return result, nil
}

func (s *Service) Login(ctx context.Context, cmd core.LoginCommand) (core.AuthResult, error) {
	email := normalizeEmail(cmd.Email)
	userModel, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.AuthResult{}, core.ErrInvalidCredentials
		}
		return core.AuthResult{}, err
	}

	if err := s.hasher.Verify(userModel.PasswordHash, cmd.Password); err != nil {
		return core.AuthResult{}, core.ErrInvalidCredentials
	}

	now := time.Now().UTC()
	_ = s.users.UpdateFields(ctx, userModel.ID, map[string]interface{}{
		"last_login_at": now,
		"updated_at":    now,
	})

	session, token, err := s.createSession(ctx, userModel.ID, cmd.UserAgent, cmd.IP)
	if err != nil {
		return core.AuthResult{}, err
	}

	user := pgxmodels.UserToCore(userModel)
	user.LastLoginAt = &now
	return core.AuthResult{
		User:    core.NewUserPublic(user),
		Session: core.NewSessionPublic(session),
		Token:   token,
	}, nil
}

func (s *Service) VerifyEmail(ctx context.Context, cmd core.VerifyEmailCommand) (core.VerifyEmailResult, error) {
	hash := hashToken(cmd.Token)
	token, err := s.verifications.FindByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
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
	if err := s.users.UpdateFields(ctx, token.UserID, map[string]interface{}{
		"is_verified": true,
		"verified_at": now,
		"updated_at":  now,
	}); err != nil {
		return core.VerifyEmailResult{}, err
	}
	if err := s.verifications.Consume(ctx, token.ID, now); err != nil {
		return core.VerifyEmailResult{}, err
	}

	userModel, err := s.users.FindByID(ctx, token.UserID)
	if err != nil {
		return core.VerifyEmailResult{}, err
	}
	return core.VerifyEmailResult{User: core.NewUserPublic(pgxmodels.UserToCore(userModel))}, nil
}

func (s *Service) ForgotPassword(ctx context.Context, cmd core.ForgotPasswordCommand) error {
	email := normalizeEmail(cmd.Email)
	userModel, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}

	token, err := s.issuePasswordReset(ctx, userModel)
	if err != nil {
		return err
	}
	return s.mailer.SendPasswordReset(ctx, pgxmodels.UserToCore(userModel), token)
}

func (s *Service) ResetPassword(ctx context.Context, cmd core.ResetPasswordCommand) (core.UserPublic, error) {
	hash := hashToken(cmd.Token)
	token, err := s.resets.FindByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
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
	if cmd.NewPassword == "" {
		return core.UserPublic{}, fmt.Errorf("%w: password is required", core.ErrInvalidInput)
	}

	hashed, err := s.hasher.Hash(cmd.NewPassword)
	if err != nil {
		return core.UserPublic{}, err
	}

	now := time.Now().UTC()
	if err := s.users.UpdateFields(ctx, token.UserID, map[string]interface{}{
		"password_hash": hashed,
		"updated_at":    now,
	}); err != nil {
		return core.UserPublic{}, err
	}
	if err := s.resets.Consume(ctx, token.ID, now); err != nil {
		return core.UserPublic{}, err
	}

	userModel, err := s.users.FindByID(ctx, token.UserID)
	if err != nil {
		return core.UserPublic{}, err
	}
	return core.NewUserPublic(pgxmodels.UserToCore(userModel)), nil
}

func (s *Service) InitiateEmailChange(ctx context.Context, cmd core.ChangeEmailCommand) error {
	userID, err := pgxmodels.UUIDFromCore(cmd.UserID)
	if err != nil {
		return fmt.Errorf("%w: invalid user id", core.ErrInvalidInput)
	}
	userModel, err := s.users.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.ErrUserNotFound
		}
		return err
	}

	if err := s.hasher.Verify(userModel.PasswordHash, cmd.Password); err != nil {
		return core.ErrInvalidCredentials
	}

	newEmail := normalizeEmail(cmd.NewEmail)
	if newEmail == "" {
		return fmt.Errorf("%w: new email is required", core.ErrInvalidInput)
	}
	if newEmail == userModel.Email {
		return core.ErrEmailExists
	}
	if err := s.ensureEmailAvailable(ctx, newEmail, userModel.ID); err != nil {
		return err
	}

	token, err := s.issueEmailChange(ctx, userModel, newEmail)
	if err != nil {
		return err
	}
	return s.mailer.SendEmailChange(ctx, pgxmodels.UserToCore(userModel), newEmail, token)
}

func (s *Service) ConfirmEmailChange(ctx context.Context, cmd core.ConfirmEmailChangeCommand) (core.ChangeEmailResult, error) {
	hash := hashToken(cmd.Token)
	req, err := s.emailChanges.FindByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
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
	update := map[string]interface{}{
		"email":       req.NewEmail,
		"updated_at":  now,
		"is_verified": true,
		"verified_at": now,
	}
	if err := s.users.UpdateFields(ctx, req.UserID, update); err != nil {
		return core.ChangeEmailResult{}, err
	}
	if err := s.emailChanges.Consume(ctx, req.ID, now); err != nil {
		return core.ChangeEmailResult{}, err
	}

	userModel, err := s.users.FindByID(ctx, req.UserID)
	if err != nil {
		return core.ChangeEmailResult{}, err
	}
	return core.ChangeEmailResult{User: core.NewUserPublic(pgxmodels.UserToCore(userModel))}, nil
}

func (s *Service) createSession(ctx context.Context, userID uuid.UUID, userAgent, ip string) (core.Session, string, error) {
	token, hash, err := s.sessionGen.Generate()
	if err != nil {
		return core.Session{}, "", err
	}
	now := time.Now().UTC()
	session := pgxmodels.Session{
		UserID:    userID,
		TokenHash: hash,
		UserAgent: userAgent,
		IP:        ip,
		ExpiresAt: now.Add(s.sessionCfg.Length),
		CreatedAt: now,
		Revoked:   false,
	}
	created, err := s.sessions.Create(ctx, session)
	if err != nil {
		return core.Session{}, "", err
	}
	return pgxmodels.SessionToCore(created), token, nil
}

func (s *Service) ensureEmailAvailable(ctx context.Context, email string, exclude uuid.UUID) error {
	if email == "" {
		return fmt.Errorf("%w: email is required", core.ErrInvalidInput)
	}
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	if exclude != uuid.Nil && user.ID == exclude {
		return nil
	}
	return core.ErrEmailExists
}

func (s *Service) ensureUsernameAvailable(ctx context.Context, username string) error {
	if username == "" {
		return fmt.Errorf("%w: username is required", core.ErrInvalidInput)
	}
	_, err := s.users.FindByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	return core.ErrUsernameExists
}

func (s *Service) issueVerification(ctx context.Context, user pgxmodels.User) (string, uuid.UUID, error) {
	token, hash, err := s.tokenGen.Generate()
	if err != nil {
		return "", uuid.Nil, err
	}
	now := time.Now().UTC()
	record := pgxmodels.VerificationToken{
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: now.Add(s.tokenCfg.VerificationTTL),
		CreatedAt: now,
	}
	created, err := s.verifications.Create(ctx, record)
	if err != nil {
		return "", uuid.Nil, err
	}
	return token, created.ID, nil
}

func (s *Service) issuePasswordReset(ctx context.Context, user pgxmodels.User) (string, error) {
	token, hash, err := s.tokenGen.Generate()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	record := pgxmodels.PasswordReset{
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: now.Add(s.tokenCfg.ResetTTL),
		CreatedAt: now,
	}
	if _, err := s.resets.Create(ctx, record); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Service) issueEmailChange(ctx context.Context, user pgxmodels.User, newEmail string) (string, error) {
	token, hash, err := s.tokenGen.Generate()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	record := pgxmodels.EmailChange{
		UserID:    user.ID,
		NewEmail:  newEmail,
		TokenHash: hash,
		ExpiresAt: now.Add(s.tokenCfg.EmailChangeTTL),
		CreatedAt: now,
	}
	if _, err := s.emailChanges.Create(ctx, record); err != nil {
		return "", err
	}
	return token, nil
}

func normalizeEmail(email string) string {
	return strings.TrimSpace(strings.ToLower(email))
}
