package mgo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/deicod/auth/config"
	"github.com/deicod/auth/core"
	"github.com/deicod/auth/email"
	"github.com/deicod/auth/mgo/models"
	"github.com/deicod/auth/mgo/repos"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Service struct {
	client        *mongo.Client
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
}

func (s *Service) Close(ctx context.Context) error {
	if s.client == nil {
		return nil
	}
	return s.client.Disconnect(ctx)
}

func NewService(ctx context.Context, cfg ServiceConfig) (*Service, error) {
	if cfg.Mongo.URI == "" {
		return nil, errors.New("mongo URI is required")
	}
	if cfg.Mongo.Database == "" {
		return nil, errors.New("mongo database is required")
	}

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.Mongo.URI))
	if err != nil {
		return nil, err
	}

	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(ctx)
		return nil, err
	}

	timeout := cfg.Mongo.OperationTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
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

	mongoCfg := cfg.Mongo
	if mongoCfg.UsersCollection == "" {
		mongoCfg.UsersCollection = "users"
	}
	if mongoCfg.SessionsCollection == "" {
		mongoCfg.SessionsCollection = "sessions"
	}
	if mongoCfg.VerificationCollection == "" {
		mongoCfg.VerificationCollection = "email_verifications"
	}
	if mongoCfg.PasswordResetCollection == "" {
		mongoCfg.PasswordResetCollection = "password_resets"
	}
	if mongoCfg.EmailChangeCollection == "" {
		mongoCfg.EmailChangeCollection = "email_changes"
	}

	db := client.Database(mongoCfg.Database)
	mailer := email.Sender(email.NopSender{})
	if cfg.Email.Host != "" {
		mailer = email.NewMailer(cfg.Email)
	}

	svc := &Service{
		client:        client,
		users:         repos.NewUserRepository(db.Collection(mongoCfg.UsersCollection), timeout),
		sessions:      repos.NewSessionRepository(db.Collection(mongoCfg.SessionsCollection), timeout),
		verifications: repos.NewVerificationRepository(db.Collection(mongoCfg.VerificationCollection), timeout),
		resets:        repos.NewPasswordResetRepository(db.Collection(mongoCfg.PasswordResetCollection), timeout),
		emailChanges:  repos.NewEmailChangeRepository(db.Collection(mongoCfg.EmailChangeCollection), timeout),
		hasher:        newPasswordHasher(argonCfg),
		sessionGen:    newTokenGenerator(48),
		tokenGen:      newTokenGenerator(32),
		sessionCfg:    sessionCfg,
		tokenCfg:      tokenCfg,
		mailer:        mailer,
	}

	return svc, nil
}

func (s *Service) Register(ctx context.Context, cmd core.RegisterCommand) (core.AuthResult, error) {
	email := normalizeEmail(cmd.Email)
	username := strings.TrimSpace(cmd.Username)

	if err := s.ensureEmailAvailable(ctx, email, primitive.NilObjectID); err != nil {
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
	role := core.RoleUser

	userModel := models.User{
		Email:        email,
		Username:     username,
		PasswordHash: hashed,
		Role:         string(role),
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
	if err := s.mailer.SendVerification(ctx, models.UserToCore(created), token); err != nil {
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

	publicUser := core.NewUserPublic(models.UserToCore(created))
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
		if errors.Is(err, mongo.ErrNoDocuments) {
			return core.AuthResult{}, core.ErrInvalidCredentials
		}
		return core.AuthResult{}, err
	}

	if err := s.hasher.Verify(userModel.PasswordHash, cmd.Password); err != nil {
		return core.AuthResult{}, core.ErrInvalidCredentials
	}

	now := time.Now().UTC()
	_ = s.users.UpdateFields(ctx, userModel.ID, bson.M{
		"last_login_at": now,
		"updated_at":    now,
	})

	session, token, err := s.createSession(ctx, userModel.ID, cmd.UserAgent, cmd.IP)
	if err != nil {
		return core.AuthResult{}, err
	}

	user := models.UserToCore(userModel)
	user.LastLoginAt = &now
	result := core.AuthResult{
		User:    core.NewUserPublic(user),
		Session: core.NewSessionPublic(session),
		Token:   token,
	}
	return result, nil
}

func (s *Service) VerifyEmail(ctx context.Context, cmd core.VerifyEmailCommand) (core.VerifyEmailResult, error) {
	hash := hashToken(cmd.Token)
	token, err := s.verifications.FindByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
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
	err = s.users.UpdateFields(ctx, token.UserID, bson.M{
		"is_verified": true,
		"verified_at": now,
		"updated_at":  now,
	})
	if err != nil {
		return core.VerifyEmailResult{}, err
	}

	if err := s.verifications.Consume(ctx, token.ID, now); err != nil {
		return core.VerifyEmailResult{}, err
	}

	userModel, err := s.users.FindByID(ctx, token.UserID)
	if err != nil {
		return core.VerifyEmailResult{}, err
	}
	user := models.UserToCore(userModel)
	result := core.VerifyEmailResult{User: core.NewUserPublic(user)}
	return result, nil
}

func (s *Service) ForgotPassword(ctx context.Context, cmd core.ForgotPasswordCommand) error {
	email := normalizeEmail(cmd.Email)
	userModel, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil
		}
		return err
	}

	token, err := s.issuePasswordReset(ctx, userModel)
	if err != nil {
		return err
	}
	return s.mailer.SendPasswordReset(ctx, models.UserToCore(userModel), token)
}

func (s *Service) ResetPassword(ctx context.Context, cmd core.ResetPasswordCommand) (core.UserPublic, error) {
	hash := hashToken(cmd.Token)
	token, err := s.resets.FindByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
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
	if err := s.users.UpdateFields(ctx, token.UserID, bson.M{
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
	return core.NewUserPublic(models.UserToCore(userModel)), nil
}

func (s *Service) InitiateEmailChange(ctx context.Context, cmd core.ChangeEmailCommand) error {
	userID, err := models.ObjectIDFromCore(cmd.UserID)
	if err != nil {
		return fmt.Errorf("%w: invalid user id", core.ErrInvalidInput)
	}
	userModel, err := s.users.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
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
	return s.mailer.SendEmailChange(ctx, models.UserToCore(userModel), newEmail, token)
}

func (s *Service) ConfirmEmailChange(ctx context.Context, cmd core.ConfirmEmailChangeCommand) (core.ChangeEmailResult, error) {
	hash := hashToken(cmd.Token)
	req, err := s.emailChanges.FindByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
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
	update := bson.M{
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
	user := core.NewUserPublic(models.UserToCore(userModel))
	return core.ChangeEmailResult{User: user}, nil
}

func (s *Service) createSession(ctx context.Context, userID primitive.ObjectID, userAgent, ip string) (core.Session, string, error) {
	token, hash, err := s.sessionGen.Generate()
	if err != nil {
		return core.Session{}, "", err
	}
	now := time.Now().UTC()
	session := models.Session{
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
	return models.SessionToCore(created), token, nil
}

func (s *Service) ensureEmailAvailable(ctx context.Context, email string, exclude primitive.ObjectID) error {
	if email == "" {
		return fmt.Errorf("%w: email is required", core.ErrInvalidInput)
	}
	existing, err := s.users.FindByEmail(ctx, email)
	if err == nil {
		if !exclude.IsZero() && existing.ID == exclude {
			return nil
		}
		return core.ErrEmailExists
	}
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil
	}
	return err
}

func (s *Service) ensureUsernameAvailable(ctx context.Context, username string) error {
	if username == "" {
		return fmt.Errorf("%w: username is required", core.ErrInvalidInput)
	}
	_, err := s.users.FindByUsername(ctx, username)
	if err == nil {
		return core.ErrUsernameExists
	}
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil
	}
	return err
}

func (s *Service) issueVerification(ctx context.Context, user models.User) (string, primitive.ObjectID, error) {
	token, hash, err := s.tokenGen.Generate()
	if err != nil {
		return "", primitive.NilObjectID, err
	}
	now := time.Now().UTC()
	record := models.VerificationToken{
		ID:        primitive.NewObjectID(),
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: now.Add(s.tokenCfg.VerificationTTL),
		CreatedAt: now,
	}
	if _, err := s.verifications.Create(ctx, record); err != nil {
		return "", primitive.NilObjectID, err
	}
	return token, record.ID, nil
}

func (s *Service) issuePasswordReset(ctx context.Context, user models.User) (string, error) {
	token, hash, err := s.tokenGen.Generate()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	record := models.PasswordReset{
		ID:        primitive.NewObjectID(),
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

func (s *Service) issueEmailChange(ctx context.Context, user models.User, newEmail string) (string, error) {
	token, hash, err := s.tokenGen.Generate()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	record := models.EmailChange{
		ID:        primitive.NewObjectID(),
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
