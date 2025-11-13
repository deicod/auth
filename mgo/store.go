package mgo

import (
	"context"
	"errors"
	"time"

	"github.com/deicod/auth/core"
	"github.com/deicod/auth/core/services"
	"github.com/deicod/auth/mgo/models"
	"github.com/deicod/auth/mgo/repos"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type userStore struct {
	repo *repos.UserRepository
}

func newUserStore(repo *repos.UserRepository) services.UserStore {
	return &userStore{repo: repo}
}

func (s *userStore) Create(ctx context.Context, params services.CreateUserParams) (core.User, error) {
	user := models.User{
		Email:        params.Email,
		Username:     params.Username,
		PasswordHash: params.PasswordHash,
		Role:         string(params.Role),
		IsVerified:   params.IsVerified,
		CreatedAt:    params.CreatedAt,
		UpdatedAt:    params.UpdatedAt,
	}
	created, err := s.repo.Create(ctx, user)
	if err != nil {
		return core.User{}, err
	}
	return models.UserToCore(created), nil
}

func (s *userStore) DeleteByID(ctx context.Context, id core.ID) error {
	oid, err := models.ObjectIDFromCore(id)
	if err != nil {
		return err
	}
	return s.repo.DeleteByID(ctx, oid)
}

func (s *userStore) FindByEmail(ctx context.Context, email string) (core.User, error) {
	user, err := s.repo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return core.User{}, core.ErrUserNotFound
		}
		return core.User{}, err
	}
	return models.UserToCore(user), nil
}

func (s *userStore) FindByUsername(ctx context.Context, username string) (core.User, error) {
	user, err := s.repo.FindByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return core.User{}, core.ErrUserNotFound
		}
		return core.User{}, err
	}
	return models.UserToCore(user), nil
}

func (s *userStore) FindByID(ctx context.Context, id core.ID) (core.User, error) {
	oid, err := models.ObjectIDFromCore(id)
	if err != nil {
		return core.User{}, err
	}
	user, err := s.repo.FindByID(ctx, oid)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return core.User{}, core.ErrUserNotFound
		}
		return core.User{}, err
	}
	return models.UserToCore(user), nil
}

func (s *userStore) UpdateFields(ctx context.Context, id core.ID, fields map[string]interface{}) error {
	oid, err := models.ObjectIDFromCore(id)
	if err != nil {
		return err
	}
	update := bson.M{}
	for k, v := range fields {
		update[k] = v
	}
	return s.repo.UpdateFields(ctx, oid, update)
}

type sessionStore struct {
	repo *repos.SessionRepository
}

func newSessionStore(repo *repos.SessionRepository) services.SessionStore {
	return &sessionStore{repo: repo}
}

func (s *sessionStore) Create(ctx context.Context, params services.CreateSessionParams) (core.Session, error) {
	userID, err := models.ObjectIDFromCore(params.UserID)
	if err != nil {
		return core.Session{}, err
	}
	session := models.Session{
		UserID:    userID,
		TokenHash: params.TokenHash,
		UserAgent: params.UserAgent,
		IP:        params.IP,
		ExpiresAt: params.ExpiresAt,
		CreatedAt: params.CreatedAt,
		Revoked:   false,
	}
	created, err := s.repo.Create(ctx, session)
	if err != nil {
		return core.Session{}, err
	}
	return models.SessionToCore(created), nil
}

func (s *sessionStore) FindByTokenHash(ctx context.Context, hash string) (core.Session, error) {
	session, err := s.repo.FindByTokenHash(ctx, hash)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return core.Session{}, core.ErrSessionNotFound
		}
		return core.Session{}, err
	}
	return models.SessionToCore(session), nil
}

func (s *sessionStore) Revoke(ctx context.Context, id core.ID) error {
	oid, err := models.ObjectIDFromCore(id)
	if err != nil {
		return err
	}
	return s.repo.Revoke(ctx, oid)
}

type verificationStore struct {
	repo *repos.VerificationRepository
}

func newVerificationStore(repo *repos.VerificationRepository) services.VerificationStore {
	return &verificationStore{repo: repo}
}

func (s *verificationStore) Create(ctx context.Context, params services.CreateVerificationParams) (core.VerificationToken, error) {
	userID, err := models.ObjectIDFromCore(params.UserID)
	if err != nil {
		return core.VerificationToken{}, err
	}
	token := models.VerificationToken{
		ID:        primitive.NewObjectID(),
		UserID:    userID,
		TokenHash: params.TokenHash,
		ExpiresAt: params.ExpiresAt,
		CreatedAt: params.CreatedAt,
	}
	created, err := s.repo.Create(ctx, token)
	if err != nil {
		return core.VerificationToken{}, err
	}
	return models.VerificationToCore(created), nil
}

func (s *verificationStore) FindByHash(ctx context.Context, hash string) (core.VerificationToken, error) {
	token, err := s.repo.FindByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return core.VerificationToken{}, core.ErrTokenNotFound
		}
		return core.VerificationToken{}, err
	}
	return models.VerificationToCore(token), nil
}

func (s *verificationStore) DeleteByID(ctx context.Context, id core.ID) error {
	oid, err := models.ObjectIDFromCore(id)
	if err != nil {
		return err
	}
	return s.repo.DeleteByID(ctx, oid)
}

func (s *verificationStore) Consume(ctx context.Context, id core.ID, consumedAt time.Time) error {
	oid, err := models.ObjectIDFromCore(id)
	if err != nil {
		return err
	}
	return s.repo.Consume(ctx, oid, consumedAt)
}

type passwordResetStore struct {
	repo *repos.PasswordResetRepository
}

func newPasswordResetStore(repo *repos.PasswordResetRepository) services.PasswordResetStore {
	return &passwordResetStore{repo: repo}
}

func (s *passwordResetStore) Create(ctx context.Context, params services.CreatePasswordResetParams) (core.PasswordResetToken, error) {
	userID, err := models.ObjectIDFromCore(params.UserID)
	if err != nil {
		return core.PasswordResetToken{}, err
	}
	token := models.PasswordReset{
		ID:        primitive.NewObjectID(),
		UserID:    userID,
		TokenHash: params.TokenHash,
		ExpiresAt: params.ExpiresAt,
		CreatedAt: params.CreatedAt,
	}
	created, err := s.repo.Create(ctx, token)
	if err != nil {
		return core.PasswordResetToken{}, err
	}
	return models.PasswordResetToCore(created), nil
}

func (s *passwordResetStore) FindByHash(ctx context.Context, hash string) (core.PasswordResetToken, error) {
	token, err := s.repo.FindByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return core.PasswordResetToken{}, core.ErrTokenNotFound
		}
		return core.PasswordResetToken{}, err
	}
	return models.PasswordResetToCore(token), nil
}

func (s *passwordResetStore) Consume(ctx context.Context, id core.ID, consumedAt time.Time) error {
	oid, err := models.ObjectIDFromCore(id)
	if err != nil {
		return err
	}
	return s.repo.Consume(ctx, oid, consumedAt)
}

type emailChangeStore struct {
	repo *repos.EmailChangeRepository
}

func newEmailChangeStore(repo *repos.EmailChangeRepository) services.EmailChangeStore {
	return &emailChangeStore{repo: repo}
}

func (s *emailChangeStore) Create(ctx context.Context, params services.CreateEmailChangeParams) (core.EmailChangeRequest, error) {
	userID, err := models.ObjectIDFromCore(params.UserID)
	if err != nil {
		return core.EmailChangeRequest{}, err
	}
	token := models.EmailChange{
		ID:        primitive.NewObjectID(),
		UserID:    userID,
		NewEmail:  params.NewEmail,
		TokenHash: params.TokenHash,
		ExpiresAt: params.ExpiresAt,
		CreatedAt: params.CreatedAt,
	}
	created, err := s.repo.Create(ctx, token)
	if err != nil {
		return core.EmailChangeRequest{}, err
	}
	return models.EmailChangeToCore(created), nil
}

func (s *emailChangeStore) FindByHash(ctx context.Context, hash string) (core.EmailChangeRequest, error) {
	token, err := s.repo.FindByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return core.EmailChangeRequest{}, core.ErrTokenNotFound
		}
		return core.EmailChangeRequest{}, err
	}
	return models.EmailChangeToCore(token), nil
}

func (s *emailChangeStore) Consume(ctx context.Context, id core.ID, consumedAt time.Time) error {
	oid, err := models.ObjectIDFromCore(id)
	if err != nil {
		return err
	}
	return s.repo.Consume(ctx, oid, consumedAt)
}
