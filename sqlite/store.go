package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/deicod/auth/core"
	"github.com/deicod/auth/core/services"
	"github.com/deicod/auth/sqlite/models"
	"github.com/deicod/auth/sqlite/repos"
)

type userStore struct {
	repo *repos.UserRepository
}

func newUserStore(repo *repos.UserRepository) services.UserStore {
	return &userStore{repo: repo}
}

func (s *userStore) Create(ctx context.Context, params services.CreateUserParams) (core.User, error) {
	user, err := s.repo.Create(ctx, repos.CreateUserParams{
		Email:        params.Email,
		Username:     params.Username,
		PasswordHash: params.PasswordHash,
		Role:         string(params.Role),
		IsVerified:   params.IsVerified,
		CreatedAt:    params.CreatedAt,
		UpdatedAt:    params.UpdatedAt,
	})
	if err != nil {
		return core.User{}, err
	}
	return models.UserToCore(user), nil
}

func (s *userStore) DeleteByID(ctx context.Context, id core.ID) error {
	return s.repo.DeleteByID(ctx, string(id))
}

func (s *userStore) FindByEmail(ctx context.Context, email string) (core.User, error) {
	user, err := s.repo.FindByEmail(ctx, email)
	if err != nil {
		if err == sql.ErrNoRows {
			return core.User{}, core.ErrUserNotFound
		}
		return core.User{}, err
	}
	return models.UserToCore(user), nil
}

func (s *userStore) FindByUsername(ctx context.Context, username string) (core.User, error) {
	user, err := s.repo.FindByUsername(ctx, username)
	if err != nil {
		if err == sql.ErrNoRows {
			return core.User{}, core.ErrUserNotFound
		}
		return core.User{}, err
	}
	return models.UserToCore(user), nil
}

func (s *userStore) FindByID(ctx context.Context, id core.ID) (core.User, error) {
	user, err := s.repo.FindByID(ctx, string(id))
	if err != nil {
		if err == sql.ErrNoRows {
			return core.User{}, core.ErrUserNotFound
		}
		return core.User{}, err
	}
	return models.UserToCore(user), nil
}

func (s *userStore) UpdateFields(ctx context.Context, id core.ID, fields map[string]interface{}) error {
	return s.repo.UpdateFields(ctx, string(id), fields)
}

type sessionStore struct {
	repo *repos.SessionRepository
}

func newSessionStore(repo *repos.SessionRepository) services.SessionStore {
	return &sessionStore{repo: repo}
}

func (s *sessionStore) Create(ctx context.Context, params services.CreateSessionParams) (core.Session, error) {
	session, err := s.repo.Create(ctx, repos.CreateSessionParams{
		UserID:    string(params.UserID),
		TokenHash: params.TokenHash,
		UserAgent: params.UserAgent,
		IP:        params.IP,
		ExpiresAt: params.ExpiresAt,
		CreatedAt: params.CreatedAt,
	})
	if err != nil {
		return core.Session{}, err
	}
	return models.SessionToCore(session), nil
}

func (s *sessionStore) FindByTokenHash(ctx context.Context, hash string) (core.Session, error) {
	session, err := s.repo.FindByTokenHash(ctx, hash)
	if err != nil {
		if err == sql.ErrNoRows {
			return core.Session{}, core.ErrSessionNotFound
		}
		return core.Session{}, err
	}
	return models.SessionToCore(session), nil
}

func (s *sessionStore) Revoke(ctx context.Context, id core.ID) error {
	return s.repo.Revoke(ctx, string(id))
}

func (s *sessionStore) RevokeByUser(ctx context.Context, userID core.ID) error {
	return s.repo.RevokeByUser(ctx, string(userID))
}

type verificationStore struct {
	repo *repos.VerificationRepository
}

func newVerificationStore(repo *repos.VerificationRepository) services.VerificationStore {
	return &verificationStore{repo: repo}
}

func (s *verificationStore) Create(ctx context.Context, params services.CreateVerificationParams) (core.VerificationToken, error) {
	token, err := s.repo.Create(ctx, repos.CreateVerificationParams{
		UserID:    string(params.UserID),
		TokenHash: params.TokenHash,
		ExpiresAt: params.ExpiresAt,
		CreatedAt: params.CreatedAt,
	})
	if err != nil {
		return core.VerificationToken{}, err
	}
	return models.VerificationToCore(token), nil
}

func (s *verificationStore) FindByHash(ctx context.Context, hash string) (core.VerificationToken, error) {
	token, err := s.repo.FindByHash(ctx, hash)
	if err != nil {
		if err == sql.ErrNoRows {
			return core.VerificationToken{}, core.ErrTokenNotFound
		}
		return core.VerificationToken{}, err
	}
	return models.VerificationToCore(token), nil
}

func (s *verificationStore) DeleteByID(ctx context.Context, id core.ID) error {
	return s.repo.DeleteByID(ctx, string(id))
}

func (s *verificationStore) Consume(ctx context.Context, id core.ID, consumedAt time.Time) error {
	return s.repo.Consume(ctx, string(id), consumedAt)
}

type passwordResetStore struct {
	repo *repos.PasswordResetRepository
}

func newPasswordResetStore(repo *repos.PasswordResetRepository) services.PasswordResetStore {
	return &passwordResetStore{repo: repo}
}

func (s *passwordResetStore) Create(ctx context.Context, params services.CreatePasswordResetParams) (core.PasswordResetToken, error) {
	token, err := s.repo.Create(ctx, repos.CreatePasswordResetParams{
		UserID:    string(params.UserID),
		TokenHash: params.TokenHash,
		ExpiresAt: params.ExpiresAt,
		CreatedAt: params.CreatedAt,
	})
	if err != nil {
		return core.PasswordResetToken{}, err
	}
	return models.PasswordResetToCore(token), nil
}

func (s *passwordResetStore) FindByHash(ctx context.Context, hash string) (core.PasswordResetToken, error) {
	token, err := s.repo.FindByHash(ctx, hash)
	if err != nil {
		if err == sql.ErrNoRows {
			return core.PasswordResetToken{}, core.ErrTokenNotFound
		}
		return core.PasswordResetToken{}, err
	}
	return models.PasswordResetToCore(token), nil
}

func (s *passwordResetStore) Consume(ctx context.Context, id core.ID, consumedAt time.Time) error {
	return s.repo.Consume(ctx, string(id), consumedAt)
}

type emailChangeStore struct {
	repo *repos.EmailChangeRepository
}

func newEmailChangeStore(repo *repos.EmailChangeRepository) services.EmailChangeStore {
	return &emailChangeStore{repo: repo}
}

func (s *emailChangeStore) Create(ctx context.Context, params services.CreateEmailChangeParams) (core.EmailChangeRequest, error) {
	req, err := s.repo.Create(ctx, repos.CreateEmailChangeParams{
		UserID:    string(params.UserID),
		NewEmail:  params.NewEmail,
		TokenHash: params.TokenHash,
		ExpiresAt: params.ExpiresAt,
		CreatedAt: params.CreatedAt,
	})
	if err != nil {
		return core.EmailChangeRequest{}, err
	}
	return models.EmailChangeToCore(req), nil
}

func (s *emailChangeStore) FindByHash(ctx context.Context, hash string) (core.EmailChangeRequest, error) {
	req, err := s.repo.FindByHash(ctx, hash)
	if err != nil {
		if err == sql.ErrNoRows {
			return core.EmailChangeRequest{}, core.ErrTokenNotFound
		}
		return core.EmailChangeRequest{}, err
	}
	return models.EmailChangeToCore(req), nil
}

func (s *emailChangeStore) Consume(ctx context.Context, id core.ID, consumedAt time.Time) error {
	return s.repo.Consume(ctx, string(id), consumedAt)
}
