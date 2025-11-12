package models

import (
	"github.com/deicod/auth/core"
)

func UserFromCore(u core.User) (User, error) {
	oid, err := ObjectIDFromCore(u.ID)
	if err != nil {
		return User{}, err
	}

	return User{
		ID:           oid,
		Email:        u.Email,
		Username:     u.Username,
		PasswordHash: u.PasswordHash,
		Role:         string(u.Role),
		IsVerified:   u.IsVerified,
		CreatedAt:    u.CreatedAt,
		UpdatedAt:    u.UpdatedAt,
		VerifiedAt:   u.VerifiedAt,
		LastLoginAt:  u.LastLoginAt,
	}, nil
}

func UserToCore(u User) core.User {
	return core.User{
		ID:           CoreIDFromObjectID(u.ID),
		Email:        u.Email,
		Username:     u.Username,
		PasswordHash: u.PasswordHash,
		Role:         core.Role(u.Role),
		IsVerified:   u.IsVerified,
		CreatedAt:    u.CreatedAt,
		UpdatedAt:    u.UpdatedAt,
		VerifiedAt:   u.VerifiedAt,
		LastLoginAt:  u.LastLoginAt,
	}
}

func SessionFromCore(s core.Session) (Session, error) {
	id, err := ObjectIDFromCore(s.ID)
	if err != nil {
		return Session{}, err
	}
	userID, err := ObjectIDFromCore(s.UserID)
	if err != nil {
		return Session{}, err
	}
	return Session{
		ID:        id,
		UserID:    userID,
		TokenHash: s.TokenHash,
		UserAgent: s.UserAgent,
		IP:        s.IP,
		ExpiresAt: s.ExpiresAt,
		CreatedAt: s.CreatedAt,
		Revoked:   s.Revoked,
	}, nil
}

func SessionToCore(s Session) core.Session {
	return core.Session{
		ID:        CoreIDFromObjectID(s.ID),
		UserID:    CoreIDFromObjectID(s.UserID),
		TokenHash: s.TokenHash,
		UserAgent: s.UserAgent,
		IP:        s.IP,
		ExpiresAt: s.ExpiresAt,
		CreatedAt: s.CreatedAt,
		Revoked:   s.Revoked,
	}
}

func VerificationToCore(t VerificationToken) core.VerificationToken {
	return core.VerificationToken{
		ID:         CoreIDFromObjectID(t.ID),
		UserID:     CoreIDFromObjectID(t.UserID),
		TokenHash:  t.TokenHash,
		ExpiresAt:  t.ExpiresAt,
		CreatedAt:  t.CreatedAt,
		ConsumedAt: t.ConsumedAt,
	}
}

func PasswordResetToCore(t PasswordReset) core.PasswordResetToken {
	return core.PasswordResetToken{
		ID:         CoreIDFromObjectID(t.ID),
		UserID:     CoreIDFromObjectID(t.UserID),
		TokenHash:  t.TokenHash,
		ExpiresAt:  t.ExpiresAt,
		CreatedAt:  t.CreatedAt,
		ConsumedAt: t.ConsumedAt,
	}
}

func EmailChangeToCore(e EmailChange) core.EmailChangeRequest {
	return core.EmailChangeRequest{
		ID:         CoreIDFromObjectID(e.ID),
		UserID:     CoreIDFromObjectID(e.UserID),
		NewEmail:   e.NewEmail,
		TokenHash:  e.TokenHash,
		ExpiresAt:  e.ExpiresAt,
		CreatedAt:  e.CreatedAt,
		ConsumedAt: e.ConsumedAt,
	}
}
