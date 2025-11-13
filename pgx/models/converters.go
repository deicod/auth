package models

import (
	"github.com/deicod/auth/core"
	"github.com/google/uuid"
)

func UUIDFromCore(id core.ID) (uuid.UUID, error) {
	if id == "" {
		return uuid.Nil, nil
	}
	return uuid.Parse(string(id))
}

func CoreIDFromUUID(id uuid.UUID) core.ID {
	if id == uuid.Nil {
		return ""
	}
	return core.ID(id.String())
}

func UserToCore(u User) core.User {
	return core.User{
		ID:           CoreIDFromUUID(u.ID),
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

func SessionToCore(s Session) core.Session {
	return core.Session{
		ID:        CoreIDFromUUID(s.ID),
		UserID:    CoreIDFromUUID(s.UserID),
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
		ID:         CoreIDFromUUID(t.ID),
		UserID:     CoreIDFromUUID(t.UserID),
		TokenHash:  t.TokenHash,
		ExpiresAt:  t.ExpiresAt,
		CreatedAt:  t.CreatedAt,
		ConsumedAt: t.ConsumedAt,
	}
}

func PasswordResetToCore(t PasswordReset) core.PasswordResetToken {
	return core.PasswordResetToken{
		ID:         CoreIDFromUUID(t.ID),
		UserID:     CoreIDFromUUID(t.UserID),
		TokenHash:  t.TokenHash,
		ExpiresAt:  t.ExpiresAt,
		CreatedAt:  t.CreatedAt,
		ConsumedAt: t.ConsumedAt,
	}
}

func EmailChangeToCore(e EmailChange) core.EmailChangeRequest {
	return core.EmailChangeRequest{
		ID:         CoreIDFromUUID(e.ID),
		UserID:     CoreIDFromUUID(e.UserID),
		NewEmail:   e.NewEmail,
		TokenHash:  e.TokenHash,
		ExpiresAt:  e.ExpiresAt,
		CreatedAt:  e.CreatedAt,
		ConsumedAt: e.ConsumedAt,
	}
}
