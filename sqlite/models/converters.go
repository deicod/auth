package models

import "github.com/deicod/auth/core"

// UserToCore converts a SQLite User model to a core.User.
func UserToCore(u User) core.User {
	return core.User{
		ID:           core.ID(u.ID),
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

// SessionToCore converts a SQLite Session model to a core.Session.
func SessionToCore(s Session) core.Session {
	return core.Session{
		ID:        core.ID(s.ID),
		UserID:    core.ID(s.UserID),
		TokenHash: s.TokenHash,
		UserAgent: s.UserAgent,
		IP:        s.IP,
		ExpiresAt: s.ExpiresAt,
		CreatedAt: s.CreatedAt,
		Revoked:   s.Revoked,
	}
}

// VerificationToCore converts a SQLite VerificationToken to a core.VerificationToken.
func VerificationToCore(t VerificationToken) core.VerificationToken {
	return core.VerificationToken{
		ID:         core.ID(t.ID),
		UserID:     core.ID(t.UserID),
		TokenHash:  t.TokenHash,
		ExpiresAt:  t.ExpiresAt,
		CreatedAt:  t.CreatedAt,
		ConsumedAt: t.ConsumedAt,
	}
}

// PasswordResetToCore converts a SQLite PasswordReset to a core.PasswordResetToken.
func PasswordResetToCore(t PasswordReset) core.PasswordResetToken {
	return core.PasswordResetToken{
		ID:         core.ID(t.ID),
		UserID:     core.ID(t.UserID),
		TokenHash:  t.TokenHash,
		ExpiresAt:  t.ExpiresAt,
		CreatedAt:  t.CreatedAt,
		ConsumedAt: t.ConsumedAt,
	}
}

// EmailChangeToCore converts a SQLite EmailChange to a core.EmailChangeRequest.
func EmailChangeToCore(e EmailChange) core.EmailChangeRequest {
	return core.EmailChangeRequest{
		ID:         core.ID(e.ID),
		UserID:     core.ID(e.UserID),
		NewEmail:   e.NewEmail,
		TokenHash:  e.TokenHash,
		ExpiresAt:  e.ExpiresAt,
		CreatedAt:  e.CreatedAt,
		ConsumedAt: e.ConsumedAt,
	}
}
