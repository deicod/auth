package core

import "time"

type UserPublic struct {
	ID          ID         `json:"id"`
	Email       string     `json:"email"`
	Username    string     `json:"username"`
	Role        Role       `json:"role"`
	IsVerified  bool       `json:"is_verified"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	VerifiedAt  *time.Time `json:"verified_at,omitempty"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

func NewUserPublic(u User) UserPublic {
	return UserPublic{
		ID:          u.ID,
		Email:       u.Email,
		Username:    u.Username,
		Role:        u.Role,
		IsVerified:  u.IsVerified,
		CreatedAt:   u.CreatedAt,
		UpdatedAt:   u.UpdatedAt,
		VerifiedAt:  u.VerifiedAt,
		LastLoginAt: u.LastLoginAt,
	}
}

type SessionPublic struct {
	ID        ID        `json:"id"`
	UserID    ID        `json:"user_id"`
	UserAgent string    `json:"user_agent"`
	IP        string    `json:"ip"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	Revoked   bool      `json:"revoked"`
}

func NewSessionPublic(s Session) SessionPublic {
	return SessionPublic{
		ID:        s.ID,
		UserID:    s.UserID,
		UserAgent: s.UserAgent,
		IP:        s.IP,
		ExpiresAt: s.ExpiresAt,
		CreatedAt: s.CreatedAt,
		Revoked:   s.Revoked,
	}
}

type AuthResult struct {
	User    UserPublic    `json:"user"`
	Token   string        `json:"token"`
	Session SessionPublic `json:"session"`
}

type VerifyEmailResult struct {
	User UserPublic `json:"user"`
}

type ChangeEmailResult struct {
	User UserPublic `json:"user"`
}
