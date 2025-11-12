package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID           primitive.ObjectID `bson:"_id,omitempty"`
	Email        string             `bson:"email"`
	Username     string             `bson:"username"`
	PasswordHash string             `bson:"password_hash"`
	Role         string             `bson:"role"`
	IsVerified   bool               `bson:"is_verified"`
	CreatedAt    time.Time          `bson:"created_at"`
	UpdatedAt    time.Time          `bson:"updated_at"`
	VerifiedAt   *time.Time         `bson:"verified_at,omitempty"`
	LastLoginAt  *time.Time         `bson:"last_login_at,omitempty"`
}

type Session struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	UserID    primitive.ObjectID `bson:"user_id"`
	TokenHash string             `bson:"token_hash"`
	UserAgent string             `bson:"user_agent"`
	IP        string             `bson:"ip"`
	ExpiresAt time.Time          `bson:"expires_at"`
	CreatedAt time.Time          `bson:"created_at"`
	Revoked   bool               `bson:"revoked"`
}

type VerificationToken struct {
	ID         primitive.ObjectID `bson:"_id,omitempty"`
	UserID     primitive.ObjectID `bson:"user_id"`
	TokenHash  string             `bson:"token_hash"`
	ExpiresAt  time.Time          `bson:"expires_at"`
	CreatedAt  time.Time          `bson:"created_at"`
	ConsumedAt *time.Time         `bson:"consumed_at,omitempty"`
}

type PasswordReset struct {
	ID         primitive.ObjectID `bson:"_id,omitempty"`
	UserID     primitive.ObjectID `bson:"user_id"`
	TokenHash  string             `bson:"token_hash"`
	ExpiresAt  time.Time          `bson:"expires_at"`
	CreatedAt  time.Time          `bson:"created_at"`
	ConsumedAt *time.Time         `bson:"consumed_at,omitempty"`
}

type EmailChange struct {
	ID         primitive.ObjectID `bson:"_id,omitempty"`
	UserID     primitive.ObjectID `bson:"user_id"`
	NewEmail   string             `bson:"new_email"`
	TokenHash  string             `bson:"token_hash"`
	ExpiresAt  time.Time          `bson:"expires_at"`
	CreatedAt  time.Time          `bson:"created_at"`
	ConsumedAt *time.Time         `bson:"consumed_at,omitempty"`
}
