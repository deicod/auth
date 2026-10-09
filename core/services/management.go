package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/deicod/auth/core"
)

// ManagementService supplies optional management operations using the same
// stores and cryptographic dependencies as AuthService. User stores must enforce
// case-insensitive username uniqueness, including concurrent writes.
type ManagementService struct {
	auth *AuthService
}

// NewManagementService adds management operations to an existing auth service.
func NewManagementService(auth *AuthService) *ManagementService {
	return &ManagementService{auth: auth}
}

// VerifyPassword authenticates an identified user without creating a session or
// modifying the user. Missing users and mismatches have the same error and hash
// verification work. Oversized passwords fail before database or hashing work.
func (s *ManagementService) VerifyPassword(ctx context.Context, userID core.ID, password string) error {
	if len(password) > maxPasswordLength {
		return core.ErrInvalidCredentials
	}
	user, err := s.auth.stores.Users.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, core.ErrUserNotFound) {
			_ = s.auth.hasher.Verify(s.auth.dummyHash, password)
			return core.ErrInvalidCredentials
		}
		return err
	}
	if err := s.auth.hasher.Verify(user.PasswordHash, password); err != nil {
		return core.ErrInvalidCredentials
	}
	return nil
}

// RevokeSessionsByUser revokes all of a user's sessions. Repeated calls, and
// calls for a missing user with a valid ID, succeed without changing user data.
func (s *ManagementService) RevokeSessionsByUser(ctx context.Context, userID core.ID) error {
	return s.auth.stores.Sessions.RevokeByUser(ctx, userID)
}

// UpdateUsername applies the same normalization, validation and availability
// rules as Register, preserving display casing and permitting case-only changes.
func (s *ManagementService) UpdateUsername(ctx context.Context, userID core.ID, username string) (core.UserPublic, error) {
	username, err := normalizeUsername(username)
	if err != nil {
		return core.UserPublic{}, err
	}
	if _, err := s.auth.stores.Users.FindByID(ctx, userID); err != nil {
		return core.UserPublic{}, err
	}
	if err := s.auth.ensureUsernameAvailable(ctx, username, userID); err != nil {
		return core.UserPublic{}, err
	}
	if err := s.auth.stores.Users.UpdateFields(ctx, userID, map[string]interface{}{
		"username":   username,
		"updated_at": time.Now().UTC(),
	}); err != nil {
		return core.UserPublic{}, err
	}
	user, err := s.auth.stores.Users.FindByID(ctx, userID)
	if err != nil {
		return core.UserPublic{}, err
	}
	return core.NewUserPublic(user), nil
}

// UpdateRole changes a user's auth role. Application authorization, locking and
// invariants belong to the caller, which can use a transaction-bound service.
func (s *ManagementService) UpdateRole(ctx context.Context, userID core.ID, role core.Role) (core.UserPublic, error) {
	if role != core.RoleUser && role != core.RoleAdmin {
		return core.UserPublic{}, fmt.Errorf("%w: invalid role", core.ErrInvalidInput)
	}
	if _, err := s.auth.stores.Users.FindByID(ctx, userID); err != nil {
		return core.UserPublic{}, err
	}
	if err := s.auth.stores.Users.UpdateFields(ctx, userID, map[string]interface{}{
		"role":       role,
		"updated_at": time.Now().UTC(),
	}); err != nil {
		return core.UserPublic{}, err
	}
	user, err := s.auth.stores.Users.FindByID(ctx, userID)
	if err != nil {
		return core.UserPublic{}, err
	}
	return core.NewUserPublic(user), nil
}
