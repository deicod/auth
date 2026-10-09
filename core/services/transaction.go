package services

import (
	"context"

	"github.com/deicod/auth/core"
)

// Transaction exposes synchronous operations bound to one SQL transaction.
// It must not outlive that transaction or be used concurrently. Abort the unit
// of work on any error. Use a backend's WithTx or InTx to obtain this object.
type Transaction struct {
	*ManagementService
	auth *AuthService
}

// NewTransaction rebinds shared auth logic without regenerating the dummy hash
// or changing crypto configuration. The backend supplies transaction-bound stores
// and is responsible for token locking and transaction lifetime.
func NewTransaction(auth *AuthService, stores Stores) *Transaction {
	bound := *auth
	bound.stores = stores
	return &Transaction{ManagementService: NewManagementService(&bound), auth: &bound}
}

// VerifyEmail checks policy before marking the user verified or consuming the
// token. A nil policy explicitly permits the mutation.
func (s *Transaction) VerifyEmail(ctx context.Context, cmd core.VerifyEmailCommand, policy core.MutationPolicy) (core.VerifyEmailResult, error) {
	return s.auth.verifyEmail(ctx, cmd, policy)
}

// ResetPassword checks policy before hashing/storing the new password,
// consuming the token or revoking sessions. A nil policy permits the mutation.
func (s *Transaction) ResetPassword(ctx context.Context, cmd core.ResetPasswordCommand, policy core.MutationPolicy) (core.UserPublic, error) {
	return s.auth.resetPassword(ctx, cmd, policy)
}

// ConfirmEmailChange checks policy before changing credentials or consuming the
// token. A nil policy explicitly permits the mutation.
func (s *Transaction) ConfirmEmailChange(ctx context.Context, cmd core.ConfirmEmailChangeCommand, policy core.MutationPolicy) (core.ChangeEmailResult, error) {
	return s.auth.confirmEmailChange(ctx, cmd, policy)
}

func checkPolicy(ctx context.Context, policy core.MutationPolicy, kind core.MutationKind, userID core.ID) error {
	if policy == nil {
		return nil
	}
	return policy(ctx, core.Mutation{Kind: kind, UserID: userID})
}
