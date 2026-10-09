package core

import "context"

// MutationKind identifies a token-authorized credential mutation.
type MutationKind string

const (
	MutationVerifyEmail        MutationKind = "verify_email"
	MutationResetPassword      MutationKind = "reset_password"
	MutationConfirmEmailChange MutationKind = "confirm_email_change"
)

// Mutation contains the identity validated by auth, never credentials or tokens.
type Mutation struct {
	Kind   MutationKind
	UserID ID
}

// MutationPolicy runs after token validation and before any credential change or
// token consumption. Callers must use the same native transaction or Mongo session
// context to check and serialize application state. An error denies the operation;
// nil explicitly permits it. A policy must not commit or roll back the transaction.
type MutationPolicy func(context.Context, Mutation) error
