package repos

import (
	"context"
	"database/sql"
	"time"

	"github.com/deicod/auth/internal/ctxutil"
	"github.com/deicod/auth/sqlite/models"
	"github.com/google/uuid"
)

// CreatePasswordResetParams holds the parameters for creating a password reset token.
type CreatePasswordResetParams struct {
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// PasswordResetRepository handles password reset token persistence in SQLite.
type PasswordResetRepository struct {
	db      *sql.DB
	timeout time.Duration
}

// NewPasswordResetRepository creates a new PasswordResetRepository.
func NewPasswordResetRepository(db *sql.DB, timeout time.Duration) *PasswordResetRepository {
	return &PasswordResetRepository{db: db, timeout: timeout}
}

func (r *PasswordResetRepository) withContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if r.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, r.timeout)
}

// Create inserts a new password reset token.
func (r *PasswordResetRepository) Create(ctx context.Context, params CreatePasswordResetParams) (models.PasswordReset, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	id := uuid.New().String()

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?)
	`,
		id,
		params.UserID,
		params.TokenHash,
		formatTime(params.ExpiresAt),
		formatTime(params.CreatedAt),
	)
	if err != nil {
		return models.PasswordReset{}, ctxutil.NormalizeError(err, "sqlite.password_reset.insert")
	}

	return models.PasswordReset{
		ID:        id,
		UserID:    params.UserID,
		TokenHash: params.TokenHash,
		ExpiresAt: params.ExpiresAt,
		CreatedAt: params.CreatedAt,
	}, nil
}

// FindByHash retrieves a password reset token by its hash.
func (r *PasswordResetRepository) FindByHash(ctx context.Context, hash string) (models.PasswordReset, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	row := r.db.QueryRowContext(ctx, `
		SELECT id, user_id, token_hash, expires_at, created_at, consumed_at
		FROM password_reset_tokens WHERE token_hash = ?
	`, hash)

	return scanPasswordReset(row)
}

// Consume marks a password reset token as consumed.
func (r *PasswordResetRepository) Consume(ctx context.Context, id string, consumedAt time.Time) error {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	_, err := r.db.ExecContext(ctx, `UPDATE password_reset_tokens SET consumed_at = ? WHERE id = ?`,
		formatTime(consumedAt), id)
	return ctxutil.NormalizeError(err, "sqlite.password_reset.consume")
}

func scanPasswordReset(row *sql.Row) (models.PasswordReset, error) {
	var token models.PasswordReset
	var expiresAt, createdAt string
	var consumedAt *string

	err := row.Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&expiresAt,
		&createdAt,
		&consumedAt,
	)
	if err != nil {
		return models.PasswordReset{}, err
	}

	token.ExpiresAt, err = parseTime(expiresAt)
	if err != nil {
		return models.PasswordReset{}, err
	}
	token.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return models.PasswordReset{}, err
	}
	token.ConsumedAt, err = parseTimePtr(consumedAt)
	if err != nil {
		return models.PasswordReset{}, err
	}

	return token, nil
}
