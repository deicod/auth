package repos

import (
	"context"
	"database/sql"
	"time"

	"github.com/deicod/auth/internal/ctxutil"
	"github.com/deicod/auth/sqlite/models"
	"github.com/google/uuid"
)

// CreateVerificationParams holds the parameters for creating a verification token.
type CreateVerificationParams struct {
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// VerificationRepository handles verification token persistence in SQLite.
type VerificationRepository struct {
	db      *sql.DB
	timeout time.Duration
}

// NewVerificationRepository creates a new VerificationRepository.
func NewVerificationRepository(db *sql.DB, timeout time.Duration) *VerificationRepository {
	return &VerificationRepository{db: db, timeout: timeout}
}

func (r *VerificationRepository) withContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if r.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, r.timeout)
}

// Create inserts a new verification token.
func (r *VerificationRepository) Create(ctx context.Context, params CreateVerificationParams) (models.VerificationToken, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	id := uuid.New().String()

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO verification_tokens (id, user_id, token_hash, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?)
	`,
		id,
		params.UserID,
		params.TokenHash,
		formatTime(params.ExpiresAt),
		formatTime(params.CreatedAt),
	)
	if err != nil {
		return models.VerificationToken{}, ctxutil.NormalizeError(err, "sqlite.verification.insert")
	}

	return models.VerificationToken{
		ID:        id,
		UserID:    params.UserID,
		TokenHash: params.TokenHash,
		ExpiresAt: params.ExpiresAt,
		CreatedAt: params.CreatedAt,
	}, nil
}

// FindByHash retrieves a verification token by its hash.
func (r *VerificationRepository) FindByHash(ctx context.Context, hash string) (models.VerificationToken, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	row := r.db.QueryRowContext(ctx, `
		SELECT id, user_id, token_hash, expires_at, created_at, consumed_at
		FROM verification_tokens WHERE token_hash = ?
	`, hash)

	return scanVerificationToken(row)
}

// DeleteByID removes a verification token by ID.
func (r *VerificationRepository) DeleteByID(ctx context.Context, id string) error {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	_, err := r.db.ExecContext(ctx, `DELETE FROM verification_tokens WHERE id = ?`, id)
	return ctxutil.NormalizeError(err, "sqlite.verification.delete_by_id")
}

// Consume marks a verification token as consumed.
func (r *VerificationRepository) Consume(ctx context.Context, id string, consumedAt time.Time) error {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	_, err := r.db.ExecContext(ctx, `UPDATE verification_tokens SET consumed_at = ? WHERE id = ?`,
		formatTime(consumedAt), id)
	return ctxutil.NormalizeError(err, "sqlite.verification.consume")
}

func scanVerificationToken(row *sql.Row) (models.VerificationToken, error) {
	var token models.VerificationToken
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
		return models.VerificationToken{}, err
	}

	token.ExpiresAt, err = parseTime(expiresAt)
	if err != nil {
		return models.VerificationToken{}, err
	}
	token.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return models.VerificationToken{}, err
	}
	token.ConsumedAt, err = parseTimePtr(consumedAt)
	if err != nil {
		return models.VerificationToken{}, err
	}

	return token, nil
}
