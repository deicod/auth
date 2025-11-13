package repos

import (
	"context"
	"time"

	"github.com/deicod/auth/pgx/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PasswordResetRepository struct {
	pool    *pgxpool.Pool
	timeout time.Duration
}

func NewPasswordResetRepository(pool *pgxpool.Pool, timeout time.Duration) *PasswordResetRepository {
	return &PasswordResetRepository{pool: pool, timeout: timeout}
}

func (r *PasswordResetRepository) withContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if r.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, r.timeout)
}

func (r *PasswordResetRepository) Create(ctx context.Context, token models.PasswordReset) (models.PasswordReset, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	row := r.pool.QueryRow(ctx, `INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at, consumed_at) VALUES (uuidv7(),$1,$2,$3,$4,$5) RETURNING id`,
		token.UserID, token.TokenHash, token.ExpiresAt, token.CreatedAt, token.ConsumedAt,
	)
	if err := row.Scan(&token.ID); err != nil {
		return models.PasswordReset{}, err
	}
	return token, nil
}

func (r *PasswordResetRepository) FindByHash(ctx context.Context, hash string) (models.PasswordReset, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()
	row := r.pool.QueryRow(ctx, `SELECT id, user_id, token_hash, expires_at, created_at, consumed_at FROM password_reset_tokens WHERE token_hash=$1`, hash)
	return scanPasswordReset(row)
}

func (r *PasswordResetRepository) Consume(ctx context.Context, id uuid.UUID, consumedAt time.Time) error {
	ctx, cancel := r.withContext(ctx)
	defer cancel()
	_, err := r.pool.Exec(ctx, `UPDATE password_reset_tokens SET consumed_at=$1 WHERE id=$2`, consumedAt, id)
	return err
}

func scanPasswordReset(row pgx.Row) (models.PasswordReset, error) {
	var token models.PasswordReset
	err := row.Scan(&token.ID, &token.UserID, &token.TokenHash, &token.ExpiresAt, &token.CreatedAt, &token.ConsumedAt)
	return token, err
}
