package repos

import (
	"context"
	"errors"
	"time"

	"github.com/deicod/auth/internal/ctxutil"
	"github.com/deicod/auth/pgx/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type VerificationRepository struct {
	pool    *pgxpool.Pool
	timeout time.Duration
}

func NewVerificationRepository(pool *pgxpool.Pool, timeout time.Duration) *VerificationRepository {
	return &VerificationRepository{pool: pool, timeout: timeout}
}

func (r *VerificationRepository) withContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if r.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, r.timeout)
}

func (r *VerificationRepository) Create(ctx context.Context, token models.VerificationToken) (models.VerificationToken, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	row := r.pool.QueryRow(ctx, `INSERT INTO verification_tokens (id, user_id, token_hash, expires_at, created_at, consumed_at) VALUES (uuidv7(),$1,$2,$3,$4,$5) RETURNING id`,
		token.UserID, token.TokenHash, token.ExpiresAt, token.CreatedAt, token.ConsumedAt,
	)
	if err := row.Scan(&token.ID); err != nil {
		return models.VerificationToken{}, ctxutil.NormalizeError(err, "pgx.verification.insert")
	}
	return token, nil
}

func (r *VerificationRepository) FindByHash(ctx context.Context, hash string) (models.VerificationToken, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	row := r.pool.QueryRow(ctx, `SELECT id, user_id, token_hash, expires_at, created_at, consumed_at FROM verification_tokens WHERE token_hash=$1`, hash)
	token, err := scanVerification(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.VerificationToken{}, err
		}
		return models.VerificationToken{}, ctxutil.NormalizeError(err, "pgx.verification.find_by_hash")
	}
	return token, nil
}

func (r *VerificationRepository) Consume(ctx context.Context, id uuid.UUID, consumedAt time.Time) error {
	ctx, cancel := r.withContext(ctx)
	defer cancel()
	_, err := r.pool.Exec(ctx, `UPDATE verification_tokens SET consumed_at=$1 WHERE id=$2`, consumedAt, id)
	return ctxutil.NormalizeError(err, "pgx.verification.consume")
}

func (r *VerificationRepository) DeleteByID(ctx context.Context, id uuid.UUID) error {
	ctx, cancel := r.withContext(ctx)
	defer cancel()
	_, err := r.pool.Exec(ctx, `DELETE FROM verification_tokens WHERE id=$1`, id)
	return ctxutil.NormalizeError(err, "pgx.verification.delete")
}

func scanVerification(row pgx.Row) (models.VerificationToken, error) {
	var token models.VerificationToken
	err := row.Scan(&token.ID, &token.UserID, &token.TokenHash, &token.ExpiresAt, &token.CreatedAt, &token.ConsumedAt)
	return token, err
}
