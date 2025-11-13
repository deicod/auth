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

type EmailChangeRepository struct {
	pool    *pgxpool.Pool
	timeout time.Duration
}

func NewEmailChangeRepository(pool *pgxpool.Pool, timeout time.Duration) *EmailChangeRepository {
	return &EmailChangeRepository{pool: pool, timeout: timeout}
}

func (r *EmailChangeRepository) withContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if r.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, r.timeout)
}

func (r *EmailChangeRepository) Create(ctx context.Context, req models.EmailChange) (models.EmailChange, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	row := r.pool.QueryRow(ctx, `INSERT INTO email_change_requests (id, user_id, new_email, token_hash, expires_at, created_at, consumed_at) VALUES (uuidv7(),$1,$2,$3,$4,$5,$6) RETURNING id`,
		req.UserID, req.NewEmail, req.TokenHash, req.ExpiresAt, req.CreatedAt, req.ConsumedAt,
	)
	if err := row.Scan(&req.ID); err != nil {
		return models.EmailChange{}, ctxutil.NormalizeError(err, "pgx.email_change.insert")
	}
	return req, nil
}

func (r *EmailChangeRepository) FindByHash(ctx context.Context, hash string) (models.EmailChange, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()
	row := r.pool.QueryRow(ctx, `SELECT id, user_id, new_email, token_hash, expires_at, created_at, consumed_at FROM email_change_requests WHERE token_hash=$1`, hash)
	req, err := scanEmailChange(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.EmailChange{}, err
		}
		return models.EmailChange{}, ctxutil.NormalizeError(err, "pgx.email_change.find_by_hash")
	}
	return req, nil
}

func (r *EmailChangeRepository) Consume(ctx context.Context, id uuid.UUID, consumedAt time.Time) error {
	ctx, cancel := r.withContext(ctx)
	defer cancel()
	_, err := r.pool.Exec(ctx, `UPDATE email_change_requests SET consumed_at=$1 WHERE id=$2`, consumedAt, id)
	return ctxutil.NormalizeError(err, "pgx.email_change.consume")
}

func scanEmailChange(row pgx.Row) (models.EmailChange, error) {
	var req models.EmailChange
	err := row.Scan(&req.ID, &req.UserID, &req.NewEmail, &req.TokenHash, &req.ExpiresAt, &req.CreatedAt, &req.ConsumedAt)
	return req, err
}
