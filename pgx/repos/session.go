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

type SessionRepository struct {
	pool    *pgxpool.Pool
	timeout time.Duration
}

func NewSessionRepository(pool *pgxpool.Pool, timeout time.Duration) *SessionRepository {
	return &SessionRepository{pool: pool, timeout: timeout}
}

func (r *SessionRepository) withContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if r.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, r.timeout)
}

func (r *SessionRepository) Create(ctx context.Context, session models.Session) (models.Session, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	row := r.pool.QueryRow(ctx, `INSERT INTO sessions (id, user_id, token_hash, user_agent, ip, expires_at, created_at, revoked) VALUES (uuidv7(),$1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		session.UserID, session.TokenHash, session.UserAgent, session.IP, session.ExpiresAt, session.CreatedAt, session.Revoked,
	)
	if err := row.Scan(&session.ID); err != nil {
		return models.Session{}, ctxutil.NormalizeError(err, "pgx.session.insert")
	}
	return session, nil
}

func (r *SessionRepository) FindByTokenHash(ctx context.Context, hash string) (models.Session, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	row := r.pool.QueryRow(ctx, `SELECT id, user_id, token_hash, user_agent, ip, expires_at, created_at, revoked FROM sessions WHERE token_hash=$1`, hash)
	session, err := scanSession(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.Session{}, err
		}
		return models.Session{}, ctxutil.NormalizeError(err, "pgx.session.find_by_hash")
	}
	return session, nil
}

func (r *SessionRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	ctx, cancel := r.withContext(ctx)
	defer cancel()
	_, err := r.pool.Exec(ctx, `UPDATE sessions SET revoked=true WHERE id=$1`, id)
	return ctxutil.NormalizeError(err, "pgx.session.revoke")
}

func scanSession(row pgx.Row) (models.Session, error) {
	var session models.Session
	err := row.Scan(&session.ID, &session.UserID, &session.TokenHash, &session.UserAgent, &session.IP, &session.ExpiresAt, &session.CreatedAt, &session.Revoked)
	return session, err
}
