package repos

import (
	"context"
	"database/sql"
	"time"

	"github.com/deicod/auth/internal/ctxutil"
	"github.com/deicod/auth/sqlite/models"
	"github.com/google/uuid"
)

// CreateSessionParams holds the parameters for creating a new session.
type CreateSessionParams struct {
	UserID    string
	TokenHash string
	UserAgent string
	IP        string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// SessionRepository handles session persistence in SQLite.
type SessionRepository struct {
	db      *sql.DB
	timeout time.Duration
}

// NewSessionRepository creates a new SessionRepository.
func NewSessionRepository(db *sql.DB, timeout time.Duration) *SessionRepository {
	return &SessionRepository{db: db, timeout: timeout}
}

func (r *SessionRepository) withContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if r.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, r.timeout)
}

// Create inserts a new session and returns the created record.
func (r *SessionRepository) Create(ctx context.Context, params CreateSessionParams) (models.Session, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	id := uuid.New().String()

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, token_hash, user_agent, ip, expires_at, created_at, revoked)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0)
	`,
		id,
		params.UserID,
		params.TokenHash,
		params.UserAgent,
		params.IP,
		formatTime(params.ExpiresAt),
		formatTime(params.CreatedAt),
	)
	if err != nil {
		return models.Session{}, ctxutil.NormalizeError(err, "sqlite.session.insert")
	}

	return models.Session{
		ID:        id,
		UserID:    params.UserID,
		TokenHash: params.TokenHash,
		UserAgent: params.UserAgent,
		IP:        params.IP,
		ExpiresAt: params.ExpiresAt,
		CreatedAt: params.CreatedAt,
		Revoked:   false,
	}, nil
}

// FindByTokenHash retrieves a session by its token hash.
func (r *SessionRepository) FindByTokenHash(ctx context.Context, hash string) (models.Session, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	row := r.db.QueryRowContext(ctx, `
		SELECT id, user_id, token_hash, user_agent, ip, expires_at, created_at, revoked
		FROM sessions WHERE token_hash = ?
	`, hash)

	return scanSession(row)
}

// Revoke marks a session as revoked.
func (r *SessionRepository) Revoke(ctx context.Context, id string) error {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	_, err := r.db.ExecContext(ctx, `UPDATE sessions SET revoked = 1 WHERE id = ?`, id)
	return ctxutil.NormalizeError(err, "sqlite.session.revoke")
}

// RevokeByUser revokes all active sessions for a user.
func (r *SessionRepository) RevokeByUser(ctx context.Context, userID string) error {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	_, err := r.db.ExecContext(ctx, `UPDATE sessions SET revoked = 1 WHERE user_id = ? AND revoked = 0`, userID)
	return ctxutil.NormalizeError(err, "sqlite.session.revoke_by_user")
}

func scanSession(row *sql.Row) (models.Session, error) {
	var session models.Session
	var revoked int
	var expiresAt, createdAt string
	var userAgent, ip sql.NullString

	err := row.Scan(
		&session.ID,
		&session.UserID,
		&session.TokenHash,
		&userAgent,
		&ip,
		&expiresAt,
		&createdAt,
		&revoked,
	)
	if err != nil {
		return models.Session{}, err
	}

	session.UserAgent = userAgent.String
	session.IP = ip.String
	session.Revoked = revoked != 0

	session.ExpiresAt, err = parseTime(expiresAt)
	if err != nil {
		return models.Session{}, err
	}
	session.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return models.Session{}, err
	}

	return session, nil
}
