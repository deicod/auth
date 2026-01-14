package repos

import (
	"context"
	"database/sql"
	"time"

	"github.com/deicod/auth/internal/ctxutil"
	"github.com/deicod/auth/sqlite/models"
	"github.com/google/uuid"
)

// CreateEmailChangeParams holds the parameters for creating an email change request.
type CreateEmailChangeParams struct {
	UserID    string
	NewEmail  string
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// EmailChangeRepository handles email change request persistence in SQLite.
type EmailChangeRepository struct {
	db      *sql.DB
	timeout time.Duration
}

// NewEmailChangeRepository creates a new EmailChangeRepository.
func NewEmailChangeRepository(db *sql.DB, timeout time.Duration) *EmailChangeRepository {
	return &EmailChangeRepository{db: db, timeout: timeout}
}

func (r *EmailChangeRepository) withContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if r.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, r.timeout)
}

// Create inserts a new email change request.
func (r *EmailChangeRepository) Create(ctx context.Context, params CreateEmailChangeParams) (models.EmailChange, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	id := uuid.New().String()

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO email_change_requests (id, user_id, new_email, token_hash, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`,
		id,
		params.UserID,
		params.NewEmail,
		params.TokenHash,
		formatTime(params.ExpiresAt),
		formatTime(params.CreatedAt),
	)
	if err != nil {
		return models.EmailChange{}, ctxutil.NormalizeError(err, "sqlite.email_change.insert")
	}

	return models.EmailChange{
		ID:        id,
		UserID:    params.UserID,
		NewEmail:  params.NewEmail,
		TokenHash: params.TokenHash,
		ExpiresAt: params.ExpiresAt,
		CreatedAt: params.CreatedAt,
	}, nil
}

// FindByHash retrieves an email change request by its token hash.
func (r *EmailChangeRepository) FindByHash(ctx context.Context, hash string) (models.EmailChange, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	row := r.db.QueryRowContext(ctx, `
		SELECT id, user_id, new_email, token_hash, expires_at, created_at, consumed_at
		FROM email_change_requests WHERE token_hash = ?
	`, hash)

	return scanEmailChange(row)
}

// Consume marks an email change request as consumed.
func (r *EmailChangeRepository) Consume(ctx context.Context, id string, consumedAt time.Time) error {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	_, err := r.db.ExecContext(ctx, `UPDATE email_change_requests SET consumed_at = ? WHERE id = ?`,
		formatTime(consumedAt), id)
	return ctxutil.NormalizeError(err, "sqlite.email_change.consume")
}

func scanEmailChange(row *sql.Row) (models.EmailChange, error) {
	var req models.EmailChange
	var expiresAt, createdAt string
	var consumedAt *string

	err := row.Scan(
		&req.ID,
		&req.UserID,
		&req.NewEmail,
		&req.TokenHash,
		&expiresAt,
		&createdAt,
		&consumedAt,
	)
	if err != nil {
		return models.EmailChange{}, err
	}

	req.ExpiresAt, err = parseTime(expiresAt)
	if err != nil {
		return models.EmailChange{}, err
	}
	req.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return models.EmailChange{}, err
	}
	req.ConsumedAt, err = parseTimePtr(consumedAt)
	if err != nil {
		return models.EmailChange{}, err
	}

	return req, nil
}
