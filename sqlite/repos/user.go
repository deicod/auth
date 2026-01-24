package repos

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/deicod/auth/internal/ctxutil"
	"github.com/deicod/auth/sqlite/models"
	"github.com/google/uuid"
)

// CreateUserParams holds the parameters for creating a new user.
type CreateUserParams struct {
	Email        string
	Username     string
	PasswordHash string
	Role         string
	IsVerified   bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
	VerifiedAt   *time.Time
	LastLoginAt  *time.Time
}

// UserRepository handles user persistence in SQLite.
type UserRepository struct {
	db      *sql.DB
	timeout time.Duration
}

// NewUserRepository creates a new UserRepository.
func NewUserRepository(db *sql.DB, timeout time.Duration) *UserRepository {
	return &UserRepository{db: db, timeout: timeout}
}

func (r *UserRepository) withContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if r.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, r.timeout)
}

func formatTime(t time.Time) string {
	return t.Format(time.RFC3339Nano)
}

func formatTimePtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.Format(time.RFC3339Nano)
	return &s
}

func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, s)
}

func parseTimePtr(s *string) (*time.Time, error) {
	if s == nil {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, *s)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// userColumns defines the standard SELECT columns for user queries.
const userColumns = `id, email, username, password_hash, role, is_verified, created_at, updated_at, verified_at, last_login_at`

// Create inserts a new user and returns the created record.
func (r *UserRepository) Create(ctx context.Context, params CreateUserParams) (models.User, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	id := uuid.New().String()

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO users (id, email, username, password_hash, role, is_verified, created_at, updated_at, verified_at, last_login_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		id,
		params.Email,
		params.Username,
		params.PasswordHash,
		params.Role,
		boolToInt(params.IsVerified),
		formatTime(params.CreatedAt),
		formatTime(params.UpdatedAt),
		formatTimePtr(params.VerifiedAt),
		formatTimePtr(params.LastLoginAt),
	)
	if err != nil {
		return models.User{}, ctxutil.NormalizeError(err, "sqlite.user.insert")
	}

	return models.User{
		ID:           id,
		Email:        params.Email,
		Username:     params.Username,
		PasswordHash: params.PasswordHash,
		Role:         params.Role,
		IsVerified:   params.IsVerified,
		CreatedAt:    params.CreatedAt,
		UpdatedAt:    params.UpdatedAt,
		VerifiedAt:   params.VerifiedAt,
		LastLoginAt:  params.LastLoginAt,
	}, nil
}

// FindByEmail retrieves a user by email address.
func (r *UserRepository) FindByEmail(ctx context.Context, email string) (models.User, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	row := r.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE email = ?`, email)

	return scanUser(row)
}

// FindByUsername retrieves a user by username.
func (r *UserRepository) FindByUsername(ctx context.Context, username string) (models.User, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	row := r.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE username = ?`, username)

	return scanUser(row)
}

// FindByID retrieves a user by ID.
func (r *UserRepository) FindByID(ctx context.Context, id string) (models.User, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	row := r.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = ?`, id)

	return scanUser(row)
}

// UpdateFields updates specific fields of a user record.
func (r *UserRepository) UpdateFields(ctx context.Context, id string, fields map[string]interface{}) error {
	if len(fields) == 0 {
		return nil
	}
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	setParts := make([]string, 0, len(fields))
	args := make([]interface{}, 0, len(fields)+1)

	for column, value := range fields {
		switch column {
		case "email", "username", "password_hash", "role", "is_verified", "created_at", "updated_at", "verified_at", "last_login_at":
		default:
			return fmt.Errorf("invalid column: %s", column)
		}

		setParts = append(setParts, fmt.Sprintf("%s = ?", column))
		// Convert time.Time to string for SQLite storage
		switch v := value.(type) {
		case time.Time:
			args = append(args, formatTime(v))
		case *time.Time:
			args = append(args, formatTimePtr(v))
		case bool:
			args = append(args, boolToInt(v))
		default:
			args = append(args, value)
		}
	}
	args = append(args, id)

	query := fmt.Sprintf("UPDATE users SET %s WHERE id = ?", strings.Join(setParts, ", "))
	_, err := r.db.ExecContext(ctx, query, args...)
	return ctxutil.NormalizeError(err, "sqlite.user.update_fields")
}

// DeleteByID removes a user by ID.
func (r *UserRepository) DeleteByID(ctx context.Context, id string) error {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	_, err := r.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return ctxutil.NormalizeError(err, "sqlite.user.delete_by_id")
}

func scanUser(row *sql.Row) (models.User, error) {
	var user models.User
	var isVerified int
	var createdAt, updatedAt string
	var verifiedAt, lastLoginAt *string

	err := row.Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.Role,
		&isVerified,
		&createdAt,
		&updatedAt,
		&verifiedAt,
		&lastLoginAt,
	)
	if err != nil {
		return models.User{}, err
	}

	user.IsVerified = isVerified != 0

	user.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return models.User{}, err
	}
	user.UpdatedAt, err = parseTime(updatedAt)
	if err != nil {
		return models.User{}, err
	}
	user.VerifiedAt, err = parseTimePtr(verifiedAt)
	if err != nil {
		return models.User{}, err
	}
	user.LastLoginAt, err = parseTimePtr(lastLoginAt)
	if err != nil {
		return models.User{}, err
	}

	return user, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
