package repos

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/deicod/auth/internal/ctxutil"
	"github.com/deicod/auth/pgx/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserRepository struct {
	pool    *pgxpool.Pool
	timeout time.Duration
}

func NewUserRepository(pool *pgxpool.Pool, timeout time.Duration) *UserRepository {
	return &UserRepository{pool: pool, timeout: timeout}
}

func (r *UserRepository) withContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if r.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, r.timeout)
}

const insertUserQuery = `
INSERT INTO users (
	id, email, username, password_hash, role, is_verified, created_at, updated_at, verified_at, last_login_at
)
VALUES (uuidv7(), $1,$2,$3,$4,$5,$6,$7,$8,$9)
RETURNING id
`

func (r *UserRepository) Create(ctx context.Context, user models.User) (models.User, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	row := r.pool.QueryRow(ctx, insertUserQuery,
		user.Email, user.Username, user.PasswordHash, user.Role, user.IsVerified,
		user.CreatedAt, user.UpdatedAt, user.VerifiedAt, user.LastLoginAt,
	)
	if err := row.Scan(&user.ID); err != nil {
		return models.User{}, ctxutil.NormalizeError(err, "pgx.user.insert")
	}
	return user, nil
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (models.User, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	row := r.pool.QueryRow(ctx, `SELECT id, email, username, password_hash, role, is_verified, created_at, updated_at, verified_at, last_login_at FROM users WHERE email=$1`, email)
	user, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.User{}, err
		}
		return models.User{}, ctxutil.NormalizeError(err, "pgx.user.find_by_email")
	}
	return user, nil
}

func (r *UserRepository) FindByUsername(ctx context.Context, username string) (models.User, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	// Use case-insensitive lookup to prevent spoofing (e.g. "Admin" vs "admin")
	row := r.pool.QueryRow(ctx, `SELECT id, email, username, password_hash, role, is_verified, created_at, updated_at, verified_at, last_login_at FROM users WHERE LOWER(username)=LOWER($1)`, username)
	user, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.User{}, err
		}
		return models.User{}, ctxutil.NormalizeError(err, "pgx.user.find_by_username")
	}
	return user, nil
}

func (r *UserRepository) FindByID(ctx context.Context, id uuid.UUID) (models.User, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	row := r.pool.QueryRow(ctx, `SELECT id, email, username, password_hash, role, is_verified, created_at, updated_at, verified_at, last_login_at FROM users WHERE id=$1`, id)
	user, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.User{}, err
		}
		return models.User{}, ctxutil.NormalizeError(err, "pgx.user.find_by_id")
	}
	return user, nil
}

func (r *UserRepository) UpdateFields(ctx context.Context, id uuid.UUID, fields map[string]interface{}) error {
	if len(fields) == 0 {
		return nil
	}
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	setParts := make([]string, 0, len(fields))
	args := make([]interface{}, 0, len(fields)+1)
	idx := 1
	for column, value := range fields {
		switch column {
		case "email", "username", "password_hash", "role", "is_verified", "created_at", "updated_at", "verified_at", "last_login_at":
		default:
			return fmt.Errorf("invalid column: %s", column)
		}

		setParts = append(setParts, fmt.Sprintf("%s=$%d", column, idx))
		args = append(args, value)
		idx++
	}
	args = append(args, id)
	query := fmt.Sprintf("UPDATE users SET %s WHERE id=$%d", strings.Join(setParts, ", "), idx)
	_, err := r.pool.Exec(ctx, query, args...)
	return ctxutil.NormalizeError(err, "pgx.user.update_fields")
}

func (r *UserRepository) DeleteByID(ctx context.Context, id uuid.UUID) error {
	ctx, cancel := r.withContext(ctx)
	defer cancel()
	_, err := r.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, id)
	return ctxutil.NormalizeError(err, "pgx.user.delete_by_id")
}

func scanUser(row pgx.Row) (models.User, error) {
	var user models.User
	err := row.Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.Role,
		&user.IsVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.VerifiedAt,
		&user.LastLoginAt,
	)
	return user, err
}
