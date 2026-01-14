package sqlite

import "time"

// Default configuration values.
const (
	DefaultSessionLength      = 30 * 24 * time.Hour
	DefaultVerificationTTL    = 48 * time.Hour
	DefaultResetTTL           = time.Hour
	DefaultEmailChangeTTL     = 24 * time.Hour
	DefaultOperationTimeout   = 30 * time.Second
)

// Config holds SQLite database configuration options.
type Config struct {
	// DSN is the SQLite database path.
	// Use ":memory:" for in-memory databases, or "file:path/to/db.sqlite?_foreign_keys=on" for file-based.
	DSN string

	// OperationTimeout is the maximum duration for database operations.
	OperationTimeout time.Duration

	// MaxOpenConns sets the maximum number of open connections to the database.
	MaxOpenConns int

	// MaxIdleConns sets the maximum number of idle connections in the pool.
	MaxIdleConns int

	// ConnMaxLifetime sets the maximum amount of time a connection may be reused.
	ConnMaxLifetime time.Duration
}

// DefaultConfig returns sensible default configuration for SQLite.
func DefaultConfig() Config {
	return Config{
		DSN:              "file:auth.db?_foreign_keys=on",
		OperationTimeout: DefaultOperationTimeout,
		MaxOpenConns:     10,
		MaxIdleConns:     5,
		ConnMaxLifetime:  time.Hour,
	}
}
