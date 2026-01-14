package sqlite

import "github.com/deicod/auth/config"

// ServiceConfig composes the SQLite-specific config with shared auth configuration.
type ServiceConfig struct {
	Sqlite  Config
	Session config.Session
	Tokens  config.Tokens
	Argon2  config.Argon2
	Email   config.Mail
}
