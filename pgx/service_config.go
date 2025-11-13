package pgx

import "github.com/deicod/auth/config"

type ServiceConfig struct {
	Pgx     Config
	Session config.Session
	Tokens  config.Tokens
	Argon2  config.Argon2
	Email   config.Mail
}
