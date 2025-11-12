package mgo

import "github.com/deicod/auth/config"

type ServiceConfig struct {
    Mongo   Config
    Session config.Session
    Tokens  config.Tokens
    Argon2  config.Argon2
    Email   config.Mail
}
