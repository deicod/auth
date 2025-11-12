package mgo

import "time"

type Config struct {
	URI                     string
	Database                string
	UsersCollection         string
	SessionsCollection      string
	VerificationCollection  string
	PasswordResetCollection string
	EmailChangeCollection   string
	OperationTimeout        time.Duration
}

func DefaultConfig() Config {
	return Config{
		URI:                     "mongodb://localhost:27017",
		Database:                "auth",
		UsersCollection:         "users",
		SessionsCollection:      "sessions",
		VerificationCollection:  "email_verifications",
		PasswordResetCollection: "password_resets",
		EmailChangeCollection:   "email_changes",
		OperationTimeout:        30 * time.Second,
	}
}
