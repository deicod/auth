package pgx

import "time"

type Config struct {
	DSN                 string
	MaxConns            int32
	MinConns            int32
	HealthCheckInterval time.Duration
	MaxConnLifetime     time.Duration
	MaxConnIdleTime     time.Duration
	OperationTimeout    time.Duration
}

func DefaultConfig() Config {
	return Config{
		DSN:                 "postgres://localhost:5432/auth?sslmode=disable",
		MaxConns:            4,
		MinConns:            0,
		HealthCheckInterval: time.Minute,
		MaxConnLifetime:     0,
		MaxConnIdleTime:     time.Minute,
		OperationTimeout:    time.Second * 30,
	}
}
