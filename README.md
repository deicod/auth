# Auth

`github.com/deicod/auth` is a storage-agnostic authentication module that bundles the domain model, services and HTTP transport needed for user registration, login, email verification, password resets and email change flows. The package exposes a single `auth.Service` interface while letting you pick the persistence layer (`mgo` for MongoDB or `pgx` for PostgreSQL) at runtime.

## Highlights
- `auth.Service` defines the full authentication surface (register, login, forgot/reset password, email verification/change) and can be backed by MongoDB or PostgreSQL without touching the rest of your code.
- `core` holds the shared commands, results, errors and user/session representations to keep handlers and services storage-neutral.
- Ready-to-use HTTP handlers (`handlers.AuthHandlers`) turn the service into JSON endpoints for `/register`, `/login`, `/logout`, `/me`, email verification and password reset workflows.
- Security defaults baked in: Argon2id password hashing, opaque session tokens, short-lived verification/reset/email-change tokens and SMTP integrations for transactional emails.
- Rich configuration via `auth.Config` with sensible defaults plus knobs for session lifetime, token TTLs, Argon2 parameters and mail transport.
- PGX backend ships with embedded SQL migrations, while the Mongo backend wires collections, indexes and repositories for you.

## Package Map

| Path | Description |
| --- | --- |
| `auth.go` | Backend switch + `auth.Service` interface definition. |
| `core/` | Domain layer: command DTOs, public models, shared errors and result structs. |
| `handlers/` | JSON HTTP handlers that wrap any `auth.Service`. |
| `mgo/` | MongoDB service implementation, repositories and configuration helpers. |
| `pgx/` | PostgreSQL (pgxpool) implementation with migrations and repositories. |
| `config/` | Shared configuration structs for sessions, tokens, Argon2 and SMTP. |
| `email/` | SMTP sender implementation with a `NopSender` fallback. |

## Installation

```bash
go get github.com/deicod/auth
```

## Config Overview

Start with `auth.DefaultConfig()` and override what you need. Important fields:

| Field | Purpose | Default |
| --- | --- | --- |
| `Backend` | `auth.BackendMongo` or `auth.BackendPostgres`. | `auth.BackendMongo` |
| `Mongo` | Pointer to `mgo.Config` (URI, db name, collection names, operation timeout). | `mgo.DefaultConfig()` |
| `Pgx` | Pointer to `pgx.Config` (DSN, pool sizing, health checks, timeouts). | `pgx.DefaultConfig()` |
| `Session` | Controls session length (`config.Session`). | 30 days |
| `Tokens` | TTLs for verification/reset/email-change tokens (`config.Tokens`). | 48h/1h/24h |
| `Argon2` | Cost settings for Argon2id hashing (`config.Argon2`). | Time=3, Memory=64MiB |
| `Email` | SMTP transport (`config.Mail`). Empty `Host` disables email sending (uses `email.NopSender`). | See `config/mail.go` |

### Mongo Config (`mgo.Config`)
- `URI`: Mongo connection string.
- `Database`: database name.
- `{Users,Sessions,Verification,PasswordReset,EmailChange}Collection`: collection names (defaults provided).
- `OperationTimeout`: per call timeout for repository operations.
- The Mongo service now ensures the essential indexes (unique `email`/`username`, unique `token_hash` values, TTL on `expires_at`) the first time it connects, so tokens and sessions expire automatically even if you forget to add indexes manually.

### PostgreSQL Config (`pgx.Config`)
- `DSN`: PostgreSQL connection string (e.g. `postgres://user:pass@localhost:5432/auth?sslmode=disable`).
- `MaxConns`, `MinConns`, `HealthCheckInterval`, `MaxConnLifetime`, `MaxConnIdleTime`: passed to `pgxpool`.
- `OperationTimeout`: context deadline used by repositories.
- Embedded migrations now create helper indexes on `expires_at` for sessions and token tables, so scheduled cleanup jobs (or `DELETE ... WHERE expires_at < now()`) stay efficient. PostgreSQL does not support TTL indexes natively, so you still need a periodic cleanup job if you want automatic removal.

> ℹ️ The pgx backend applies embedded SQL migrations automatically and expects PostgreSQL 16+ (for the `uuidv7()` default). If you're on an older version, replace the default in `pgx/migrations/0001_init.sql` or create the function manually.

## Example: MongoDB Backend (`mgo`)

```go
package main

import (
    "context"
    "log"
    "net/http"

    "github.com/deicod/auth"
    "github.com/deicod/auth/handlers"
)

func main() {
    ctx := context.Background()

    cfg := auth.DefaultConfig()
    cfg.Backend = auth.BackendMongo
    cfg.Mongo.URI = "mongodb://localhost:27017"
    cfg.Mongo.Database = "auth_demo"

    svc, err := auth.NewService(ctx, cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer closeService(ctx, svc)

    authHandlers := handlers.New(svc)
    mux := http.NewServeMux()
    mux.Handle("/auth/register", authHandlers.Register())
    mux.Handle("/auth/login", authHandlers.Login())
    mux.Handle("/auth/verify", authHandlers.VerifyEmail())
    mux.Handle("/auth/forgot", authHandlers.ForgotPassword())
    mux.Handle("/auth/reset", authHandlers.ResetPassword())
    mux.Handle("/auth/email-change", authHandlers.InitiateEmailChange())
    mux.Handle("/auth/email-confirm", authHandlers.ConfirmEmailChange())

    log.Println("auth API listening on :8080")
    log.Fatal(http.ListenAndServe(":8080", mux))
}

func closeService(ctx context.Context, svc auth.Service) {
    if closer, ok := svc.(interface{ Close(context.Context) error }); ok {
        _ = closer.Close(ctx)
    }
}
```

Sample request/response:

```bash
curl -X POST http://localhost:8080/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","username":"alice","password":"Sup3rSecret"}'

# => {"user":{"id":"...","email":"alice@example.com","username":"alice"},"session":{"id":"...","expires_at":"..."},"token":"opaque-session-token"}
```

Emails are sent only when `cfg.Email.Host` is set. Without SMTP configuration the service still works, but verification/reset tokens are stored and must be delivered manually for testing.

## Example: PostgreSQL Backend (`pgx`)

```go
package main

import (
    "context"
    "log"
    "net/http"
    "time"

    "github.com/deicod/auth"
    "github.com/deicod/auth/handlers"
)

func main() {
    ctx := context.Background()

    cfg := auth.DefaultConfig()
    cfg.Backend = auth.BackendPostgres
    cfg.Pgx.DSN = "postgres://auth:auth@localhost:5432/auth?sslmode=disable"
    cfg.Pgx.MaxConns = 8
    cfg.Session.Length = 14 * 24 * time.Hour
    cfg.Tokens.ResetTTL = 15 * time.Minute

    svc, err := auth.NewService(ctx, cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer closeService(ctx, svc)

    router := http.NewServeMux()
    authHandlers := handlers.New(svc)
    router.Handle("/auth/login", authHandlers.Login())
    router.Handle("/auth/register", authHandlers.Register())
    router.Handle("/auth/verify", authHandlers.VerifyEmail())

    log.Fatal(http.ListenAndServe(":3000", router))
}

func closeService(ctx context.Context, svc auth.Service) {
    if closer, ok := svc.(interface{ Close(context.Context) error }); ok {
        _ = closer.Close(ctx)
    }
}
```

The pgx service automatically runs the embedded migration (`pgx/migrations/0001_init.sql`) when it connects. Ensure the configured database user can create tables and that the `uuid-ossp` extension or PostgreSQL 16+ UUID helpers are available.

## HTTP Handlers & JSON Contracts

All handlers accept/return JSON and bubble up `core` errors with appropriate HTTP status codes.

| Handler | Method + Path | Request Body | Response |
| --- | --- | --- | --- |
| `Register()` | `POST /auth/register` | `{email, username, password}` | `core.AuthResult` (user, session, token). |
| `Login()` | `POST /auth/login` | `{email, password}` | `core.AuthResult`. |
| `Logout()` | `POST /auth/logout` | Bearer token header | `204 No Content`. |
| `Me()` | `GET /auth/me` | Bearer token header | `{user, session}`. |
| `VerifyEmail()` | `POST /auth/verify` | `{token}` | `core.VerifyEmailResult`. |
| `ForgotPassword()` | `POST /auth/forgot` | `{email}` | `{"status":"email_sent"}`. |
| `ResetPassword()` | `POST /auth/reset` | `{token, new_password}` | `core.UserPublic`. |
| `InitiateEmailChange()` | `POST /auth/email-change` | `{user_id, password, new_email}` | `{"status":"email_sent"}`. |
| `ConfirmEmailChange()` | `POST /auth/email-confirm` | `{token}` | `core.ChangeEmailResult`. |

Use the helpers in `core/errors.go` to distinguish conflicts, bad requests, unauthorized cases, etc., if you need to customize error rendering.

## Middleware Usage

`Register` and `Login` both return an opaque session token. Store it client-side and send it as `Authorization: Bearer <token>` on requests that hit your own APIs. The service exposes `AuthenticateSession`, and the `middleware` package wraps it for you:

```go
import (
    "net/http"

    "github.com/deicod/auth/middleware"
)

requireAuth := middleware.RequireAuth(svc)
mux.Handle("/profile", requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    if user, ok := middleware.UserFromContext(r.Context()); ok {
        respondJSON(w, http.StatusOK, user)
        return
    }
    http.Error(w, "user missing", http.StatusInternalServerError)
})))
```

`middleware.SessionFromContext` is also available if you need to inspect the active session (user agent, IP, expiry, etc.). No additional database wiring is required—the middleware simply calls `svc.AuthenticateSession`, which hashes the bearer token, fetches the session record via the configured backend and returns the associated user.

## Tokens, Sessions and Email

- Sessions store a hashed token plus metadata (IP, user-agent) and respect `config.Session.Length`.
- Password resets revoke all of the user's existing sessions to force fresh logins.
- Verification, password reset and email-change tokens are short-lived; customize TTLs through `cfg.Tokens`.
- Passwords use Argon2id (via `cfg.Argon2`). Raising `Memory` or `Time` enforces stronger hashing requirements.
- Set `cfg.Email` to an SMTP server (host, port, credentials, `UseSSL`) to enable automated verification/reset/email-change emails. With an empty host, the `email.NopSender` satisfies the interface so the flows still succeed in tests.

## Error Handling

Service methods return errors from `core/errors.go` (`ErrEmailExists`, `ErrInvalidCredentials`, `ErrTokenExpired`, etc.). The provided handlers already translate them to HTTP status codes, but you can wrap the service with your own transport knowing the error contracts are consistent across backends.

## Development Tips
- When switching backends, reuse the same handlers and only change `cfg.Backend` plus backend-specific config.
- For integration tests, keep SMTP disabled and read verification/reset tokens directly from the database collections/tables.
- The service implementations expose `Close(context.Context) error`; type-assert the returned `auth.Service` if you need to cleanly close Mongo clients or pgx pools at shutdown.
