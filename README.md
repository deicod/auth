# Auth Package

Reusable authentication package with pluggable storage engines. Currently MongoDB is fully implemented while a PostgreSQL backend stub is provided for future expansion.

## Features

- Shared domain models (`mgo/models/`) and repository interfaces (`repositories/`).
- Business logic in `mgo/services/` covering password hashing (Argon2id), registration, login and session management.
- HTTP handlers (`mgo/handlers/`) for `/register`, `/login`, `/logout`, `/me` endpoints.
- Authentication middleware (`mgo/middleware/`) that validates bearer tokens and enriches the request context.
- MongoDB backend (`mgo/`) with dedicated collections for users and sessions, including required indexes and TTL cleanup.
- Root `auth` package exposes a unified `Manager` for wiring services, handlers and middleware while selecting the backend.

## Quick Start

```go
ctx := context.Background()
manager, err := auth.New(ctx, auth.Config{
    Backend: auth.BackendMongo,
    Mongo: &mgo.Config{
        URI:      "mongodb://localhost:27017",
        Database: "auth",
    },
})
if err != nil {
    log.Fatal(err)
}
defer manager.Close(ctx)

http.Handle("/auth/", http.StripPrefix("/auth", manager.Handler()))
protected := manager.Middleware()(myAppHandler)
```

Attach `protected` to routes that require authentication. Use the middleware/context helpers to fetch the authenticated user.
