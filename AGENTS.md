# Repository Guidelines

## Project Structure & Module Organization

This project is a storage-agnostic authentication module for Go. Use the following structure to locate key components:

- **`auth.go`**: Defines the main `auth.Service` interface and backend configuration.
- **`sqlite/`, `mgo/`, `pgx/`**: Backend implementations for SQLite, MongoDB, and PostgreSQL respectively. Each contains `repos/` for data access logic.
- **`core/`**: Contains domain logic, DTOs, and shared errors (`core/errors.go`).
- **`handlers/`**: Implements HTTP handlers returning JSON.
- **`middleware/`**: Provides authentication middleware.
- **`config/`**: Shared configuration structs (Sessions, Tokens, etc.).
- **`email/`**: SMTP email sender logic.

## Build, Test, and Development Commands

Use the standard Go toolchain for development:

- **Run Tests**: `go test ./...`
  - Runs all unit and integration tests across the project.
- **Test with Coverage**: `go test -cover ./...`
- **Download Dependencies**: `go mod tidy`
  - Ensures all module dependencies are updated.
- **Format**: `go fmt ./...`
- **Lint**: `golangci-lint run ./...`

## Coding Style & Naming Conventions

Adhere to standard Go conventions ("Effective Go"):

- **Formatting**: Go code must be formatted with `gofmt`.
- **Naming**:
  - Exported types/functions: `PascalCase`.
  - Internal types/functions: `camelCase`.
- **Errors**: Use predefined errors in `core/errors.go` for consistency across backends. Return errors as the last return value.
- **Configuration**: Use `auth.DefaultConfig()` as a starting point for any new configuration patterns.

## Testing Guidelines

- **Framework**: Standard Go `testing` package.
- **Backend Tests**: Ensure new backends (like `sqlite`) have parity with existing tests in `mgo` and `pgx`.
- **Mocking**: Use `fakeService` or similar mocks in `handlers/auth_test.go` to test handlers without a live database.
- **Coverage**: Aim to cover edge cases, especially for critical auth flows (login, register, token handling).

## Commit & Pull Request Guidelines

- **Commit Messages**: Use clear, imperative verbs (e.g., "Add SQLite support", "Refactor user repository"). Keep summaries concise.
- **Pull Requests**:
  - Provide a clear summary of changes.
  - Link relevant issues.
  - Ensure all tests pass (`go test ./...`) before requesting review.
  - Keep changes focused on a single logical task.
