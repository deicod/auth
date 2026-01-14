# Repository Guidelines

## Project Structure & Module Organization

This project is a storage-agnostic authentication module for Go. Use the following structure to locate key components:

- **`auth.go`**: Defines the main `auth.Service` interface and backend configuration.
- **`core/`**: Contains domain logic, DTOs, and shared errors (`core/errors.go`).
- **`handlers/`**: Implements HTTP handlers returning JSON.
- **`middleware/`**: Provides authentication middleware.
- **`mgo/` & `pgx/`**: Backend implementations for MongoDB and PostgreSQL.
- **`config/`**: Shared configuration structs (Sessions, Tokens, etc.).
- **`email/`**: SMTP email sender logic.

## Build, Test, and Development Commands

- **Run Tests**: `go test ./...`
  - Runs all unit and integration tests across the project.
- **Download Dependencies**: `go mod tidy` or `go get ./...`
  - Ensures all module dependencies are up to date.

## Coding Style & Naming Conventions

- **Formatting**: Go code must be formatted with `gofmt`.
- **Naming**:
  - Exported types/functions: `PascalCase`.
  - Internal types/functions: `camelCase`.
- **Errors**: Use predefined errors in `core/errors.go` for consistency across backends.
- **Configuration**: Use `auth.DefaultConfig()` as a starting point for any new configuration patterns.

## Testing Guidelines

- **Framework**: Standard Go `testing` package.
- **Integration Tests**: Tests in `handlers/` and `core/services/` often simulate backend interactions.
- **Mocking**: Use `fakeService` or similar mocks in `handlers/auth_test.go` to test handlers without a live database.
- **Coverage**: Aim to cover edge cases, especially for critical auth flows (login, register, token handling).

## Commit & Pull Request Guidelines

- **Commit Messages**: Be specific and descriptive (e.g., "Migrated from MongoDB v1 to v2", "Add comprehensive tests for auth handlers").
- **Pull Requests**:
  - Provide a clear summary of changes.
  - Link relevant issues.
  - Ensure all tests pass before merging (`go test ./...`).
