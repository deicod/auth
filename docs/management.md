# Management and transactions

The SQL backends expose additive management capabilities. `auth.Service` and
the existing factories keep their v1.2.0 signatures, so external services and
HTTP-handler mocks do not need new methods. This change is suitable for a minor
release; it does not tag or otherwise publish a release.

`auth.NewManagementService` and `auth.NewManagementServiceWithMailer` return
`auth.ManagementService`, which embeds `auth.Service` and adds:

- `VerifyPassword(ctx, userID, password) error`
- `RevokeSessionsByUser(ctx, userID) error`
- `UpdateUsername(ctx, userID, username) (core.UserPublic, error)`
- `UpdateRole(ctx, userID, role) (core.UserPublic, error)`

The returned service also exposes `Close(ctx)` for resource cleanup.

The backend-specific `pgx.NewService` and `sqlite.NewService` also expose these
methods directly. The new management factory supports PostgreSQL and SQLite;
MongoDB retains its existing API. Authorization, application account state,
global administrator invariants and audit records belong to the consumer.

Password verification uses the same hasher, dummy hash for missing users and
early password-length bound as login. Missing users, invalid IDs and password
mismatches return `core.ErrInvalidCredentials`; database failures remain errors.
It creates no session or token and writes no timestamps. Session revocation is
idempotent, including for a missing user with a valid ID.

Username registration and updates share trimming, ASCII character validation,
the 3–30 byte length bound and availability checking. Casing is preserved for
display. Updating to one's own username, including a different casing, is valid.
Both creation and updates map final database uniqueness violations to
`core.ErrUsernameExists`. Role updates accept the roles defined by auth; they do
not enforce application authorization or a minimum number of administrators.

## Explicit units of work

SQL services expose `WithTx(ctx, tx)` to bind operations to an existing `pgx.Tx`
or `*sql.Tx`, and `InTx(ctx, callback)` to begin and finish a transaction. The
callback receives the native transaction and the bound auth operations, so it
can lock and modify its own tables on the same connection. Consumers using a
different pool must point it at the same migrated auth database/schema.

The bound object exposes only management operations and the three synchronous
token-completion operations. It deliberately omits flows that send mail or
start background work. It reuses the service's cryptographic dependencies and
dummy hash; binding does not perform additional Argon2 work.

`WithTx` never commits or rolls back the caller's transaction. Return any auth
error from the callback, or roll back an externally owned transaction on error.
Do not continue and commit a unit of work after an operation fails. Bound
objects must stay within their transaction's lifetime and must not be used
concurrently. `InTx` rolls back on errors and panics and commits only after a
successful callback. It does not retry callbacks, which may have side effects.

For PostgreSQL, transaction-bound token lookup takes a `FOR UPDATE` lock. The
lock serializes consumers of the same token through commit/rollback. Consumers
choose any broader lock order and isolation requirements before invoking auth
(for example a shared application lock before checking an administrator count).
For SQLite, binding executes a zero-row write to reserve the write transaction
before any auth reads or policy checks. This is necessary because a deferred
read transaction cannot always upgrade to a writer. An already-stale caller
transaction can fail to bind with `SQLITE_BUSY`/`SQLITE_BUSY_SNAPSHOT`; roll back
and retry the entire unit of work. Configure a busy timeout for contention.

## Policy before token and credential changes

Bound `VerifyEmail`, `ResetPassword` and `ConfirmEmailChange` require an explicit
`core.MutationPolicy` argument. A policy receives the context and a mutation
kind/user ID after token validation, but before credential changes or token
consumption. It can check and lock application rows using the native transaction
captured by the callback. Returning an error denies the operation and preserves
that error. `nil` explicitly allows the operation without a policy.

No policy is stored in context or installed globally. The existing pool methods
retain their signatures and have no application policy. Applications requiring
state checks must use the bound token operations and keep their policy reads,
locks and auth changes in that same transaction. Lock mutable policy rows, or
use an equivalent serialization scheme; a plain unlocked read under PostgreSQL
READ COMMITTED is not a sufficient concurrent state guard.

For example, a PostgreSQL consumer can check its own table and record a change
using the same native transaction (`authpgx` denotes `github.com/deicod/auth/pgx`):

```go
err := svc.InTx(ctx, func(tx pgx.Tx, bound *authpgx.Transaction) error {
    policy := func(ctx context.Context, m core.Mutation) error {
        var allowed bool
        err := tx.QueryRow(ctx,
            `SELECT allow_credentials FROM app_identity_policy WHERE user_id = $1 FOR UPDATE`,
            string(m.UserID)).Scan(&allowed)
        if err != nil {
            return err
        }
        if !allowed {
            return errPolicyDenied // an application-owned error
        }
        return nil
    }
    result, err := bound.ResetPassword(ctx, cmd, policy)
    if err != nil {
        return err
    }
    _, err = tx.Exec(ctx,
        `INSERT INTO app_changes (user_id, kind) VALUES ($1, $2)`,
        string(result.ID), "password_reset")
    return err
})
```

SQLite uses `func(tx *sql.Tx, bound *authsqlite.Transaction) error`,
`tx.QueryRowContext`/`tx.ExecContext` and `?` placeholders. Omit `FOR UPDATE`;
binding has already reserved SQLite's writer. For a transaction started through
the application's own pool, bind before performing reads:

```go
tx, err := appDB.BeginTx(ctx, nil)
if err != nil {
    return err
}
defer tx.Rollback()
bound, err := svc.WithTx(ctx, tx)
if err != nil {
    return err
}
if _, err := bound.UpdateUsername(ctx, userID, username); err != nil {
    return err
}
if _, err := tx.ExecContext(ctx,
    `INSERT INTO app_changes (user_id, kind) VALUES (?, ?)`,
    string(userID), "username_update"); err != nil {
    return err
}
return tx.Commit()
```

## Schema upgrade

The idempotent `0002` migrations add a unique expression index on
`LOWER(username COLLATE "C")` in PostgreSQL and a unique
`username COLLATE NOCASE` index in SQLite. Lookup and uniqueness use the same
comparison. Accepted usernames are ASCII, so SQLite's ASCII-only NOCASE is
sufficient. PostgreSQL lookup also explicitly uses C collation to fold ASCII I/i
consistently even with Turkish database/column collations. The original
case-sensitive constraint remains for compatibility with existing schemas.

Migrations run atomically, including on an unversioned v1.2.0 database. Existing
case-insensitive collisions cause startup to fail with `core.ErrUsernameExists`
and a remediation message. Resolve the conflicting usernames explicitly and
restart; auth does not choose an account to rename or delete. Clean legacy data,
fresh databases and repeated startup use the same migration path.

To locate collisions before upgrading:

```sql
-- PostgreSQL
SELECT LOWER(username COLLATE "C"), COUNT(*)
FROM users GROUP BY LOWER(username COLLATE "C") HAVING COUNT(*) > 1;

-- SQLite
SELECT username COLLATE NOCASE, COUNT(*)
FROM users GROUP BY username COLLATE NOCASE HAVING COUNT(*) > 1;
```

The design follows [SQLite transaction semantics](https://www.sqlite.org/lang_transaction.html),
[SQLite NOCASE comparison](https://www.sqlite.org/datatype3.html#collating_sequences),
and [PostgreSQL expression indexes](https://www.postgresql.org/docs/current/indexes-expressional.html).
PostgreSQL's [string function documentation](https://www.postgresql.org/docs/current/functions-string.html)
describes locale-dependent lowercasing, which is why the ASCII comparison is explicit.
