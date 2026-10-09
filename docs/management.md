# Management and transactions

All backends expose additive management capabilities. `auth.Service` and
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

The backend-specific `pgx.NewService`, `sqlite.NewService` and `mgo.NewService`
also expose these methods directly. The management factory supports all three
backends. Authorization, application account state,
global administrator invariants and audit records belong to the consumer.

| Backend | Management | Shared native transactions |
| --- | --- | --- |
| PostgreSQL | Yes | `pgx.Tx` |
| SQLite | Yes | `*sql.Tx` |
| MongoDB / PSMDB | Yes, including standalone | `mongo.Session` on a replica set or sharded cluster |

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

## SQL units of work

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
consumption or session revocation. It can check and lock application rows using the native transaction
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

## Mongo units of work

MongoDB and Percona Server for MongoDB use native sessions, rather than a SQL
transaction adapter. With the MongoDB Go **v2** driver used by this module, a
session context is a `context.Context` carrying a `*mongo.Session`;
there is no separate `mongo.SessionContext` type. Use the context supplied by
`Session.WithTransaction`, or `mongo.NewSessionContext(ctx, session)` for a
manually started session transaction.

`mgo.Service.InTx(ctx, func(context.Context, *mgo.Transaction) error, opts...)`
starts a session and invokes native `WithTransaction`, with snapshot read
concern and majority write concern by default. Optional native
`options.Transaction()` settings override those defaults. Pass a context with
a deadline to bound the complete unit of work. The callback context must be
used for **every** auth and consumer Mongo operation. Auth uses its configured
database and collection names; consumer collections use the session's client:

```go
// authmongo denotes github.com/deicod/auth/mgo.
err := svc.InTx(ctx, func(txCtx context.Context, bound *authmongo.Transaction) error {
    appDB := mongo.SessionFromContext(txCtx).Client().Database(appDatabaseName)
    policy := func(ctx context.Context, m core.Mutation) error {
        var control struct {
            AllowCredentials bool `bson:"allow_credentials"`
        }
        // A real write serializes concurrent state changes. A snapshot read
        // alone does not prevent another transaction changing this document.
        err := appDB.Collection("identity_policy").FindOneAndUpdate(ctx,
            bson.M{"_id": string(m.UserID)},
            bson.M{"$inc": bson.M{"lock_version": 1}}).Decode(&control)
        if err != nil {
            return err
        }
        if !control.AllowCredentials {
            return errPolicyDenied // application-owned error
        }
        return nil
    }
    result, err := bound.ResetPassword(txCtx, cmd, policy)
    if err != nil {
        return err
    }
    _, err = appDB.Collection("changes").InsertOne(txCtx,
        bson.M{"user_id": string(result.ID), "kind": "password_reset"})
    return err
})
```

Both the callback and its policies **may run multiple times**, according to the
driver's retry rules for transient transaction/commit errors. Keep side effects
inside the transaction; send mail or perform other external effects only after
`InTx` succeeds. Always return operation errors, preserving Mongo error labels;
do not swallow a failed write and continue to commit. Auth does not implement a
second retry loop. A panic propagates after the session is ended and its active
transaction aborted. Neither `InTx` nor a bound operation permits parallel use
of the session. The callback must not commit, abort or retain it; an aborted
session cannot be reported as a successful `InTx` commit.

For a consumer-owned session, use `WithTx(txCtx)` **inside** each transaction
attempt. It never starts, commits or aborts that transaction:

```go
session, err := appClient.StartSession()
if err != nil {
    return err
}
defer session.EndSession(ctx)
_, err = session.WithTransaction(ctx, func(txCtx context.Context) (any, error) {
    bound, err := svc.WithTx(txCtx)
    if err != nil {
        return nil, err
    }
    if _, err = bound.UpdateUsername(txCtx, userID, username); err != nil {
        return nil, err
    }
    _, err = appClient.Database(appDatabaseName).Collection("changes").InsertOne(txCtx,
        bson.M{"user_id": string(userID), "kind": "username_update"})
    return nil, err
})
return err
```

The consumer's session can originate from a different client connected to the
same migrated Mongo deployment. Auth rebinds its repositories to **that** client
and its own configured database; it does not pass the session to an incompatible
client. Create a fresh binding for each attempt and discard it afterwards. Bound
operations require the matching active session context, including contexts
derived from it. An absent, different or inactive session returns
`core.ErrTransactionRequired` before any database operation. `InTx` rejects an
existing session; use `WithTx` when the caller owns it. No global hook or hidden
session is installed.

The same three token methods accept `core.MutationPolicy`. The policy receives
the native session context after token validation and before any credential,
verification, email, session-revocation or token-consumption write. Its own
collection writes and auth changes commit or roll back together. For concurrent
state guards, perform a real write on the policy document (such as the increment
above); Mongo snapshot reads alone do not lock mutable state. All competing
state transitions must participate in that serialization scheme. Native write
conflicts retry the whole transaction. Conditional token consumption plus those
conflicts ensure only one transaction can complete a token. Propagate a denial
to abort the entire unit of work. Policies must not commit or abort sessions;
auth also checks the session remains active after a policy returns.

### Transaction prerequisites and errors

Multi-document transactions require a **replica set or sharded cluster**, with
session/transaction support and suitable permissions. Both transaction entry
points check the server's `hello` capabilities. A standalone server returns
`core.ErrTransactionsUnsupported`; `InTx` does not invoke its callback and
`WithTx` does not bind. There is **no non-atomic fallback**. Driver, topology,
authorization, context and commit errors are propagated; server configuration
must support the selected transaction options. `hello` checks topology outside
the transaction and does not substitute for server enforcement.

Normal auth methods and `ManagementService` remain usable on standalone Mongo
independently of transaction support. As before, ordinary multi-document auth
flows outside a transaction do not provide the shared atomicity or application
policy guarantees of the bound API.

This follows the [MongoDB Go driver transaction API](https://www.mongodb.com/docs/drivers/go/current/crud/transactions/)
and [MongoDB production transaction requirements](https://www.mongodb.com/docs/manual/core/transactions-production-consideration/).

## SQL schema upgrade

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

## Mongo username index upgrade

On startup, Mongo adds `users_username_nocase_unique` on `username` with
`{locale: "en", strength: 2, alternate: "non-ignorable"}`. Username lookup uses
an explicit `$eq` string comparison in fixed BSON fields, with the identical
collation instead of a case-insensitive regex.
For auth's allowed ASCII usernames, this provides case-insensitive equality
(including `I`/`i`) while preserving punctuation and digit-string differences.
The database enforces that equality for concurrent registration and updates;
duplicate username writes map to `core.ErrUsernameExists`.

The legacy `users_username_unique` index remains in place. Index creation is
additive and idempotent, requires index-management permissions, and changes no
user document. Clean legacy databases and fresh databases follow the same path.
Colliding existing usernames block startup with `core.ErrUsernameExists` and a
remediation message. Auth never chooses an account to rename, merge or delete.
Resolve collisions explicitly and restart; a failed index build preserves the
legacy index and account data. Mongo index setup is not a transactional SQL
migration; individual index builds can complete before a later build fails.

Find collisions before upgrading, using the configured users collection:

```javascript
db.users.aggregate([
    {$group: {_id: "$username", ids: {$push: "$_id"}, count: {$sum: 1}}},
    {$match: {count: {$gt: 1}}}
], {collation: {locale: "en", strength: 2, alternate: "non-ignorable"}})
```

See [MongoDB case-insensitive indexes](https://www.mongodb.com/docs/v7.0/core/index-case-insensitive/)
and [collation options](https://www.mongodb.com/docs/manual/reference/collation/).

## Reproducible PSMDB integration tests

With Docker running, from the repository root:

```sh
./scripts/test-mongo.sh                      # go test ./...
./scripts/test-mongo.sh go test -race ./...   # include the race detector
./scripts/test-mongo.sh go test ./mgo -count=1
```

The script pins `percona/percona-server-mongodb:8.0` by digest (PSMDB 8.0.32-14),
starts an ephemeral **single-node replica set**, runs `rs.initiate()`, waits for
its primary, and also starts a standalone negative fixture. A single node is
sufficient to test these transaction invariants; failover/replication resilience
is outside this test suite. Connections set `replicaSet=auth-rs` and
`directConnection=true` to reach the published Docker port without requiring
the container's advertised hostname to resolve on the host. These remain real
native `WithTransaction` operations, with no Mongo mocks.

Both containers bind dynamic ports on localhost. Tests use unique disposable
databases, and the script removes its containers and volumes on exit. Set
`AUTH_TEST_PSMDB_IMAGE` to try another compatible image, or
`AUTH_TEST_MONGO_LOGS=1` to print server logs on test failure. No persistent or
external database is required. CI runs `go test -race ./...` through this script
alongside PostgreSQL and the SQLite tests.

For manually managed fixtures, set `AUTH_TEST_MONGO_URI` to a replica-set/sharded
URI and `AUTH_TEST_MONGO_STANDALONE_URI` to a standalone URI. Integration tests
skip the corresponding fixture if its environment variable is absent; the
script and CI supply both. PostgreSQL tests additionally use
`AUTH_TEST_POSTGRES_DSN`, as before.

The container setup uses [Percona's Docker image](https://docs.percona.com/percona-server-for-mongodb/8.0/install/docker.html).
