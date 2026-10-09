-- Accepted usernames are ASCII, matching SQLite's NOCASE comparison.
CREATE UNIQUE INDEX IF NOT EXISTS users_username_nocase_unique ON users (username COLLATE NOCASE);
