-- Accepted usernames are ASCII. Match lookup independently of database locale.
CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_unique ON users (LOWER(username COLLATE "C"));
