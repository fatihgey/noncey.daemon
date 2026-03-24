CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT    NOT NULL UNIQUE,
    password_hash TEXT   NOT NULL,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS providers (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id             INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tag                 TEXT    NOT NULL,
    extract_source      TEXT    NOT NULL DEFAULT 'body',
    extract_mode        TEXT    NOT NULL DEFAULT 'auto',
    nonce_start_marker  TEXT    NOT NULL DEFAULT '',
    nonce_end_marker    TEXT,
    nonce_length        INTEGER,
    sample_email        TEXT,
    UNIQUE(user_id, tag)
);

CREATE TABLE IF NOT EXISTS provider_matchers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_id     INTEGER NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    sender_email    TEXT,
    subject_pattern TEXT
);

CREATE TABLE IF NOT EXISTS nonces (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
    provider_id  INTEGER NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    nonce_value  TEXT    NOT NULL,
    received_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at   TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash   TEXT    NOT NULL UNIQUE,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at   TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS unmatched_emails (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sender      TEXT,
    subject     TEXT,
    body_text   TEXT,
    received_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_nonces_user_expires   ON nonces(user_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash   ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user         ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_unmatched_user        ON unmatched_emails(user_id, received_at);
