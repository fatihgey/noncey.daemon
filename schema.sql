CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    email         TEXT    DEFAULT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS configurations (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name              TEXT    NOT NULL,
    version           TEXT    NOT NULL DEFAULT '-1',
    description       TEXT    DEFAULT NULL,
    status            TEXT    NOT NULL DEFAULT 'incomplete',
    -- incomplete | valid | valid_tested | pending_review
    visibility        TEXT    NOT NULL DEFAULT 'private',
    -- private | public
    activated         INTEGER NOT NULL DEFAULT 0,
    prompt            TEXT    DEFAULT NULL,
    -- JSON: {"url": "...", "selector": "..."}
    client_test_count INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at        TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(owner_id, name, version)
);

CREATE TABLE IF NOT EXISTS subscriptions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    config_id  INTEGER NOT NULL REFERENCES configurations(id) ON DELETE CASCADE,
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(user_id, config_id)
);

CREATE TABLE IF NOT EXISTS providers (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id             INTEGER NOT NULL REFERENCES users(id)         ON DELETE CASCADE,
    config_id           INTEGER          REFERENCES configurations(id) ON DELETE SET NULL,
    tag                 TEXT    NOT NULL,
    channel_type        TEXT    NOT NULL DEFAULT 'email'
                            CHECK(channel_type IN ('email', 'sms')),
    extract_source      TEXT    NOT NULL DEFAULT 'body',
    extract_mode        TEXT    NOT NULL DEFAULT 'auto',
    nonce_start_marker  TEXT    NOT NULL DEFAULT '',
    nonce_end_marker    TEXT,
    nonce_length        INTEGER,
    sample_email        TEXT,
    UNIQUE(config_id, tag)
);

CREATE TABLE IF NOT EXISTS provider_matchers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_id     INTEGER NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    sender_email    TEXT,
    subject_pattern TEXT,
    sender_phone    TEXT,
    body_pattern    TEXT,
    body_match_type TEXT CHECK(body_match_type IN ('starts_with', 'regex'))
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
    client_type  TEXT    NOT NULL DEFAULT 'browser'
                     CHECK(client_type IN ('browser', 'chrome', 'android')),
    created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at   TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS unmatched_items (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    channel_type TEXT    NOT NULL DEFAULT 'email'
                     CHECK(channel_type IN ('email', 'sms')),
    sender       TEXT,
    fwd_sender   TEXT,
    subject      TEXT,
    body_text    TEXT,
    received_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS marketplace_reviews (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    config_id   INTEGER NOT NULL REFERENCES configurations(id) ON DELETE CASCADE,
    reviewer_id INTEGER          REFERENCES users(id) ON DELETE SET NULL,
    decision    TEXT    NOT NULL,  -- 'approved' | 'rejected'
    note        TEXT    DEFAULT NULL,
    reviewed_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_nonces_user_expires    ON nonces(user_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash    ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user          ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_unmatched_user         ON unmatched_items(user_id, received_at);
CREATE INDEX IF NOT EXISTS idx_providers_config       ON providers(config_id);
CREATE INDEX IF NOT EXISTS idx_configs_owner          ON configurations(owner_id);
CREATE INDEX IF NOT EXISTS idx_configs_status         ON configurations(status);
CREATE INDEX IF NOT EXISTS idx_subscriptions_user     ON subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_config   ON subscriptions(config_id);
