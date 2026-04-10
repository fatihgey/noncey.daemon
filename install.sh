#!/usr/bin/env bash
# =============================================================================
# noncey install script
#
# Usage:
#   sudo ./install.sh [/path/to/noncey.conf]
#
# Default config path: /opt/noncey/daemon/etc/noncey.conf
#
# Before running, create and fill in the config:
#   mkdir -p /opt/noncey/daemon/etc
#   cp noncey.conf.example /opt/noncey/daemon/etc/noncey.conf
#   editor /opt/noncey/daemon/etc/noncey.conf
#
# Safe to re-run: all steps are idempotent.
# Files outside /opt/noncey/ are only symlinks or idempotent edits.
# =============================================================================
set -euo pipefail

# ── Paths ──────────────────────────────────────────────────────────────────────
CONF="${1:-/opt/noncey/daemon/etc/noncey.conf}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="${SCRIPT_DIR}"

# ── Version ────────────────────────────────────────────────────────────────────
FORMAL_VERSION=$(git -C "${SCRIPT_DIR}" describe --tags --abbrev=0 2>/dev/null \
    | sed 's/^v//' || true)
[[ -n "${FORMAL_VERSION}" ]] || FORMAL_VERSION="1.0.0"
GIT_HASH=$(git -C "${SCRIPT_DIR}" rev-parse --short HEAD 2>/dev/null || true)
[[ -n "${GIT_HASH}" ]] || GIT_HASH="unknown"
DISPLAY_VERSION="${FORMAL_VERSION}+${GIT_HASH}"

# ── Output helpers ─────────────────────────────────────────────────────────────
BOLD='\033[1m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
_step=0
step()  { _step=$((_step+1)); echo -e "\n${BOLD}[${_step}]${NC} $*"; }
ok()    { echo -e "  ${GREEN}ok${NC}   $*"; }
warn()  { echo -e "  ${YELLOW}warn${NC} $*"; }
info()  { echo    "       $*"; }
die()   { echo -e "\n${RED}FATAL:${NC} $*\n" >&2; exit 1; }

# ── Create a symlink, backing up any pre-existing real file ───────────────────
# Usage: make_symlink <target> <link>
make_symlink() {
    local target="$1" link="$2"
    if [[ -L "$link" ]]; then
        ln -sf "$target" "$link"          # update existing symlink in-place
    elif [[ -e "$link" ]]; then
        local bak="${link}.pre-noncey.$(date +%Y%m%d%H%M%S)"
        mv "$link" "$bak"
        warn "Pre-existing file backed up → $bak"
        ln -sf "$target" "$link"
    else
        ln -sf "$target" "$link"
    fi
    ok "Symlink: $link → $target"
}

# ── Read one value from the INI config ────────────────────────────────────────
conf() {  # conf <section> <key>
    python3 - "$CONF" "$1" "$2" <<'PY'
import sys, configparser
c = configparser.ConfigParser()
c.read(sys.argv[1])
print(c.get(sys.argv[2], sys.argv[3], fallback=''))
PY
}

# =============================================================================
echo -e "\n${BOLD}noncey installer${NC}"
echo   "  config : $CONF"
echo   "  source : $SOURCE_DIR"

# ── Preflight ─────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]]      || die "Must run as root."
[[ -d "$SOURCE_DIR" ]] || die "Source directory not found: $SOURCE_DIR"

if [[ ! -f "$CONF" ]]; then
    die "Config not found: $CONF\n\n" \
        "  Create it first:\n" \
        "    mkdir -p $(dirname "$CONF")\n" \
        "    cp ${SOURCE_DIR}/noncey.conf.example $CONF\n" \
        "    editor $CONF"
fi

for cmd in python3 mysql postconf a2ensite a2enmod systemctl; do
    command -v "$cmd" >/dev/null || die "Required command not found: $cmd"
done
python3 -c "import ensurepip" 2>/dev/null \
    || die "python3 ensurepip module missing.\n  Run: apt install python3-venv"

# ── Parse and validate config ─────────────────────────────────────────────────
DOMAIN=$(conf general domain)
FLASK_PORT=$(conf general flask_port);              FLASK_PORT=${FLASK_PORT:-5000}
ARCHIVE_RETENTION=$(conf general archive_retention_d); ARCHIVE_RETENTION=${ARCHIVE_RETENTION:-30}
SECRET_KEY=$(conf general secret_key)

INSTALL_DIR=$(conf paths install_dir);             INSTALL_DIR=${INSTALL_DIR:-/opt/noncey/daemon}
DB_PATH=$(conf paths db_path);                     DB_PATH=${DB_PATH:-${INSTALL_DIR}/var/noncey.db}
ARCHIVE_PATH=$(conf paths archive_path);           ARCHIVE_PATH=${ARCHIVE_PATH:-${INSTALL_DIR}/var/archive}

MYSQL_HOST=$(conf mysql host);                     MYSQL_HOST=${MYSQL_HOST:-localhost}
MYSQL_USER=$(conf mysql user)
MYSQL_PASS=$(conf mysql password)
MYSQL_DB=$(conf mysql database)

TLS_CERT=$(conf tls cert)
TLS_KEY=$(conf tls key)

ETC_DIR="${INSTALL_DIR}/etc"
VAR_DIR="${INSTALL_DIR}/var"
VENV="${INSTALL_DIR}/venv"

for pair in \
    "DOMAIN:general.domain" \
    "SECRET_KEY:general.secret_key" \
    "MYSQL_USER:mysql.user"         "MYSQL_PASS:mysql.password" \
    "MYSQL_DB:mysql.database" \
    "TLS_CERT:tls.cert"             "TLS_KEY:tls.key"
do
    varname="${pair%%:*}"; cfgkey="${pair##*:}"
    [[ -n "${!varname}" ]] || die "Missing required config value: [$cfgkey]"
done

[[ "$SECRET_KEY" != "CHANGE_ME" ]] || die \
    "secret_key is still 'CHANGE_ME'.\n  Run: python3 -c \"import secrets; print(secrets.token_hex(32))\""

[[ -f "$TLS_CERT" ]] || die "TLS certificate not found: $TLS_CERT"
[[ -f "$TLS_KEY"  ]] || die "TLS key not found: $TLS_KEY"

mysql -h"$MYSQL_HOST" -u"$MYSQL_USER" -p"$MYSQL_PASS" "$MYSQL_DB" \
    -e "SELECT 1;" >/dev/null 2>&1 \
    || die "MySQL connection failed — check [mysql] credentials in $CONF"

ok "Config valid  |  domain: $DOMAIN  |  install: $INSTALL_DIR"

# Stop any running instance before overwriting files
systemctl stop noncey 2>/dev/null && info "Stopped running noncey service." || true

# =============================================================================
step "System user"
if id noncey >/dev/null 2>&1; then
    ok "User 'noncey' already exists."
else
    useradd --system --no-create-home --shell /usr/sbin/nologin noncey
    ok "User 'noncey' created."
fi

# =============================================================================
step "Directory structure under $INSTALL_DIR"
#
# /opt/noncey/daemon/
#   etc/   — config + generated service/map files; symlinked into system dirs
#   var/   — runtime data (db, archive)
#   venv/  — Python virtualenv
#
# /opt/noncey/common/ would hold shared components if a second server-side
# component is ever added; nothing lives there currently.
#
mkdir -p \
    "${INSTALL_DIR}" \
    "${ETC_DIR}" \
    "${VAR_DIR}" \
    "${ARCHIVE_PATH}"

# App files and venv: owned by noncey, readable by noncey
chown -R root:root  "${INSTALL_DIR}"
chown    root:root  "${ETC_DIR}"      && chmod 755 "${ETC_DIR}"
chown  noncey:noncey "${VAR_DIR}"     && chmod 750 "${VAR_DIR}"
chown  noncey:noncey "${ARCHIVE_PATH}"&& chmod 750 "${ARCHIVE_PATH}"

# Config file: readable only by root and noncey
chown root:noncey "$CONF" && chmod 640 "$CONF"
ok "Directories ready."

# =============================================================================
step "Application files  →  $INSTALL_DIR"
# Copy source files. The source has no etc/ subdir, so the user's config
# at ${ETC_DIR}/noncey.conf is not affected by this copy.
cp -r "${SOURCE_DIR}"/. "${INSTALL_DIR}/"
chown -R root:root    "${INSTALL_DIR}"
# Restore var/ recursively — subdirectories (e.g. archive/username/) may exist
# from previous runs and must be owned by noncey, not root.
chown -R noncey:noncey "${VAR_DIR}"
chown    root:noncey   "${ETC_DIR}"      "$CONF"
ok "Files copied."

# Write version.py (generated from git; not stored in source tree)
printf 'FORMAL_VERSION  = "%s"\nDISPLAY_VERSION = "%s"\n' \
    "${FORMAL_VERSION}" "${DISPLAY_VERSION}" > "${INSTALL_DIR}/version.py"
chown root:root "${INSTALL_DIR}/version.py"
chmod 644       "${INSTALL_DIR}/version.py"
ok "Version: ${DISPLAY_VERSION}"

# =============================================================================
step "Python virtualenv  +  pip install"
if [[ ! -f "$VENV/bin/pip" ]]; then
    [[ -d "$VENV" ]] && rm -rf "$VENV" && warn "Removed incomplete virtualenv, recreating."
    python3 -m venv "$VENV"
    ok "Virtualenv created: $VENV"
else
    ok "Virtualenv already exists."
fi
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r "${INSTALL_DIR}/requirements.txt"
chown -R noncey:noncey "$VENV"
ok "Dependencies installed."

# =============================================================================
step "Database initialisation"

# Run column migrations BEFORE flask init-db so that existing tables already
# have all new columns when schema.sql tries to create indexes on them.
# Each migration is guarded by both a table-existence check (no-op on fresh
# installs where the table does not exist yet) and a column-existence check
# (idempotent on repeat runs).
sudo -u noncey "$VENV/bin/python3" - "$DB_PATH" <<'PY'
import sys, sqlite3
db = sqlite3.connect(sys.argv[1])

tables = {r[0] for r in db.execute(
    "SELECT name FROM sqlite_master WHERE type='table'"
).fetchall()}

if 'providers' in tables:
    cols = {r[1] for r in db.execute("PRAGMA table_info(providers)").fetchall()}
    for col, sql in [
        ("extract_source", "ALTER TABLE providers ADD COLUMN extract_source TEXT NOT NULL DEFAULT 'body'"),
        ("extract_mode",   "ALTER TABLE providers ADD COLUMN extract_mode   TEXT NOT NULL DEFAULT 'auto'"),
        ("nonce_length",   "ALTER TABLE providers ADD COLUMN nonce_length   INTEGER"),
        ("config_id",      "ALTER TABLE providers ADD COLUMN config_id INTEGER REFERENCES configurations(id) ON DELETE SET NULL"),
    ]:
        if col not in cols:
            db.execute(sql)

if 'unmatched_emails' in tables:
    cols = {r[1] for r in db.execute("PRAGMA table_info(unmatched_emails)").fetchall()}
    for col, sql in [
        ("fwd_sender", "ALTER TABLE unmatched_emails ADD COLUMN fwd_sender TEXT"),
    ]:
        if col not in cols:
            db.execute(sql)

if 'users' in tables:
    cols = {r[1] for r in db.execute("PRAGMA table_info(users)").fetchall()}
    for col, sql in [
        ("email",    "ALTER TABLE users ADD COLUMN email    TEXT DEFAULT NULL"),
        ("is_admin", "ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0"),
    ]:
        if col not in cols:
            db.execute(sql)

db.commit()
db.close()
PY
ok "Column migrations applied (legacy)."

# Second migration block: new configuration model (v2)
# Adds visibility/prompt/activated/client_test_count; renames status values;
# creates subscriptions table; migrates source_config_id relationships.
sudo -u noncey "$VENV/bin/python3" - "$DB_PATH" <<'PY'
import sys, sqlite3
db = sqlite3.connect(sys.argv[1])
db.execute("PRAGMA foreign_keys = OFF")

tables = {r[0] for r in db.execute(
    "SELECT name FROM sqlite_master WHERE type='table'"
).fetchall()}

if 'configurations' in tables:
    cols = {r[1] for r in db.execute("PRAGMA table_info(configurations)").fetchall()}
    for col, sql in [
        ('visibility',         "ALTER TABLE configurations ADD COLUMN visibility TEXT NOT NULL DEFAULT 'private'"),
        ('prompt',             "ALTER TABLE configurations ADD COLUMN prompt TEXT DEFAULT NULL"),
        ('client_test_count',  "ALTER TABLE configurations ADD COLUMN client_test_count INTEGER NOT NULL DEFAULT 0"),
        ('activated',          "ALTER TABLE configurations ADD COLUMN activated INTEGER NOT NULL DEFAULT 0"),
    ]:
        if col not in cols:
            db.execute(sql)

    # Rename status values and derive activated flag from old status
    # Order matters: most specific first to avoid double-updating
    db.execute(
        "UPDATE configurations SET visibility='public', status='valid', activated=0 "
        "WHERE status='public'"
    )
    db.execute(
        "UPDATE configurations SET status='valid_tested', activated=1 "
        "WHERE status='tested'"
    )
    db.execute(
        "UPDATE configurations SET status='valid', activated=1 "
        "WHERE status='active'"
    )
    db.execute(
        "UPDATE configurations SET status='incomplete', activated=0 "
        "WHERE status='draft'"
    )
    # pending_review: keep status, set activated=1 (were tested before submitting)
    db.execute(
        "UPDATE configurations SET activated=1 "
        "WHERE status='pending_review'"
    )

if 'subscriptions' not in tables:
    db.execute("""
        CREATE TABLE subscriptions (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            config_id  INTEGER NOT NULL REFERENCES configurations(id) ON DELETE CASCADE,
            created_at TEXT    NOT NULL DEFAULT (datetime('now')),
            UNIQUE(user_id, config_id)
        )
    """)
    db.execute("CREATE INDEX idx_subscriptions_user   ON subscriptions(user_id)")
    db.execute("CREATE INDEX idx_subscriptions_config ON subscriptions(config_id)")

    if 'configurations' in tables:
        cols = {r[1] for r in db.execute("PRAGMA table_info(configurations)").fetchall()}
        if 'source_config_id' in cols:
            # Migrate cloned subscriptions: owner → source config
            rows = db.execute(
                "SELECT owner_id, source_config_id FROM configurations "
                "WHERE source_config_id IS NOT NULL"
            ).fetchall()
            for row in rows:
                try:
                    db.execute(
                        "INSERT OR IGNORE INTO subscriptions (user_id, config_id) VALUES (?, ?)",
                        (row[0], row[1])
                    )
                except Exception:
                    pass
        # Auto-subscribe owners to their own public configs
        db.execute("""
            INSERT OR IGNORE INTO subscriptions (user_id, config_id)
            SELECT owner_id, id FROM configurations WHERE visibility='public'
        """)

db.execute("PRAGMA foreign_keys = ON")
db.commit()
db.close()
PY
ok "Configuration model v2 migrations applied."

# Third migration block: SMS channel support (v3)
# - Renames unmatched_emails → unmatched_items (preserving all rows)
# - Adds channel_type discriminator to unmatched_items and providers
# - Adds sender_phone to provider_matchers
# - Adds client_type to sessions (for Change #20 session management UI)
sudo -u noncey "$VENV/bin/python3" - "$DB_PATH" <<'PY'
import sys, sqlite3
db = sqlite3.connect(sys.argv[1])
db.execute("PRAGMA foreign_keys = OFF")

tables = {r[0] for r in db.execute(
    "SELECT name FROM sqlite_master WHERE type='table'"
).fetchall()}

# ── Rename unmatched_emails → unmatched_items ─────────────────────────────────
# If the old table exists and the new one does not, rename it so all existing
# rows are preserved.  If both exist (partial upgrade), leave them as-is and
# let the column-add below bring unmatched_items up to date.
if 'unmatched_emails' in tables and 'unmatched_items' not in tables:
    db.execute("ALTER TABLE unmatched_emails RENAME TO unmatched_items")
    # Drop the old index (name referenced the old table name); the new one is
    # created by flask init-db / schema.sql under idx_unmatched_user.
    db.execute("DROP INDEX IF EXISTS idx_unmatched_user")
    tables.add('unmatched_items')
    tables.discard('unmatched_emails')

# ── Add channel_type to unmatched_items ───────────────────────────────────────
if 'unmatched_items' in tables:
    cols = {r[1] for r in db.execute("PRAGMA table_info(unmatched_items)").fetchall()}
    if 'channel_type' not in cols:
        db.execute(
            "ALTER TABLE unmatched_items ADD COLUMN channel_type TEXT NOT NULL DEFAULT 'email' "
            "CHECK(channel_type IN ('email', 'sms'))"
        )

# ── Add channel_type to providers ─────────────────────────────────────────────
if 'providers' in tables:
    cols = {r[1] for r in db.execute("PRAGMA table_info(providers)").fetchall()}
    if 'channel_type' not in cols:
        db.execute(
            "ALTER TABLE providers ADD COLUMN channel_type TEXT NOT NULL DEFAULT 'email' "
            "CHECK(channel_type IN ('email', 'sms'))"
        )

# ── Add sender_phone to provider_matchers ─────────────────────────────────────
if 'provider_matchers' in tables:
    cols = {r[1] for r in db.execute("PRAGMA table_info(provider_matchers)").fetchall()}
    if 'sender_phone' not in cols:
        db.execute("ALTER TABLE provider_matchers ADD COLUMN sender_phone TEXT")

# ── Add client_type to sessions ───────────────────────────────────────────────
if 'sessions' in tables:
    cols = {r[1] for r in db.execute("PRAGMA table_info(sessions)").fetchall()}
    if 'client_type' not in cols:
        db.execute(
            "ALTER TABLE sessions ADD COLUMN client_type TEXT NOT NULL DEFAULT 'browser' "
            "CHECK(client_type IN ('browser', 'chrome', 'android'))"
        )

# ── Add body_pattern / body_match_type to provider_matchers (v4) ─────────────
if 'provider_matchers' in tables:
    cols = {r[1] for r in db.execute("PRAGMA table_info(provider_matchers)").fetchall()}
    if 'body_pattern' not in cols:
        db.execute("ALTER TABLE provider_matchers ADD COLUMN body_pattern TEXT")
    if 'body_match_type' not in cols:
        db.execute(
            "ALTER TABLE provider_matchers ADD COLUMN body_match_type TEXT "
            "CHECK(body_match_type IN ('starts_with', 'regex'))"
        )

# ── Fix providers UNIQUE constraint: (user_id, tag) → (config_id, tag) ────────
# SQLite cannot ALTER a UNIQUE constraint; must rebuild the table.
tbl_sql = db.execute(
    "SELECT sql FROM sqlite_master WHERE type='table' AND name='providers'"
).fetchone()
if tbl_sql and 'user_id, tag' in tbl_sql[0]:
    db.execute("PRAGMA foreign_keys = OFF")
    db.execute("DROP TABLE IF EXISTS providers_new")
    db.execute("""
        CREATE TABLE providers_new (
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
        )
    """)
    # Explicitly map columns by name so the INSERT is order-independent.
    # Existing rows may have channel_type = NULL if the ALTER TABLE DEFAULT
    # wasn't applied uniformly; coerce to 'email' to satisfy the CHECK.
    db.execute("""
        INSERT INTO providers_new
            (id, user_id, config_id, tag, channel_type, extract_source,
             extract_mode, nonce_start_marker, nonce_end_marker,
             nonce_length, sample_email)
        SELECT id, user_id, config_id, tag,
               COALESCE(channel_type, 'email'),
               COALESCE(extract_source, 'body'),
               COALESCE(extract_mode, 'auto'),
               COALESCE(nonce_start_marker, ''),
               nonce_end_marker, nonce_length, sample_email
        FROM providers
    """)
    db.execute("DROP TABLE providers")
    db.execute("ALTER TABLE providers_new RENAME TO providers")

db.execute("PRAGMA foreign_keys = ON")
db.commit()
db.close()
PY
ok "SMS support migrations applied (v3/v4)."

# Fourth migration block: account deletion + orphaned public config support (v5)
# - Adds delete_at column to users
# - Rebuilds configurations to make owner_id nullable (ON DELETE SET NULL)
# - Rebuilds providers to make user_id nullable (ON DELETE SET NULL)
sudo -u noncey "$VENV/bin/python3" - "$DB_PATH" <<'PY'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
db.row_factory = sqlite3.Row
tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}

# ── Add delete_at to users ────────────────────────────────────────────────────
if 'users' in tables:
    cols = {r[1] for r in db.execute("PRAGMA table_info(users)").fetchall()}
    if 'delete_at' not in cols:
        db.execute("ALTER TABLE users ADD COLUMN delete_at TEXT DEFAULT NULL")
    if 'comment' not in cols:
        db.execute("ALTER TABLE users ADD COLUMN comment TEXT DEFAULT NULL")

# ── Make configurations.owner_id nullable (ON DELETE SET NULL) ─────────────────
if 'configurations' in tables:
    tbl_sql = db.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='configurations'"
    ).fetchone()
    if tbl_sql and 'NOT NULL' in tbl_sql[0] and 'owner_id' in tbl_sql[0].split('NOT NULL')[0]:
        db.execute("PRAGMA foreign_keys = OFF")
        db.execute("DROP TABLE IF EXISTS configurations_new")
        db.execute("""
            CREATE TABLE configurations_new (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id          INTEGER REFERENCES users(id) ON DELETE SET NULL,
                name              TEXT    NOT NULL,
                version           TEXT    NOT NULL DEFAULT '-1',
                description       TEXT    DEFAULT NULL,
                status            TEXT    NOT NULL DEFAULT 'incomplete',
                visibility        TEXT    NOT NULL DEFAULT 'private',
                activated         INTEGER NOT NULL DEFAULT 0,
                prompt            TEXT    DEFAULT NULL,
                client_test_count INTEGER NOT NULL DEFAULT 0,
                created_at        TEXT    NOT NULL DEFAULT (datetime('now')),
                updated_at        TEXT    NOT NULL DEFAULT (datetime('now')),
                UNIQUE(owner_id, name, version)
            )
        """)
        db.execute("""
            INSERT INTO configurations_new
                (id, owner_id, name, version, description, status,
                 visibility, activated, prompt, client_test_count,
                 created_at, updated_at)
            SELECT id, owner_id, name, version, description, status,
                   COALESCE(visibility, 'private'),
                   COALESCE(activated, 0),
                   prompt,
                   COALESCE(client_test_count, 0),
                   created_at, updated_at
            FROM configurations
        """)
        db.execute("DROP TABLE configurations")
        db.execute("ALTER TABLE configurations_new RENAME TO configurations")
        db.execute("PRAGMA foreign_keys = ON")

# ── Make providers.user_id nullable (ON DELETE SET NULL) ───────────────────────
if 'providers' in tables:
    tbl_sql = db.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='providers'"
    ).fetchone()
    if tbl_sql and 'user_id             INTEGER NOT NULL' in tbl_sql[0]:
        db.execute("PRAGMA foreign_keys = OFF")
        db.execute("DROP TABLE IF EXISTS providers_new")
        db.execute("""
            CREATE TABLE providers_new (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id             INTEGER REFERENCES users(id)         ON DELETE SET NULL,
                config_id           INTEGER REFERENCES configurations(id) ON DELETE SET NULL,
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
            )
        """)
        db.execute("""
            INSERT INTO providers_new
                (id, user_id, config_id, tag, channel_type, extract_source,
                 extract_mode, nonce_start_marker, nonce_end_marker,
                 nonce_length, sample_email)
            SELECT id, user_id, config_id, tag,
                   COALESCE(channel_type, 'email'),
                   COALESCE(extract_source, 'body'),
                   COALESCE(extract_mode, 'auto'),
                   COALESCE(nonce_start_marker, ''),
                   nonce_end_marker, nonce_length, sample_email
            FROM providers
        """)
        db.execute("DROP TABLE providers")
        db.execute("ALTER TABLE providers_new RENAME TO providers")
        db.execute("PRAGMA foreign_keys = ON")

db.commit()
db.close()
PY
ok "Account deletion support migrations applied (v5)."

(
    cd "$INSTALL_DIR"
    sudo -u noncey \
        env FLASK_APP="${INSTALL_DIR}/app.py" NONCEY_CONF="$CONF" \
        "$VENV/bin/flask" init-db
)
[[ -f "$DB_PATH" ]] && chown noncey:noncey "$DB_PATH" && chmod 640 "$DB_PATH"
ok "Schema initialised: $DB_PATH"

# =============================================================================
step "Postfix: ${ETC_DIR}/nonce_accept.cf"
#
# A dedicated Postfix MySQL map that accepts any address at the nonce domain
# without per-user rows.  The query accesses no table — it echoes the recipient
# address, making it "known" to Postfix.  The virtual_transport row then routes
# the whole domain to the nonce-pipe transport.
#
cat > "${ETC_DIR}/nonce_accept.cf" <<EOF
# noncey — domain-level virtual alias acceptance map.
# Accepts any address at the nonce domain without per-user rows.
hosts    = ${MYSQL_HOST}
user     = ${MYSQL_USER}
password = ${MYSQL_PASS}
dbname   = ${MYSQL_DB}
query    = SELECT '%s' WHERE '%d' = '${DOMAIN}'
EOF
chown root:postfix "${ETC_DIR}/nonce_accept.cf"
chmod 640          "${ETC_DIR}/nonce_accept.cf"

make_symlink "${ETC_DIR}/nonce_accept.cf" /etc/postfix/nonce_accept.cf

# =============================================================================
step "Postfix: virtual_alias_maps  (main.cf)"
# Append nonce_accept.cf to virtual_alias_maps — idempotent via grep check.
CURRENT_MAPS=$(postconf -h virtual_alias_maps 2>/dev/null || true)
if echo "$CURRENT_MAPS" | grep -q "nonce_accept.cf"; then
    ok "nonce_accept.cf already in virtual_alias_maps."
else
    if [[ -n "$CURRENT_MAPS" ]]; then
        NEW_MAPS="${CURRENT_MAPS}, mysql:/etc/postfix/nonce_accept.cf"
    else
        NEW_MAPS="mysql:/etc/postfix/nonce_accept.cf"
    fi
    postconf -e "virtual_alias_maps = ${NEW_MAPS}"
    ok "virtual_alias_maps updated."
fi

# =============================================================================
step "Postfix: ingest-pipe wrapper  (${INSTALL_DIR}/ingest-pipe)"
# A small wrapper script that sets NONCEY_CONF before exec'ing ingest.py.
# Using a wrapper avoids relying on the pipe(8) env= attribute, which is
# parsed by the Postfix pipe daemon and can fail on some builds.
cat > "${INSTALL_DIR}/ingest-pipe" <<EOF
#!/bin/bash
export NONCEY_CONF=${CONF}
exec ${VENV}/bin/python3 ${INSTALL_DIR}/ingest.py "\$@"
EOF
chmod 755 "${INSTALL_DIR}/ingest-pipe"
chown root:root "${INSTALL_DIR}/ingest-pipe"
ok "Wrapper written: ${INSTALL_DIR}/ingest-pipe"

# =============================================================================
step "Postfix: nonce-pipe transport  (master.cf)"
MASTER_CF="/etc/postfix/master.cf"
if grep -q "^nonce-pipe" "$MASTER_CF"; then
    # Refresh the argv path in case INSTALL_DIR changed.
    sed -i "s|argv=.*/ingest-pipe|argv=${INSTALL_DIR}/ingest-pipe|" "$MASTER_CF"
    ok "nonce-pipe already present in master.cf (argv refreshed)."
else
    cp "$MASTER_CF" "${MASTER_CF}.pre-noncey.$(date +%Y%m%d%H%M%S)"
    # maxproc=1 serialises deliveries, preventing concurrent SQLite writes.
    cat >> "$MASTER_CF" <<EOF

# ── noncey OTP relay ──────────────────────────────────────────────────────────
nonce-pipe  unix  -  n  n  -  1  pipe
  flags=Rq user=noncey argv=${INSTALL_DIR}/ingest-pipe \${recipient}
EOF
    ok "nonce-pipe entry added to master.cf."
fi

# =============================================================================
step "Postfix: MySQL transport map  (${ETC_DIR}/noncey-transport.cf)"
#
# A MySQL map that reads the transport column from the virtual_transport table.
# Adding this to transport_maps lets the INSERT IGNORE row we write below
# override the global virtual_transport=lmtp default for our domain.
#
cat > "${ETC_DIR}/noncey-transport.cf" <<EOF
# noncey — per-domain transport lookup against virtual_transport table.
hosts    = ${MYSQL_HOST}
user     = ${MYSQL_USER}
password = ${MYSQL_PASS}
dbname   = ${MYSQL_DB}
query    = SELECT transport FROM virtual_transport WHERE domain='%s'
EOF
chown root:postfix "${ETC_DIR}/noncey-transport.cf"
chmod 640          "${ETC_DIR}/noncey-transport.cf"

make_symlink "${ETC_DIR}/noncey-transport.cf" /etc/postfix/noncey-transport.cf
ok "MySQL transport map written."

CURRENT_TRANSPORT=$(postconf -h transport_maps 2>/dev/null || true)
if echo "$CURRENT_TRANSPORT" | grep -q "noncey-transport.cf"; then
    ok "noncey-transport.cf already in transport_maps."
else
    if [[ -n "$CURRENT_TRANSPORT" ]]; then
        NEW_TRANSPORT="mysql:/etc/postfix/noncey-transport.cf, ${CURRENT_TRANSPORT}"
    else
        NEW_TRANSPORT="mysql:/etc/postfix/noncey-transport.cf"
    fi
    postconf -e "transport_maps = ${NEW_TRANSPORT}"
    ok "transport_maps updated."
fi

# =============================================================================
step "Postfix: virtual_transport row in MySQL"
# Routes the entire nonce domain to nonce-pipe (idempotent via INSERT IGNORE).
if mysql -h"$MYSQL_HOST" -u"$MYSQL_USER" -p"$MYSQL_PASS" "$MYSQL_DB" \
    -e "INSERT IGNORE INTO virtual_transport (domain, transport)
        VALUES ('${DOMAIN}', 'nonce-pipe:');" 2>/dev/null; then
    ok "virtual_transport: ${DOMAIN} → nonce-pipe:"
else
    warn "Could not insert virtual_transport row — check MySQL permissions."
fi

# =============================================================================
step "Postfix: reload"
postfix check || die "postfix check failed — fix errors and re-run."
systemctl reload postfix 2>/dev/null || postfix reload
ok "Postfix reloaded."

# =============================================================================
step "Apache2: ${ETC_DIR}/noncey-nonces.conf"
cat > "${ETC_DIR}/noncey-nonces.conf" <<EOF
<VirtualHost *:443>
    ServerName ${DOMAIN}

    SSLEngine             on
    SSLCertificateFile    ${TLS_CERT}
    SSLCertificateKeyFile ${TLS_KEY}

    ProxyPreserveHost On

    # REST API (Chrome extension)
    ProxyPass        /api/    http://127.0.0.1:${FLASK_PORT}/api/
    ProxyPassReverse /api/    http://127.0.0.1:${FLASK_PORT}/api/

    # User / admin UI — / redirects to /auth/ (remove when root has content)
    RedirectMatch permanent ^/$ /auth/
    RedirectMatch permanent ^/auth$ /auth/
    ProxyPass        /auth/ http://127.0.0.1:${FLASK_PORT}/auth/
    ProxyPassReverse /auth/ http://127.0.0.1:${FLASK_PORT}/auth/

    ErrorLog  \${APACHE_LOG_DIR}/noncey-error.log
    CustomLog \${APACHE_LOG_DIR}/noncey-access.log combined
</VirtualHost>
EOF
chown root:root "${ETC_DIR}/noncey-nonces.conf"
chmod 644       "${ETC_DIR}/noncey-nonces.conf"

make_symlink "${ETC_DIR}/noncey-nonces.conf" \
    /etc/apache2/sites-available/noncey-nonces.conf

# =============================================================================
step "Apache2: enable modules + site"
a2enmod proxy proxy_http ssl headers >/dev/null 2>&1
a2ensite noncey-nonces >/dev/null 2>&1
apache2ctl configtest \
    || die "Apache2 config test failed — fix errors then: systemctl reload apache2"
systemctl reload apache2
ok "Apache2 reloaded."

# =============================================================================
step "systemd: ${ETC_DIR}/noncey.service"
cat > "${ETC_DIR}/noncey.service" <<EOF
[Unit]
Description=noncey OTP relay daemon
After=network.target

[Service]
Type=simple
User=noncey
WorkingDirectory=${INSTALL_DIR}
Environment=FLASK_APP=${INSTALL_DIR}/app.py
Environment=NONCEY_CONF=${CONF}
ExecStart=${VENV}/bin/flask run --host=127.0.0.1 --port=${FLASK_PORT}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
chown root:root "${ETC_DIR}/noncey.service"
chmod 644       "${ETC_DIR}/noncey.service"

make_symlink "${ETC_DIR}/noncey.service" /etc/systemd/system/noncey.service

systemctl daemon-reload
systemctl enable noncey >/dev/null 2>&1
ok "Service enabled."

# =============================================================================
step "Cron: ${ETC_DIR}/noncey.cron"
cat > "${ETC_DIR}/noncey.cron" <<EOF
# noncey — purge email archives (.eml) and SMS archives (.json) older than ${ARCHIVE_RETENTION} days
0 3 * * *  noncey  find ${ARCHIVE_PATH} -name "*.eml"  -mtime +${ARCHIVE_RETENTION} -delete 2>/dev/null
0 3 * * *  noncey  find ${ARCHIVE_PATH} -name "*.json" -mtime +${ARCHIVE_RETENTION} -delete 2>/dev/null
# noncey — delete accounts whose 3-day deletion timer has expired
0 * * * *  noncey  FLASK_APP=${INSTALL_DIR}/app.py NONCEY_CONF=${CONF} ${VENV}/bin/flask delete-pending-accounts >/dev/null 2>&1
EOF
chown root:root "${ETC_DIR}/noncey.cron"
chmod 644       "${ETC_DIR}/noncey.cron"

make_symlink "${ETC_DIR}/noncey.cron" /etc/cron.d/noncey

# =============================================================================
step "Start service"
systemctl start noncey
sleep 2
if systemctl is-active --quiet noncey; then
    ok "noncey.service is running."
else
    warn "noncey.service did not start cleanly."
    info "Diagnose: journalctl -u noncey -n 40"
fi

# =============================================================================
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Installed  —  ${YELLOW}2 manual steps remain${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════════════${NC}"
echo ""

cat <<MANUAL
${BOLD}A — Register the nonce domain in Postfix virtual_alias_domains${NC}

  Postfix must recognise '${DOMAIN}' as a local virtual domain so that
  virtual_alias_maps (and therefore nonce_accept.cf) is consulted for it.

  If your setup uses a MySQL virtual_domains table:

    mysql -h${MYSQL_HOST} -u${MYSQL_USER} -p ${MYSQL_DB} <<SQL
    INSERT IGNORE INTO virtual_domains (name) VALUES ('${DOMAIN}');
    SQL

  Adapt the table/column names to your schema if needed, then:

    systemctl reload postfix

${BOLD}Verify${NC}

  1. Create your first user:
       cd ${INSTALL_DIR} && sudo -u noncey \\
         env FLASK_APP=app.py NONCEY_CONF=${CONF} \\
         ${VENV}/bin/flask add-user

  2. Test the API:
       curl -s -X POST https://${DOMAIN}/api/auth/login \\
            -H 'Content-Type: application/json' \\
            -d '{"username":"alice","password":"secret"}'

  3. Send a test email to nonce-alice@${DOMAIN}
     and watch: journalctl -u noncey -f

MANUAL
