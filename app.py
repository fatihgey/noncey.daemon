#!/usr/bin/env python3
"""
noncey — Flask application (Component A)
Runs on 127.0.0.1:5000 via systemd, reverse-proxied by Apache2.

REST endpoints (all under /api/):
  POST   /api/auth/login
  POST   /api/auth/logout
  GET    /api/nonces
  DELETE /api/nonces/<id>
  GET    /api/configs
  POST   /api/configs/<id>/prompt
  POST   /api/configs/<id>/client-test
  POST   /api/configs/<id>/activate
  POST   /api/configs/<id>/deactivate
  DELETE /api/subscriptions/<config_id>
  POST   /api/sms/ingest

Admin UI (all under /auth/, proxied via nonces VirtualHost):
  see admin.py

Flask CLI:
  flask init-db     — initialise SQLite schema (idempotent)
  flask add-user    — create a user interactively
  flask remove-user — delete a user and all associated data
"""

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import bcrypt
import jwt
from flask import Flask, g, jsonify, request

from admin import admin_bp


def _parse_dt(s: str) -> datetime:
    """Parse an ISO-8601 datetime string tolerating Z suffix and variable fractional digits.

    Python 3.10 fromisoformat rejects 'Z' and requires exactly 3 or 6 fractional digits.
    Android's ISO_OFFSET_DATE_TIME emits 'Z' for UTC and trims trailing fractional zeros
    (e.g. '2026-04-04T21:15:09.11Z').
    """
    s = s.replace('Z', '+00:00')
    s = re.sub(r'\.(\d+)', lambda m: '.' + m.group(1).ljust(6, '0')[:6], s)
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt
from db import cfg, get_config, get_db
from provision import ProvisionError, validate_username

# ── App ───────────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = cfg('general', 'secret_key')   # also used for Flask session / flash
app.permanent_session_lifetime = timedelta(days=30)
app.register_blueprint(admin_bp)


# Jinja2 helper: {{ some_json_text | fromjson }}
app.jinja_env.filters['fromjson'] = json.loads

# ── Database teardown ─────────────────────────────────────────────────────────

SCHEMA_FILE = Path(__file__).parent / 'schema.sql'


@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()


@app.cli.command('init-db')
def init_db_command():
    """Initialise (or upgrade) the SQLite schema. Safe to run multiple times."""
    db = get_db()
    db.executescript(SCHEMA_FILE.read_text())
    db.commit()
    print('noncey: database initialised.')


# ── Auth helpers ──────────────────────────────────────────────────────────────

SESSION_LIFETIME_DAYS = 30


def _secret() -> str:
    s = cfg('general', 'secret_key')
    if not s:
        raise RuntimeError("secret_key not set in noncey.conf [general]")
    return s


def make_token(user_id: int, session_id: int) -> str:
    payload = {
        'sub': str(user_id),
        'sid': session_id,
        'iat': datetime.now(timezone.utc),
    }
    return jwt.encode(payload, _secret(), algorithm='HS256')


def decode_token(token: str) -> dict:
    return jwt.decode(token, _secret(), algorithms=['HS256'],
                      options={'verify_exp': False})


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Unauthorized'}), 401
        token = auth[7:]
        try:
            decode_token(token)
        except jwt.PyJWTError:
            return jsonify({'error': 'Invalid token'}), 401

        db  = get_db()
        th  = hash_token(token)
        now = datetime.now(timezone.utc).isoformat()
        session = db.execute(
            "SELECT id, user_id FROM sessions "
            "WHERE token_hash = ? AND expires_at > ?",
            (th, now)
        ).fetchone()
        if not session:
            return jsonify({'error': 'Session expired or revoked'}), 401

        db.execute(
            "UPDATE sessions SET last_used_at = ? WHERE id = ?",
            (now, session['id'])
        )
        db.commit()

        g.user_id    = session['user_id']
        g.session_id = session['id']
        return f(*args, **kwargs)
    return decorated


# ── REST routes ───────────────────────────────────────────────────────────────

@app.post('/api/auth/login')
def login():
    data        = request.get_json(silent=True) or {}
    username    = data.get('username', '').strip()
    password    = data.get('password', '')
    client_type = data.get('client_type', 'browser')
    if client_type not in ('browser', 'chrome', 'android'):
        client_type = 'browser'
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400

    db   = get_db()
    user = db.execute(
        "SELECT id, password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    ok = bcrypt.checkpw(password.encode(), user['password_hash'].encode())
    if not ok:
        return jsonify({'error': 'Invalid credentials'}), 401

    now        = datetime.now(timezone.utc)
    expires_at = (now + timedelta(days=SESSION_LIFETIME_DAYS)).isoformat()

    cur = db.execute(
        "INSERT INTO sessions (user_id, token_hash, created_at, last_used_at, expires_at, client_type) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (user['id'], '_placeholder_', now.isoformat(), now.isoformat(), expires_at, client_type)
    )
    session_id = cur.lastrowid
    db.commit()

    token = make_token(user['id'], session_id)
    db.execute("UPDATE sessions SET token_hash = ? WHERE id = ?",
               (hash_token(token), session_id))
    db.commit()

    return jsonify({'token': token, 'expires_at': expires_at}), 200


@app.post('/api/auth/logout')
@require_auth
def logout():
    db = get_db()
    db.execute("DELETE FROM sessions WHERE id = ?", (g.session_id,))
    db.commit()
    return '', 204


@app.get('/api/nonces')
@require_auth
def list_nonces():
    db  = get_db()
    now = datetime.now(timezone.utc)

    db.execute(
        "DELETE FROM nonces WHERE user_id = ? AND expires_at <= ?",
        (g.user_id, now.isoformat())
    )
    db.commit()

    rows = db.execute(
        "SELECT n.id, p.tag AS provider_tag, n.nonce_value, "
        "       n.received_at, n.expires_at, c.name AS configuration_name "
        "FROM   nonces n "
        "JOIN   providers p ON p.id = n.provider_id "
        "LEFT JOIN configurations c ON c.id = p.config_id "
        "WHERE  n.user_id = ? "
        "ORDER  BY n.received_at DESC",
        (g.user_id,)
    ).fetchall()

    result = []
    for row in rows:
        received_at = _parse_dt(row['received_at'])
        result.append({
            'id':                 row['id'],
            'provider_tag':       row['provider_tag'],
            'configuration_name': row['configuration_name'],
            'nonce_value':        row['nonce_value'],
            'received_at':        row['received_at'],
            'expires_at':         row['expires_at'],
            'age_seconds':        int((now - received_at).total_seconds()),
        })

    return jsonify(result), 200


@app.delete('/api/nonces/<int:nonce_id>')
@require_auth
def delete_nonce(nonce_id: int):
    db  = get_db()
    cur = db.execute(
        "DELETE FROM nonces WHERE id = ? AND user_id = ?",
        (nonce_id, g.user_id)
    )
    db.commit()
    if cur.rowcount == 0:
        return jsonify({'error': 'Not found'}), 404
    return '', 204


@app.get('/api/configs')
@require_auth
def list_configs():
    db = get_db()

    # Own private configs: valid enough to be useful to the extension
    own_rows = db.execute(
        "SELECT id, name, version, status, visibility, activated, prompt "
        "FROM   configurations "
        "WHERE  owner_id = ? AND visibility = 'private' "
        "  AND  status IN ('incomplete', 'valid', 'valid_tested', 'pending_review') "
        "ORDER  BY name, version",
        (g.user_id,)
    ).fetchall()

    # Subscribed public configs
    sub_rows = db.execute(
        "SELECT c.id, c.name, c.version, c.status, c.visibility, c.prompt "
        "FROM   configurations c "
        "JOIN   subscriptions s ON s.config_id = c.id "
        "WHERE  s.user_id = ? AND c.visibility = 'public' "
        "ORDER  BY c.name, c.version",
        (g.user_id,)
    ).fetchall()

    result = []

    def _provider_info(config_id):
        """Return (tags, channel_types, sms_matchers) for a config."""
        providers = db.execute(
            "SELECT id, tag, channel_type FROM providers WHERE config_id = ?",
            (config_id,)
        ).fetchall()
        tags          = [p['tag']          for p in providers]
        channel_types = [p['channel_type'] for p in providers]
        sms_matchers  = []
        for p in providers:
            if p['channel_type'] == 'sms':
                rows = db.execute(
                    "SELECT sender_phone, body_pattern, body_match_type "
                    "FROM provider_matchers WHERE provider_id = ?",
                    (p['id'],)
                ).fetchall()
                for r in rows:
                    sms_matchers.append({
                        'sender_phone':    r['sender_phone'],
                        'body_pattern':    r['body_pattern'],
                        'body_match_type': r['body_match_type'],
                    })
        return tags, channel_types, sms_matchers

    for row in own_rows:
        tags, channel_types, sms_matchers = _provider_info(row['id'])
        prompt_data = json.loads(row['prompt']) if row['prompt'] else None
        result.append({
            'id':            row['id'],
            'name':          row['name'],
            'version':       row['version'],
            'status':        row['status'],
            'visibility':    row['visibility'],
            'activated':     bool(row['activated']),
            'prompt':        prompt_data,
            'is_owned':      True,
            'provider_tags': tags,
            'channel_types': channel_types,
            'sms_matchers':  sms_matchers,
        })

    for row in sub_rows:
        tags, channel_types, sms_matchers = _provider_info(row['id'])
        prompt_data = json.loads(row['prompt']) if row['prompt'] else None
        result.append({
            'id':            row['id'],
            'name':          row['name'],
            'version':       row['version'],
            'status':        row['status'],
            'visibility':    row['visibility'],
            'activated':     None,
            'prompt':        prompt_data,
            'is_owned':      False,
            'provider_tags': tags,
            'channel_types': channel_types,
            'sms_matchers':  sms_matchers,
        })

    return jsonify(result), 200


@app.post('/api/configs/<int:config_id>/prompt')
@require_auth
def set_prompt(config_id: int):
    data      = request.get_json(silent=True) or {}
    url       = data.get('url', '').strip()
    selector  = data.get('selector', '').strip()
    url_match = data.get('url_match', 'prefix')
    if url_match not in ('exact', 'prefix', 'regex'):
        url_match = 'prefix'

    if not url or not selector:
        return jsonify({'error': 'url and selector required'}), 400

    db  = get_db()
    cur = db.execute(
        "UPDATE configurations SET prompt = ?, updated_at = datetime('now') "
        "WHERE  id = ? AND owner_id = ? AND visibility = 'private'",
        (json.dumps({'url': url, 'url_match': url_match, 'selector': selector}),
         config_id, g.user_id)
    )
    if cur.rowcount == 0:
        return jsonify({'error': 'Not found'}), 404

    # Structural change: reset valid_tested → valid; or promote incomplete → valid
    config = db.execute(
        "SELECT status FROM configurations WHERE id = ?", (config_id,)
    ).fetchone()
    if config:
        if config['status'] == 'valid_tested':
            db.execute(
                "UPDATE configurations SET status = 'valid', updated_at = datetime('now') "
                "WHERE id = ?", (config_id,)
            )
        elif config['status'] == 'incomplete':
            # Check if channels + headers are present
            providers = db.execute(
                "SELECT id FROM providers WHERE config_id = ?", (config_id,)
            ).fetchall()
            has_headers = any(
                db.execute(
                    "SELECT id FROM provider_matchers WHERE provider_id = ?", (p['id'],)
                ).fetchone()
                for p in providers
            )
            if has_headers:
                db.execute(
                    "UPDATE configurations SET status = 'valid', "
                    "updated_at = datetime('now') WHERE id = ?",
                    (config_id,)
                )

    db.commit()
    return '', 204


@app.post('/api/configs/<int:config_id>/client-test')
@require_auth
def report_client_test(config_id: int):
    db = get_db()
    # Allow for both owned private configs and subscribed public configs
    cur = db.execute(
        "UPDATE configurations "
        "SET client_test_count = client_test_count + 1, updated_at = datetime('now') "
        "WHERE id = ? "
        "  AND (owner_id = ? "
        "       OR id IN (SELECT config_id FROM subscriptions WHERE user_id = ?))",
        (config_id, g.user_id, g.user_id)
    )
    if cur.rowcount == 0:
        return jsonify({'error': 'Not found'}), 404

    # Advance to valid_tested once 3 successful fills reported (private configs only)
    db.execute(
        "UPDATE configurations SET status = 'valid_tested', updated_at = datetime('now') "
        "WHERE id = ? AND status = 'valid' AND client_test_count >= 3 AND visibility = 'private'",
        (config_id,)
    )
    db.commit()
    return '', 204


@app.post('/api/configs/<int:config_id>/activate')
@require_auth
def api_config_activate(config_id: int):
    db  = get_db()
    cur = db.execute(
        "UPDATE configurations "
        "SET activated=1, updated_at=datetime('now') "
        "WHERE id=? AND owner_id=? AND visibility='private' "
        "  AND status IN ('valid', 'valid_tested')",
        (config_id, g.user_id)
    )
    if cur.rowcount == 0:
        return jsonify({'error': 'Not found or not activatable'}), 404
    db.commit()
    return '', 204


@app.post('/api/configs/<int:config_id>/deactivate')
@require_auth
def api_config_deactivate(config_id: int):
    db  = get_db()
    cur = db.execute(
        "UPDATE configurations "
        "SET activated=0, updated_at=datetime('now') "
        "WHERE id=? AND owner_id=? AND visibility='private'",
        (config_id, g.user_id)
    )
    if cur.rowcount == 0:
        return jsonify({'error': 'Not found'}), 404
    db.commit()
    return '', 204


@app.delete('/api/subscriptions/<int:config_id>')
@require_auth
def api_unsubscribe(config_id: int):
    db  = get_db()
    cur = db.execute(
        "DELETE FROM subscriptions WHERE user_id=? AND config_id=?",
        (g.user_id, config_id)
    )
    if cur.rowcount == 0:
        return jsonify({'error': 'Subscription not found'}), 404
    db.commit()
    return '', 204


@app.post('/api/sms/ingest')
@require_auth
def sms_ingest():
    from ingest import match_sms_provider, extract_nonce, archive_sms

    data        = request.get_json(silent=True) or {}
    sender      = (data.get('sender') or '').strip()
    body        = data.get('body') or ''
    received_at_raw = (data.get('received_at') or '').strip()
    try:
        received_at = _parse_dt(received_at_raw).isoformat()
    except (ValueError, AttributeError):
        received_at = received_at_raw
    config_id   = data.get('config_id')   # optional manual override

    if not sender or not received_at:
        return jsonify({'error': 'sender and received_at are required'}), 400

    db           = get_db()
    archive_root = cfg('paths', 'archive_path',
                       fallback='/opt/noncey/daemon/var/archive')
    lifetime_h   = float(cfg('general', 'nonce_lifetime_h', fallback='2'))

    db_conn = db  # Flask's get_db() returns a sqlite3.Connection

    # ── Resolve provider ──────────────────────────────────────────────────────
    provider = None
    if config_id:
        # Manual funnel: use the provider attached to the specified config
        provider = db_conn.execute(
            "SELECT p.id, p.config_id, p.extract_mode, "
            "       p.nonce_start_marker, p.nonce_end_marker, p.nonce_length "
            "FROM   providers p "
            "LEFT JOIN configurations c ON c.id = p.config_id "
            "WHERE  p.config_id = ? AND p.channel_type = 'sms' "
            "  AND (c.owner_id = ? "
            "       OR EXISTS (SELECT 1 FROM subscriptions s "
            "                  WHERE s.user_id = ? AND s.config_id = c.id))",
            (config_id, g.user_id, g.user_id)
        ).fetchone()
    else:
        provider = match_sms_provider(db_conn, g.user_id, sender, body)

    # ── Archive ───────────────────────────────────────────────────────────────
    username = db_conn.execute(
        "SELECT username FROM users WHERE id=?", (g.user_id,)
    ).fetchone()['username']
    archive_sms(archive_root, username, sender, body, received_at)

    # ── Match or unmatched ────────────────────────────────────────────────────
    if provider:
        nonce = extract_nonce(
            body,
            provider['extract_mode']       or 'auto',
            provider['nonce_start_marker'] or '',
            provider['nonce_end_marker'],
            provider['nonce_length'],
        )
        if nonce:
            now        = datetime.now(timezone.utc)
            expires_at = now + timedelta(hours=lifetime_h)
            db_conn.execute(
                "INSERT INTO nonces "
                "  (user_id, provider_id, nonce_value, received_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (g.user_id, provider['id'], nonce,
                 received_at, expires_at.isoformat())
            )
            db_conn.commit()
            return '', 204

    # No match or extraction failed — store as unmatched
    db_conn.execute(
        "INSERT INTO unmatched_items "
        "  (user_id, channel_type, sender, body_text, received_at) "
        "VALUES (?, 'sms', ?, ?, ?)",
        (g.user_id, sender, body, received_at)
    )
    db_conn.commit()
    return '', 204


# ── Management CLI ────────────────────────────────────────────────────────────

@app.cli.command('add-user')
def add_user_command():
    """Create a new noncey user (prompts for username + password)."""
    import getpass
    username = input('Username: ').strip()
    try:
        validate_username(username)
    except ProvisionError as exc:
        print(f"Error: {exc}")
        return
    password = getpass.getpass('Password: ')
    if not password:
        print('Aborted: empty password.')
        return

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, pw_hash)
        )
        db.commit()
    except sqlite3.IntegrityError:
        print(f"Error: user {username!r} already exists.")
        return

    print(f"noncey: user {username!r} created.")


@app.cli.command('remove-user')
def remove_user_command():
    """Delete a user and all their associated data."""
    username = input('Username to remove: ').strip()
    if not username:
        print('Aborted: empty username.')
        return
    confirm = input(f"Remove user {username!r} and all associated data? [yes/N]: ").strip()
    if confirm.lower() != 'yes':
        print('Aborted.')
        return

    db = get_db()
    row = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        print(f"Error: user {username!r} not found.")
        return

    db.execute("DELETE FROM users WHERE username = ?", (username,))
    db.commit()
    print(f"noncey: user {username!r} removed.")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(cfg('general', 'flask_port', fallback='5000'))
    app.run(host='127.0.0.1', port=port)
