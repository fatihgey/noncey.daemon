#!/usr/bin/env python3
"""
noncey — Flask application (Component A)
Runs on 127.0.0.1:5000 via systemd, reverse-proxied by Apache2.

REST endpoints (all under /api/):
  POST   /api/auth/login
  POST   /api/auth/logout
  GET    /api/nonces
  DELETE /api/nonces/<id>

Admin UI (all under /noncey/, proxied via admin VirtualHost):
  see admin.py

Flask CLI:
  flask init-db     — initialise SQLite schema (idempotent)
  flask add-user    — create a user interactively
  flask remove-user — delete a user and all associated data
"""

import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import bcrypt
import jwt
from flask import Flask, g, jsonify, request

from admin import admin_bp
from db import cfg, get_config, get_db
from provision import ProvisionError, validate_username

# ── App ───────────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = cfg('general', 'secret_key')   # also used for Flask session / flash
app.register_blueprint(admin_bp)

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
        'sub': user_id,
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
    data     = request.get_json(silent=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400

    db   = get_db()
    user = db.execute(
        "SELECT id, password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    dummy_hash = '$2b$12$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    stored     = user['password_hash'] if user else dummy_hash
    ok         = bcrypt.checkpw(password.encode(), stored.encode())
    if not user or not ok:
        return jsonify({'error': 'Invalid credentials'}), 401

    now        = datetime.now(timezone.utc)
    expires_at = (now + timedelta(days=SESSION_LIFETIME_DAYS)).isoformat()

    cur = db.execute(
        "INSERT INTO sessions (user_id, token_hash, created_at, last_used_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (user['id'], '_placeholder_', now.isoformat(), now.isoformat(), expires_at)
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
        "       n.received_at, n.expires_at "
        "FROM   nonces n "
        "JOIN   providers p ON p.id = n.provider_id "
        "WHERE  n.user_id = ? "
        "ORDER  BY n.received_at DESC",
        (g.user_id,)
    ).fetchall()

    result = []
    for row in rows:
        received_at = datetime.fromisoformat(row['received_at'])
        if received_at.tzinfo is None:
            received_at = received_at.replace(tzinfo=timezone.utc)
        result.append({
            'id':           row['id'],
            'provider_tag': row['provider_tag'],
            'nonce_value':  row['nonce_value'],
            'received_at':  row['received_at'],
            'expires_at':   row['expires_at'],
            'age_seconds':  int((now - received_at).total_seconds()),
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
