#!/usr/bin/env python3
"""
Postfix pipe transport handler for noncey.
Called by master.cf as: ingest.py ${recipient}
Reads raw email from stdin, extracts and stores the nonce.
Exit codes follow sendmail/postfix conventions:
  0  = success
  65 = EX_DATAERR   (bad email data)
  67 = EX_NOUSER    (unknown user)
  75 = EX_TEMPFAIL  (retry later)
"""

import sys
import os
import re
import email
import sqlite3
import configparser
from datetime import datetime, timedelta, timezone
from email import policy
from pathlib import Path

CONFIG_PATH = os.environ.get('NONCEY_CONF', '/etc/noncey/noncey.conf')


# ── Config / DB helpers ──────────────────────────────────────────────────────

def load_config():
    cfg = configparser.ConfigParser()
    cfg.read(CONFIG_PATH)
    return cfg


def open_db(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# ── Email helpers ────────────────────────────────────────────────────────────

def extract_username(recipient: str) -> str:
    """nonce-{username}@nonces.example.com  →  username"""
    local = recipient.split('@')[0]
    if not local.startswith('nonce-'):
        raise ValueError(f"unexpected recipient format: {recipient!r}")
    return local[len('nonce-'):]


def get_plaintext(msg) -> str:
    """Return the best plain-text representation of the email."""
    parts = []
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == 'text/plain':
                parts.append(part.get_content())
            elif ct == 'text/html' and not parts:
                html = part.get_content()
                parts.append(re.sub(r'<[^>]+>', ' ', html))
    else:
        parts.append(msg.get_content())
    return '\n'.join(parts)


def extract_nonce(text: str, start_marker: str, end_marker: str | None) -> str | None:
    """Slice the nonce value between start_marker and end_marker (or EOL)."""
    idx = text.find(start_marker)
    if idx == -1:
        return None
    after = text[idx + len(start_marker):]
    if end_marker:
        end_idx = after.find(end_marker)
        if end_idx == -1:
            end_idx = after.find('\n')
    else:
        end_idx = after.find('\n')
    nonce = (after[:end_idx].strip() if end_idx != -1 else after.strip())
    return nonce or None


def normalise_address(raw: str) -> str:
    """Extract bare address from 'Display Name <addr@example.com>' or plain."""
    m = re.search(r'<([^>]+)>', raw)
    return (m.group(1) if m else raw).lower().strip()


# ── Archive ──────────────────────────────────────────────────────────────────

def archive_email(archive_root: str, username: str, raw_bytes: bytes) -> None:
    user_dir = Path(archive_root) / username
    user_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')
    (user_dir / f"{ts}.eml").write_bytes(raw_bytes)


# ── Provider matching ────────────────────────────────────────────────────────

def find_matching_provider(conn, user_id: int, sender_addr: str, subject: str):
    """
    Return the first providers row whose matchers match sender + subject,
    or None if no match.
    """
    providers = conn.execute(
        "SELECT id, nonce_start_marker, nonce_end_marker "
        "FROM providers WHERE user_id = ?",
        (user_id,)
    ).fetchall()

    for prov in providers:
        matchers = conn.execute(
            "SELECT sender_email, subject_pattern "
            "FROM provider_matchers WHERE provider_id = ?",
            (prov['id'],)
        ).fetchall()
        for m in matchers:
            sender_ok  = (not m['sender_email'])    or (sender_addr == m['sender_email'].lower())
            subject_ok = (not m['subject_pattern']) or bool(
                re.search(m['subject_pattern'], subject, re.IGNORECASE)
            )
            if sender_ok and subject_ok:
                return prov
    return None


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("noncey ingest: missing recipient argument", file=sys.stderr)
        sys.exit(75)

    recipient  = sys.argv[1].lower().strip()
    raw_bytes  = sys.stdin.buffer.read()

    try:
        cfg = load_config()
    except Exception as exc:
        print(f"noncey ingest: config error: {exc}", file=sys.stderr)
        sys.exit(75)

    db_path      = cfg.get('paths',   'db_path',           fallback='/var/lib/noncey/noncey.db')
    archive_root = cfg.get('paths',   'archive_path',      fallback='/var/lib/noncey/archive')
    lifetime_h   = cfg.getfloat('general', 'nonce_lifetime_h', fallback=2.0)

    try:
        username = extract_username(recipient)
    except ValueError as exc:
        print(f"noncey ingest: {exc}", file=sys.stderr)
        sys.exit(67)

    try:
        msg = email.message_from_bytes(raw_bytes, policy=policy.default)
    except Exception as exc:
        print(f"noncey ingest: email parse error: {exc}", file=sys.stderr)
        sys.exit(65)

    sender_addr = normalise_address(msg.get('From', ''))
    subject     = msg.get('Subject', '')

    try:
        conn = open_db(db_path)
    except Exception as exc:
        print(f"noncey ingest: db open error: {exc}", file=sys.stderr)
        sys.exit(75)

    try:
        user = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if not user:
            print(f"noncey ingest: unknown user: {username!r}", file=sys.stderr)
            sys.exit(67)

        user_id  = user['id']
        text     = get_plaintext(msg)
        provider = find_matching_provider(conn, user_id, sender_addr, subject)

        if not provider:
            # Not an email we were configured to handle — archive and store for review.
            archive_email(archive_root, username, raw_bytes)
            with conn:
                conn.execute(
                    "INSERT INTO unmatched_emails "
                    "  (user_id, sender, subject, body_text) "
                    "VALUES (?, ?, ?, ?)",
                    (user_id, sender_addr, subject, text)
                )
            sys.exit(0)

        nonce = extract_nonce(text, provider['nonce_start_marker'], provider['nonce_end_marker'])

        if not nonce:
            print(
                f"noncey ingest: nonce markers found no value "
                f"(user={username}, provider={provider['id']})",
                file=sys.stderr
            )
            archive_email(archive_root, username, raw_bytes)
            sys.exit(0)

        now        = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=lifetime_h)

        with conn:
            conn.execute(
                "INSERT INTO nonces "
                "  (user_id, provider_id, nonce_value, received_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (user_id, provider['id'], nonce,
                 now.isoformat(), expires_at.isoformat())
            )

        archive_email(archive_root, username, raw_bytes)

    finally:
        conn.close()

    sys.exit(0)


if __name__ == '__main__':
    main()
