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
from email.utils import parseaddr
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


# Matches forwarding header blocks inserted by email clients, e.g.:
#   ---------- Forwarded message ---------
#   From: X  /  Date: Y  /  Subject: Z  /  To: W
#   (blank line)
# Also handles "Original Message", German "Weitergeleitete Nachricht", etc.
_FORWARDED_BLOCK_RE = re.compile(
    r'^[ \t]*-{4,}[ \t]*'
    r'(?:forwarded message|original message|weitergeleitete nachricht'
    r'|message transmis|mensaje reenviado)'
    r'[^\n]*-{4,}[ \t]*\n'
    r'(?:[ \t]*[A-Z][a-zA-Z\- ]+:[ \t]*[^\n]*\n)*'
    r'[ \t]*\n?',
    re.IGNORECASE | re.MULTILINE,
)


def strip_forwarded_headers(text: str) -> str:
    """Remove forwarded-message header blocks (handles multiple nestings)."""
    while True:
        stripped = _FORWARDED_BLOCK_RE.sub('', text)
        if stripped == text:
            return text.strip()
        text = stripped


def _extract_forwarded_sender(text: str) -> str | None:
    """
    Return the sender address of the innermost (first/original) forwarded email.
    The LAST forwarded-block match in the text is the deepest nesting level,
    which corresponds to the original forwarded message.
    """
    last_match = None
    for m in _FORWARDED_BLOCK_RE.finditer(text):
        last_match = m
    if not last_match:
        return None
    block = last_match.group(0)
    from_m = re.search(r'^From:\s*(.+)', block, re.MULTILINE | re.IGNORECASE)
    if not from_m:
        return None
    _, addr = parseaddr(from_m.group(1).strip())
    return addr.lower() if addr else None


# Keyword pattern used by auto extraction (multilingual)
_OTP_KEYWORD_RE = re.compile(
    r'(?:code|otp|token|passcode|pin|one.time|verif\w*|security\s+code|access\s+code|'
    r'sicherheitscode|einmalpasswort|zugangscode|passwort|kennwort)'
    r'(?:[^\w\n]{1,15})'
    r'([A-Z0-9]{4,10}|\d{4,9})',
    re.IGNORECASE,
)


def _extract_auto(text: str) -> str | None:
    """Heuristic OTP extraction with no configuration."""
    # 1. Text near a keyword (most reliable)
    m = _OTP_KEYWORD_RE.search(text)
    if m:
        return m.group(1)
    # 2. Standalone 5–9-digit sequence
    m = re.search(r'(?<!\d)(\d{5,9})(?!\d)', text)
    if m:
        return m.group(1)
    # 3. Standalone 4-digit sequence — skip obvious years (1900-2099)
    for m in re.finditer(r'(?<!\d)(\d{4})(?!\d)', text):
        val = m.group(1)
        if not re.match(r'^(?:19|20)\d{2}$', val):
            return val
    return None


def extract_nonce(
    text: str,
    mode: str,
    start_marker: str,
    end_marker: str | None,
    length: int | None,
) -> str | None:
    """Extract OTP from *text* according to the provider's extraction settings."""
    if mode == 'auto':
        # If derived markers are available (from example OTP at setup time), try
        # start+length first; fall back to pure heuristics only if not found.
        if start_marker:
            idx = text.find(start_marker)
            if idx != -1:
                after = text[idx + len(start_marker):]
                stripped = after.lstrip(' \t')
                if stripped and stripped[0] != '\n':
                    n = length or len(stripped.split('\n')[0].strip())
                    candidate = stripped[:n]
                    if candidate:
                        return candidate
        return _extract_auto(text)

    if not start_marker:
        return None

    idx = text.find(start_marker)
    if idx == -1:
        return None
    after = text[idx + len(start_marker):]

    # Per-line safeguard (6.3): restrict search to the current line only.
    line_end = after.find('\n')
    search_area = after[:line_end] if line_end != -1 else after

    if mode == 'start_length':
        stripped = search_area.lstrip(' \t')
        if not stripped:
            return None
        return stripped[:length] if length else stripped.strip() or None

    # mode == 'markers'
    if end_marker:
        end_idx = search_area.find(end_marker)
        if end_idx == -1:
            return None  # end marker not found on same line
        nonce = search_area[:end_idx].strip()
    else:
        nonce = search_area.strip()
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

    A provider is considered active if:
    - it has no config_id (unassigned / always active), OR
    - its configuration's status is 'active', 'tested', or 'public'.
    """
    providers = conn.execute(
        "SELECT p.id, p.config_id, p.extract_source, p.extract_mode, "
        "       p.nonce_start_marker, p.nonce_end_marker, p.nonce_length "
        "FROM providers p "
        "LEFT JOIN configurations c ON c.id = p.config_id "
        "WHERE p.user_id = ? "
        "  AND (p.config_id IS NULL OR c.status IN ('active', 'tested', 'public'))",
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

        user_id   = user['id']
        plaintext = get_plaintext(msg)
        fwd_sender = _extract_forwarded_sender(plaintext)
        body      = strip_forwarded_headers(plaintext)
        provider  = find_matching_provider(conn, user_id, sender_addr, subject)

        if not provider:
            # Not an email we were configured to handle — archive and store for review.
            archive_email(archive_root, username, raw_bytes)
            with conn:
                conn.execute(
                    "INSERT INTO unmatched_emails "
                    "  (user_id, sender, fwd_sender, subject, body_text) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (user_id, sender_addr, fwd_sender, subject, body)
                )
            sys.exit(0)

        src  = provider['extract_source'] or 'body'
        text = subject if src == 'subject' else body
        nonce = extract_nonce(
            text,
            provider['extract_mode']       or 'auto',
            provider['nonce_start_marker'] or '',
            provider['nonce_end_marker'],
            provider['nonce_length'],
        )

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
            # Increment test_count on the owning configuration and advance to
            # 'tested' automatically once the threshold is reached.
            if provider['config_id']:
                conn.execute(
                    "UPDATE configurations "
                    "SET test_count = test_count + 1, updated_at = ? "
                    "WHERE id = ? AND status = 'active'",
                    (now.isoformat(), provider['config_id'])
                )
                conn.execute(
                    "UPDATE configurations "
                    "SET status = 'tested', updated_at = ? "
                    "WHERE id = ? AND status = 'active' "
                    "  AND test_count >= test_threshold",
                    (now.isoformat(), provider['config_id'])
                )

        archive_email(archive_root, username, raw_bytes)

    finally:
        conn.close()

    sys.exit(0)


if __name__ == '__main__':
    main()
