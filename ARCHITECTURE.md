# noncey — Architecture Reference

This document describes the architecture of noncey: an email-based OTP relay system that
intercepts nonce/OTP emails arriving at a dedicated domain, extracts the code, and makes it
available to a browser extension for automated field-filling. It is intended as a durable
reference for migrations, server rebuilds, and future contributors.

---

## 1. Component Overview

```
 ┌────────────────────────────────────────────────────────────┐
 │  nonces.yourdomain.com  (Ubuntu server)                    │
 │                                                            │
 │  ┌──────────┐   pipe    ┌────────────┐   SQLite            │
 │  │ Postfix  │──────────▶│ ingest.py  │──────────┐          │
 │  │  (SMTP)  │           │            │          │          │
 │  └──────────┘           └────────────┘          ▼          │
 │       ▲                                  ┌────────────┐    │
 │       │ SMTP :25                         │  noncey.db │    │
 │       │                                  └─────┬──────┘    │
 │  ┌────┴───────────────────────────────┐        │           │
 │  │  Apache2                           │        │           │
 │  │  :443  nonces.yourdomain.com       │  ┌─────▼──────┐   │
 │  │    /api/  ──proxy──▶ Flask :5000   │  │  app.py    │   │
 │  │                                    │  │  (Flask)   │   │
 │  │  :443  admin.yourdomain.com        │  └─────┬──────┘   │
 │  │    /noncey/ ──proxy──▶ Flask :5000 │        │           │
 │  └────────────────────────────────────┘        │           │
 │                                                │           │
 │  ┌──────────────────────────────────┐          │           │
 │  │  MySQL  (Postfix virtual maps)   │◀─────────┘           │
 │  │  virtual_aliases                 │   (user provision)   │
 │  │  virtual_transport               │                      │
 │  └──────────────────────────────────┘                      │
 └────────────────────────────────────────────────────────────┘

 ┌───────────────────────────────────┐
 │  Browser (user's machine)         │
 │  noncey Chrome Extension          │
 │    polls GET /api/nonces  ──────▶ nonces.yourdomain.com :443
 │    fills OTP field                │
 └───────────────────────────────────┘
```

### Components

| Component | Language / Runtime | Location |
|---|---|---|
| **noncey.daemon** — `ingest.py` | Python 3, stdlib only | `/opt/noncey/ingest.py` |
| **noncey.daemon** — `app.py` | Python 3, Flask | `/opt/noncey/app.py` |
| **noncey.extension** | Vanilla JS, Chrome MV3 | User's browser |
| Apache2 (TLS + proxy) | System package | `/etc/apache2/` |
| Postfix (SMTP + pipe) | System package | `/etc/postfix/` |
| MySQL (virtual maps) | System package | existing install |

### Data Stores

| Store | Path | Owner | Purpose |
|---|---|---|---|
| SQLite | `/var/lib/noncey/noncey.db` | `noncey` | Users, providers, nonces, sessions |
| .eml archive | `/var/lib/noncey/archive/{username}/` | `noncey` | Flat-file email archive for audit/debug |
| MySQL | existing `postfix` database | `noncey` (limited) | Postfix virtual alias + transport routing |

---

## 2. End-to-End Data Flow

### 2a. Inbound email → stored nonce

```
External sender
  │
  │  SMTP :25
  ▼
Postfix  ──  MX record resolves nonces.yourdomain.com to this server
  │
  │  virtual_transport table:
  │    nonces.yourdomain.com  →  nonce-pipe:
  │
  │  virtual_aliases table:
  │    nonce-alice@nonces.yourdomain.com  →  nonce-alice@nonces.yourdomain.com
  │    (loopback alias keeps address valid; transport overrides delivery)
  │
  │  master.cf:
  │    nonce-pipe  unix  -  n  n  -  1  pipe
  │      flags=Rq user=noncey argv=/opt/noncey/ingest.py ${recipient}
  │
  ▼
ingest.py  (stdin = raw .eml bytes, argv[1] = recipient address)
  │
  ├─ extract username from "nonce-{username}@..." local part
  ├─ parse email (sender, subject, body)
  ├─ look up user in SQLite → find matching provider via provider_matchers
  ├─ extract nonce value using start/end markers
  ├─ INSERT into nonces table (with expires_at = now + nonce_lifetime_h)
  └─ write raw .eml to /var/lib/noncey/archive/{username}/{timestamp}.eml
```

### 2b. Extension polling → nonce delivered to browser

```
Chrome extension  (tab URL matches configured provider)
  │
  │  GET /api/nonces
  │  Authorization: Bearer <jwt>
  │  (every 1–3 seconds while tab is active)
  │
  ▼
Apache2 :443  nonces.yourdomain.com
  │  TLS termination (user-provided cert)
  │  ProxyPass /api/ → http://127.0.0.1:5000/api/
  ▼
Flask app.py
  ├─ verify JWT signature + look up session in SQLite
  ├─ hard-delete expired nonces for this user
  └─ return JSON array [{id, provider_tag, nonce_value, received_at, expires_at, age_seconds}]
  │
  ▼
Extension
  ├─ displays nonces in dropdown (truncated value + age)
  └─ on selection: writes nonce_value into OTP field via CSS selector
```

### 2c. User provisioning flow

```
Admin (web UI or flask add-user)
  │
  ├─ validate username (lowercase alnum + . _ -, max 64 chars)
  └─ INSERT into SQLite: users  (bcrypt password hash)
       that's it — no MySQL operation required

Admin (web UI or flask remove-user)
  │
  └─ DELETE from SQLite: users
       CASCADE removes providers, provider_matchers, nonces, sessions
       that's it — no MySQL operation required
```

Postfix accepts ALL addresses at the nonce domain via a dedicated MySQL map file
(`nonce_accept.cf`) installed once at setup time — see §7 (Operational Notes).
No per-user alias rows are maintained.

---

## 3. API Reference

All REST endpoints are served by Flask on `127.0.0.1:5000` and exposed externally via
Apache2 at `https://nonces.yourdomain.com/api/`.

### Authentication

Tokens are long-lived JWTs (HS256, no `exp` claim). Expiry is enforced by the `sessions`
table (`expires_at` = 30 days from login, sliding window via `last_used_at`). The token
itself is stored only as a SHA-256 hash in the DB.

Include in requests as: `Authorization: Bearer <token>`

### Endpoints

#### `POST /api/auth/login`
Authenticate and receive a session token.

Request body (JSON):
```json
{ "username": "alice", "password": "secret" }
```
Response `200`:
```json
{ "token": "<jwt>", "expires_at": "2026-04-22T10:00:00+00:00" }
```
Errors: `400` missing fields, `401` bad credentials.

---

#### `POST /api/auth/logout`
Revoke the current session token.

Response: `204 No Content`

---

#### `GET /api/nonces`
Return all unexpired nonces for the authenticated user. Expired nonces are hard-deleted
as a side effect of this call.

Response `200`:
```json
[
  {
    "id": 42,
    "provider_tag": "github",
    "nonce_value": "847291",
    "received_at": "2026-03-23T09:14:00+00:00",
    "expires_at":  "2026-03-23T11:14:00+00:00",
    "age_seconds": 37
  }
]
```

---

#### `DELETE /api/nonces/<id>`
Delete a specific nonce (e.g. after successful use).

Response: `204 No Content`, or `404` if not found / not owned by the caller.

---

### Admin UI routes (step 3, not yet implemented)
Will be served under `https://admin.yourdomain.com/noncey/` via the existing Apache2
admin VirtualHost (Apache-level auth in place). Routes TBD.

---

### Ports & defaults

| Service | Bind address | Port | Configurable in |
|---|---|---|---|
| Flask | `127.0.0.1` | `5000` | `[general] flask_port` |
| Apache2 (API + email domain) | `0.0.0.0` | `443` | Apache2 VirtualHost |
| Apache2 (admin) | `0.0.0.0` | `443` | existing VirtualHost |
| Postfix (SMTP) | `0.0.0.0` | `25` | `/etc/postfix/main.cf` |
| MySQL | `127.0.0.1` | `3306` | `[mysql] host` |

Flask is **never** exposed directly. Apache2 handles all external TLS and proxies inward.

---

## 4. Configuration

Single INI file: `/etc/noncey/noncey.conf` (template: `noncey.conf.example`).

Both `ingest.py` and `app.py` read this file at startup. The path can be overridden with
the environment variable `NONCEY_CONF` (useful for testing).

### Sections

**`[general]`**

| Key | Default | Description |
|---|---|---|
| `domain` | — | The nonce email domain, e.g. `nonces.yourdomain.com` |
| `admin_domain` | — | Admin VirtualHost FQDN |
| `nonce_lifetime_h` | `2` | Hours until a stored nonce expires |
| `archive_retention_d` | `30` | Days to keep archived .eml files (enforced by cron) |
| `flask_port` | `5000` | Flask listen port |
| `secret_key` | — | **Required.** HMAC key for JWT signing. Generate with `python3 -c "import secrets; print(secrets.token_hex(32))"` |

**`[mysql]`**

| Key | Description |
|---|---|
| `host` | MySQL host (usually `localhost`) |
| `user` | MySQL user — needs CONNECT + INSERT on `virtual_transport` for install; no grants needed at runtime |
| `password` | MySQL password |
| `database` | Postfix database name |

**`[tls]`**

| Key | Description |
|---|---|
| `cert` | Path to TLS certificate (fullchain) |
| `key` | Path to TLS private key |

Used by the Apache2 VirtualHost template in the install script.

**`[paths]`**

| Key | Default | Description |
|---|---|---|
| `install_dir` | `/opt/noncey/daemon` | Application root — app code, venv, etc/, var/ all live here |
| `db_path` | `/opt/noncey/daemon/var/noncey.db` | SQLite database file |
| `archive_path` | `/opt/noncey/daemon/var/archive` | Root directory for .eml archives |

---

## 5. Database Schema (SQLite)

```
users
  id            PK
  username      UNIQUE
  password_hash bcrypt

providers                        ← one per OTP service per user
  id            PK
  user_id       FK → users
  tag           human label, e.g. "github"
  nonce_start_marker  text that immediately precedes the OTP in the email body
  nonce_end_marker    text that immediately follows (optional; defaults to EOL)
  sample_email  optional raw email for reference/testing

provider_matchers                ← one or more matching rules per provider
  id            PK
  provider_id   FK → providers
  sender_email  exact match on From address (optional)
  subject_pattern  regex match on Subject (optional)
  (a matcher fires if BOTH present conditions match)

nonces                           ← short-lived; purged on expiry
  id            PK
  user_id       FK → users
  provider_id   FK → providers
  nonce_value   the extracted OTP string
  received_at   ISO-8601 UTC
  expires_at    ISO-8601 UTC  (= received_at + nonce_lifetime_h)

sessions                         ← one row per active login
  id            PK
  user_id       FK → users
  token_hash    SHA-256 of JWT  (the raw token is never stored)
  created_at    ISO-8601 UTC
  last_used_at  ISO-8601 UTC  (updated on every authenticated request)
  expires_at    ISO-8601 UTC  (30 days from creation)
```

---

## 6. Design Choices

### Security

**Timing-safe login.**
`bcrypt.checkpw` is always executed, even when the username does not exist (a dummy hash
is used). This prevents username enumeration via response-time differences.

**Token stored as hash, not plaintext.**
The JWT is hashed (SHA-256) before being stored in `sessions.token_hash`. If the database
is read by an attacker, the raw tokens cannot be recovered and replayed.

**No `exp` claim in JWT.**
Expiry is enforced exclusively by `sessions.expires_at` in the database. This means a
token can be revoked instantly (logout, admin action) without waiting for a JWT expiry
window. The trade-off is that every authenticated request requires a DB round-trip — which
is acceptable given Flask already queries SQLite on every request anyway.

**Flask bound to localhost only.**
`app.run(host='127.0.0.1')` and the systemd unit ensure Flask is never reachable from the
network directly. All external traffic goes through Apache2, which handles TLS and can
apply rate-limiting, IP allowlisting, or other controls independently of the application.

**Minimal MySQL permissions.**
The `noncey` MySQL user has `INSERT` and `DELETE` on `virtual_aliases` and
`virtual_transport` only. It cannot read the rest of the Postfix database, and cannot
modify table structure. Compromise of this credential does not expose mail routing for
other domains.

**Dedicated system user.**
`ingest.py` and `app.py` run as the `noncey` system user (no login shell, no sudo). File
permissions on `/var/lib/noncey/` and `/opt/noncey/` are scoped to this user.

### Maintenance

**Lazy nonce expiry.**
Expired nonces are deleted on `GET /api/nonces` rather than by a dedicated cron job. This
keeps the row count low for active users without requiring a separate scheduled process.
For users who stop polling (e.g. logged out of the extension) old rows persist until next
login — acceptable given the 2-hour TTL.

**Email archive for debugging.**
Every inbound email is written to `/var/lib/noncey/archive/{username}/` as a timestamped
.eml file, including emails that did not match any provider. This is the primary debugging
tool when nonce extraction fails silently. Retention is enforced by a cron job
(configured by the install script) using `find ... -mtime +N -delete`.

**Idempotent schema initialisation.**
`flask init-db` executes `schema.sql` which uses `CREATE TABLE IF NOT EXISTS` throughout.
It is safe to run on an existing database — useful after upgrades that add new tables.

**Single config file.**
Both `ingest.py` (spawned by Postfix per message) and `app.py` (long-running Flask
process) read the same `/etc/noncey/noncey.conf`. There is one source of truth for paths,
credentials, and tunables. Config reload for Flask requires a service restart; `ingest.py`
re-reads config on every invocation.

### Postfix Integration

**Transport-level routing, no per-user alias rows.**
The entire `nonces.yourdomain.com` domain is routed to the `nonce-pipe` transport via a
single row in `virtual_transport`. Postfix would normally reject any address not found in
`virtual_alias_maps`; rather than maintaining a row per user, a dedicated MySQL map file
(`nonce_accept.cf`) is added to `virtual_alias_maps` at install time with the query:

```sql
SELECT '%s' WHERE '%d' = 'nonces.yourdomain.com'
```

Postfix substitutes `%s` → full recipient address and `%d` → domain before executing.
For any `@nonces.yourdomain.com` address this always returns one row — the address itself —
without touching any table. User create/delete therefore requires no MySQL operations at
all. The `[mysql]` config section is consumed only by the install script when writing
`nonce_accept.cf`; the running Flask app and `ingest.py` never connect to MySQL.

**Pipe flags `Rq`.**
`R` prepends a `Return-Path:` header. `q` quotes special characters in the recipient
address. Together they match Postfix's `local` delivery defaults and ensure `ingest.py`
receives a clean, parseable recipient argument.

**`maxproc=1` on the pipe transport.**
The pipe transport entry in `master.cf` sets `maxproc=1` so that concurrent email
deliveries to the same user do not race on SQLite writes. Postfix will queue and serialise.

**Postfix exit code contract.**
`ingest.py` exits with standard `sysexits.h` codes:

| Code | Value | Meaning to Postfix |
|---|---|---|
| `EX_OK` | 0 | Accepted — message consumed |
| `EX_DATAERR` | 65 | Bad message data — bounce to sender |
| `EX_NOUSER` | 67 | Unknown recipient — bounce |
| `EX_TEMPFAIL` | 75 | Transient error — Postfix will retry |

Config errors and DB open failures use `EX_TEMPFAIL` so messages are not lost while the
service is being repaired.

### Provider Matching

**Regex subject matching.**
`subject_pattern` is a Python `re.search` pattern, not a substring match. This handles
subjects like `"Your 6-digit code is ready"` where the interesting content is elsewhere,
or localised subjects that vary by region. The pattern is case-insensitive.

**Both matcher fields optional.**
A matcher with only `sender_email` set matches any subject from that sender. A matcher
with only `subject_pattern` set matches that subject from any sender. Both empty matches
everything (useful for a catch-all provider during initial setup).

**Start/end marker extraction.**
Rather than a regex on the nonce itself (which varies by provider), the user configures
the static text that immediately surrounds the OTP in the email body. This is more stable
across OTP format changes (4-digit → 6-digit, numeric → alphanumeric) and avoids false
positives on other numbers in the email.

### API Design

**`age_seconds` field.**
The extension calculates display age from `age_seconds` (server-computed at query time)
rather than parsing `received_at` and comparing to the client clock. This avoids clock
skew issues when the user's machine and the server disagree on the current time.

**Nonce ownership enforced at DELETE.**
`DELETE /api/nonces/<id>` filters on both `id` and `user_id`. A JWT from user A cannot
delete user B's nonces even if the ID is known.

**`/api/` prefix on all REST routes.**
Apache2 proxies only requests matching `/api/` to Flask, leaving other paths available
for static files or future services without reconfiguring the application.

---

## 7. Operational Notes

### Installation layout

All noncey files live under `/opt/noncey/`. The install script manages the full lifecycle.

```
/opt/noncey/
  daemon/                         ← Component A root (maps to noncey.daemon/ in source)
    *.py, templates/, schema.sql  ← application code (root:root, world-readable)
    venv/                         ← Python virtualenv (noncey:noncey)
    etc/                          ← config + generated service/map files (root:root 755)
      noncey.conf                 ← main config, user-created  (root:noncey 640)
      nonce_accept.cf             ← Postfix map  (root:postfix 640)
      noncey-nonces.conf          ← Apache2 VirtualHost  (root:root 644)
      noncey-admin-proxy.conf     ← Apache2 ProxyPass snippet  (root:root 644)
      noncey.service              ← systemd unit  (root:root 644)
      noncey.cron                 ← cron job  (root:root 644)
    var/                          ← runtime data  (noncey:noncey 750)
      noncey.db                   ← SQLite database
      archive/                    ← flat .eml archive

  common/                         ← reserved for shared components (currently unused)
```

Files outside `/opt/noncey/` are **symlinks** or **idempotent in-place edits**, never
standalone copies:

| System path | Type | Points to |
|---|---|---|
| `/etc/postfix/nonce_accept.cf` | symlink | `…/daemon/etc/nonce_accept.cf` |
| `/etc/apache2/sites-available/noncey-nonces.conf` | symlink | `…/daemon/etc/noncey-nonces.conf` |
| `/etc/systemd/system/noncey.service` | symlink | `…/daemon/etc/noncey.service` |
| `/etc/cron.d/noncey` | symlink | `…/daemon/etc/noncey.cron` |
| `/etc/postfix/main.cf` | edited | `virtual_alias_maps` line appended via `postconf -e` |
| `/etc/postfix/master.cf` | edited | `nonce-pipe` transport block appended (grep-guarded) |

### Pre-install setup

```bash
mkdir -p /opt/noncey/daemon/etc
cp /path/to/noncey/noncey.daemon/noncey.conf.example \
   /opt/noncey/daemon/etc/noncey.conf
editor /opt/noncey/daemon/etc/noncey.conf     # fill in all values
sudo ./install.sh                             # optionally: ./install.sh /custom/path/noncey.conf
```

### Postfix `nonce_accept.cf` (generated by install script)

```ini
# /opt/noncey/daemon/etc/nonce_accept.cf  (symlinked to /etc/postfix/nonce_accept.cf)
hosts    = localhost
user     = <mysql.user>
password = <mysql.password>
dbname   = <mysql.database>
query    = SELECT '%s' WHERE '%d' = 'nonces.yourdomain.com'
```

Appended to `virtual_alias_maps` in `main.cf` by `postconf -e`:
```
virtual_alias_maps = mysql:/etc/postfix/mysql-virtual-aliases.cf,
                     mysql:/etc/postfix/nonce_accept.cf
```

### Postfix `master.cf` entry (appended by install script)

```
nonce-pipe  unix  -  n  n  -  1  pipe
  flags=Rq user=noncey argv=/opt/noncey/daemon/venv/bin/python3 \
    /opt/noncey/daemon/ingest.py ${recipient}
```
`maxproc=1` serialises deliveries to prevent concurrent SQLite writes.

### Apache2 VirtualHost (nonces domain)

Generated at `/opt/noncey/daemon/etc/noncey-nonces.conf`, symlinked to
`/etc/apache2/sites-available/`, enabled with `a2ensite`.

### Apache2 admin VirtualHost (manual step)

The install script writes a ready-to-include snippet at
`/opt/noncey/daemon/etc/noncey-admin-proxy.conf`. Add to the admin VirtualHost:

```apache
<VirtualHost *:443>
    ServerName admin.yourdomain.com
    # ... existing SSL and auth config ...

    Include /opt/noncey/daemon/etc/noncey-admin-proxy.conf
</VirtualHost>
```

### systemd unit

Generated at `/opt/noncey/daemon/etc/noncey.service`, symlinked to
`/etc/systemd/system/noncey.service`.

### cron — archive cleanup

Generated at `/opt/noncey/daemon/etc/noncey.cron`, symlinked to `/etc/cron.d/noncey`.
Runs daily at 03:00; retention controlled by `archive_retention_d` in config.

---

## 8. Migration Checklist

When moving to a new server:

- [ ] Install system packages: `python3`, `python3-venv`, `apache2`, `postfix`, `mysql-client`
- [ ] Copy `/opt/noncey/daemon/etc/noncey.conf` (contains secrets — transfer securely)
- [ ] Copy TLS certificates referenced in `[tls]`
- [ ] Restore `/opt/noncey/daemon/var/noncey.db` or run `flask init-db` for a clean start
- [ ] Restore `/opt/noncey/daemon/var/archive/` if audit trail is needed
- [ ] Run `sudo ./install.sh` — recreates user, dirs, venv, all symlinks, and system edits
- [ ] Re-insert `virtual_transport` row for the nonce domain
- [ ] Re-create `nonce_accept.cf` and ensure it is in `virtual_alias_maps` in `main.cf`
- [ ] No per-user `virtual_aliases` rows needed — the map file covers all addresses at the domain
- [ ] Re-apply `master.cf` pipe transport entry; `postfix reload`
- [ ] Re-apply Apache2 VirtualHost blocks; `apache2ctl configtest && systemctl reload apache2`
- [ ] Enable and start `noncey.service`
- [ ] Update DNS MX record for `nonces.yourdomain.com` to point to new server
- [ ] Verify: send a test email and confirm it appears via `GET /api/nonces`
