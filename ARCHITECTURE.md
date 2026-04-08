# noncey — Architecture Reference

This document describes the architecture of noncey: an email-based OTP relay system that
intercepts nonce/OTP emails arriving at a dedicated domain, extracts the code, and makes it
available to a browser extension for automated field-filling. It is intended as a durable
reference for migrations, server rebuilds, and future contributors.

---

## 1. Component Overview

```
 ┌────────────────────────────────────────────────────────────┐
 │  noncey.tld  (Ubuntu server)                               │
 │                                                            │
 │  ┌──────────┐   pipe    ┌────────────┐   SQLite            │
 │  │ Postfix  │─────────->│ ingest.py  │──────────┐          │
 │  │  (SMTP)  │           │            │          │          │
 │  └──────────┘           └────────────┘          v          │
 │       ^                                  ┌────────────┐    │
 │       │ SMTP :25                         │  noncey.db │    │
 │       │                                  └─────┬──────┘    │
 │  ┌────┴───────────────────────────────┐        │           │
 │  │  Apache2                           │        │           │
 │  │  :443  noncey.tld                  │  ┌─────v──────┐   │
 │  │    /api/  ->proxy-> Flask :5000    │  │  app.py    │   │
 │  │    /auth/ ->proxy-> Flask :5000    │  │  (Flask)   │   │
 │  └────────────────────────────────────┘  └────────────┘   │
 │                                                            │
 │  ┌──────────────────────────────────┐                      │
 │  │  MySQL  (Postfix virtual maps)   │                      │
 │  │  virtual_aliases                 │                      │
 │  │  virtual_transport               │                      │
 │  └──────────────────────────────────┘                      │
 └────────────────────────────────────────────────────────────┘

 ┌───────────────────────────────────┐
 │  Browser (user's machine)         │
 │  noncey Chrome Extension          │
 │    polls GET /api/nonces  ──────> noncey.tld :443
 │    fills OTP field                │
 └───────────────────────────────────┘
```

### Components

| Component | Language / Runtime | Location |
|---|---|---|
| **noncey.daemon** — `ingest.py` | Python 3, stdlib only | `/opt/noncey/daemon/ingest.py` |
| **noncey.daemon** — `app.py` | Python 3, Flask | `/opt/noncey/daemon/app.py` |
| **noncey.daemon** — `admin.py` | Python 3, Flask Blueprint | `/opt/noncey/daemon/admin.py` |
| **noncey.client.chromeextension** | Vanilla JS, Chrome MV3 | User's browser |
| Apache2 (TLS + proxy) | System package | `/etc/apache2/` |
| Postfix (SMTP + pipe) | System package | `/etc/postfix/` |
| MySQL (virtual maps) | System package | existing install |

### Data Stores

| Store | Path | Owner | Purpose |
|---|---|---|---|
| SQLite | `/opt/noncey/daemon/var/noncey.db` | `noncey` | Users, configs, providers, nonces, sessions |
| .eml archive | `/opt/noncey/daemon/var/archive/{username}/` | `noncey` | Flat-file email archive for audit/debug |
| MySQL | existing `postfix` database | `noncey` (limited) | Postfix virtual alias + transport routing |

---

## 2. End-to-End Data Flow

### 2a. Inbound email → stored nonce

```
External sender
  │
  │  SMTP :25
  v
Postfix  ──  MX record resolves noncey.tld to this server
  │
  │  virtual_transport table:
  │    noncey.tld  →  nonce-pipe:
  │
  │  virtual_aliases table (nonce_accept.cf):
  │    any @noncey.tld  →  accepted (domain-wide MySQL map)
  │
  │  master.cf:
  │    nonce-pipe  unix  -  n  n  -  1  pipe
  │      flags=Rq user=noncey argv=/opt/noncey/daemon/ingest-pipe ${recipient}
  │
  v
ingest.py  (stdin = raw .eml bytes, argv[1] = recipient address)
  │
  ├─ extract username from "nonce-{username}@..." local part
  ├─ parse email (sender, subject, body)
  ├─ strip forwarded-message headers; extract fwd_sender if present
  ├─ look up user in SQLite
  ├─ find matching provider via provider_matchers
  │     (only providers whose configuration is active or subscribed)
  ├─ extract nonce value using configured extraction mode
  ├─ INSERT into nonces table (expires_at = now + nonce_lifetime_h)
  ├─ if no matching provider: INSERT into unmatched_emails for review
  └─ write raw .eml to archive/{username}/{timestamp}.eml
```

### 2b. Extension polling → nonce delivered to browser

```
Chrome extension  (tab URL matches configured provider)
  │
  │  GET /api/nonces
  │  Authorization: Bearer <jwt>
  │  (every 1–3 seconds while tab is active)
  │
  v
Apache2 :443  noncey.tld
  │  TLS termination
  │  ProxyPass /api/ → http://127.0.0.1:5000/api/
  v
Flask app.py
  ├─ verify JWT + session in SQLite
  ├─ hard-delete expired nonces for this user
  └─ return JSON array [{id, provider_tag, configuration_name,
                         nonce_value, received_at, expires_at, age_seconds}]
  │
  v
Extension
  ├─ groups nonces by configuration_name for display
  └─ on selection: writes nonce_value into OTP field
```

### 2c. User / configuration provisioning

```
User (authenticated Server UI at noncey.tld/auth/)
  │
  ├─ self-service: change password, download Gmail filter XML
  ├─ configuration CRUD: create → add channels + headers → activate
  │     → accumulate test runs → submit for review → published (public)
  ├─ subscribe to a public marketplace configuration
  │     (creates subscriptions row; no data copied; source config read at runtime)
  └─ update subscription when a newer version is published

Admin (is_admin=1)
  ├─ all of the above, plus:
  ├─ user CRUD (create, edit, delete)
  └─ marketplace review queue: approve → visibility='public'; reject → status='valid_tested'

CLI (flask add-user / flask remove-user)
  └─ headless user management for initial setup
```

---

## 3. API Reference

All REST endpoints are served by Flask on `127.0.0.1:5000` and exposed externally via
Apache2 at `https://noncey.tld/api/`.

### Authentication (REST API — Chrome extension)

Tokens are long-lived JWTs (HS256, no `exp` claim). Expiry is enforced by the `sessions`
table (`expires_at` = 30 days from login). The raw token is stored only as a SHA-256 hash.

Include in requests as: `Authorization: Bearer <token>`

### Authentication (Server UI — browser)

Flask signed cookie session (`session['user_id']`). Sessions are permanent with a 30-day
lifetime (`app.permanent_session_lifetime`). Apache2 no longer handles authentication for
the `/auth/` path — Flask does it entirely.

### REST Endpoints

#### `POST /api/auth/login`
```json
// request
{ "username": "alice", "password": "secret" }
// response 200
{ "token": "<jwt>", "expires_at": "2026-04-22T10:00:00+00:00" }
```
Errors: `400` missing fields, `401` bad credentials.

---

#### `POST /api/auth/logout`
Revoke the current session. Response: `204 No Content`

---

#### `GET /api/nonces`
Return all unexpired nonces for the authenticated user (expired nonces are hard-deleted
as a side effect).

Response `200`:
```json
[
  {
    "id": 42,
    "provider_tag": "github",
    "configuration_name": "github-otp",
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
Response: `204 No Content`, or `404` if not found / not owned by caller.

---

#### `GET /api/configs`
Return the authenticated user's configurations that are in an actionable status.
Includes own private configs and subscribed public configs.

Response `200`:
```json
[
  {
    "id": 7,
    "name": "github-otp",
    "version": "202603-01",
    "status": "valid",
    "activated": true,
    "visibility": "public",
    "is_owned": false,
    "prompt": { "url": "https://github.com/login/...", "selector": "#otp-field" },
    "provider_tags": ["github"]
  }
]
```

---

#### `POST /api/configs/<id>/prompt`
Store the fill prompt for a configuration owned by the caller.
Called by the Chrome extension after the user picks the OTP field visually.

```json
// request body
{ "url": "https://example.com/login/otp", "selector": "#otp-input" }
```

Response: `200 OK` with updated config object.

---

#### `POST /api/configs/<id>/client-test`
Report a successful end-to-end fill. The daemon increments `client_test_count`
and auto-advances status to `valid_tested` when the count reaches the threshold (3).

```json
// request body
{ "count": 1 }
```

Response: `204 No Content`.

---

### Server UI routes (`/auth/`)

| Route | Description |
|---|---|
| `GET/POST /auth/login` | Login form |
| `POST /auth/logout` | Clear session |
| `GET /auth/` | Dashboard: owned + subscribed configs with update badges |
| `GET/POST /auth/configs/new` | Create configuration (wizard) |
| `GET/POST /auth/configs/<id>/edit` | Edit configuration metadata |
| `GET /auth/configs/<id>` | Configuration detail (channels, lifecycle controls) |
| `POST /auth/configs/<id>/activate` | Toggle active/inactive |
| `POST /auth/configs/<id>/submit` | Submit tested config for marketplace review |
| `GET/POST /auth/configs/<id>/delete` | Delete configuration |
| `GET/POST /auth/configs/<id>/channels/new` | Add channel to config |
| `GET /auth/configs/<id>/channels/<pid>` | View channel (public config, read-only) |
| `GET/POST /auth/configs/<id>/channels/<pid>/edit` | Edit channel |
| `GET/POST /auth/configs/<id>/channels/<pid>/delete` | Delete channel |
| `POST /auth/configs/<id>/channels/<pid>/headers/new` | Add header |
| `POST /auth/configs/<id>/channels/<pid>/headers/<mid>/delete` | Remove header |
| `GET /auth/unmatched` | User's unmatched email inbox |
| `GET/POST /auth/unmatched/<id>` | Inspect + promote to channel (with config selector) |
| `POST /auth/unmatched/<id>/dismiss` | Dismiss unmatched email |
| `GET /auth/marketplace` | Browse public configurations |
| `POST /auth/marketplace/<id>/subscribe` | Subscribe to a public config |
| `POST /auth/marketplace/<id>/update/<local_id>` | Update subscription to newer version |
| `GET /auth/account/settings` | Change own password (legacy: `/auth/account/password`) |
| `GET /auth/account/close` | Mark / unmark account for deletion |
| `GET /auth/account/gmail-filters.xml` | Download Gmail Atom filter XML |
| `GET /auth/admin/users` | *(admin)* User list |
| `GET/POST /auth/admin/users/new` | *(admin)* Create user |
| `GET/POST /auth/admin/users/<id>/edit` | *(admin)* Edit user |
| `GET/POST /auth/admin/users/<id>/delete` | *(admin)* Delete user |
| `GET /auth/admin/marketplace` | *(admin)* Review queue |
| `POST /auth/admin/marketplace/<id>/approve` | *(admin)* Approve → public |
| `POST /auth/admin/marketplace/<id>/reject` | *(admin)* Reject → back to valid_tested |

---

## 4. Configuration

Single INI file: `/opt/noncey/daemon/etc/noncey.conf` (template: `noncey.conf.example`).

Both `ingest.py` and `app.py` read this file at startup. Override path with `NONCEY_CONF`.

### Sections

**`[general]`**

| Key | Default | Description |
|---|---|---|
| `domain` | — | The nonce email domain, e.g. `noncey.tld` |
| `nonce_lifetime_h` | `2` | Hours until a stored nonce expires |
| `archive_retention_d` | `30` | Days to keep archived .eml files |
| `flask_port` | `5000` | Flask listen port |
| `secret_key` | — | **Required.** HMAC key for JWT + Flask session signing |

**`[mysql]`** — consumed only by the install script; not used at runtime.

**`[tls]`** — cert/key paths used by the Apache2 VirtualHost template.

**`[paths]`**

| Key | Default | Description |
|---|---|---|
| `install_dir` | `/opt/noncey/daemon` | Application root |
| `db_path` | `…/var/noncey.db` | SQLite database |
| `archive_path` | `…/var/archive` | .eml archive root |

---

## 5. Database Schema (SQLite)

> **Conceptual model:** For the full Provider Configuration lifecycle — terminology,
> status/visibility state machine, versioning, creation wizard, subscription model,
> and all related flows — see **[CONCEPT_CONFIGURATION.md](CONCEPT_CONFIGURATION.md)**.

```
users
  id            PK
  username      UNIQUE NOT NULL
  password_hash bcrypt NOT NULL
  email         TEXT (optional)
  is_admin      INTEGER DEFAULT 0
  created_at    TEXT

configurations                   ← named+versioned bundles of channels
  id               PK
  owner_id         FK → users (CASCADE)
  name             TEXT NOT NULL
  version          TEXT NOT NULL DEFAULT '-1'  (YYYYMM-NN for public; -1 for private)
  description      TEXT
  status           TEXT  incomplete|valid|valid_tested|pending_review
  visibility       TEXT  private|public  DEFAULT 'private'
  activated        INTEGER DEFAULT 0
  prompt           TEXT  (nullable JSON: {"url": "...", "selector": "..."})
  client_test_count INTEGER DEFAULT 0
  created_at       TEXT
  updated_at       TEXT
  UNIQUE(owner_id, name, version)

subscriptions                    ← user↔public-config many-to-many (no data copied)
  id         PK
  user_id    FK → users (CASCADE)
  config_id  FK → configurations (CASCADE)
  created_at TEXT
  UNIQUE(user_id, config_id)

providers                        ← one channel per OTP source, scoped to a configuration
  id                 PK
  user_id            FK → users (CASCADE)
  config_id          FK → configurations (SET NULL on delete; NULL = unassigned/always-active)
  tag                TEXT UNIQUE per user  (e.g. "github")
  extract_source     body | subject
  extract_mode       auto | markers | start_length
  nonce_start_marker TEXT
  nonce_end_marker   TEXT  (optional; markers mode only)
  nonce_length       INTEGER  (start_length mode)
  sample_email       TEXT  (cleared on marketplace approval)

provider_matchers                ← one or more routing headers per channel
  id              PK
  provider_id     FK → providers (CASCADE)
  sender_email    exact match on From address (optional)
  subject_pattern regex match on Subject (optional)
  (a header fires when every set condition matches; channel needs ≥1 firing header)

nonces                           ← short-lived; purged on GET /api/nonces
  id           PK
  user_id      FK → users (CASCADE)
  provider_id  FK → providers (CASCADE)
  nonce_value  TEXT
  received_at  ISO-8601 UTC
  expires_at   ISO-8601 UTC  (= received_at + nonce_lifetime_h)

sessions                         ← one row per active REST API login
  id           PK
  user_id      FK → users (CASCADE)
  token_hash   SHA-256 of JWT (UNIQUE; raw token never stored)
  created_at   ISO-8601 UTC
  last_used_at ISO-8601 UTC
  expires_at   ISO-8601 UTC  (30 days from creation)

unmatched_emails                 ← emails that matched no channel; await user review
  id          PK
  user_id     FK → users (CASCADE)
  sender      TEXT
  fwd_sender  TEXT  (innermost forwarded-from address, if email was forwarded)
  subject     TEXT
  body_text   TEXT  (hidden in UI when user has public configurations)
  received_at ISO-8601 UTC

marketplace_reviews              ← admin audit trail for approve/reject decisions
  id          PK
  config_id   FK → configurations (CASCADE)
  reviewer_id FK → users (SET NULL)
  decision    approved | rejected
  note        TEXT (optional rejection reason)
  reviewed_at ISO-8601 UTC
```

---

## 6. Design Choices

### Security

**Timing-safe login.**
`bcrypt.checkpw` is always executed, even when the username does not exist (a dummy hash
is used). Prevents username enumeration via response-time differences.

**Token stored as hash, not plaintext.**
JWT is SHA-256 hashed before storage in `sessions.token_hash`. A stolen DB cannot be used
to replay sessions.

**No `exp` claim in JWT.**
Expiry is enforced exclusively by `sessions.expires_at`. Tokens can be revoked instantly
(logout, admin action) without a JWT expiry window.

**Flask session (Server UI) vs JWT (REST API).**
The Server UI uses a signed cookie session managed entirely by Flask — no Apache BasicAuth.
The REST API (used by the extension) uses Bearer JWT. The two auth systems share the same
`secret_key` but operate independently.

**Privacy: sample_email cleared on approval.**
When a configuration is approved for the marketplace, all `sample_email` fields on its
providers are set to NULL. Unmatched email bodies are hidden in the UI for users who have
any public configuration.

**Flask bound to localhost only.**
Never reachable from the network directly; all external traffic goes through Apache2.

**Minimal MySQL permissions.**
Used only by the install script; `ingest.py` and `app.py` never connect to MySQL at runtime.

### Maintenance

**Lazy nonce expiry.**
Expired nonces are deleted on `GET /api/nonces` rather than by a dedicated cron job.

**Idempotent schema initialisation + migrations.**
`flask init-db` runs `schema.sql` (uses `CREATE TABLE IF NOT EXISTS`). Column additions for
existing databases are handled by the `ALTER TABLE ADD COLUMN` migration block in
`install.sh`, guarded by `PRAGMA table_info` checks.

### Postfix Integration

**Transport-level routing, no per-user alias rows.**
`nonce_accept.cf` (domain-level MySQL map) accepts all addresses at the nonce domain with
a single row. `ingest.py` resolves the actual user from the local part at runtime.

**`maxproc=1`.**
Serialises deliveries to prevent concurrent SQLite writes.

### API Design

**`age_seconds` field.**
Computed server-side to avoid client clock skew when displaying nonce age.

**`configuration_name` field.**
Added to `GET /api/nonces` so the extension can group or label nonces by configuration,
not just provider tag.

---

## 8. Operational Notes

### Installation layout

```
/opt/noncey/
  daemon/                         ← noncey.daemon source root
    *.py, templates/, schema.sql  ← application code (root:root)
    venv/                         ← Python virtualenv (noncey:noncey)
    etc/                          ← config + generated files (root:root 755)
      noncey.conf                 ← main config  (root:noncey 640)
      nonce_accept.cf             ← Postfix map  (root:postfix 640)
      noncey-nonces.conf          ← Apache2 VirtualHost (API + UI)
      noncey.service              ← systemd unit
      noncey.cron                 ← cron job
    var/                          ← runtime data  (noncey:noncey 750)
      noncey.db                   ← SQLite database
      archive/                    ← flat .eml archive
```

Files outside `/opt/noncey/` are symlinks or idempotent edits:

| System path | Type | Points to |
|---|---|---|
| `/etc/postfix/nonce_accept.cf` | symlink | `…/daemon/etc/nonce_accept.cf` |
| `/etc/apache2/sites-available/noncey-nonces.conf` | symlink | `…/daemon/etc/noncey-nonces.conf` |
| `/etc/systemd/system/noncey.service` | symlink | `…/daemon/etc/noncey.service` |
| `/etc/cron.d/noncey` | symlink | `…/daemon/etc/noncey.cron` |
| `/etc/postfix/main.cf` | edited | `virtual_alias_maps` appended via `postconf -e` |
| `/etc/postfix/master.cf` | edited | `nonce-pipe` transport block appended |

### Apache2 VirtualHost

Both the REST API (`/api/`) and the Server UI (`/auth/`) are served from
the same VirtualHost (`noncey.tld`). The generated `noncey-nonces.conf`
contains both ProxyPass directives and is symlinked into `sites-available/` by
`install.sh`. No separate admin VirtualHost or manually-included snippet is needed.

### cron — archive cleanup

Runs daily at 03:00; retention controlled by `archive_retention_d` in config.

---

## 9. Migration Checklist

When moving to a new server:

- [ ] Install system packages: `python3`, `python3-venv`, `apache2`, `postfix`, `mysql-client`
- [ ] Copy `/opt/noncey/daemon/etc/noncey.conf` (contains secrets — transfer securely)
- [ ] Copy TLS certificates referenced in `[tls]`
- [ ] Restore `/opt/noncey/daemon/var/noncey.db` or run `flask init-db` for a clean start
- [ ] Restore `/opt/noncey/daemon/var/archive/` if audit trail is needed
- [ ] Run `sudo ./install.sh` — recreates user, dirs, venv, all symlinks, and system edits
- [ ] Re-insert `virtual_transport` row for the nonce domain
- [ ] Re-create `nonce_accept.cf` and ensure it is in `virtual_alias_maps` in `main.cf`
- [ ] No per-user `virtual_aliases` rows needed
- [ ] Re-apply `master.cf` pipe transport; `postfix reload`
- [ ] Re-apply Apache2 VirtualHost (no BasicAuth needed — Flask handles auth)
- [ ] Enable and start `noncey.service`
- [ ] Update DNS MX record for `noncey.tld` to new server
- [ ] Verify: send test email → appears via `GET /api/nonces`
