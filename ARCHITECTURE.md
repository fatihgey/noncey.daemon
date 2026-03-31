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
 │  │    /api/    ──proxy──▶ Flask :5000 │  │  app.py    │   │
 │  │    /noncey/ ──proxy──▶ Flask :5000 │  │  (Flask)   │   │
 │  └────────────────────────────────────┘  └─────┬──────┘   │
 │                                                │           │
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
  ▼
Postfix  ──  MX record resolves nonces.yourdomain.com to this server
  │
  │  virtual_transport table:
  │    nonces.yourdomain.com  →  nonce-pipe:
  │
  │  virtual_aliases table (nonce_accept.cf):
  │    any @nonces.yourdomain.com  →  accepted (domain-wide MySQL map)
  │
  │  master.cf:
  │    nonce-pipe  unix  -  n  n  -  1  pipe
  │      flags=Rq user=noncey argv=/opt/noncey/daemon/ingest-pipe ${recipient}
  │
  ▼
ingest.py  (stdin = raw .eml bytes, argv[1] = recipient address)
  │
  ├─ extract username from "nonce-{username}@..." local part
  ├─ parse email (sender, subject, body)
  ├─ strip forwarded-message headers; extract fwd_sender if present
  ├─ look up user in SQLite
  ├─ find matching provider via provider_matchers
  │     (only providers whose configuration.status IN active/tested/public,
  │      or providers with no config_id)
  ├─ extract nonce value using configured extraction mode
  ├─ INSERT into nonces table (expires_at = now + nonce_lifetime_h)
  ├─ if provider has a config_id: increment config.test_count;
  │     auto-advance config.status → 'tested' if test_count ≥ test_threshold
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
  ▼
Apache2 :443  nonces.yourdomain.com
  │  TLS termination
  │  ProxyPass /api/ → http://127.0.0.1:5000/api/
  ▼
Flask app.py
  ├─ verify JWT + session in SQLite
  ├─ hard-delete expired nonces for this user
  └─ return JSON array [{id, provider_tag, configuration_name,
                         nonce_value, received_at, expires_at, age_seconds}]
  │
  ▼
Extension
  ├─ groups nonces by configuration_name for display
  └─ on selection: writes nonce_value into OTP field
```

### 2c. User / configuration provisioning

```
User (authenticated web UI at nonces.yourdomain.com/noncey/)
  │
  ├─ self-service: change password, download Gmail filter XML
  ├─ configuration CRUD: create → add providers + matchers → activate
  │     → accumulate test runs → submit for review → published (public)
  ├─ subscribe to a public marketplace configuration
  │     (copies providers+matchers to subscriber's account; source_config_id tracked)
  └─ update subscription when owner publishes a newer version

Admin (is_admin=1 or single user in DB)
  ├─ all of the above, plus:
  ├─ user CRUD (create, edit, delete)
  └─ marketplace review queue: approve → status='public'; reject → status='tested'

CLI (flask add-user / flask remove-user)
  └─ headless user management for initial setup
```

---

## 3. API Reference

All REST endpoints are served by Flask on `127.0.0.1:5000` and exposed externally via
Apache2 at `https://nonces.yourdomain.com/api/`.

### Authentication (REST API — Chrome extension)

Tokens are long-lived JWTs (HS256, no `exp` claim). Expiry is enforced by the `sessions`
table (`expires_at` = 30 days from login). The raw token is stored only as a SHA-256 hash.

Include in requests as: `Authorization: Bearer <token>`

### Authentication (Admin UI — browser)

Flask signed cookie session (`session['user_id']`). Sessions are permanent with a 30-day
lifetime (`app.permanent_session_lifetime`). Apache2 no longer handles authentication for
the `/noncey/` path — Flask does it entirely.

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
Return the authenticated user's configurations that are in an actionable status
(`active`, `tested`, `pending_review`, or `public`).

Response `200`:
```json
[
  {
    "id": 7,
    "name": "github-otp",
    "version": "202603-01",
    "status": "active",
    "prompt_assigned": false,
    "provider_tags": ["github"]
  }
]
```

`prompt_assigned` is `true` once the Chrome extension has stored a local prompt
for this configuration and called `POST /api/configs/<id>/prompt-assigned`.

---

#### `POST /api/configs/<id>/prompt-assigned`
Set `configurations.prompt_assigned = 1` for a configuration owned by the caller.
Called by the Chrome extension after it stores a fill prompt locally.

Response: `204 No Content`, or `404` if not found / not owned by caller.

---

### Admin UI routes (`/noncey/`)

| Route | Description |
|---|---|
| `GET/POST /noncey/login` | Login form |
| `POST /noncey/logout` | Clear session |
| `GET /noncey/` | Dashboard: owned + subscribed configs with update badges |
| `GET/POST /noncey/configs/new` | Create configuration |
| `GET/POST /noncey/configs/<id>/edit` | Edit configuration metadata |
| `GET /noncey/configs/<id>` | Configuration detail (providers, lifecycle controls) |
| `POST /noncey/configs/<id>/activate` | Toggle draft ↔ active |
| `POST /noncey/configs/<id>/submit` | Submit tested config for marketplace review |
| `GET/POST /noncey/configs/<id>/delete` | Delete configuration |
| `GET/POST /noncey/configs/<id>/providers/new` | Add provider to config |
| `GET/POST /noncey/configs/<id>/providers/<pid>/edit` | Edit provider |
| `GET/POST /noncey/configs/<id>/providers/<pid>/delete` | Delete provider |
| `POST /noncey/configs/<id>/providers/<pid>/matchers/new` | Add matcher |
| `POST /noncey/configs/<id>/providers/<pid>/matchers/<mid>/delete` | Remove matcher |
| `GET /noncey/unmatched` | User's unmatched email inbox |
| `GET/POST /noncey/unmatched/<id>` | Inspect + promote to provider (with config selector) |
| `POST /noncey/unmatched/<id>/dismiss` | Dismiss unmatched email |
| `GET /noncey/marketplace` | Browse public configurations |
| `POST /noncey/marketplace/<id>/subscribe` | Subscribe (copy) a public config |
| `POST /noncey/marketplace/<id>/update/<local_id>` | Update subscription to newer version |
| `GET/POST /noncey/account/password` | Change own password |
| `GET /noncey/account/gmail-filters.xml` | Download Gmail Atom filter XML |
| `GET /noncey/admin/users` | *(admin)* User list |
| `GET/POST /noncey/admin/users/new` | *(admin)* Create user |
| `GET/POST /noncey/admin/users/<id>/edit` | *(admin)* Edit user |
| `GET/POST /noncey/admin/users/<id>/delete` | *(admin)* Delete user |
| `GET /noncey/admin/marketplace` | *(admin)* Review queue |
| `POST /noncey/admin/marketplace/<id>/approve` | *(admin)* Approve → public |
| `POST /noncey/admin/marketplace/<id>/reject` | *(admin)* Reject → back to tested |

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

Single INI file: `/opt/noncey/daemon/etc/noncey.conf` (template: `noncey.conf.example`).

Both `ingest.py` and `app.py` read this file at startup. Override path with `NONCEY_CONF`.

### Sections

**`[general]`**

| Key | Default | Description |
|---|---|---|
| `domain` | — | The nonce email domain, e.g. `nonces.yourdomain.com` |
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

```
users
  id            PK
  username      UNIQUE NOT NULL
  password_hash bcrypt NOT NULL
  email         TEXT (optional, for admin contact)
  is_admin      INTEGER DEFAULT 0
  created_at    TEXT

configurations                   ← named+versioned bundles of providers
  id               PK
  owner_id         FK → users (CASCADE)
  name             TEXT NOT NULL
  version          TEXT NOT NULL  (recommended: YYYYMM-NN)
  description      TEXT
  status           TEXT  draft|active|tested|pending_review|public
  source_config_id FK → configurations (NULL = original; non-NULL = subscription/copy)
  prompt_assigned  INTEGER DEFAULT 0  (set by Chrome extension when prompt is stored)
  test_threshold   INTEGER DEFAULT 3  (extractions needed to advance active→tested)
  test_count       INTEGER DEFAULT 0  (incremented by ingest.py on each nonce insert)
  created_at       TEXT
  updated_at       TEXT
  UNIQUE(owner_id, name, version)

providers                        ← one per OTP service, scoped to a configuration
  id                 PK
  user_id            FK → users (CASCADE)
  config_id          FK → configurations (SET NULL on delete; NULL = unassigned/always-active)
  tag                TEXT UNIQUE per user  (e.g. "github")
  extract_source     body | subject
  extract_mode       auto | markers | start_length
  nonce_start_marker TEXT  (derived from example OTP in auto mode)
  nonce_end_marker   TEXT  (optional; markers mode only)
  nonce_length       INTEGER  (start_length and auto modes)
  sample_email       TEXT  (raw email for reference; cleared on marketplace approval)

provider_matchers                ← one or more matching rules per provider
  id              PK
  provider_id     FK → providers (CASCADE)
  sender_email    exact match on From address (optional)
  subject_pattern regex match on Subject (optional)
  (a matcher fires when every set condition matches; provider needs ≥1 firing matcher)

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

unmatched_emails                 ← emails that matched no provider; await user review
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

### Configuration status lifecycle

```
draft  ──(activate: needs ≥1 provider+matcher)──▶  active
                                                       │
                                             test_count ≥ test_threshold
                                             (auto-advanced by ingest.py)
                                                       │
                                                       ▼
public ◀──(admin approve)── pending_review ◀──(submit)── tested
  │                                ▲
  │                         (admin reject)
  └────────────────────────────────┘  (back to tested; owner revises and resubmits)
```

### Subscription model

A subscription is a `configurations` row with `source_config_id IS NOT NULL` pointing to
the public original. `_copy_providers()` copies all providers+matchers at subscribe time,
clearing `sample_email` for privacy. Tag collisions are resolved by suffixing (`_1`, `_2`).
"Update available" is detected by querying for a newer public config with the same
`(owner_id, name)` and a higher `version` string (lexicographic; YYYYMM-NN format works).

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

**Flask session (admin UI) vs JWT (REST API).**
The admin UI uses a signed cookie session managed entirely by Flask — no Apache BasicAuth.
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

**Auto test counting.**
`ingest.py` increments `test_count` on every successful nonce INSERT for a configuration
in `active` status, and automatically transitions to `tested` when the threshold is reached.
No polling or cron needed.

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

## 7. Planned Chrome Extension Changes

The following changes to `noncey.client.chromeextension` are planned but **not yet
implemented**. They are noted here to preserve design intent across context boundaries.

### 7a. Configuration-aware display

Currently the extension groups nonces by `provider_tag`. With configurations:

- Group nonces by `configuration_name` (from the new API field) as the primary label.
- `provider_tag` becomes secondary / used for disambiguation when one config has multiple providers.
- Show `configuration_name` in the popup dropdown header.

### 7b. Configuration selection / active config

- The extension should allow the user to select which configuration is "active" (or all).
- Active configuration determines which nonces are surfaced automatically vs hidden.
- Selection stored in `chrome.storage.local` as `{ activeConfigName: "github-otp" | null }`.
  `null` = show all.

### 7c. Prompt storage (`prompt_assigned` flag)

- Each public configuration has an optional "prompt" — instructions for how to fill the OTP
  field (CSS selector, iframe handling, multi-step flows, etc.).
- The prompt lives in the extension (not the daemon) since it is browser-side logic.
- Storage: `chrome.storage.sync` keyed by `"prompt:" + configName + ":" + configVersion`.
- When a user subscribes to a public configuration, the extension checks if a prompt is
  already stored for that `(name, version)`. If not, the user is prompted to enter one
  (or it can be left blank for manual fill).
- `prompt_assigned` on the daemon side is a boolean flag set via a new API endpoint
  (`POST /api/configs/<id>/prompt-assigned`) once the extension stores a prompt. The flag
  is used in the marketplace UI to indicate to prospective subscribers whether a prompt
  is available.

### 7d. New API endpoint needed (daemon side)

```
POST /api/configs/<id>/prompt-assigned
Authorization: Bearer <jwt>
```
Sets `configurations.prompt_assigned = 1` for the given config (owned by the caller).
Response: `204 No Content`. This endpoint does not exist yet in `app.py`.

### 7e. Popup UX changes

- Add a "Configuration" section in the popup above the nonce list.
- Show current active config name + version.
- "Change" button opens a config selector (lists configs from `GET /api/nonces` response
  unique `configuration_name` values, or a dedicated `GET /api/configs` endpoint).
- Nonce list filtered accordingly.

### 7f. Potential new REST endpoint

`GET /api/configs` — list the authenticated user's active configurations (name, version,
prompt_assigned, provider_tags). Allows the extension to populate the config selector
without waiting for a nonce to arrive. Not strictly required if the extension derives the
list from nonce history, but improves UX for fresh installs.

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

Both the REST API (`/api/`) and the user/admin UI (`/noncey/`) are served from
the same VirtualHost (`nonces.yourdomain.com`). The generated `noncey-nonces.conf`
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
- [ ] Re-apply Apache2 VirtualHost (no BasicAuth needed now — Flask handles auth)
- [ ] Enable and start `noncey.service`
- [ ] Update DNS MX record for `nonces.yourdomain.com` to new server
- [ ] Verify: send test email → appears via `GET /api/nonces`

---

## 10. Chrome Extension Client — Windows Installation

The extension repository (`noncey.client.chromeextension`) ships an `install.bat`
script for Windows. It must be run from a Command Prompt opened in the root of the
cloned repository.

### Running the installer

```
install.bat
```

The script self-elevates to Administrator if needed, then:

1. Creates `C:\Program Files\noncey\client\` (if it does not exist)
2. Copies `manifest.json`, `background.js`, `content.js`, `picker.js`
3. Copies the `popup\` and `options\` subdirectories

### Loading in Chrome (first run)

After the installer completes:

1. Open Chrome → `chrome://extensions`
2. Enable **Developer mode** (toggle, top-right)
3. Click **Load unpacked**
4. Select `C:\Program Files\noncey\client\`

### Updating

After pulling changes from the repository, re-run `install.bat`, then click
the **↺** reload button next to noncey in `chrome://extensions`.
