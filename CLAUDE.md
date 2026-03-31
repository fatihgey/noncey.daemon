# noncey.daemon — CLAUDE.md

## What this is

The server-side component of noncey. Receives OTP emails via a Postfix pipe,
extracts nonce values, stores them in SQLite, and exposes them over a REST API
to the Chrome extension. Also serves an admin web UI for user/provider management.

Full architecture detail: `ARCHITECTURE.md` in this repo.

Sibling repos:
- `C:\Claude\noncey\` — umbrella: tests, docs
- `C:\Claude\noncey.client.chromeextension\` — Chrome extension

GitHub remote: https://github.com/fatihgey/noncey.daemon.git

---

## Key files

| File | Role |
|---|---|
| `app.py` | Flask app factory, REST API endpoints (`/api/`), session auth |
| `admin.py` | Admin UI Blueprint (`/auth/`), full CRUD for users/configs/providers |
| `db.py` | Shared SQLite helpers (`get_db`, `close_db`) |
| `ingest.py` | Postfix pipe — reads raw .eml from stdin, extracts nonce, inserts to DB |
| `provision.py` | `flask add-user` / `flask remove-user` CLI commands |
| `schema.sql` | SQLite schema, all `CREATE TABLE IF NOT EXISTS` |
| `install.sh` | Idempotent installer — run as root on the target server |
| `noncey.conf.example` | Config template — one INI file drives everything |
| `requirements.txt` | Python deps: flask, PyJWT, bcrypt |
| `templates/admin/` | Jinja2 templates for the admin UI |
| `ARCHITECTURE.md` | Full architecture reference — read this for deep context |

---

## Runtime layout on server

```
/opt/noncey/daemon/          install_dir — app files land here
  *.py, templates/, schema.sql
  venv/                      Python virtualenv (noncey:noncey)
  etc/                       Config + generated files (root:root)
    noncey.conf              Main config (root:noncey 640) — created once, manually
    nonce_accept.cf          Postfix MySQL map → symlinked to /etc/postfix/
    noncey-transport.cf      Postfix transport map → symlinked to /etc/postfix/
    noncey-nonces.conf       Apache2 VirtualHost → symlinked to sites-available/
    noncey-admin-proxy.conf  Apache2 ProxyPass snippet — manually Included
    noncey.service           systemd unit → symlinked to /etc/systemd/system/
    noncey.cron              cron job → symlinked to /etc/cron.d/
  var/                       Runtime data (noncey:noncey)
    noncey.db                SQLite database
    archive/                 Flat .eml archive per user
```

---

## Config

Single INI file: `/opt/noncey/daemon/etc/noncey.conf`
Override path with `NONCEY_CONF` env var.

Key sections: `[general]` (domain, secret_key, nonce_lifetime_h),
`[mysql]` (Postfix map credentials), `[tls]` (cert/key paths), `[paths]`.

---

## Auth model

- **REST API** (extension): Bearer JWT. Long-lived token, expiry enforced by
  `sessions` table (30 days). Token stored only as SHA-256 hash. No `exp` in JWT.
- **Admin UI** (browser): Flask signed cookie session, 30-day lifetime. No Apache
  BasicAuth — Flask handles it entirely.

---

## Database

SQLite at `var/noncey.db`. Tables: `users`, `configurations`, `providers`,
`provider_matchers`, `nonces`, `sessions`, `unmatched_emails`, `marketplace_reviews`.

Schema: `schema.sql` (idempotent). Column migrations for existing DBs: inline
Python block in `install.sh`, guarded by `PRAGMA table_info` checks.

---

## Commit & push policy

After every change: commit and push to GitHub.

---

## Planned work (Chrome extension side — see ARCHITECTURE.md §7)

The following daemon changes are pending to support upcoming extension features:

- `POST /api/configs/<id>/prompt-assigned` — set `configurations.prompt_assigned = 1`
- `GET /api/configs` — list authenticated user's active configurations (optional)
