# noncey.daemon

Server-side component of noncey. Receives OTP emails via a Postfix pipe, extracts
nonce values, stores them in SQLite, and exposes them over a REST API to the Chrome
extension and Android app. Also serves an admin web UI for user/provider management.

See [ARCHITECTURE.md](ARCHITECTURE.md) for full design detail.

---

## Quick start

```bash
pip install -r requirements.txt
python app.py
```

Configure Postfix to pipe incoming mail to `ingest.py`. See `noncey.conf.example`
and `install.sh` for a guided setup.

---

## License

MIT — see [LICENSE](LICENSE).
