"""
noncey — user-facing Blueprint (admin + regular users).
Served under /auth/ via Apache2 reverse proxy.
Flask handles authentication; Apache needs no auth directives.
"""

import re
import sqlite3
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parseaddr
from functools import wraps
from urllib.parse import urlparse

import bcrypt
from flask import (Blueprint, Response, flash, jsonify, redirect,
                   render_template, request, session, url_for)

from db import cfg, get_db
from provision import ProvisionError, validate_username

admin_bp = Blueprint(
    'admin', __name__,
    url_prefix='/auth',
    template_folder='templates',
)




# ── Auth helpers ──────────────────────────────────────────────────────────────

def _is_admin(user_id: int) -> bool:
    db = get_db()
    user = db.execute("SELECT is_admin FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        return False
    if user['is_admin']:
        return True
    return db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('admin.auth_login', next=request.path))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('admin.auth_login'))
        if not _is_admin(session['user_id']):
            flash('Administrator access required.', 'error')
            return redirect(url_for('admin.dashboard'))
        return f(*args, **kwargs)
    return decorated


@admin_bp.context_processor
def inject_user():
    current_user = None
    user_is_admin = False
    if 'user_id' in session:
        current_user = get_db().execute(
            "SELECT id, username, email, is_admin FROM users WHERE id=?",
            (session['user_id'],)
        ).fetchone()
        if current_user:
            user_is_admin = _is_admin(session['user_id'])
    return {'current_user': current_user, 'user_is_admin': user_is_admin}


def _safe_next(next_url: str) -> str:
    if next_url and next_url.startswith('/'):
        return next_url
    return url_for('admin.dashboard')


# ── Shared query helpers ───────────────────────────────────────────────────────

def _get_config(config_id: int, user_id: int):
    return get_db().execute(
        "SELECT * FROM configurations WHERE id=? AND owner_id=?",
        (config_id, user_id)
    ).fetchone()


def _get_provider(provider_id: int, config_id: int, user_id: int):
    return get_db().execute(
        "SELECT p.* FROM providers p "
        "JOIN configurations c ON c.id = p.config_id "
        "WHERE p.id=? AND p.config_id=? AND c.owner_id=?",
        (provider_id, config_id, user_id)
    ).fetchone()


def _get_any_public_config(config_id: int):
    return get_db().execute(
        "SELECT * FROM configurations WHERE id=? AND visibility='public'",
        (config_id,)
    ).fetchone()


def _get_public_provider(provider_id: int, config_id: int):
    return get_db().execute(
        "SELECT p.* FROM providers p "
        "JOIN configurations c ON c.id = p.config_id "
        "WHERE p.id=? AND p.config_id=? AND c.visibility='public'",
        (provider_id, config_id)
    ).fetchone()


def _derive_auto_markers(text: str, example_otp: str):
    if not example_otp or not text:
        return '', None
    idx = text.find(example_otp)
    if idx == -1:
        return '', None
    before = text[:idx]
    line_start = before.rfind('\n') + 1
    return before[line_start:], len(example_otp)


def _providers_with_matchers(db, config_id: int) -> tuple:
    providers = db.execute(
        "SELECT * FROM providers WHERE config_id=? ORDER BY tag", (config_id,)
    ).fetchall()
    matchers = {
        p['id']: db.execute(
            "SELECT * FROM provider_matchers WHERE provider_id=?", (p['id'],)
        ).fetchall()
        for p in providers
    }
    return providers, matchers


def _config_activatable(providers, matchers) -> bool:
    """A configuration can be activated if it has at least one channel with a header."""
    return any(matchers.get(p['id']) for p in providers)


def _auto_update_status(db, config_id: int):
    """
    Recompute status after a structural change (channel/header/prompt added or removed).
    Does NOT commit — caller is responsible.

    Transitions:
      incomplete  ↔  valid          (based on whether all elements are present)
      valid_tested →  valid          (reset when structure changes)
      pending_review: untouched      (locked during review)
    """
    config = db.execute(
        "SELECT status, prompt FROM configurations WHERE id=?", (config_id,)
    ).fetchone()
    if not config or config['status'] == 'pending_review':
        return

    providers = db.execute(
        "SELECT id FROM providers WHERE config_id=?", (config_id,)
    ).fetchall()
    has_channel_with_header = any(
        db.execute(
            "SELECT id FROM provider_matchers WHERE provider_id=?", (p['id'],)
        ).fetchone()
        for p in providers
    )
    has_prompt = config['prompt'] is not None

    new_status = 'valid' if (has_channel_with_header and has_prompt) else 'incomplete'
    db.execute(
        "UPDATE configurations SET status=?, updated_at=datetime('now') WHERE id=?",
        (new_status, config_id)
    )


# ── Auth routes ───────────────────────────────────────────────────────────────

@admin_bp.route('/login', methods=['GET', 'POST'])
def auth_login():
    if 'user_id' in session:
        return redirect(url_for('admin.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        next_url = request.form.get('next', '')

        db   = get_db()
        user = db.execute(
            "SELECT id, password_hash FROM users WHERE username=?", (username,)
        ).fetchone()
        if not user:
            flash('Invalid username or password.', 'error')
            return render_template('admin/login.html', next=next_url)

        ok = bcrypt.checkpw(password.encode(), user['password_hash'].encode())
        if not ok:
            flash('Invalid username or password.', 'error')
            return render_template('admin/login.html', next=next_url)

        session['user_id'] = user['id']
        session.permanent  = True
        return redirect(_safe_next(next_url))

    return render_template('admin/login.html', next=request.args.get('next', ''))


@admin_bp.post('/logout')
@login_required
def auth_logout():
    session.clear()
    return redirect(url_for('admin.auth_login'))


# ── Dashboard ─────────────────────────────────────────────────────────────────

@admin_bp.get('/')
@admin_bp.get('')
@login_required
def dashboard():
    user_id = session['user_id']
    db      = get_db()

    unmatched_count = db.execute(
        "SELECT COUNT(*) FROM unmatched_items WHERE user_id=?", (user_id,)
    ).fetchone()[0]

    # Own private configurations
    own_configs = db.execute(
        "SELECT c.*, "
        "  (SELECT COUNT(*) FROM providers p WHERE p.config_id=c.id) AS provider_count, "
        "  (SELECT COUNT(*) FROM nonces n "
        "   JOIN providers p2 ON n.provider_id=p2.id "
        "   WHERE p2.config_id=c.id) AS nonce_count "
        "FROM configurations c "
        "WHERE c.owner_id=? AND c.visibility='private' "
        "ORDER BY c.updated_at DESC",
        (user_id,)
    ).fetchall()

    # Subscribed public configurations
    sub_configs = db.execute(
        "SELECT c.*, "
        "  (SELECT COUNT(*) FROM providers p WHERE p.config_id=c.id) AS provider_count, "
        "  (SELECT COUNT(*) FROM nonces n "
        "   JOIN providers p2 ON n.provider_id=p2.id "
        "   WHERE p2.config_id=c.id) AS nonce_count "
        "FROM configurations c "
        "JOIN subscriptions s ON s.config_id=c.id "
        "WHERE s.user_id=? AND c.visibility='public' "
        "ORDER BY c.name, c.version",
        (user_id,)
    ).fetchall()

    # Check update availability: is there a newer public version of the same name?
    update_available = {}
    for c in sub_configs:
        newer = db.execute(
            "SELECT id FROM configurations "
            "WHERE visibility='public' AND name=? AND version>? AND id!=? "
            "ORDER BY version DESC LIMIT 1",
            (c['name'], c['version'], c['id'])
        ).fetchone()
        if newer:
            update_available[c['id']] = newer['id']

    return render_template('admin/dashboard.html',
                           own_configs=own_configs,
                           sub_configs=sub_configs,
                           unmatched_count=unmatched_count,
                           update_available=update_available)


# ── Configuration management ──────────────────────────────────────────────────

@admin_bp.route('/configs/new', methods=['GET', 'POST'])
@login_required
def config_new():
    user_id = session['user_id']

    if request.method == 'POST':
        name        = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip() or None

        if not name:
            flash('Name is required.', 'error')
            return render_template('admin/config_form.html', config=None)

        db = get_db()
        try:
            db.execute(
                "INSERT INTO configurations (owner_id, name, version, description, status) "
                "VALUES (?, ?, '-1', ?, 'incomplete')",
                (user_id, name, description)
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash(f"A configuration named '{name}' already exists.", 'error')
            return render_template('admin/config_form.html', config=None)

        flash(f"Configuration '{name}' created.", 'success')
        config_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        return redirect(url_for('admin.config_detail', config_id=config_id))

    return render_template('admin/config_form.html', config=None)


@admin_bp.route('/configs/<int:config_id>/edit', methods=['GET', 'POST'])
@login_required
def config_edit(config_id):
    user_id = session['user_id']
    config  = _get_config(config_id, user_id)
    if not config:
        flash('Configuration not found.', 'error')
        return redirect(url_for('admin.dashboard'))

    if config['visibility'] == 'public':
        flash('Public configurations are read-only.', 'error')
        return redirect(url_for('admin.config_detail', config_id=config_id))

    if request.method == 'POST':
        name        = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip() or None

        if not name:
            flash('Name is required.', 'error')
            return render_template('admin/config_form.html', config=config)

        db = get_db()
        try:
            db.execute(
                "UPDATE configurations SET name=?, description=?, "
                "updated_at=datetime('now') WHERE id=?",
                (name, description, config_id)
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash(f"A configuration named '{name}' already exists.", 'error')
            return render_template('admin/config_form.html', config=config)

        flash('Configuration updated.', 'success')
        return redirect(url_for('admin.config_detail', config_id=config_id))

    return render_template('admin/config_form.html', config=config)


@admin_bp.route('/configs/<int:config_id>/delete', methods=['GET', 'POST'])
@login_required
def config_delete(config_id):
    user_id = session['user_id']
    config  = _get_config(config_id, user_id)
    if not config and _is_admin(user_id):
        config = _get_any_public_config(config_id)
    if not config:
        flash('Configuration not found.', 'error')
        return redirect(url_for('admin.dashboard'))

    if config['visibility'] == 'public' and not _is_admin(user_id):
        flash('Public configurations can only be deleted by an administrator.', 'error')
        return redirect(url_for('admin.config_detail', config_id=config_id))

    if request.method == 'POST':
        db = get_db()
        db.execute("DELETE FROM configurations WHERE id=?", (config_id,))
        db.commit()
        flash(f"Configuration '{config['name']}' deleted.", 'success')
        return redirect(url_for('admin.dashboard'))

    return render_template('admin/config_delete.html', config=config)


@admin_bp.post('/configs/<int:config_id>/activate')
@login_required
def config_activate(config_id):
    user_id = session['user_id']
    config  = _get_config(config_id, user_id)
    if not config:
        flash('Configuration not found.', 'error')
        return redirect(url_for('admin.dashboard'))

    if config['visibility'] == 'public':
        flash('Public configurations are managed via subscriptions.', 'error')
        return redirect(url_for('admin.config_detail', config_id=config_id))

    db = get_db()

    if config['activated']:
        db.execute(
            "UPDATE configurations SET activated=0, updated_at=datetime('now') WHERE id=?",
            (config_id,)
        )
        db.commit()
        flash('Configuration deactivated.', 'success')
    elif config['status'] in ('valid', 'valid_tested'):
        db.execute(
            "UPDATE configurations SET activated=1, updated_at=datetime('now') WHERE id=?",
            (config_id,)
        )
        db.commit()
        flash('Configuration activated.', 'success')
    else:
        flash('Configuration must be valid before activating.', 'error')

    return redirect(url_for('admin.config_detail', config_id=config_id))


@admin_bp.post('/configs/<int:config_id>/submit')
@login_required
def config_submit(config_id):
    user_id = session['user_id']
    config  = _get_config(config_id, user_id)
    if not config:
        flash('Configuration not found.', 'error')
        return redirect(url_for('admin.dashboard'))

    if config['status'] != 'valid_tested':
        flash('Only tested configurations can be submitted for review.', 'error')
        return redirect(url_for('admin.config_detail', config_id=config_id))
    if not config['description']:
        flash('A description is required before submitting for marketplace review.', 'error')
        return redirect(url_for('admin.config_edit', config_id=config_id))

    db = get_db()
    db.execute(
        "UPDATE configurations SET status='pending_review', updated_at=datetime('now') WHERE id=?",
        (config_id,)
    )
    db.commit()
    flash('Submitted for marketplace review.', 'success')
    return redirect(url_for('admin.config_detail', config_id=config_id))


@admin_bp.get('/configs/<int:config_id>')
@login_required
def config_detail(config_id):
    user_id = session['user_id']
    config  = _get_config(config_id, user_id) or _get_any_public_config(config_id)
    if not config:
        flash('Configuration not found.', 'error')
        return redirect(url_for('admin.dashboard'))

    db = get_db()
    providers, matchers = _providers_with_matchers(db, config_id)
    activatable = _config_activatable(providers, matchers)

    return render_template('admin/config_detail.html',
                           config=config,
                           providers=providers,
                           matchers=matchers,
                           activatable=activatable,
                           source_config=None)


@admin_bp.post('/configs/<int:config_id>/clear-nonces')
@login_required
def config_clear_nonces(config_id):
    user_id = session['user_id']
    config  = _get_config(config_id, user_id)
    if not config:
        flash('Configuration not found.', 'error')
        return redirect(url_for('admin.dashboard'))

    db = get_db()
    db.execute(
        "DELETE FROM nonces WHERE provider_id IN "
        "(SELECT id FROM providers WHERE config_id=?)",
        (config_id,)
    )
    db.commit()
    return redirect(url_for('admin.dashboard'))


# ── Provider management (config-scoped) ───────────────────────────────────────

def _render_provider_form(config, provider, matchers, sample_sender):
    return render_template('admin/provider_form.html',
                           config=config, provider=provider,
                           matchers=matchers, sample_sender=sample_sender)


def _process_provider_form(request, config, provider, db):
    """Parse and validate the provider form. Returns (ok, fields_dict, error_html)."""
    tag          = request.form.get('tag', '').strip()
    channel_type = request.form.get('channel_type', 'email')
    if channel_type not in ('email', 'sms'):
        channel_type = 'email'
    # For SMS channels extract_source is always body; ignore the form value.
    source = 'body' if channel_type == 'sms' else request.form.get('extract_source', 'body')
    mode   = request.form.get('extract_mode', 'auto')
    end    = request.form.get('nonce_end_marker', '').strip() or None
    sample = request.form.get('sample_email', '').strip() or None
    try:
        length = int(request.form['nonce_length']) if request.form.get('nonce_length', '').strip() else None
    except ValueError:
        length = None

    if mode == 'auto':
        example_otp = request.form.get('example_otp', '').strip()
        if not example_otp:
            return False, None, 'Example OTP is required for auto extraction mode.'
        sample_text = sample or ''
        src_m = re.search(r'^Subject:\s*(.+)', sample_text, re.MULTILINE | re.IGNORECASE)
        derive_from = src_m.group(1) if (source == 'subject' and src_m) else sample_text
        start, length = _derive_auto_markers(derive_from, example_otp)
        if not start:
            return False, None, 'Example OTP not found in the sample text.'
    else:
        start = (request.form.get('nonce_regex_pattern', '').strip()
                 if mode == 'regex'
                 else request.form.get('nonce_start_marker', '').strip())

    if not tag:
        return False, None, 'Tag is required.'
    if mode != 'auto' and not start:
        return False, None, 'Start marker is required for this extraction mode.'

    return True, dict(tag=tag, channel_type=channel_type, mode=mode, source=source,
                      start=start, end=end, length=length, sample=sample), None


@admin_bp.route('/configs/<int:config_id>/channels/new', methods=['GET', 'POST'])
@login_required
def channel_new(config_id):
    user_id = session['user_id']
    config  = _get_config(config_id, user_id)
    if not config:
        flash('Configuration not found.', 'error')
        return redirect(url_for('admin.dashboard'))
    if config['visibility'] == 'public':
        flash('Channels of a public configuration cannot be edited.', 'error')
        return redirect(url_for('admin.config_detail', config_id=config_id))

    if request.method == 'POST':
        ok, fields, err = _process_provider_form(request, config, None, get_db())
        if not ok:
            flash(err, 'error')
            return _render_provider_form(config, None, [], None)

        db = get_db()
        try:
            db.execute(
                "INSERT INTO providers "
                "  (user_id, config_id, tag, channel_type, extract_source, extract_mode, "
                "   nonce_start_marker, nonce_end_marker, nonce_length, sample_email) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (user_id, config_id, fields['tag'], fields['channel_type'],
                 fields['source'], fields['mode'],
                 fields['start'], fields['end'], fields['length'], fields['sample'])
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash(f"Channel tag '{fields['tag']}' already exists.", 'error')
            return _render_provider_form(config, None, [], None)

        _auto_update_status(db, config_id)
        db.commit()
        flash(f"Channel '{fields['tag']}' created.", 'success')
        return redirect(url_for('admin.config_detail', config_id=config_id))

    return _render_provider_form(config, None, [], None)


@admin_bp.get('/configs/<int:config_id>/channels/<int:provider_id>')
@login_required
def channel_view(config_id, provider_id):
    user_id  = session['user_id']
    config   = _get_any_public_config(config_id)
    provider = _get_public_provider(provider_id, config_id)
    if not config or not provider:
        flash('Not found.', 'error')
        return redirect(url_for('admin.dashboard'))

    db       = get_db()
    matchers = db.execute(
        "SELECT * FROM provider_matchers WHERE provider_id=?", (provider_id,)
    ).fetchall()

    return render_template('admin/provider_view.html',
                           config=config, provider=provider, matchers=matchers)


@admin_bp.route('/configs/<int:config_id>/channels/<int:provider_id>/edit',
                methods=['GET', 'POST'])
@login_required
def channel_edit(config_id, provider_id):
    user_id  = session['user_id']
    config   = _get_config(config_id, user_id)
    provider = _get_provider(provider_id, config_id, user_id)
    if not config or not provider:
        flash('Not found.', 'error')
        return redirect(url_for('admin.config_detail', config_id=config_id))
    if config['visibility'] == 'public':
        flash('Channels of a public configuration cannot be edited.', 'error')
        return redirect(url_for('admin.config_detail', config_id=config_id))

    db       = get_db()
    matchers = db.execute(
        "SELECT * FROM provider_matchers WHERE provider_id=?", (provider_id,)
    ).fetchall()

    sample_sender = None
    if provider['sample_email']:
        m = re.search(r'^From:\s*(.+)', provider['sample_email'], re.MULTILINE | re.IGNORECASE)
        if m:
            _, addr = parseaddr(m.group(1).strip())
            sample_sender = addr.lower() if addr else None

    if request.method == 'POST':
        ok, fields, err = _process_provider_form(request, config, provider, db)
        if not ok:
            flash(err, 'error')
            return _render_provider_form(config, provider, matchers, sample_sender)

        try:
            db.execute(
                "UPDATE providers SET tag=?, extract_source=?, extract_mode=?, "
                "  nonce_start_marker=?, nonce_end_marker=?, nonce_length=?, sample_email=? "
                "WHERE id=?",
                (fields['tag'], fields['source'], fields['mode'],
                 fields['start'], fields['end'], fields['length'],
                 fields['sample'], provider_id)
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash(f"Channel tag '{fields['tag']}' already exists.", 'error')
            return _render_provider_form(config, provider, matchers, sample_sender)

        _auto_update_status(db, config_id)
        db.commit()
        flash(f"Channel '{fields['tag']}' updated.", 'success')
        return redirect(url_for('admin.config_detail', config_id=config_id))

    return _render_provider_form(config, provider, matchers, sample_sender)


@admin_bp.route('/configs/<int:config_id>/channels/<int:provider_id>/delete',
                methods=['GET', 'POST'])
@login_required
def channel_delete(config_id, provider_id):
    user_id  = session['user_id']
    config   = _get_config(config_id, user_id)
    provider = _get_provider(provider_id, config_id, user_id)
    if not config or not provider:
        flash('Not found.', 'error')
        return redirect(url_for('admin.config_detail', config_id=config_id))

    if request.method == 'POST':
        db = get_db()
        db.execute("DELETE FROM providers WHERE id=?", (provider_id,))
        _auto_update_status(db, config_id)

        # Auto-delete the configuration if it now has no channels and no prompt.
        remaining = db.execute(
            "SELECT COUNT(*) FROM providers WHERE config_id=?", (config_id,)
        ).fetchone()[0]
        cfg_row = db.execute(
            "SELECT prompt FROM configurations WHERE id=?", (config_id,)
        ).fetchone()
        if remaining == 0 and cfg_row and cfg_row['prompt'] is None:
            db.execute("DELETE FROM configurations WHERE id=?", (config_id,))
            db.commit()
            flash(f"Channel '{provider['tag']}' deleted. "
                  "Configuration had no remaining elements and was removed.", 'success')
            return redirect(url_for('admin.dashboard'))

        db.commit()
        flash(f"Channel '{provider['tag']}' deleted.", 'success')
        return redirect(url_for('admin.config_detail', config_id=config_id))

    return render_template('admin/provider_delete.html', config=config, provider=provider)


# ── Matcher management ────────────────────────────────────────────────────────

@admin_bp.post('/configs/<int:config_id>/channels/<int:provider_id>/matchers/new')
@login_required
def matcher_new(config_id, provider_id):
    user_id  = session['user_id']
    provider = _get_provider(provider_id, config_id, user_id)
    if not provider:
        flash('Channel not found.', 'error')
        return redirect(url_for('admin.config_detail', config_id=config_id))

    db = get_db()

    if provider['channel_type'] == 'sms':
        # SMS channel: sender phone + optional body pattern
        sender_mode = request.form.get('sender_mode', 'sample')
        if sender_mode == 'sample':
            phone = provider['sample_email'] or ''   # sample_email reused as sample_body
        elif sender_mode == 'custom':
            phone = request.form.get('sender_custom', '').strip()
        else:
            phone = ''
        phone = phone.strip() or None

        body_mode = request.form.get('body_mode', 'any')
        if body_mode == 'starts_with':
            body_pattern    = request.form.get('body_text', '').strip() or None
            body_match_type = 'starts_with' if body_pattern else None
        elif body_mode == 'regex':
            body_pattern    = request.form.get('body_regex', '').strip() or None
            body_match_type = 'regex' if body_pattern else None
        else:
            body_pattern    = None
            body_match_type = None

        if not phone and not body_pattern:
            flash('An SMS header requires a phone number, a body pattern, or both.', 'error')
            return redirect(url_for('admin.channel_edit',
                                    config_id=config_id, provider_id=provider_id))

        db.execute(
            "INSERT INTO provider_matchers "
            "  (provider_id, sender_phone, body_pattern, body_match_type) "
            "VALUES (?, ?, ?, ?)",
            (provider_id, phone, body_pattern, body_match_type)
        )
    else:
        # Email channel
        sender_mode = request.form.get('sender_mode', 'any')
        if sender_mode == 'sample':
            sample_text = provider['sample_email'] or ''
            m = re.search(r'^From:\s*(.+)', sample_text, re.MULTILINE | re.IGNORECASE)
            if m:
                _, addr = parseaddr(m.group(1).strip())
                sender = addr.lower() if addr else None
            else:
                sender = None
        elif sender_mode == 'custom':
            sender = request.form.get('sender_custom', '').strip().lower() or None
        elif sender_mode == 'fwd':
            sender = request.form.get('sender_fwd', '').strip().lower() or None
        else:
            sender = None

        subject_mode = request.form.get('subject_mode', 'any')
        if subject_mode == 'contains':
            text    = request.form.get('subject_text', '').strip()
            subject = re.escape(text) if text else None
        elif subject_mode == 'regex':
            subject = request.form.get('subject_regex', '').strip() or None
        else:
            subject = None

        if not sender and not subject:
            flash('At least one of sender or subject must be specified.', 'error')
            return redirect(url_for('admin.channel_edit',
                                    config_id=config_id, provider_id=provider_id))

        db.execute(
            "INSERT INTO provider_matchers (provider_id, sender_email, subject_pattern) "
            "VALUES (?, ?, ?)",
            (provider_id, sender, subject)
        )

    _auto_update_status(db, config_id)
    db.commit()
    flash('Matcher added.', 'success')
    return redirect(url_for('admin.channel_edit',
                            config_id=config_id, provider_id=provider_id))


@admin_bp.post('/configs/<int:config_id>/channels/<int:provider_id>'
               '/matchers/<int:matcher_id>/delete')
@login_required
def matcher_delete(config_id, provider_id, matcher_id):
    db  = get_db()
    cur = db.execute(
        "DELETE FROM provider_matchers WHERE id=? AND provider_id=?",
        (matcher_id, provider_id)
    )
    if cur.rowcount:
        _auto_update_status(db, config_id)
    db.commit()
    flash('Matcher removed.' if cur.rowcount else 'Matcher not found.', 'success')
    return redirect(url_for('admin.channel_edit',
                            config_id=config_id, provider_id=provider_id))


# ── Unmatched emails ───────────────────────────────────────────────────────────

@admin_bp.get('/unmatched')
@login_required
def unmatched_list():
    user_id = session['user_id']
    rows = get_db().execute(
        "SELECT id, channel_type, sender, subject, received_at "
        "FROM   unmatched_items "
        "WHERE  user_id=? "
        "ORDER  BY received_at DESC",
        (user_id,)
    ).fetchall()
    return render_template('admin/unmatched_list.html', emails=rows)


@admin_bp.route('/unmatched/<int:email_id>', methods=['GET', 'POST'])
@login_required
def unmatched_detail(email_id):
    user_id = session['user_id']
    db      = get_db()
    row     = db.execute(
        "SELECT * FROM unmatched_items WHERE id=? AND user_id=?",
        (email_id, user_id)
    ).fetchone()
    if not row:
        flash('Not found.', 'error')
        return redirect(url_for('admin.unmatched_list'))

    # User's private configurations for the target config selector.
    # COALESCE handles the edge case where visibility is NULL (migration gap).
    # Includes valid_tested — adding a channel is allowed and resets it to valid.
    user_configs = db.execute(
        "SELECT id, name, version FROM configurations "
        "WHERE owner_id=? AND COALESCE(visibility,'private') = 'private' "
        "AND status NOT IN ('pending_review') "
        "ORDER BY name, version",
        (user_id,)
    ).fetchall()

    if request.method == 'POST':
        action = request.form.get('action', '')

        if action == 'promote':
            # ── Target configuration ──────────────────────────────────────────
            config_choice = request.form.get('config_choice', '').strip()
            if config_choice == 'new':
                new_name = request.form.get('new_config_name', '').strip()
                if not new_name:
                    flash('Configuration name is required.', 'error')
                    return render_template('admin/unmatched_detail.html',
                                           row=row, user_configs=user_configs)
                try:
                    db.execute(
                        "INSERT INTO configurations (owner_id, name, version, status) VALUES (?,?,'-1','incomplete')",
                        (user_id, new_name)
                    )
                    config_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
                except sqlite3.IntegrityError:
                    flash(f"A configuration named '{new_name}' already exists.", 'error')
                    return render_template('admin/unmatched_detail.html',
                                           row=row, user_configs=user_configs)
            elif config_choice:
                config_id = int(config_choice)
                if not _get_config(config_id, user_id):
                    flash('Configuration not found.', 'error')
                    return render_template('admin/unmatched_detail.html',
                                           row=row, user_configs=user_configs)
            else:
                flash('Select or create a target configuration.', 'error')
                return render_template('admin/unmatched_detail.html',
                                       row=row, user_configs=user_configs)

            # ── Extraction settings ───────────────────────────────────────────
            tag    = request.form.get('tag', '').strip()
            mode   = request.form.get('extract_mode', 'auto')
            source = request.form.get('extract_source', 'body')
            end    = request.form.get('nonce_end_marker', '').strip() or None
            try:
                length = int(request.form['nonce_length']) if request.form.get('nonce_length', '').strip() else None
            except ValueError:
                length = None

            if mode == 'auto':
                example_otp = request.form.get('example_otp', '').strip()
                if not example_otp:
                    flash('Example OTP is required for auto extraction mode.', 'error')
                    return render_template('admin/unmatched_detail.html',
                                           row=row, user_configs=user_configs)
                derive_from = row['subject'] if source == 'subject' else (row['body_text'] or '')
                start, length = _derive_auto_markers(derive_from, example_otp)
                if not start:
                    flash('Example OTP not found in the email text.', 'error')
                    return render_template('admin/unmatched_detail.html',
                                           row=row, user_configs=user_configs)
            else:
                start = (request.form.get('nonce_regex_pattern', '').strip()
                 if mode == 'regex'
                 else request.form.get('nonce_start_marker', '').strip())

            channel_type = row['channel_type']   # propagate from the unmatched item

            if channel_type == 'sms':
                # ── SMS sender ────────────────────────────────────────────────
                sender_mode = request.form.get('sender_mode', 'sample')
                if sender_mode == 'sample':
                    sender_phone = row['sender'] or None
                elif sender_mode == 'custom':
                    sender_phone = request.form.get('sender_custom', '').strip() or None
                else:
                    sender_phone = None
                sender_email    = None
                subject_pattern = None
                # ── SMS body pattern ──────────────────────────────────────────
                body_mode = request.form.get('body_mode', 'any')
                if body_mode == 'starts_with':
                    body_pattern    = request.form.get('body_text', '').strip() or None
                    body_match_type = 'starts_with' if body_pattern else None
                elif body_mode == 'regex':
                    body_pattern    = request.form.get('body_regex', '').strip() or None
                    body_match_type = 'regex' if body_pattern else None
                else:
                    body_pattern    = None
                    body_match_type = None

                if not sender_phone and not body_pattern:
                    flash('An SMS header requires a phone number, a body pattern, or both.', 'error')
                    return render_template('admin/unmatched_detail.html',
                                           row=row, user_configs=user_configs)
            else:
                # ── Email sender ──────────────────────────────────────────────
                sender_mode = request.form.get('sender_mode', 'any')
                if sender_mode == 'sample':
                    sender_email = row['sender'] or None
                elif sender_mode == 'fwd':
                    sender_email = row['fwd_sender'] or None
                elif sender_mode == 'custom':
                    sender_email = request.form.get('sender_custom', '').strip().lower() or None
                else:
                    sender_email = None

                # ── Subject ───────────────────────────────────────────────────
                subject_mode = request.form.get('subject_mode', 'any')
                if subject_mode == 'contains':
                    text            = request.form.get('subject_text', '').strip()
                    subject_pattern = re.escape(text) if text else None
                elif subject_mode == 'regex':
                    subject_pattern = request.form.get('subject_regex', '').strip() or None
                else:
                    subject_pattern = None

                sender_phone = None

            if not tag:
                flash('Tag is required.', 'error')
                return render_template('admin/unmatched_detail.html',
                                       row=row, user_configs=user_configs)
            if mode != 'auto' and not start:
                flash('Start marker is required for this extraction mode.', 'error')
                return render_template('admin/unmatched_detail.html',
                                       row=row, user_configs=user_configs)

            try:
                db.execute(
                    "INSERT INTO providers "
                    "  (user_id, config_id, tag, channel_type, extract_source, extract_mode, "
                    "   nonce_start_marker, nonce_end_marker, nonce_length) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (user_id, config_id, tag, channel_type, source, mode, start, end, length)
                )
                provider_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
                db.execute(
                    "INSERT INTO provider_matchers "
                    "  (provider_id, sender_email, subject_pattern, sender_phone, "
                    "   body_pattern, body_match_type) "
                    "VALUES (?,?,?,?,?,?)",
                    (provider_id, sender_email, subject_pattern, sender_phone,
                     body_pattern if channel_type == 'sms' else None,
                     body_match_type if channel_type == 'sms' else None)
                )
                db.execute("DELETE FROM unmatched_items WHERE id=?", (email_id,))
                _auto_update_status(db, config_id)
                db.commit()
            except sqlite3.IntegrityError:
                flash(f"Channel name '{tag}' already exists.", 'error')
                return render_template('admin/unmatched_detail.html',
                                       row=row, user_configs=user_configs)

            flash(f"Channel '{tag}' created.", 'success')
            return redirect(url_for('admin.config_detail', config_id=config_id))

    return render_template('admin/unmatched_detail.html',
                           row=row, user_configs=user_configs)


@admin_bp.post('/unmatched/<int:email_id>/dismiss')
@login_required
def unmatched_dismiss(email_id):
    user_id = session['user_id']
    db      = get_db()
    db.execute("DELETE FROM unmatched_items WHERE id=? AND user_id=?",
               (email_id, user_id))
    db.commit()
    flash('Item dismissed.', 'success')
    return redirect(url_for('admin.unmatched_list'))


# ── Marketplace ───────────────────────────────────────────────────────────────

@admin_bp.get('/marketplace')
@login_required
def marketplace_browse():
    user_id = session['user_id']
    db      = get_db()

    configs = db.execute(
        "SELECT c.*, u.username AS owner_name "
        "FROM configurations c "
        "JOIN users u ON u.id = c.owner_id "
        "WHERE c.visibility='public' AND c.status='valid' "
        "ORDER BY c.name, c.version DESC",
    ).fetchall()

    subscribed = set(
        row[0] for row in db.execute(
            "SELECT config_id FROM subscriptions WHERE user_id=?", (user_id,)
        ).fetchall()
    )

    # Build channel_types_map: config_id → list of distinct channel types (e.g. ['email','sms'])
    channel_types_map = {}
    for c in configs:
        rows = db.execute(
            "SELECT DISTINCT channel_type FROM providers WHERE config_id=?", (c['id'],)
        ).fetchall()
        channel_types_map[c['id']] = [r['channel_type'] for r in rows]

    sub_data = {}
    if _is_admin(user_id):
        for c in configs:
            rows = db.execute(
                "SELECT u.username FROM subscriptions s "
                "JOIN users u ON u.id = s.user_id "
                "WHERE s.config_id=?",
                (c['id'],)
            ).fetchall()
            sub_data[c['id']] = [r['username'] for r in rows]

    return render_template('admin/marketplace.html',
                           configs=configs,
                           subscribed=subscribed,
                           channel_types_map=channel_types_map,
                           sub_data=sub_data)


@admin_bp.post('/marketplace/<int:src_config_id>/subscribe')
@login_required
def marketplace_subscribe(src_config_id):
    user_id = session['user_id']
    db      = get_db()

    src = db.execute(
        "SELECT * FROM configurations WHERE id=? AND visibility='public'",
        (src_config_id,)
    ).fetchone()
    if not src:
        flash('Configuration not found or not public.', 'error')
        return redirect(url_for('admin.marketplace_browse'))

    existing = db.execute(
        "SELECT id FROM subscriptions WHERE user_id=? AND config_id=?",
        (user_id, src_config_id)
    ).fetchone()
    if existing:
        flash('Already subscribed to this configuration.', 'error')
        return redirect(url_for('admin.marketplace_browse'))

    db.execute(
        "INSERT INTO subscriptions (user_id, config_id) VALUES (?, ?)",
        (user_id, src_config_id)
    )
    db.commit()
    flash(f"Subscribed to '{src['name']}' {src['version']}.", 'success')
    return redirect(url_for('admin.dashboard'))


@admin_bp.post('/marketplace/<int:config_id>/unsubscribe')
@login_required
def marketplace_unsubscribe(config_id):
    user_id = session['user_id']
    db      = get_db()
    cur = db.execute(
        "DELETE FROM subscriptions WHERE user_id=? AND config_id=?",
        (user_id, config_id)
    )
    db.commit()
    if cur.rowcount:
        flash('Unsubscribed.', 'success')
    else:
        flash('Subscription not found.', 'error')
    return redirect(url_for('admin.marketplace_browse'))


@admin_bp.post('/marketplace/<int:old_config_id>/update/<int:new_config_id>')
@login_required
def marketplace_update(old_config_id, new_config_id):
    user_id = session['user_id']
    db      = get_db()

    existing = db.execute(
        "SELECT id FROM subscriptions WHERE user_id=? AND config_id=?",
        (user_id, old_config_id)
    ).fetchone()
    if not existing:
        flash('Subscription not found.', 'error')
        return redirect(url_for('admin.dashboard'))

    new_cfg = db.execute(
        "SELECT name, version FROM configurations WHERE id=? AND visibility='public'",
        (new_config_id,)
    ).fetchone()
    if not new_cfg:
        flash('New version not found.', 'error')
        return redirect(url_for('admin.dashboard'))

    db.execute(
        "UPDATE subscriptions SET config_id=? WHERE user_id=? AND config_id=?",
        (new_config_id, user_id, old_config_id)
    )
    db.commit()
    flash(f"Updated to '{new_cfg['name']}' {new_cfg['version']}.", 'success')
    return redirect(url_for('admin.dashboard'))


# ── Account settings ──────────────────────────────────────────────────────────

@admin_bp.route('/account/password', methods=['GET', 'POST'])
@login_required
def account_password():
    user_id = session['user_id']
    if request.method == 'POST':
        current   = request.form.get('current_password', '')
        new_pw    = request.form.get('password', '')
        confirm   = request.form.get('password2', '')

        db   = get_db()
        user = db.execute("SELECT password_hash FROM users WHERE id=?",
                          (user_id,)).fetchone()
        if not bcrypt.checkpw(current.encode(), user['password_hash'].encode()):
            flash('Current password is incorrect.', 'error')
            return render_template('admin/account_settings.html')
        if not new_pw:
            flash('New password must not be empty.', 'error')
            return render_template('admin/account_settings.html')
        if new_pw != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('admin/account_settings.html')

        pw_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
        db.execute("UPDATE users SET password_hash=? WHERE id=?", (pw_hash, user_id))
        db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        db.commit()
        session.clear()
        flash('Password changed. Please log in again.', 'success')
        return redirect(url_for('admin.auth_login'))

    return render_template('admin/account_settings.html')


@admin_bp.get('/account/gmail-filters.xml')
@login_required
def account_gmail_xml():
    user_id = session['user_id']
    db      = get_db()

    username = db.execute("SELECT username FROM users WHERE id=?",
                          (user_id,)).fetchone()['username']
    domain   = cfg('general', 'domain', fallback='nonces.example.com')
    forward_to = f"nonce-{username}@{domain}"

    senders = db.execute(
        "SELECT DISTINCT pm.sender_email "
        "FROM provider_matchers pm "
        "JOIN providers p ON p.id = pm.provider_id "
        "LEFT JOIN configurations c ON c.id = p.config_id "
        "WHERE p.user_id=? AND pm.sender_email IS NOT NULL "
        "  AND (p.config_id IS NULL "
        "       OR (c.visibility='private' AND c.activated=1 "
        "           AND c.status IN ('valid','valid_tested')) "
        "       OR (c.visibility='public' "
        "           AND EXISTS (SELECT 1 FROM subscriptions s "
        "                       WHERE s.user_id=? AND s.config_id=c.id)))",
        (user_id, user_id)
    ).fetchall()

    # Build Atom/Gmail filter XML
    APPS_NS = 'http://schemas.google.com/apps/2006'
    feed = ET.Element('feed', {
        'xmlns': 'http://www.w3.org/2005/Atom',
        'xmlns:apps': APPS_NS,
    })
    ET.SubElement(feed, 'title').text = 'Mail Filters'

    for row in senders:
        sender = row['sender_email']
        entry  = ET.SubElement(feed, 'entry')
        ET.SubElement(entry, 'category', term='filter')
        ET.SubElement(entry, 'title').text = 'Mail Filter'
        ET.SubElement(entry, f'{{{APPS_NS}}}property',
                      name='from', value=sender)
        ET.SubElement(entry, f'{{{APPS_NS}}}property',
                      name='label', value='noncey')
        ET.SubElement(entry, f'{{{APPS_NS}}}property',
                      name='forwardTo', value=forward_to)
        ET.SubElement(entry, f'{{{APPS_NS}}}property',
                      name='shouldNeverSpam', value='true')
        ET.SubElement(entry, f'{{{APPS_NS}}}property',
                      name='shouldArchive', value='true')

    xml_str = "<?xml version='1.0' encoding='UTF-8'?>\n" + ET.tostring(feed, encoding='unicode')
    return Response(
        xml_str,
        mimetype='application/xml',
        headers={'Content-Disposition': 'attachment; filename="gmail_filters.xml"'}
    )


# ── Admin: user management ────────────────────────────────────────────────────

@admin_bp.get('/admin/users')
@admin_required
def admin_users():
    db    = get_db()
    now   = datetime.now(timezone.utc).isoformat()
    users = db.execute(
        "SELECT u.id, u.username, u.email, u.is_admin, u.created_at, "
        "       COUNT(DISTINCT c.id) AS config_count "
        "FROM users u "
        "LEFT JOIN configurations c ON c.owner_id = u.id AND c.visibility='private' "
        "GROUP BY u.id ORDER BY u.username"
    ).fetchall()
    # session counts per user, grouped by client_type (active sessions only)
    session_rows = db.execute(
        "SELECT user_id, client_type, COUNT(*) AS cnt "
        "FROM sessions WHERE expires_at > ? "
        "GROUP BY user_id, client_type",
        (now,)
    ).fetchall()
    # build dict: {user_id: {'chrome': n, 'android': n, 'browser': n, 'total': n}}
    session_map = {}
    for r in session_rows:
        uid  = r['user_id']
        ctyp = r['client_type']
        cnt  = r['cnt']
        if uid not in session_map:
            session_map[uid] = {'browser': 0, 'chrome': 0, 'android': 0, 'total': 0}
        session_map[uid][ctyp] = cnt
        session_map[uid]['total'] += cnt
    return render_template('admin/admin_users.html', users=users, session_map=session_map)


@admin_bp.get('/admin/users/<int:user_id>/sessions')
@admin_required
def admin_user_sessions(user_id):
    db   = get_db()
    user = db.execute("SELECT id, username FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('admin.admin_users'))
    now      = datetime.now(timezone.utc).isoformat()
    sessions = db.execute(
        "SELECT id, client_type, created_at, last_used_at, expires_at "
        "FROM sessions WHERE user_id=? AND expires_at > ? "
        "ORDER BY last_used_at DESC",
        (user_id, now)
    ).fetchall()
    return render_template('admin/admin_user_sessions.html', user=user, sessions=sessions)


@admin_bp.post('/admin/users/<int:user_id>/sessions/<int:session_id>/revoke')
@admin_required
def admin_user_session_revoke(user_id, session_id):
    db = get_db()
    db.execute(
        "DELETE FROM sessions WHERE id=? AND user_id=?",
        (session_id, user_id)
    )
    db.commit()
    flash('Session revoked.', 'success')
    return redirect(url_for('admin.admin_user_sessions', user_id=user_id))


@admin_bp.post('/admin/users/<int:user_id>/sessions/revoke-all')
@admin_required
def admin_user_sessions_revoke_all(user_id):
    db = get_db()
    db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    db.commit()
    flash('All sessions revoked.', 'success')
    return redirect(url_for('admin.admin_user_sessions', user_id=user_id))


@admin_bp.route('/admin/users/new', methods=['GET', 'POST'])
@admin_required
def admin_user_new():
    if request.method == 'POST':
        username  = request.form.get('username', '').strip()
        email     = request.form.get('email', '').strip() or None
        password  = request.form.get('password', '')
        password2 = request.form.get('password2', '')
        is_admin  = 1 if request.form.get('is_admin') else 0

        try:
            validate_username(username)
        except ProvisionError as exc:
            flash(str(exc), 'error')
            return render_template('admin/admin_user_form.html', user=None)

        if not password:
            flash('Password must not be empty.', 'error')
            return render_template('admin/admin_user_form.html', user=None)
        if password != password2:
            flash('Passwords do not match.', 'error')
            return render_template('admin/admin_user_form.html', user=None)

        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, email, is_admin) VALUES (?,?,?,?)",
                (username, pw_hash, email, is_admin)
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash(f"User '{username}' already exists.", 'error')
            return render_template('admin/admin_user_form.html', user=None)

        flash(f"User '{username}' created.", 'success')
        return redirect(url_for('admin.admin_users'))

    return render_template('admin/admin_user_form.html', user=None)


@admin_bp.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_user_edit(user_id):
    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('admin.admin_users'))

    if request.method == 'POST':
        email     = request.form.get('email', '').strip() or None
        is_admin  = 1 if request.form.get('is_admin') else 0
        password  = request.form.get('password', '')
        password2 = request.form.get('password2', '')

        if password:
            if password != password2:
                flash('Passwords do not match.', 'error')
                return render_template('admin/admin_user_form.html', user=user)
            pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            db.execute(
                "UPDATE users SET email=?, is_admin=?, password_hash=? WHERE id=?",
                (email, is_admin, pw_hash, user_id)
            )
            db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        else:
            db.execute(
                "UPDATE users SET email=?, is_admin=? WHERE id=?",
                (email, is_admin, user_id)
            )
        db.commit()
        flash(f"User '{user['username']}' updated.", 'success')
        return redirect(url_for('admin.admin_users'))

    return render_template('admin/admin_user_form.html', user=user)


@admin_bp.route('/admin/users/<int:user_id>/delete', methods=['GET', 'POST'])
@admin_required
def admin_user_delete(user_id):
    if user_id == session['user_id']:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('admin.admin_users'))

    db   = get_db()
    user = db.execute("SELECT id, username FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('admin.admin_users'))

    if request.method == 'POST':
        db.execute("DELETE FROM users WHERE id=?", (user_id,))
        db.commit()
        flash(f"User '{user['username']}' deleted.", 'success')
        return redirect(url_for('admin.admin_users'))

    return render_template('admin/admin_user_delete.html', user=user)


# ── Admin: marketplace moderation ─────────────────────────────────────────────

@admin_bp.get('/admin/marketplace')
@admin_required
def admin_marketplace():
    db      = get_db()
    pending = db.execute(
        "SELECT c.*, u.username AS owner_name "
        "FROM configurations c "
        "JOIN users u ON u.id = c.owner_id "
        "WHERE c.status='pending_review' "
        "ORDER BY c.updated_at",
    ).fetchall()
    return render_template('admin/admin_marketplace.html', configs=pending)


@admin_bp.post('/admin/marketplace/<int:config_id>/approve')
@admin_required
def admin_marketplace_approve(config_id):
    db     = get_db()
    config = db.execute(
        "SELECT * FROM configurations WHERE id=? AND status='pending_review'",
        (config_id,)
    ).fetchone()
    if not config:
        flash('Configuration not found or not pending review.', 'error')
        return redirect(url_for('admin.admin_marketplace'))

    # Assign version: YYYYMM-NN (auto-increment within the publication month)
    year_month = datetime.now(timezone.utc).strftime('%Y%m')
    latest = db.execute(
        "SELECT version FROM configurations "
        "WHERE name=? AND visibility='public' AND version LIKE ? "
        "ORDER BY version DESC LIMIT 1",
        (config['name'], f'{year_month}-%')
    ).fetchone()
    nn      = (int(latest['version'].split('-')[1]) + 1) if latest else 1
    version = f"{year_month}-{nn:02d}"

    db.execute(
        "UPDATE configurations SET visibility='public', status='valid', version=?, "
        "activated=0, updated_at=datetime('now') WHERE id=?",
        (version, config_id)
    )
    # Clear sample_email from all providers for privacy
    db.execute("UPDATE providers SET sample_email=NULL WHERE config_id=?", (config_id,))
    # Auto-subscribe the owner
    db.execute(
        "INSERT OR IGNORE INTO subscriptions (user_id, config_id) VALUES (?, ?)",
        (config['owner_id'], config_id)
    )
    db.execute(
        "INSERT INTO marketplace_reviews (config_id, reviewer_id, decision) VALUES (?,?,?)",
        (config_id, session['user_id'], 'approved')
    )
    db.commit()
    flash(f"Configuration approved and published as {version}.", 'success')
    return redirect(url_for('admin.admin_marketplace'))


@admin_bp.post('/admin/marketplace/<int:config_id>/reject')
@admin_required
def admin_marketplace_reject(config_id):
    note = request.form.get('note', '').strip() or None
    db   = get_db()
    db.execute(
        "UPDATE configurations SET status='valid_tested', updated_at=datetime('now') WHERE id=?",
        (config_id,)
    )
    db.execute(
        "INSERT INTO marketplace_reviews (config_id, reviewer_id, decision, note) VALUES (?,?,?,?)",
        (config_id, session['user_id'], 'rejected', note)
    )
    db.commit()
    flash('Configuration rejected; owner can revise and resubmit.', 'success')
    return redirect(url_for('admin.admin_marketplace'))


# ── Creation wizard ────────────────────────────────────────────────────────────

@admin_bp.route('/wizard/new', methods=['GET', 'POST'])
@login_required
def wizard_start():
    user_id = session['user_id']
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        if not name:
            flash('Name is required.', 'error')
            return render_template('admin/wizard_new.html')
        db = get_db()
        try:
            db.execute(
                "INSERT INTO configurations (owner_id, name, version, status) VALUES (?, ?, '-1', 'incomplete')",
                (user_id, name)
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash(f"A configuration named '{name}' already exists.", 'error')
            return render_template('admin/wizard_new.html')
        config_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        return redirect(url_for('admin.wizard_step1', config_id=config_id))
    return render_template('admin/wizard_new.html')


@admin_bp.get('/wizard/<int:config_id>/1')
@login_required
def wizard_step1(config_id):
    user_id = session['user_id']
    config  = _get_config(config_id, user_id)
    if not config:
        flash('Configuration not found.', 'error')
        return redirect(url_for('admin.dashboard'))

    db = get_db()

    # If channels already set up, skip ahead
    providers = db.execute(
        "SELECT id FROM providers WHERE config_id=?", (config_id,)
    ).fetchall()
    if providers:
        return redirect(url_for('admin.wizard_step3', config_id=config_id))

    username      = db.execute(
        "SELECT username FROM users WHERE id=?", (user_id,)
    ).fetchone()['username']
    domain        = cfg('general', 'domain', fallback='nonces.example.com')
    noncey_address = f"nonce-{username}@{domain}"

    unmatched = db.execute(
        "SELECT id, sender, fwd_sender, subject, received_at "
        "FROM unmatched_items WHERE user_id=? AND channel_type='email' "
        "ORDER BY received_at DESC LIMIT 20",
        (user_id,)
    ).fetchall()

    return render_template('admin/wizard_step1.html',
                           config=config,
                           noncey_address=noncey_address,
                           unmatched=unmatched)


@admin_bp.route('/wizard/<int:config_id>/2/<int:email_id>', methods=['GET', 'POST'])
@login_required
def wizard_step2(config_id, email_id):
    user_id = session['user_id']
    config  = _get_config(config_id, user_id)
    if not config:
        flash('Configuration not found.', 'error')
        return redirect(url_for('admin.dashboard'))

    db    = get_db()
    email = db.execute(
        "SELECT * FROM unmatched_items WHERE id=? AND user_id=? AND channel_type='email'",
        (email_id, user_id)
    ).fetchone()
    if not email:
        flash('Email not found. It may have already been used.', 'error')
        return redirect(url_for('admin.wizard_step1', config_id=config_id))

    if request.method == 'POST':
        tag    = request.form.get('tag', '').strip()
        mode   = request.form.get('extract_mode', 'auto')
        source = request.form.get('extract_source', 'body')
        end    = request.form.get('nonce_end_marker', '').strip() or None
        try:
            length = int(request.form['nonce_length']) if request.form.get('nonce_length', '').strip() else None
        except ValueError:
            length = None

        if mode == 'auto':
            example_otp = request.form.get('example_otp', '').strip()
            if not example_otp:
                flash('Example OTP is required for auto extraction mode.', 'error')
                return render_template('admin/wizard_step2.html',
                                       config=config, email=email)
            derive_from = email['subject'] if source == 'subject' else (email['body_text'] or '')
            start, length = _derive_auto_markers(derive_from, example_otp)
            if not start:
                flash('Example OTP not found in the email text.', 'error')
                return render_template('admin/wizard_step2.html',
                                       config=config, email=email)
        else:
            start = (request.form.get('nonce_regex_pattern', '').strip()
                 if mode == 'regex'
                 else request.form.get('nonce_start_marker', '').strip())

        sender_mode = request.form.get('sender_mode', 'any')
        if sender_mode == 'sample':
            sender = email['sender'] or None
        elif sender_mode == 'fwd':
            sender = email['fwd_sender'] or None
        elif sender_mode == 'custom':
            sender = request.form.get('sender_custom', '').strip().lower() or None
        else:
            sender = None

        subject_mode = request.form.get('subject_mode', 'any')
        if subject_mode == 'contains':
            text            = request.form.get('subject_text', '').strip()
            subject_pattern = re.escape(text) if text else None
        elif subject_mode == 'regex':
            subject_pattern = request.form.get('subject_regex', '').strip() or None
        else:
            subject_pattern = None

        if not tag:
            flash('Channel name is required.', 'error')
            return render_template('admin/wizard_step2.html',
                                   config=config, email=email)
        if mode != 'auto' and not start:
            flash('Start marker is required for this extraction mode.', 'error')
            return render_template('admin/wizard_step2.html',
                                   config=config, email=email)

        try:
            db.execute(
                "INSERT INTO providers "
                "  (user_id, config_id, tag, channel_type, extract_source, extract_mode, "
                "   nonce_start_marker, nonce_end_marker, nonce_length) "
                "VALUES (?,?,'email',?,?,?,?,?,?)",
                (user_id, config_id, tag, source, mode, start, end, length)
            )
            provider_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
            db.execute(
                "INSERT INTO provider_matchers (provider_id, sender_email, subject_pattern) "
                "VALUES (?,?,?)",
                (provider_id, sender, subject_pattern)
            )
            db.execute("DELETE FROM unmatched_items WHERE id=?", (email_id,))
            _auto_update_status(db, config_id)
            db.commit()
        except sqlite3.IntegrityError:
            flash(f"Channel name '{tag}' already exists.", 'error')
            return render_template('admin/wizard_step2.html',
                                   config=config, email=email)

        return redirect(url_for('admin.wizard_step3', config_id=config_id))

    return render_template('admin/wizard_step2.html',
                           config=config, email=email)


@admin_bp.get('/wizard/<int:config_id>/3')
@login_required
def wizard_step3(config_id):
    user_id = session['user_id']
    config  = _get_config(config_id, user_id)
    if not config:
        flash('Configuration not found.', 'error')
        return redirect(url_for('admin.dashboard'))

    # If prompt already received, skip to step 4
    if config['prompt']:
        return redirect(url_for('admin.wizard_step4', config_id=config_id))

    return render_template('admin/wizard_step3.html', config=config)


@admin_bp.get('/wizard/<int:config_id>/prompt-status')
@login_required
def wizard_prompt_status(config_id):
    user_id = session['user_id']
    config  = _get_config(config_id, user_id)
    if not config:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'received': config['prompt'] is not None})


@admin_bp.get('/wizard/<int:config_id>/4')
@login_required
def wizard_step4(config_id):
    user_id = session['user_id']
    config  = _get_config(config_id, user_id)
    if not config:
        flash('Configuration not found.', 'error')
        return redirect(url_for('admin.dashboard'))
    return render_template('admin/wizard_step4.html', config=config)
