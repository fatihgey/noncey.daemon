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
from flask import (Blueprint, Response, flash, redirect, render_template,
                   request, session, url_for)

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
    """A configuration can be activated if it has at least one provider with a matcher."""
    return any(matchers.get(p['id']) for p in providers)


def _update_config_status_check(db, config_id: int):
    """After test_count changes, advance to 'tested' if threshold reached."""
    db.execute(
        "UPDATE configurations SET status='tested', updated_at=datetime('now') "
        "WHERE id=? AND status='active' AND test_count >= test_threshold",
        (config_id,)
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
        dummy = '$2b$12$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        stored = user['password_hash'] if user else dummy
        ok     = bcrypt.checkpw(password.encode(), stored.encode())

        if not user or not ok:
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

    # Count unmatched emails
    unmatched_count = db.execute(
        "SELECT COUNT(*) FROM unmatched_emails WHERE user_id=?", (user_id,)
    ).fetchone()[0]

    # Owned + subscribed configurations with stats
    configs = db.execute(
        "SELECT c.*, "
        "  (SELECT COUNT(*) FROM providers p WHERE p.config_id=c.id) AS provider_count "
        "FROM configurations c "
        "WHERE c.owner_id=? "
        "ORDER BY c.source_config_id IS NULL DESC, c.updated_at DESC",
        (user_id,)
    ).fetchall()

    # Check update availability for subscribed configs
    update_available = {}
    for c in configs:
        if c['source_config_id']:
            src = db.execute(
                "SELECT owner_id, name, version FROM configurations WHERE id=?",
                (c['source_config_id'],)
            ).fetchone()
            if src:
                newer = db.execute(
                    "SELECT id FROM configurations "
                    "WHERE owner_id=? AND name=? AND status='public' AND version>?",
                    (src['owner_id'], src['name'], src['version'])
                ).fetchone()
                if newer:
                    update_available[c['id']] = newer['id']

    return render_template('admin/dashboard.html',
                           configs=configs,
                           unmatched_count=unmatched_count,
                           update_available=update_available)


# ── Configuration management ──────────────────────────────────────────────────

@admin_bp.route('/configs/new', methods=['GET', 'POST'])
@login_required
def config_new():
    user_id = session['user_id']
    default_version = datetime.now(timezone.utc).strftime('%Y%m-01')

    if request.method == 'POST':
        name        = request.form.get('name', '').strip()
        version     = request.form.get('version', default_version).strip()
        description = request.form.get('description', '').strip() or None
        try:
            threshold = int(request.form.get('test_threshold', '3'))
        except ValueError:
            threshold = 3

        if not name or not version:
            flash('Name and version are required.', 'error')
            return render_template('admin/config_form.html',
                                   config=None, default_version=default_version)
        db = get_db()
        try:
            db.execute(
                "INSERT INTO configurations (owner_id, name, version, description, test_threshold) "
                "VALUES (?, ?, ?, ?, ?)",
                (user_id, name, version, description, threshold)
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash(f"A configuration named '{name}' v{version} already exists.", 'error')
            return render_template('admin/config_form.html',
                                   config=None, default_version=default_version)
        flash(f"Configuration '{name}' created.", 'success')
        config_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        return redirect(url_for('admin.config_detail', config_id=config_id))

    return render_template('admin/config_form.html',
                           config=None, default_version=default_version)


@admin_bp.route('/configs/<int:config_id>/edit', methods=['GET', 'POST'])
@login_required
def config_edit(config_id):
    user_id = session['user_id']
    config  = _get_config(config_id, user_id)
    if not config:
        flash('Configuration not found.', 'error')
        return redirect(url_for('admin.dashboard'))

    if request.method == 'POST':
        name        = request.form.get('name', '').strip()
        version     = request.form.get('version', '').strip()
        description = request.form.get('description', '').strip() or None
        try:
            threshold = int(request.form.get('test_threshold', '3'))
        except ValueError:
            threshold = 3

        if not name or not version:
            flash('Name and version are required.', 'error')
            return render_template('admin/config_form.html',
                                   config=config, default_version=config['version'])
        db = get_db()
        try:
            db.execute(
                "UPDATE configurations SET name=?, version=?, description=?, "
                "test_threshold=?, updated_at=datetime('now') WHERE id=?",
                (name, version, description, threshold, config_id)
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash(f"A configuration named '{name}' v{version} already exists.", 'error')
            return render_template('admin/config_form.html',
                                   config=config, default_version=config['version'])
        flash('Configuration updated.', 'success')
        return redirect(url_for('admin.config_detail', config_id=config_id))

    return render_template('admin/config_form.html',
                           config=config, default_version=config['version'])


@admin_bp.route('/configs/<int:config_id>/delete', methods=['GET', 'POST'])
@login_required
def config_delete(config_id):
    user_id = session['user_id']
    config  = _get_config(config_id, user_id)
    if not config:
        flash('Configuration not found.', 'error')
        return redirect(url_for('admin.dashboard'))

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

    db = get_db()
    providers, matchers = _providers_with_matchers(db, config_id)

    if config['status'] == 'active':
        db.execute(
            "UPDATE configurations SET status='draft', updated_at=datetime('now') WHERE id=?",
            (config_id,)
        )
        db.commit()
        flash('Configuration deactivated.', 'success')
    elif config['status'] in ('draft',):
        if not _config_activatable(providers, matchers):
            flash('Add at least one provider with a matcher before activating.', 'error')
        else:
            db.execute(
                "UPDATE configurations SET status='active', updated_at=datetime('now') WHERE id=?",
                (config_id,)
            )
            db.commit()
            flash('Configuration activated.', 'success')
    else:
        flash(f"Cannot activate from status '{config['status']}'.", 'error')

    return redirect(url_for('admin.config_detail', config_id=config_id))


@admin_bp.post('/configs/<int:config_id>/submit')
@login_required
def config_submit(config_id):
    user_id = session['user_id']
    config  = _get_config(config_id, user_id)
    if not config:
        flash('Configuration not found.', 'error')
        return redirect(url_for('admin.dashboard'))

    if config['status'] != 'tested':
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
    config  = _get_config(config_id, user_id)
    if not config:
        flash('Configuration not found.', 'error')
        return redirect(url_for('admin.dashboard'))

    db = get_db()
    providers, matchers = _providers_with_matchers(db, config_id)
    activatable = _config_activatable(providers, matchers)

    # Source config info (for subscriptions)
    source_config = None
    if config['source_config_id']:
        source_config = db.execute(
            "SELECT c.name, c.version, u.username AS owner "
            "FROM configurations c JOIN users u ON u.id = c.owner_id "
            "WHERE c.id=?",
            (config['source_config_id'],)
        ).fetchone()

    # Check if user has public configs (hides unmatched body for privacy)
    has_public = db.execute(
        "SELECT COUNT(*) FROM configurations WHERE owner_id=? AND status='public'",
        (user_id,)
    ).fetchone()[0] > 0

    return render_template('admin/config_detail.html',
                           config=config,
                           providers=providers,
                           matchers=matchers,
                           activatable=activatable,
                           source_config=source_config,
                           has_public=has_public)


# ── Provider management (config-scoped) ───────────────────────────────────────

def _render_provider_form(config, provider, matchers, sample_sender):
    return render_template('admin/provider_form.html',
                           config=config, provider=provider,
                           matchers=matchers, sample_sender=sample_sender)


def _process_provider_form(request, config, provider, db):
    """Parse and validate the provider form. Returns (ok, fields_dict, error_html)."""
    tag    = request.form.get('tag', '').strip()
    mode   = request.form.get('extract_mode', 'auto')
    source = request.form.get('extract_source', 'body')
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
            return False, None, 'Example OTP not found in the sample email text.'
    else:
        start = request.form.get('nonce_start_marker', '').strip()

    if not tag:
        return False, None, 'Tag is required.'
    if mode != 'auto' and not start:
        return False, None, 'Start marker is required for this extraction mode.'

    return True, dict(tag=tag, mode=mode, source=source, start=start,
                      end=end, length=length, sample=sample), None


@admin_bp.route('/configs/<int:config_id>/providers/new', methods=['GET', 'POST'])
@login_required
def provider_new(config_id):
    user_id = session['user_id']
    config  = _get_config(config_id, user_id)
    if not config:
        flash('Configuration not found.', 'error')
        return redirect(url_for('admin.dashboard'))

    if request.method == 'POST':
        ok, fields, err = _process_provider_form(request, config, None, get_db())
        if not ok:
            flash(err, 'error')
            return _render_provider_form(config, None, [], None)

        db = get_db()
        try:
            db.execute(
                "INSERT INTO providers "
                "  (user_id, config_id, tag, extract_source, extract_mode, "
                "   nonce_start_marker, nonce_end_marker, nonce_length, sample_email) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (user_id, config_id, fields['tag'], fields['source'], fields['mode'],
                 fields['start'], fields['end'], fields['length'], fields['sample'])
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash(f"Provider tag '{fields['tag']}' already exists.", 'error')
            return _render_provider_form(config, None, [], None)

        flash(f"Provider '{fields['tag']}' created.", 'success')
        return redirect(url_for('admin.config_detail', config_id=config_id))

    return _render_provider_form(config, None, [], None)


@admin_bp.route('/configs/<int:config_id>/providers/<int:provider_id>/edit',
                methods=['GET', 'POST'])
@login_required
def provider_edit(config_id, provider_id):
    user_id  = session['user_id']
    config   = _get_config(config_id, user_id)
    provider = _get_provider(provider_id, config_id, user_id)
    if not config or not provider:
        flash('Not found.', 'error')
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
            flash(f"Provider tag '{fields['tag']}' already exists.", 'error')
            return _render_provider_form(config, provider, matchers, sample_sender)

        flash(f"Provider '{fields['tag']}' updated.", 'success')
        return redirect(url_for('admin.config_detail', config_id=config_id))

    return _render_provider_form(config, provider, matchers, sample_sender)


@admin_bp.route('/configs/<int:config_id>/providers/<int:provider_id>/delete',
                methods=['GET', 'POST'])
@login_required
def provider_delete(config_id, provider_id):
    user_id  = session['user_id']
    config   = _get_config(config_id, user_id)
    provider = _get_provider(provider_id, config_id, user_id)
    if not config or not provider:
        flash('Not found.', 'error')
        return redirect(url_for('admin.config_detail', config_id=config_id))

    if request.method == 'POST':
        db = get_db()
        db.execute("DELETE FROM providers WHERE id=?", (provider_id,))
        db.commit()
        flash(f"Provider '{provider['tag']}' deleted.", 'success')
        return redirect(url_for('admin.config_detail', config_id=config_id))

    return render_template('admin/provider_delete.html', config=config, provider=provider)


# ── Matcher management ────────────────────────────────────────────────────────

@admin_bp.post('/configs/<int:config_id>/providers/<int:provider_id>/matchers/new')
@login_required
def matcher_new(config_id, provider_id):
    user_id  = session['user_id']
    provider = _get_provider(provider_id, config_id, user_id)
    if not provider:
        flash('Provider not found.', 'error')
        return redirect(url_for('admin.config_detail', config_id=config_id))

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
        return redirect(url_for('admin.provider_edit',
                                config_id=config_id, provider_id=provider_id))

    db = get_db()
    db.execute(
        "INSERT INTO provider_matchers (provider_id, sender_email, subject_pattern) "
        "VALUES (?, ?, ?)",
        (provider_id, sender, subject)
    )
    db.commit()
    flash('Matcher added.', 'success')
    return redirect(url_for('admin.provider_edit',
                            config_id=config_id, provider_id=provider_id))


@admin_bp.post('/configs/<int:config_id>/providers/<int:provider_id>'
               '/matchers/<int:matcher_id>/delete')
@login_required
def matcher_delete(config_id, provider_id, matcher_id):
    db  = get_db()
    cur = db.execute(
        "DELETE FROM provider_matchers WHERE id=? AND provider_id=?",
        (matcher_id, provider_id)
    )
    db.commit()
    flash('Matcher removed.' if cur.rowcount else 'Matcher not found.', 'success')
    return redirect(url_for('admin.provider_edit',
                            config_id=config_id, provider_id=provider_id))


# ── Unmatched emails ───────────────────────────────────────────────────────────

@admin_bp.get('/unmatched')
@login_required
def unmatched_list():
    user_id = session['user_id']
    rows = get_db().execute(
        "SELECT id, sender, subject, received_at "
        "FROM   unmatched_emails "
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
        "SELECT * FROM unmatched_emails WHERE id=? AND user_id=?",
        (email_id, user_id)
    ).fetchone()
    if not row:
        flash('Not found.', 'error')
        return redirect(url_for('admin.unmatched_list'))

    # Privacy: if user has public configs, hide email body
    has_public = db.execute(
        "SELECT COUNT(*) FROM configurations WHERE owner_id=? AND status='public'",
        (user_id,)
    ).fetchone()[0] > 0

    # User's configurations for the target config selector
    user_configs = db.execute(
        "SELECT id, name, version FROM configurations "
        "WHERE owner_id=? AND status IN ('draft','active') "
        "AND source_config_id IS NULL "
        "ORDER BY name, version",
        (user_id,)
    ).fetchall()

    if request.method == 'POST':
        action = request.form.get('action', '')

        if action == 'promote':
            # ── Target configuration ──────────────────────────────────────────
            config_choice = request.form.get('config_choice', '').strip()
            if config_choice == 'new':
                new_name    = request.form.get('new_config_name', '').strip()
                new_version = request.form.get('new_config_version', '').strip() or \
                              datetime.now(timezone.utc).strftime('%Y%m-01')
                if not new_name:
                    flash('Configuration name is required.', 'error')
                    return render_template('admin/unmatched_detail.html',
                                           row=row, user_configs=user_configs,
                                           has_public=has_public)
                try:
                    db.execute(
                        "INSERT INTO configurations (owner_id, name, version) VALUES (?,?,?)",
                        (user_id, new_name, new_version)
                    )
                    config_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
                except sqlite3.IntegrityError:
                    flash(f"Configuration '{new_name}' v{new_version} already exists.", 'error')
                    return render_template('admin/unmatched_detail.html',
                                           row=row, user_configs=user_configs,
                                           has_public=has_public)
            elif config_choice:
                config_id = int(config_choice)
                if not _get_config(config_id, user_id):
                    flash('Configuration not found.', 'error')
                    return render_template('admin/unmatched_detail.html',
                                           row=row, user_configs=user_configs,
                                           has_public=has_public)
            else:
                flash('Select or create a target configuration.', 'error')
                return render_template('admin/unmatched_detail.html',
                                       row=row, user_configs=user_configs,
                                       has_public=has_public)

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
                                           row=row, user_configs=user_configs,
                                           has_public=has_public)
                derive_from = row['subject'] if source == 'subject' else (row['body_text'] or '')
                start, length = _derive_auto_markers(derive_from, example_otp)
                if not start:
                    flash('Example OTP not found in the email text.', 'error')
                    return render_template('admin/unmatched_detail.html',
                                           row=row, user_configs=user_configs,
                                           has_public=has_public)
            else:
                start = request.form.get('nonce_start_marker', '').strip()

            # ── Sender ───────────────────────────────────────────────────────
            sender_mode = request.form.get('sender_mode', 'any')
            if sender_mode == 'sample':
                sender = row['sender'] or None
            elif sender_mode == 'fwd':
                sender = row['fwd_sender'] or None
            elif sender_mode == 'custom':
                sender = request.form.get('sender_custom', '').strip().lower() or None
            else:
                sender = None

            # ── Subject ──────────────────────────────────────────────────────
            subject_mode = request.form.get('subject_mode', 'any')
            if subject_mode == 'contains':
                text            = request.form.get('subject_text', '').strip()
                subject_pattern = re.escape(text) if text else None
            elif subject_mode == 'regex':
                subject_pattern = request.form.get('subject_regex', '').strip() or None
            else:
                subject_pattern = None

            if not tag:
                flash('Tag is required.', 'error')
                return render_template('admin/unmatched_detail.html',
                                       row=row, user_configs=user_configs,
                                       has_public=has_public)
            if mode != 'auto' and not start:
                flash('Start marker is required for this extraction mode.', 'error')
                return render_template('admin/unmatched_detail.html',
                                       row=row, user_configs=user_configs,
                                       has_public=has_public)

            try:
                db.execute(
                    "INSERT INTO providers "
                    "  (user_id, config_id, tag, extract_source, extract_mode, "
                    "   nonce_start_marker, nonce_end_marker, nonce_length) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (user_id, config_id, tag, source, mode, start, end, length)
                )
                provider_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
                db.execute(
                    "INSERT INTO provider_matchers (provider_id, sender_email, subject_pattern) "
                    "VALUES (?,?,?)",
                    (provider_id, sender, subject_pattern)
                )
                db.execute("DELETE FROM unmatched_emails WHERE id=?", (email_id,))
                db.commit()
            except sqlite3.IntegrityError:
                flash(f"Provider tag '{tag}' already exists.", 'error')
                return render_template('admin/unmatched_detail.html',
                                       row=row, user_configs=user_configs,
                                       has_public=has_public)

            flash(f"Provider '{tag}' created.", 'success')
            return redirect(url_for('admin.config_detail', config_id=config_id))

    return render_template('admin/unmatched_detail.html',
                           row=row, user_configs=user_configs,
                           has_public=has_public)


@admin_bp.post('/unmatched/<int:email_id>/dismiss')
@login_required
def unmatched_dismiss(email_id):
    user_id = session['user_id']
    db      = get_db()
    db.execute("DELETE FROM unmatched_emails WHERE id=? AND user_id=?",
               (email_id, user_id))
    db.commit()
    flash('Email dismissed.', 'success')
    return redirect(url_for('admin.unmatched_list'))


# ── Marketplace ───────────────────────────────────────────────────────────────

@admin_bp.get('/marketplace')
@login_required
def marketplace_browse():
    user_id = session['user_id']
    db      = get_db()

    # All public configurations, grouped by (owner, name) showing latest version
    configs = db.execute(
        "SELECT c.*, u.username AS owner_name, "
        "  (SELECT id FROM configurations "
        "   WHERE owner_id=c.owner_id AND name=c.name AND status='public' "
        "   ORDER BY version DESC LIMIT 1) AS latest_id "
        "FROM configurations c "
        "JOIN users u ON u.id = c.owner_id "
        "WHERE c.status='public' "
        "ORDER BY c.name, c.version DESC",
        ()
    ).fetchall()

    # Mark which ones the user is already subscribed to
    subscribed = set(
        row[0] for row in db.execute(
            "SELECT source_config_id FROM configurations "
            "WHERE owner_id=? AND source_config_id IS NOT NULL",
            (user_id,)
        ).fetchall()
    )

    return render_template('admin/marketplace.html',
                           configs=configs,
                           subscribed=subscribed)


@admin_bp.post('/marketplace/<int:src_config_id>/subscribe')
@login_required
def marketplace_subscribe(src_config_id):
    user_id = session['user_id']
    db      = get_db()

    src = db.execute(
        "SELECT * FROM configurations WHERE id=? AND status='public'",
        (src_config_id,)
    ).fetchone()
    if not src:
        flash('Configuration not found or not public.', 'error')
        return redirect(url_for('admin.marketplace_browse'))

    if src['owner_id'] == user_id:
        flash('You cannot subscribe to your own configuration.', 'error')
        return redirect(url_for('admin.marketplace_browse'))

    existing = db.execute(
        "SELECT id FROM configurations WHERE owner_id=? AND source_config_id=?",
        (user_id, src_config_id)
    ).fetchone()
    if existing:
        flash('Already subscribed to this configuration.', 'error')
        return redirect(url_for('admin.marketplace_browse'))

    # Create subscriber's local copy
    db.execute(
        "INSERT INTO configurations "
        "  (owner_id, name, version, description, status, source_config_id, prompt_assigned) "
        "VALUES (?,?,?,?,'active',?,?)",
        (user_id, src['name'], src['version'], src['description'],
         src_config_id, src['prompt_assigned'])
    )
    local_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    # Copy providers + matchers, clearing sample_email
    _copy_providers(db, src_config_id, user_id, local_id)
    db.commit()
    flash(f"Subscribed to '{src['name']}' v{src['version']}.", 'success')
    return redirect(url_for('admin.dashboard'))


@admin_bp.post('/marketplace/<int:src_config_id>/update/<int:local_config_id>')
@login_required
def marketplace_update(src_config_id, local_config_id):
    user_id = session['user_id']
    db      = get_db()

    local = _get_config(local_config_id, user_id)
    if not local or local['source_config_id'] is None:
        flash('Subscription not found.', 'error')
        return redirect(url_for('admin.dashboard'))

    # Find the specific newer public config to update to
    src = db.execute(
        "SELECT * FROM configurations WHERE id=? AND status='public'",
        (src_config_id,)
    ).fetchone()
    if not src:
        flash('New version not found.', 'error')
        return redirect(url_for('admin.dashboard'))

    # Replace providers: delete old copies, copy new ones
    db.execute("DELETE FROM providers WHERE config_id=?", (local_config_id,))
    _copy_providers(db, src_config_id, user_id, local_config_id)

    db.execute(
        "UPDATE configurations SET version=?, description=?, source_config_id=?, "
        "updated_at=datetime('now') WHERE id=?",
        (src['version'], src['description'], src_config_id, local_config_id)
    )
    db.commit()
    flash(f"Updated to '{src['name']}' v{src['version']}.", 'success')
    return redirect(url_for('admin.dashboard'))


def _copy_providers(db, src_config_id: int, dest_user_id: int, dest_config_id: int):
    """Copy all providers+matchers from src_config to dest_config, clearing sample_email."""
    src_providers = db.execute(
        "SELECT * FROM providers WHERE config_id=?", (src_config_id,)
    ).fetchall()
    for prov in src_providers:
        tag = prov['tag']
        base_tag, suffix = tag, 1
        while db.execute("SELECT id FROM providers WHERE user_id=? AND tag=?",
                         (dest_user_id, tag)).fetchone():
            tag = f"{base_tag}_{suffix}"
            suffix += 1

        db.execute(
            "INSERT INTO providers "
            "  (user_id, config_id, tag, extract_source, extract_mode, "
            "   nonce_start_marker, nonce_end_marker, nonce_length, sample_email) "
            "VALUES (?,?,?,?,?,?,?,?,NULL)",
            (dest_user_id, dest_config_id, tag,
             prov['extract_source'], prov['extract_mode'],
             prov['nonce_start_marker'], prov['nonce_end_marker'],
             prov['nonce_length'])
        )
        new_prov_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        for m in db.execute(
            "SELECT * FROM provider_matchers WHERE provider_id=?", (prov['id'],)
        ).fetchall():
            db.execute(
                "INSERT INTO provider_matchers (provider_id, sender_email, subject_pattern) "
                "VALUES (?,?,?)",
                (new_prov_id, m['sender_email'], m['subject_pattern'])
            )


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
        "  AND (p.config_id IS NULL OR c.status IN ('active','tested','public'))",
        (user_id,)
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
    users = get_db().execute(
        "SELECT u.id, u.username, u.email, u.is_admin, u.created_at, "
        "       COUNT(DISTINCT c.id) AS config_count "
        "FROM users u "
        "LEFT JOIN configurations c ON c.owner_id = u.id AND c.source_config_id IS NULL "
        "GROUP BY u.id ORDER BY u.username"
    ).fetchall()
    return render_template('admin/admin_users.html', users=users)


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
    db = get_db()
    db.execute(
        "UPDATE configurations SET status='public', updated_at=datetime('now') WHERE id=?",
        (config_id,)
    )
    # Clear sample_email from all providers for privacy
    db.execute("UPDATE providers SET sample_email=NULL WHERE config_id=?", (config_id,))
    db.execute(
        "INSERT INTO marketplace_reviews (config_id, reviewer_id, decision) VALUES (?,?,?)",
        (config_id, session['user_id'], 'approved')
    )
    db.commit()
    flash('Configuration approved and published.', 'success')
    return redirect(url_for('admin.admin_marketplace'))


@admin_bp.post('/admin/marketplace/<int:config_id>/reject')
@admin_required
def admin_marketplace_reject(config_id):
    note = request.form.get('note', '').strip() or None
    db   = get_db()
    db.execute(
        "UPDATE configurations SET status='tested', updated_at=datetime('now') WHERE id=?",
        (config_id,)
    )
    db.execute(
        "INSERT INTO marketplace_reviews (config_id, reviewer_id, decision, note) VALUES (?,?,?,?)",
        (config_id, session['user_id'], 'rejected', note)
    )
    db.commit()
    flash('Configuration rejected; owner can revise and resubmit.', 'success')
    return redirect(url_for('admin.admin_marketplace'))
