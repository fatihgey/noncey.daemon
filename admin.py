"""
noncey — admin Blueprint
Served under /noncey/ via the admin Apache2 VirtualHost.
Apache handles authentication; no auth layer is added here.
"""

import re
import sqlite3
from email.utils import parseaddr

import bcrypt
from flask import Blueprint, flash, redirect, render_template, request, url_for

from db import get_db
from provision import ProvisionError, validate_username

admin_bp = Blueprint(
    'admin', __name__,
    url_prefix='/noncey',
    template_folder='templates',
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_user(user_id: int):
    return get_db().execute(
        "SELECT id, username, created_at FROM users WHERE id = ?", (user_id,)
    ).fetchone()


def _get_provider(provider_id: int, user_id: int):
    return get_db().execute(
        "SELECT * FROM providers WHERE id = ? AND user_id = ?",
        (provider_id, user_id)
    ).fetchone()


def _derive_auto_markers(text: str, example_otp: str):
    """
    Given the source text and the known OTP value, derive start_marker and
    nonce_length so the daemon can reliably re-extract it without heuristics.
    Returns (start_marker, nonce_length) or ('', None) if not found.
    """
    if not example_otp or not text:
        return '', None
    idx = text.find(example_otp)
    if idx == -1:
        return '', None
    before    = text[:idx]
    line_start = before.rfind('\n') + 1
    start_marker = before[line_start:]
    return start_marker, len(example_otp)


# ── Dashboard ─────────────────────────────────────────────────────────────────

@admin_bp.get('/')
@admin_bp.get('')
def dashboard():
    users = get_db().execute(
        "SELECT u.id, u.username, u.created_at, "
        "       COUNT(DISTINCT p.id)   AS provider_count, "
        "       COUNT(DISTINCT n.id)   AS active_nonce_count, "
        "       COUNT(DISTINCT um.id)  AS unmatched_count "
        "FROM   users u "
        "LEFT JOIN providers p       ON p.user_id  = u.id "
        "LEFT JOIN nonces n          ON n.user_id  = u.id "
        "                            AND n.expires_at > datetime('now') "
        "LEFT JOIN unmatched_emails um ON um.user_id = u.id "
        "GROUP  BY u.id "
        "ORDER  BY u.username"
    ).fetchall()
    return render_template('admin/dashboard.html', users=users)


# ── User management ───────────────────────────────────────────────────────────

@admin_bp.route('/users/new', methods=['GET', 'POST'])
def user_new():
    if request.method == 'POST':
        username  = request.form.get('username', '').strip()
        password  = request.form.get('password', '')
        password2 = request.form.get('password2', '')

        try:
            validate_username(username)
        except ProvisionError as exc:
            flash(str(exc), 'error')
            return render_template('admin/user_new.html')

        if not password:
            flash('Password must not be empty.', 'error')
            return render_template('admin/user_new.html')
        if password != password2:
            flash('Passwords do not match.', 'error')
            return render_template('admin/user_new.html')

        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        try:
            db = get_db()
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, pw_hash)
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash(f"User '{username}' already exists.", 'error')
            return render_template('admin/user_new.html')

        flash(f"User '{username}' created.", 'success')
        return redirect(url_for('admin.dashboard'))

    return render_template('admin/user_new.html')


@admin_bp.route('/users/<int:user_id>/delete', methods=['GET', 'POST'])
def user_delete(user_id):
    user = _get_user(user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('admin.dashboard'))

    if request.method == 'POST':
        db = get_db()
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
        flash(f"User '{user['username']}' deleted.", 'success')
        return redirect(url_for('admin.dashboard'))

    return render_template('admin/user_delete.html', user=user)


@admin_bp.route('/users/<int:user_id>/password', methods=['GET', 'POST'])
def user_password(user_id):
    user = _get_user(user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('admin.dashboard'))

    if request.method == 'POST':
        password  = request.form.get('password', '')
        password2 = request.form.get('password2', '')

        if not password:
            flash('Password must not be empty.', 'error')
            return render_template('admin/user_password.html', user=user)
        if password != password2:
            flash('Passwords do not match.', 'error')
            return render_template('admin/user_password.html', user=user)

        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        db = get_db()
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (pw_hash, user_id))
        db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        db.commit()
        flash(f"Password updated for '{user['username']}'. All sessions invalidated.", 'success')
        return redirect(url_for('admin.dashboard'))

    return render_template('admin/user_password.html', user=user)


# ── Provider management ───────────────────────────────────────────────────────

@admin_bp.get('/users/<int:user_id>/providers')
def provider_list(user_id):
    user = _get_user(user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('admin.dashboard'))

    db        = get_db()
    providers = db.execute(
        "SELECT * FROM providers WHERE user_id = ? ORDER BY tag", (user_id,)
    ).fetchall()
    matchers  = {
        p['id']: db.execute(
            "SELECT * FROM provider_matchers WHERE provider_id = ?", (p['id'],)
        ).fetchall()
        for p in providers
    }
    return render_template('admin/providers.html',
                           user=user, providers=providers, matchers=matchers)


@admin_bp.route('/users/<int:user_id>/providers/new', methods=['GET', 'POST'])
def provider_new(user_id):
    user = _get_user(user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('admin.dashboard'))

    if request.method == 'POST':
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
                flash('Example OTP is required for auto extraction mode.', 'error')
                return render_template('admin/provider_form.html',
                                       user=user, provider=None, matchers=[], sample_sender=None)
            # Derive markers from sample email text + example OTP
            sample_text = sample or ''
            src_text = re.search(r'^Subject:\s*(.+)', sample_text, re.MULTILINE | re.IGNORECASE)
            body_text = sample_text  # use full sample for body source
            derive_from = src_text.group(1) if (source == 'subject' and src_text) else body_text
            start, length = _derive_auto_markers(derive_from, example_otp)
            if not start:
                flash('Example OTP not found in the sample email text.', 'error')
                return render_template('admin/provider_form.html',
                                       user=user, provider=None, matchers=[], sample_sender=None)
        else:
            start = request.form.get('nonce_start_marker', '').strip()

        if not tag:
            flash('Tag is required.', 'error')
            return render_template('admin/provider_form.html',
                                   user=user, provider=None, matchers=[], sample_sender=None)
        if mode != 'auto' and not start:
            flash('Start marker is required for this extraction mode.', 'error')
            return render_template('admin/provider_form.html',
                                   user=user, provider=None, matchers=[], sample_sender=None)

        try:
            db = get_db()
            db.execute(
                "INSERT INTO providers "
                "  (user_id, tag, extract_source, extract_mode, "
                "   nonce_start_marker, nonce_end_marker, nonce_length, sample_email) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (user_id, tag, source, mode, start, end, length, sample)
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash(f"Provider tag '{tag}' already exists for this user.", 'error')
            return render_template('admin/provider_form.html',
                                   user=user, provider=None, matchers=[], sample_sender=None)

        flash(f"Provider '{tag}' created.", 'success')
        return redirect(url_for('admin.provider_list', user_id=user_id))

    return render_template('admin/provider_form.html',
                           user=user, provider=None, matchers=[], sample_sender=None)


@admin_bp.route('/users/<int:user_id>/providers/<int:provider_id>/edit', methods=['GET', 'POST'])
def provider_edit(user_id, provider_id):
    user     = _get_user(user_id)
    provider = _get_provider(provider_id, user_id)
    if not user or not provider:
        flash('Not found.', 'error')
        return redirect(url_for('admin.provider_list', user_id=user_id))

    db       = get_db()
    matchers = db.execute(
        "SELECT * FROM provider_matchers WHERE provider_id = ?", (provider_id,)
    ).fetchall()

    # Extract sender address from sample_email for the "from sample" matcher option.
    sample_sender = None
    if provider['sample_email']:
        m = re.search(r'^From:\s*(.+)', provider['sample_email'],
                      re.MULTILINE | re.IGNORECASE)
        if m:
            _, addr = parseaddr(m.group(1).strip())
            sample_sender = addr.lower() if addr else None

    if request.method == 'POST':
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
                flash('Example OTP is required for auto extraction mode.', 'error')
                return render_template('admin/provider_form.html',
                                       user=user, provider=provider, matchers=matchers,
                                       sample_sender=sample_sender)
            sample_text = sample or ''
            src_text = re.search(r'^Subject:\s*(.+)', sample_text, re.MULTILINE | re.IGNORECASE)
            derive_from = src_text.group(1) if (source == 'subject' and src_text) else sample_text
            start, length = _derive_auto_markers(derive_from, example_otp)
            if not start:
                flash('Example OTP not found in the sample email text.', 'error')
                return render_template('admin/provider_form.html',
                                       user=user, provider=provider, matchers=matchers,
                                       sample_sender=sample_sender)
        else:
            start = request.form.get('nonce_start_marker', '').strip()

        if not tag:
            flash('Tag is required.', 'error')
            return render_template('admin/provider_form.html',
                                   user=user, provider=provider, matchers=matchers,
                                   sample_sender=sample_sender)
        if mode != 'auto' and not start:
            flash('Start marker is required for this extraction mode.', 'error')
            return render_template('admin/provider_form.html',
                                   user=user, provider=provider, matchers=matchers,
                                   sample_sender=sample_sender)
        try:
            db.execute(
                "UPDATE providers "
                "SET tag=?, extract_source=?, extract_mode=?, "
                "    nonce_start_marker=?, nonce_end_marker=?, nonce_length=?, sample_email=? "
                "WHERE id=?",
                (tag, source, mode, start, end, length, sample, provider_id)
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash(f"Provider tag '{tag}' already exists for this user.", 'error')
            return render_template('admin/provider_form.html',
                                   user=user, provider=provider, matchers=matchers,
                                   sample_sender=sample_sender)

        flash(f"Provider '{tag}' updated.", 'success')
        return redirect(url_for('admin.provider_list', user_id=user_id))

    return render_template('admin/provider_form.html',
                           user=user, provider=provider, matchers=matchers,
                           sample_sender=sample_sender)


@admin_bp.route('/users/<int:user_id>/providers/<int:provider_id>/delete', methods=['GET', 'POST'])
def provider_delete(user_id, provider_id):
    user     = _get_user(user_id)
    provider = _get_provider(provider_id, user_id)
    if not user or not provider:
        flash('Not found.', 'error')
        return redirect(url_for('admin.provider_list', user_id=user_id))

    if request.method == 'POST':
        db = get_db()
        db.execute("DELETE FROM providers WHERE id = ?", (provider_id,))
        db.commit()
        flash(f"Provider '{provider['tag']}' deleted.", 'success')
        return redirect(url_for('admin.provider_list', user_id=user_id))

    return render_template('admin/provider_delete.html', user=user, provider=provider)


# ── Matcher management ────────────────────────────────────────────────────────

@admin_bp.post('/users/<int:user_id>/providers/<int:provider_id>/matchers/new')
def matcher_new(user_id, provider_id):
    provider = _get_provider(provider_id, user_id)
    if not provider:
        flash('Provider not found.', 'error')
        return redirect(url_for('admin.provider_list', user_id=user_id))

    # ── C: sender ──────────────────────────────────────────────────────────────
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
    else:  # 'any'
        sender = None

    # ── D: subject ─────────────────────────────────────────────────────────────
    subject_mode = request.form.get('subject_mode', 'any')
    if subject_mode == 'contains':
        text = request.form.get('subject_text', '').strip()
        subject = re.escape(text) if text else None
    elif subject_mode == 'regex':
        subject = request.form.get('subject_regex', '').strip() or None
    else:  # 'any'
        subject = None

    if not sender and not subject:
        flash('At least one of sender or subject must be set (not both "any").', 'error')
        return redirect(url_for('admin.provider_edit',
                                user_id=user_id, provider_id=provider_id))

    db = get_db()
    db.execute(
        "INSERT INTO provider_matchers (provider_id, sender_email, subject_pattern) "
        "VALUES (?, ?, ?)",
        (provider_id, sender, subject)
    )
    db.commit()
    flash('Matcher added.', 'success')
    return redirect(url_for('admin.provider_edit',
                            user_id=user_id, provider_id=provider_id))


@admin_bp.post('/users/<int:user_id>/providers/<int:provider_id>/matchers/<int:matcher_id>/delete')
def matcher_delete(user_id, provider_id, matcher_id):
    db  = get_db()
    cur = db.execute(
        "DELETE FROM provider_matchers WHERE id = ? AND provider_id = ?",
        (matcher_id, provider_id)
    )
    db.commit()
    flash('Matcher removed.' if cur.rowcount else 'Matcher not found.', 'success')
    return redirect(url_for('admin.provider_edit',
                            user_id=user_id, provider_id=provider_id))


# ── Unmatched emails ───────────────────────────────────────────────────────────

@admin_bp.get('/users/<int:user_id>/unmatched')
def unmatched_list(user_id):
    user = _get_user(user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('admin.dashboard'))
    rows = get_db().execute(
        "SELECT id, sender, subject, received_at "
        "FROM   unmatched_emails "
        "WHERE  user_id = ? "
        "ORDER  BY received_at DESC",
        (user_id,)
    ).fetchall()
    return render_template('admin/unmatched_list.html', user=user, emails=rows)


@admin_bp.route('/unmatched/<int:email_id>', methods=['GET', 'POST'])
def unmatched_detail(email_id):
    db  = get_db()
    row = db.execute(
        "SELECT e.*, u.id AS user_id, u.username "
        "FROM   unmatched_emails e "
        "JOIN   users u ON u.id = e.user_id "
        "WHERE  e.id = ?", (email_id,)
    ).fetchone()
    if not row:
        flash('Not found.', 'error')
        return redirect(url_for('admin.dashboard'))

    if request.method == 'POST':
        action = request.form.get('action', '')

        if action == 'promote':
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
                    return render_template('admin/unmatched_detail.html', row=row)
                derive_from = row['subject'] if source == 'subject' else (row['body_text'] or '')
                start, length = _derive_auto_markers(derive_from, example_otp)
                if not start:
                    flash('Example OTP not found in the email text.', 'error')
                    return render_template('admin/unmatched_detail.html', row=row)
            else:
                start = request.form.get('nonce_start_marker', '').strip()

            # ── C: sender ──────────────────────────────────────────────────────
            sender_mode = request.form.get('sender_mode', 'sample')
            if sender_mode == 'sample':
                sender = row['sender'] or None
            elif sender_mode == 'fwd':
                sender = row['fwd_sender'] or None
            elif sender_mode == 'custom':
                sender = request.form.get('sender_custom', '').strip().lower() or None
            else:  # 'any'
                sender = None

            # ── D: subject ─────────────────────────────────────────────────────
            subject_mode = request.form.get('subject_mode', 'any')
            if subject_mode == 'contains':
                text = request.form.get('subject_text', '').strip()
                subject_pattern = re.escape(text) if text else None
            elif subject_mode == 'regex':
                subject_pattern = request.form.get('subject_regex', '').strip() or None
            else:  # 'any'
                subject_pattern = None

            if not tag:
                flash('Tag is required.', 'error')
                return render_template('admin/unmatched_detail.html', row=row)
            if mode != 'auto' and not start:
                flash('Start marker is required for this extraction mode.', 'error')
                return render_template('admin/unmatched_detail.html', row=row)

            user_id = row['user_id']
            try:
                db.execute(
                    "INSERT INTO providers "
                    "  (user_id, tag, extract_source, extract_mode, "
                    "   nonce_start_marker, nonce_end_marker, nonce_length) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (user_id, tag, source, mode, start, end, length)
                )
                provider_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
                db.execute(
                    "INSERT INTO provider_matchers "
                    "  (provider_id, sender_email, subject_pattern) "
                    "VALUES (?, ?, ?)",
                    (provider_id, sender, subject_pattern)
                )
                db.execute("DELETE FROM unmatched_emails WHERE id = ?", (email_id,))
                db.commit()
            except sqlite3.IntegrityError:
                flash(f"Provider tag '{tag}' already exists for this user.", 'error')
                return render_template('admin/unmatched_detail.html', row=row)

            flash(f"Provider '{tag}' created.", 'success')
            return redirect(url_for('admin.provider_edit',
                                    user_id=user_id, provider_id=provider_id))

    return render_template('admin/unmatched_detail.html', row=row)


@admin_bp.post('/unmatched/<int:email_id>/dismiss')
def unmatched_dismiss(email_id):
    db  = get_db()
    row = db.execute(
        "SELECT user_id FROM unmatched_emails WHERE id = ?", (email_id,)
    ).fetchone()
    db.execute("DELETE FROM unmatched_emails WHERE id = ?", (email_id,))
    db.commit()
    flash('Email dismissed.', 'success')
    user_id = row['user_id'] if row else None
    if user_id:
        return redirect(url_for('admin.unmatched_list', user_id=user_id))
    return redirect(url_for('admin.dashboard'))
