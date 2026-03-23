"""
noncey — admin Blueprint
Served under /noncey/ via the admin Apache2 VirtualHost.
Apache handles authentication; no auth layer is added here.
"""

import sqlite3

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


# ── Dashboard ─────────────────────────────────────────────────────────────────

@admin_bp.get('/')
@admin_bp.get('')
def dashboard():
    users = get_db().execute(
        "SELECT u.id, u.username, u.created_at, "
        "       COUNT(DISTINCT p.id)  AS provider_count, "
        "       COUNT(DISTINCT n.id)  AS active_nonce_count "
        "FROM   users u "
        "LEFT JOIN providers p ON p.user_id = u.id "
        "LEFT JOIN nonces n    ON n.user_id = u.id "
        "                      AND n.expires_at > datetime('now') "
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
        start  = request.form.get('nonce_start_marker', '').strip()
        end    = request.form.get('nonce_end_marker', '').strip() or None
        sample = request.form.get('sample_email', '').strip() or None

        if not tag or not start:
            flash('Tag and start marker are required.', 'error')
            return render_template('admin/provider_form.html', user=user, provider=None, matchers=[])

        try:
            db = get_db()
            db.execute(
                "INSERT INTO providers "
                "  (user_id, tag, nonce_start_marker, nonce_end_marker, sample_email) "
                "VALUES (?, ?, ?, ?, ?)",
                (user_id, tag, start, end, sample)
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash(f"Provider tag '{tag}' already exists for this user.", 'error')
            return render_template('admin/provider_form.html', user=user, provider=None, matchers=[])

        flash(f"Provider '{tag}' created.", 'success')
        return redirect(url_for('admin.provider_list', user_id=user_id))

    return render_template('admin/provider_form.html', user=user, provider=None, matchers=[])


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

    if request.method == 'POST':
        tag    = request.form.get('tag', '').strip()
        start  = request.form.get('nonce_start_marker', '').strip()
        end    = request.form.get('nonce_end_marker', '').strip() or None
        sample = request.form.get('sample_email', '').strip() or None

        if not tag or not start:
            flash('Tag and start marker are required.', 'error')
            return render_template('admin/provider_form.html',
                                   user=user, provider=provider, matchers=matchers)
        try:
            db.execute(
                "UPDATE providers "
                "SET tag=?, nonce_start_marker=?, nonce_end_marker=?, sample_email=? "
                "WHERE id=?",
                (tag, start, end, sample, provider_id)
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash(f"Provider tag '{tag}' already exists for this user.", 'error')
            return render_template('admin/provider_form.html',
                                   user=user, provider=provider, matchers=matchers)

        flash(f"Provider '{tag}' updated.", 'success')
        return redirect(url_for('admin.provider_list', user_id=user_id))

    return render_template('admin/provider_form.html',
                           user=user, provider=provider, matchers=matchers)


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

    sender  = request.form.get('sender_email', '').strip().lower() or None
    subject = request.form.get('subject_pattern', '').strip() or None

    if not sender and not subject:
        flash('At least one of sender email or subject pattern must be provided.', 'error')
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
