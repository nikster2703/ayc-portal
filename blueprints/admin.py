"""
AYC Portal — Admin blueprint.
Routes:
  /api/settings, /api/admin/branding/*
  /api/admin/users/*
  /api/admin/staff-roles/*
  /api/admin/permissions, /api/admin/roles/*
  /api/tags, /api/admin/tags/*
  /api/members/<id>/tags/*
  /api/admin/member-types/*, /api/admin/field-definitions/*
  /api/admin/logs/*, /api/admin/maintenance/*
  /api/admin/import/*
  /api/register/notes/*  (session notes)
"""

import csv as _csv_mod
import glob
import json
import os
import re as _re
import shutil
import sqlcipher3 as sqlite3
import tempfile
import uuid as _uuid_mod
from datetime import datetime

import bcrypt
from flask import Blueprint, Response, current_app, g, jsonify, request, send_file, session
from werkzeug.utils import secure_filename

from config import (
    BRANDING_DIR, CLUB_SHORT_NAME, DATABASE, INSTANCE_DIR, LOG_DIR,
    ROLE_DISPLAY_NAMES,
)
from extensions import csrf
from helpers import (
    get_db, log_action, login_required, permission_required, has_permission,
    _assigned_session, _connect_db, _validate_hex_colour, _invalidate_brand_cache,
    get_brand_settings, get_valid_session_names, validate_password,
)

bp = Blueprint('admin', __name__)

ALLOWED_LOGO_EXTENSIONS = {'png', 'jpg', 'jpeg', 'svg', 'webp', 'gif'}


# ── Settings ──────────────────────────────────────────────────────────────────

@bp.route('/api/settings')
@permission_required('admin.settings')
def api_settings_get():
    """Return all settings as a key/value dict."""
    db   = get_db()
    rows = db.execute('SELECT key, value FROM settings').fetchall()
    return jsonify({r['key']: r['value'] for r in rows})


@bp.route('/api/settings', methods=['POST'])
@permission_required('admin.settings')
def api_settings_save():
    """Save one or more settings.
    v8.0: alert rule thresholds are now per-rule in alert_rules.
    ALLOWED_KEYS is empty — extend here when new generic settings are needed."""
    data = request.get_json() or {}
    ALLOWED_KEYS = set()   # No generic settings require saving via this endpoint post-v8.0
    db   = get_db()
    saved = {}
    for key, value in data.items():
        if key not in ALLOWED_KEYS:
            continue
        db.execute(
            'INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, datetime("now"), ?)'
            ' ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at,'
            ' updated_by = excluded.updated_by',
            (key, str(value), session['user_id'])
        )
        saved[key] = value
    db.commit()
    if saved:
        log_action('update_settings', 'settings', None, {'changes': saved})
    return jsonify({'success': True})


# ── Branding ──────────────────────────────────────────────────────────────────

@bp.route('/api/admin/branding')
@permission_required('admin.settings')
def api_branding_get():
    brand = get_brand_settings()
    return jsonify({
        'accent':     brand.get('brand_accent', '#0096b4'),
        'nav_style':  brand.get('brand_nav_style', 'dark'),
        'club_name':  brand.get('brand_club_name', ''),
        'short_name': brand.get('brand_short_name', ''),
        'has_logo':   bool(brand.get('brand_logo_file')),
    })


@bp.route('/api/admin/branding', methods=['POST'])
@permission_required('admin.settings')
def api_branding_save():
    data    = request.get_json() or {}
    updates = {}

    if 'accent' in data:
        v = str(data['accent']).strip()
        if not _re.match(r'^#[0-9a-fA-F]{6}$', v):
            return jsonify({'error': 'accent must be a 6-digit hex colour e.g. #ff5500'}), 400
        updates['brand_accent'] = v

    if 'nav_style' in data:
        v = str(data['nav_style']).strip()
        if v not in ('dark', 'accent', 'white'):
            return jsonify({'error': 'nav_style must be dark, accent or white'}), 400
        updates['brand_nav_style'] = v

    if 'club_name' in data:
        updates['brand_club_name'] = str(data['club_name']).strip()[:120]

    if 'short_name' in data:
        updates['brand_short_name'] = str(data['short_name']).strip()[:30]

    if not updates:
        return jsonify({'success': True, 'message': 'Nothing to update'})

    db = get_db()
    for key, val in updates.items():
        db.execute(
            'INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, datetime("now"), ?)'
            ' ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at,'
            ' updated_by=excluded.updated_by',
            (key, val, session['user_id'])
        )
    db.commit()
    _invalidate_brand_cache()
    log_action('update_branding', 'settings', None, updates)
    return jsonify({'success': True})


@bp.route('/api/admin/branding/logo', methods=['POST'])
@permission_required('admin.settings')
def api_branding_logo_upload():
    if 'logo' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    f = request.files['logo']
    if not f.filename:
        return jsonify({'error': 'No file selected'}), 400

    ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else ''
    if ext not in ALLOWED_LOGO_EXTENSIONS:
        return jsonify({'error': f'File type .{ext} not allowed — use PNG, JPG, SVG or WebP'}), 400

    filename  = f'logo.{ext}'
    save_path = os.path.join(BRANDING_DIR, filename)

    for old in os.listdir(BRANDING_DIR):
        if old.startswith('logo.'):
            try:
                os.remove(os.path.join(BRANDING_DIR, old))
            except OSError:
                pass

    f.save(save_path)
    db = get_db()
    db.execute(
        'INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, datetime("now"), ?)'
        ' ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at,'
        ' updated_by=excluded.updated_by',
        ('brand_logo_file', filename, session['user_id'])
    )
    db.commit()
    _invalidate_brand_cache()
    log_action('upload_branding_logo', 'settings', None, {'filename': filename})
    return jsonify({'success': True, 'filename': filename})


@bp.route('/api/admin/branding/logo', methods=['DELETE'])
@permission_required('admin.settings')
def api_branding_logo_delete():
    brand    = get_brand_settings()
    filename = brand.get('brand_logo_file', '')
    if filename:
        path = os.path.join(BRANDING_DIR, os.path.basename(filename))
        try:
            if os.path.isfile(path):
                os.remove(path)
        except OSError:
            pass

    db = get_db()
    db.execute(
        'INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, datetime("now"), ?)'
        ' ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at,'
        ' updated_by=excluded.updated_by',
        ('brand_logo_file', '', session['user_id'])
    )
    db.commit()
    _invalidate_brand_cache()
    log_action('delete_branding_logo', 'settings', None, {})
    return jsonify({'success': True})


# ── Users CRUD ────────────────────────────────────────────────────────────────

@bp.route('/api/admin/users')
@permission_required('users.view')
def api_users_list():
    db     = get_db()
    scoped = _assigned_session()
    if scoped is not None:
        users = db.execute(
            'SELECT id, username, email, role, session_assigned, active, '
            'created_at, last_login FROM users '
            "WHERE role != 'admin' AND session_assigned = ? ORDER BY username",
            (scoped,)
        ).fetchall()
    else:
        users = db.execute(
            'SELECT id, username, email, role, session_assigned, active, '
            'created_at, last_login FROM users ORDER BY username'
        ).fetchall()
    return jsonify([dict(u) for u in users])


@bp.route('/api/admin/users', methods=['POST'])
@permission_required('users.create')
def api_users_create():
    data     = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    role     = data.get('role', 'readonly')
    email    = data.get('email', '').strip()
    sess     = data.get('session_assigned', '')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    pw_error = validate_password(password)
    if pw_error:
        return jsonify({'error': pw_error}), 400

    db              = get_db()
    target_role_row = db.execute('SELECT id, permissions FROM roles WHERE name = ?', (role,)).fetchone()
    if not target_role_row:
        return jsonify({'error': 'Invalid role'}), 400

    target_perms = json.loads(target_role_row['permissions'])
    if 'users.create.admin' in target_perms and not has_permission('users.create.admin'):
        return jsonify({'error': 'You do not have permission to assign this role'}), 403

    if 'admin.maintenance' not in target_perms and not sess:
        return jsonify({'error': 'A session must be assigned for non-admin users'}), 400
    if sess and sess not in get_valid_session_names():
        return jsonify({'error': 'Invalid session'}), 400

    scoped = _assigned_session()
    if scoped is not None and sess != scoped:
        return jsonify({'error': 'You can only create users for your own session'}), 403

    pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    try:
        db.execute(
            'INSERT INTO users (username, email, password_hash, role, role_id, session_assigned)'
            ' VALUES (?,?,?,?,?,?)',
            (username, email, pw_hash, role, target_role_row['id'], sess)
        )
        db.commit()
        log_action('create_user', 'users', None,
                   {'username': username, 'role': role, 'created_by': session.get('username')})
        return jsonify({'success': True})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 409


@bp.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@permission_required('users.edit')
def api_users_update(user_id):
    data    = request.get_json() or {}
    db      = get_db()
    updates = []
    params  = []

    if user_id == session['user_id'] and data.get('active') is False:
        return jsonify({'error': 'You cannot deactivate your own account'}), 400

    before_row = db.execute(
        'SELECT username, email, role, session_assigned, active FROM users WHERE id = ?', (user_id,)
    ).fetchone()

    if 'role' in data:
        target_role_row = db.execute(
            'SELECT id, permissions FROM roles WHERE name = ?', (data['role'],)
        ).fetchone()
        if not target_role_row:
            return jsonify({'error': 'Invalid role'}), 400
        target_perms = json.loads(target_role_row['permissions'])
        if 'users.create.admin' in target_perms and not has_permission('users.create.admin'):
            return jsonify({'error': 'You do not have permission to assign this role'}), 403

    scoped = _assigned_session()
    if scoped is not None:
        target = db.execute('SELECT role, session_assigned FROM users WHERE id = ?', (user_id,)).fetchone()
        if not target or target['role'] == 'admin':
            return jsonify({'error': 'Forbidden'}), 403
        if target['session_assigned'] != scoped:
            return jsonify({'error': 'You can only manage users in your own session'}), 403
        if 'session_assigned' in data and data['session_assigned'] != scoped:
            return jsonify({'error': 'You cannot move a user to a different session'}), 403

    if 'email' in data:
        updates.append('email = ?'); params.append(data['email'])

    if 'role' in data:
        target_role_row = db.execute('SELECT id FROM roles WHERE name = ?', (data['role'],)).fetchone()
        updates.append('role = ?'); params.append(data['role'])
        if target_role_row:
            updates.append('role_id = ?'); params.append(target_role_row['id'])

    if 'session_assigned' in data:
        updates.append('session_assigned = ?'); params.append(data['session_assigned'])

    if 'active' in data:
        updates.append('active = ?'); params.append(1 if data['active'] else 0)

    if 'password' in data and data['password']:
        pw_error = validate_password(data['password'])
        if pw_error:
            return jsonify({'error': pw_error}), 400
        pw_hash = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        updates.append('password_hash = ?'); params.append(pw_hash)

    if updates:
        params.append(user_id)
        db.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)
        db.commit()

        if before_row:
            field_changes = {}
            if 'email' in data and data.get('email') != before_row['email']:
                field_changes['email'] = {'from': before_row['email'], 'to': data['email']}
            if 'role' in data and data['role'] != before_row['role']:
                field_changes['role'] = {'from': before_row['role'], 'to': data['role']}
            if 'session_assigned' in data and data.get('session_assigned') != before_row['session_assigned']:
                field_changes['session_assigned'] = {'from': before_row['session_assigned'], 'to': data['session_assigned']}
            if 'active' in data:
                new_active = 1 if data['active'] else 0
                if new_active != before_row['active']:
                    field_changes['active'] = {'from': bool(before_row['active']), 'to': bool(new_active)}
            log_action('update_user', 'users', user_id, {
                'username':       before_row['username'],
                'changes':        field_changes,
                'password_reset': True if ('password' in data and data['password']) else None,
            })

    return jsonify({'success': True})


@bp.route('/api/admin/users/<int:user_id>/permanent', methods=['DELETE'])
@permission_required('users.delete')
def api_users_permanent_delete(user_id):
    """Permanently delete a portal user account. Requires {"confirm_username": "<username>"}."""
    data = request.get_json() or {}
    db   = get_db()

    if user_id == session['user_id']:
        return jsonify({'error': 'You cannot delete your own account'}), 400

    user = db.execute('SELECT id, username FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    confirm = (data.get('confirm_username') or '').strip().lower()
    if confirm != user['username'].lower():
        return jsonify({'error': 'Username confirmation does not match'}), 400

    username = user['username']
    try:
        db.execute('BEGIN')
        db.execute('UPDATE members               SET updated_by = NULL WHERE updated_by = ?', (user_id,))
        db.execute('UPDATE pending_registrations SET reviewed_by = NULL WHERE reviewed_by = ?', (user_id,))
        db.execute('UPDATE documents             SET uploaded_by = NULL WHERE uploaded_by = ?', (user_id,))
        db.execute('UPDATE email_templates       SET created_by  = NULL WHERE created_by  = ?', (user_id,))
        db.execute('UPDATE mailshot_log          SET sent_by     = NULL WHERE sent_by     = ?', (user_id,))
        db.execute('UPDATE attendance            SET recorded_by = NULL WHERE recorded_by = ?', (user_id,))
        db.execute('UPDATE term_sessions         SET created_by  = NULL WHERE created_by  = ?', (user_id,))
        db.execute('UPDATE session_activities    SET added_by    = NULL WHERE added_by    = ?', (user_id,))
        db.execute('UPDATE audit_log             SET user_id     = NULL WHERE user_id     = ?', (user_id,))
        db.execute('DELETE FROM users WHERE id = ?', (user_id,))
        db.execute(
            'INSERT INTO audit_log (user_id, action, table_name, record_id, details, ip_address)'
            ' VALUES (?, ?, ?, ?, ?, ?)',
            (
                session['user_id'], 'delete_user', 'users', user_id,
                json.dumps({'username': username}),
                request.remote_addr,
            )
        )
        db.execute('COMMIT')
    except Exception as exc:
        db.execute('ROLLBACK')
        current_app.logger.error(f'Permanent user delete failed (username={username}): {exc}')
        return jsonify({'error': 'Deletion failed and was rolled back. Check server logs for details.'}), 500

    return jsonify({'success': True, 'deleted': username})


# ── Staff roles admin CRUD ────────────────────────────────────────────────────

@bp.route('/api/admin/staff-roles', methods=['GET'])
@permission_required('admin.settings')
def api_admin_staff_roles_get():
    db   = get_db()
    rows = db.execute(
        'SELECT id, name, active, display_order FROM staff_roles ORDER BY display_order, name'
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route('/api/admin/staff-roles', methods=['POST'])
@permission_required('admin.settings')
def api_admin_staff_roles_create():
    data = request.get_json() or {}
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'error': 'name is required'}), 400

    db        = get_db()
    max_order = db.execute('SELECT COALESCE(MAX(display_order), -1) FROM staff_roles').fetchone()[0]
    try:
        cur = db.execute(
            'INSERT INTO staff_roles (name, active, display_order) VALUES (?,1,?)',
            (name, max_order + 1)
        )
        db.commit()
        log_action('create_staff_role', 'staff_roles', cur.lastrowid, {'name': name})
        row = db.execute('SELECT * FROM staff_roles WHERE id = ?', (cur.lastrowid,)).fetchone()
        return jsonify(dict(row)), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': f'A role named "{name}" already exists'}), 409


@bp.route('/api/admin/staff-roles/<int:role_id>', methods=['PUT'])
@permission_required('admin.settings')
def api_admin_staff_roles_update(role_id):
    data    = request.get_json() or {}
    db      = get_db()
    current = db.execute('SELECT * FROM staff_roles WHERE id = ?', (role_id,)).fetchone()
    if not current:
        return jsonify({'error': 'Role not found'}), 404

    name   = data.get('name', current['name']).strip()
    active = int(data.get('active', current['active']))

    if not name:
        return jsonify({'error': 'name is required'}), 400

    if not active:
        active_count = db.execute(
            'SELECT COUNT(*) FROM staff_roles WHERE active = 1 AND id != ?', (role_id,)
        ).fetchone()[0]
        if active_count == 0:
            return jsonify({'error': 'Cannot deactivate the only active staff role'}), 400

    try:
        db.execute('UPDATE staff_roles SET name = ?, active = ? WHERE id = ?', (name, active, role_id))
        db.commit()
        log_action('update_staff_role', 'staff_roles', role_id, {'name': name, 'active': active})
        return jsonify(dict(db.execute('SELECT * FROM staff_roles WHERE id = ?', (role_id,)).fetchone()))
    except sqlite3.IntegrityError:
        return jsonify({'error': f'A role named "{name}" already exists'}), 409


@bp.route('/api/admin/staff-roles/reorder', methods=['POST'])
@permission_required('admin.settings')
def api_admin_staff_roles_reorder():
    items = request.get_json() or []
    db    = get_db()
    for item in items:
        db.execute('UPDATE staff_roles SET display_order = ? WHERE id = ?',
                   (item.get('display_order', 0), item.get('id')))
    db.commit()
    return jsonify({'success': True})


# ── Permissions + Roles CRUD ──────────────────────────────────────────────────

@bp.route('/api/admin/permissions')
@permission_required('admin.settings')
def api_permissions_list():
    db   = get_db()
    rows = db.execute(
        'SELECT code, name, description, category FROM permissions ORDER BY category, code'
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route('/api/admin/roles')
@permission_required('admin.settings')
def api_roles_list():
    db   = get_db()
    rows = db.execute(
        'SELECT id, name, display_name, is_default, permissions, created_at FROM roles ORDER BY name'
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        if not d.get('display_name'):
            d['display_name'] = ROLE_DISPLAY_NAMES.get(d['name'], d['name'])
        try:
            d['permissions'] = json.loads(d['permissions'])
        except (TypeError, ValueError):
            d['permissions'] = []
        result.append(d)
    return jsonify(result)


@bp.route('/api/admin/roles', methods=['POST'])
@permission_required('admin.settings')
def api_roles_create():
    data         = request.get_json() or {}
    name         = data.get('name', '').strip()
    display_name = data.get('display_name', '').strip() or name
    perms        = data.get('permissions', [])

    if not name:
        return jsonify({'error': 'Role name is required'}), 400
    if not isinstance(perms, list):
        return jsonify({'error': 'permissions must be a list'}), 400

    db          = get_db()
    valid_codes = {r['code'] for r in db.execute('SELECT code FROM permissions').fetchall()}
    bad = [p for p in perms if p not in valid_codes]
    if bad:
        return jsonify({'error': f'Unknown permission code(s): {", ".join(bad)}'}), 400

    if 'users.create.admin' in perms and not has_permission('users.create.admin'):
        return jsonify({'error': 'You do not have permission to assign users.create.admin'}), 403

    try:
        cur = db.execute(
            'INSERT INTO roles (name, display_name, permissions, is_default) VALUES (?,?,?,0)',
            (name, display_name, json.dumps(perms))
        )
        db.commit()
        log_action('create_role', 'roles', cur.lastrowid, {'name': name, 'permissions': perms})
        row = db.execute(
            'SELECT id, name, display_name, is_default, permissions, created_at FROM roles WHERE id = ?',
            (cur.lastrowid,)
        ).fetchone()
        d = dict(row); d['permissions'] = json.loads(d['permissions'])
        return jsonify(d), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': f'A role named "{name}" already exists'}), 409


@bp.route('/api/admin/roles/<int:role_id>', methods=['PUT'])
@permission_required('admin.settings')
def api_roles_update(role_id):
    data  = request.get_json() or {}
    db    = get_db()
    role  = db.execute('SELECT * FROM roles WHERE id = ?', (role_id,)).fetchone()
    if not role:
        return jsonify({'error': 'Role not found'}), 404

    name         = data.get('name', role['name']).strip()
    display_name = data.get('display_name', role['display_name'] or role['name']).strip() or name
    perms        = data.get('permissions', json.loads(role['permissions']))

    if not name:
        return jsonify({'error': 'Role name is required'}), 400
    if not isinstance(perms, list):
        return jsonify({'error': 'permissions must be a list'}), 400

    valid_codes = {r['code'] for r in db.execute('SELECT code FROM permissions').fetchall()}
    bad = [p for p in perms if p not in valid_codes]
    if bad:
        return jsonify({'error': f'Unknown permission code(s): {", ".join(bad)}'}), 400

    old_perms = json.loads(role['permissions'])
    if 'users.create.admin' in perms and 'users.create.admin' not in old_perms:
        if not has_permission('users.create.admin'):
            return jsonify({'error': 'You do not have permission to assign users.create.admin'}), 403

    try:
        db.execute(
            'UPDATE roles SET name = ?, display_name = ?, permissions = ? WHERE id = ?',
            (name, display_name, json.dumps(perms), role_id)
        )
        db.commit()
        log_action('update_role', 'roles', role_id,
                   {'name': name, 'display_name': display_name, 'permissions': perms})
    except sqlite3.IntegrityError:
        return jsonify({'error': f'A role named "{name}" already exists'}), 409

    row = db.execute(
        'SELECT id, name, display_name, is_default, permissions, created_at FROM roles WHERE id = ?',
        (role_id,)
    ).fetchone()
    d = dict(row); d['permissions'] = json.loads(d['permissions'])
    return jsonify(d)


@bp.route('/api/admin/roles/<int:role_id>', methods=['DELETE'])
@permission_required('admin.settings')
def api_roles_delete(role_id):
    db   = get_db()
    role = db.execute('SELECT * FROM roles WHERE id = ?', (role_id,)).fetchone()
    if not role:
        return jsonify({'error': 'Role not found'}), 404

    if role['is_default']:
        return jsonify({'error': 'Default roles cannot be deleted'}), 400

    user_count = db.execute('SELECT COUNT(*) FROM users WHERE role_id = ?', (role_id,)).fetchone()[0]
    if user_count:
        return jsonify({'error': f'Cannot delete — {user_count} user(s) are assigned to this role'}), 400

    db.execute('DELETE FROM roles WHERE id = ?', (role_id,))
    db.commit()
    log_action('delete_role', 'roles', role_id, {'name': role['name']})
    return jsonify({'success': True})


# ── Tag definitions CRUD ──────────────────────────────────────────────────────

@bp.route('/api/tags')
@permission_required('members.view')
def api_tags_public():
    db   = get_db()
    rows = db.execute(
        'SELECT id, name, category, icon, colour FROM tag_definitions '
        'WHERE active = 1 ORDER BY sort_order, name'
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route('/api/admin/tags')
@permission_required('admin.settings')
def api_tags_list():
    db   = get_db()
    rows = db.execute(
        'SELECT id, name, category, icon, colour, active, sort_order '
        'FROM tag_definitions ORDER BY sort_order, name'
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route('/api/admin/tags', methods=['POST'])
@permission_required('admin.settings')
def api_tags_create():
    data            = request.get_json() or {}
    name            = data.get('name', '').strip()
    category        = data.get('category', 'General').strip() or 'General'
    icon            = data.get('icon', '🏷').strip() or '🏷'
    colour, col_err = _validate_hex_colour(data.get('colour', ''), '#3b82f6')

    if not name:
        return jsonify({'error': 'name is required'}), 400
    if col_err:
        return jsonify({'error': col_err}), 400

    db        = get_db()
    max_order = db.execute('SELECT COALESCE(MAX(sort_order), -1) FROM tag_definitions').fetchone()[0]
    try:
        cur = db.execute(
            'INSERT INTO tag_definitions (name, category, icon, colour, active, sort_order) VALUES (?,?,?,?,1,?)',
            (name, category, icon, colour, max_order + 1)
        )
        db.commit()
        log_action('create_tag', 'tag_definitions', cur.lastrowid, {'name': name})
        return jsonify(dict(db.execute('SELECT * FROM tag_definitions WHERE id = ?', (cur.lastrowid,)).fetchone())), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': f'A tag named "{name}" already exists'}), 409


@bp.route('/api/admin/tags/<int:tag_id>', methods=['PUT'])
@permission_required('admin.settings')
def api_tags_update(tag_id):
    db  = get_db()
    row = db.execute('SELECT * FROM tag_definitions WHERE id = ?', (tag_id,)).fetchone()
    if not row:
        return jsonify({'error': 'Tag not found'}), 404

    data            = request.get_json() or {}
    name            = data.get('name',     row['name']).strip()
    category        = data.get('category', row['category']).strip() or 'General'
    icon            = data.get('icon',     row['icon']).strip() or '🏷'
    colour, col_err = _validate_hex_colour(data.get('colour', row['colour']), row['colour'])
    active          = int(data.get('active', row['active']))

    if not name:
        return jsonify({'error': 'name is required'}), 400
    if col_err:
        return jsonify({'error': col_err}), 400
    try:
        db.execute(
            'UPDATE tag_definitions SET name=?, category=?, icon=?, colour=?, active=? WHERE id=?',
            (name, category, icon, colour, active, tag_id)
        )
        db.commit()
        log_action('update_tag', 'tag_definitions', tag_id, {'name': name, 'active': active})
        return jsonify(dict(db.execute('SELECT * FROM tag_definitions WHERE id = ?', (tag_id,)).fetchone()))
    except sqlite3.IntegrityError:
        return jsonify({'error': f'A tag named "{name}" already exists'}), 409


@bp.route('/api/admin/tags/reorder', methods=['POST'])
@permission_required('admin.settings')
def api_tags_reorder():
    items = request.get_json() or []
    db    = get_db()
    for item in items:
        db.execute('UPDATE tag_definitions SET sort_order = ? WHERE id = ?',
                   (item.get('sort_order', 0), item.get('id')))
    db.commit()
    return jsonify({'success': True})


# ── Member types CRUD ─────────────────────────────────────────────────────────

def _slugify(text):
    text = text.lower().strip()
    text = _re.sub(r'[^\w\s-]', '', text)
    text = _re.sub(r'[\s_]+', '-', text)
    text = _re.sub(r'-+', '-', text)
    return text.strip('-')


@bp.route('/api/admin/member-types', methods=['GET'])
@permission_required('admin.settings')
def api_admin_member_types_list():
    db   = get_db()
    rows = db.execute('''
        SELECT mt.*,
               (SELECT COUNT(*) FROM member_type_fields mtf WHERE mtf.member_type_id = mt.id) AS field_count
        FROM   member_types mt
        ORDER  BY mt.sort_order, mt.name
    ''').fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route('/api/admin/member-types', methods=['POST'])
@permission_required('admin.settings')
def api_admin_member_types_create():
    data                = request.get_json() or {}
    name                = data.get('name', '').strip()
    slug                = data.get('slug', '').strip() or _slugify(name)
    icon                = data.get('icon', '👤').strip() or '👤'
    colour, col_err     = _validate_hex_colour(data.get('colour', ''), '#1b2d4f')
    description         = data.get('description', '').strip() or None
    public_registration = int(data.get('public_registration', 0))

    if not name:
        return jsonify({'error': 'name is required'}), 400
    if not slug:
        return jsonify({'error': 'slug is required'}), 400
    if col_err:
        return jsonify({'error': col_err}), 400

    db        = get_db()
    max_order = db.execute('SELECT COALESCE(MAX(sort_order), -1) FROM member_types').fetchone()[0]
    try:
        cur = db.execute(
            '''INSERT INTO member_types
               (name, slug, icon, colour, description, public_registration, sort_order)
               VALUES (?,?,?,?,?,?,?)''',
            (name, slug, icon, colour, description, public_registration, max_order + 1),
        )
        db.commit()
        log_action('create_member_type', 'member_types', cur.lastrowid, {'name': name, 'slug': slug})
        row = db.execute(
            '''SELECT mt.*, (SELECT COUNT(*) FROM member_type_fields mtf WHERE mtf.member_type_id = mt.id) AS field_count
               FROM member_types mt WHERE mt.id = ?''', (cur.lastrowid,)
        ).fetchone()
        return jsonify(dict(row)), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'A member type with that name or slug already exists'}), 409


@bp.route('/api/admin/member-types/<int:type_id>', methods=['PUT'])
@permission_required('admin.settings')
def api_admin_member_types_update(type_id):
    data    = request.get_json() or {}
    db      = get_db()
    current = db.execute('SELECT * FROM member_types WHERE id = ?', (type_id,)).fetchone()
    if not current:
        return jsonify({'error': 'Member type not found'}), 404

    name                = (data.get('name') or current['name']).strip()
    icon                = (data.get('icon') or current['icon'] or '👤').strip() or '👤'
    colour, col_err     = _validate_hex_colour(data.get('colour', current['colour']), current['colour'] or '#1b2d4f')
    description         = data.get('description', current['description'])
    if description is not None:
        description = description.strip() or None
    public_registration = int(data.get('public_registration', current['public_registration']))
    active              = int(data.get('active', current['active']))
    sort_order          = int(data.get('sort_order', current['sort_order']))

    if not name:
        return jsonify({'error': 'name is required'}), 400
    if col_err:
        return jsonify({'error': col_err}), 400

    if not active:
        active_count = db.execute(
            'SELECT COUNT(*) FROM member_types WHERE active = 1 AND id != ?', (type_id,)
        ).fetchone()[0]
        if active_count == 0:
            return jsonify({'error': 'Cannot deactivate the only active member type'}), 400

    try:
        db.execute(
            '''UPDATE member_types
               SET name=?, icon=?, colour=?, description=?, public_registration=?, active=?, sort_order=?
               WHERE id=?''',
            (name, icon, colour, description, public_registration, active, sort_order, type_id),
        )
        db.commit()
        log_action('update_member_type', 'member_types', type_id, {'name': name, 'active': active})
        row = db.execute(
            '''SELECT mt.*, (SELECT COUNT(*) FROM member_type_fields mtf WHERE mtf.member_type_id = mt.id) AS field_count
               FROM member_types mt WHERE mt.id = ?''', (type_id,)
        ).fetchone()
        return jsonify(dict(row))
    except sqlite3.IntegrityError:
        return jsonify({'error': f'A member type named "{name}" already exists'}), 409


@bp.route('/api/admin/member-types/<int:type_id>', methods=['DELETE'])
@permission_required('admin.settings')
def api_admin_member_types_delete(type_id):
    db  = get_db()
    row = db.execute('SELECT * FROM member_types WHERE id = ?', (type_id,)).fetchone()
    if not row:
        return jsonify({'error': 'Member type not found'}), 404

    member_count = db.execute(
        'SELECT COUNT(*) FROM members WHERE member_type = ?', (row['slug'],)
    ).fetchone()[0]
    if member_count:
        return jsonify({'error': f'Cannot delete — {member_count} member(s) use this type'}), 409

    active_count = db.execute(
        'SELECT COUNT(*) FROM member_types WHERE active = 1 AND id != ?', (type_id,)
    ).fetchone()[0]
    if row['active'] and active_count == 0:
        return jsonify({'error': 'Cannot delete the only active member type'}), 400

    db.execute('DELETE FROM member_types WHERE id = ?', (type_id,))
    db.commit()
    log_action('delete_member_type', 'member_types', type_id, {'name': row['name']})
    return jsonify({'success': True})


# ── Field definitions CRUD ────────────────────────────────────────────────────

@bp.route('/api/admin/field-definitions', methods=['GET'])
@permission_required('admin.settings')
def api_admin_field_definitions_list():
    db   = get_db()
    rows = db.execute('''
        SELECT fd.*,
               (SELECT COUNT(*) FROM member_type_fields mtf WHERE mtf.field_id = fd.id) AS assigned_to
        FROM   field_definitions fd
        ORDER  BY fd.sort_order, fd.label
    ''').fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route('/api/admin/field-definitions', methods=['POST'])
@permission_required('admin.settings')
def api_admin_field_definitions_create():
    data        = request.get_json() or {}
    label       = (data.get('label') or '').strip()
    field_type  = (data.get('field_type') or 'text').strip() or 'text'
    placeholder = (data.get('placeholder') or '').strip() or None
    help_text   = (data.get('help_text') or '').strip() or None
    options     = (data.get('options') or '').strip() or None

    if not label:
        return jsonify({'error': 'label is required'}), 400

    key = _slugify(label).replace('-', '_')
    if not key:
        return jsonify({'error': 'Could not generate a valid key from the label'}), 400

    db        = get_db()
    max_order = db.execute('SELECT COALESCE(MAX(sort_order), -1) FROM field_definitions').fetchone()[0]

    # Ensure key uniqueness
    base_key = key
    suffix   = 1
    while db.execute('SELECT id FROM field_definitions WHERE key = ?', (key,)).fetchone():
        key = f'{base_key}_{suffix}'; suffix += 1

    try:
        cur = db.execute(
            '''INSERT INTO field_definitions
               (key, label, field_type, placeholder, help_text, options, system_field, sort_order)
               VALUES (?,?,?,?,?,?,0,?)''',
            (key, label, field_type, placeholder, help_text, options, max_order + 1),
        )
        db.commit()
        log_action('create_field_definition', 'field_definitions', cur.lastrowid,
                   {'key': key, 'label': label, 'field_type': field_type})
        row = db.execute(
            '''SELECT fd.*, (SELECT COUNT(*) FROM member_type_fields mtf WHERE mtf.field_id = fd.id) AS assigned_to
               FROM field_definitions fd WHERE fd.id = ?''', (cur.lastrowid,)
        ).fetchone()
        return jsonify(dict(row)), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': f'A field with key "{key}" already exists'}), 409


@bp.route('/api/admin/field-definitions/<int:field_id>', methods=['PUT'])
@permission_required('admin.settings')
def api_admin_field_definitions_update(field_id):
    data    = request.get_json() or {}
    db      = get_db()
    current = db.execute('SELECT * FROM field_definitions WHERE id = ?', (field_id,)).fetchone()
    if not current:
        return jsonify({'error': 'Field definition not found'}), 404

    if current['system_field'] and 'field_type' in data and data['field_type'] != current['field_type']:
        return jsonify({'error': 'Cannot change the field type of a system field'}), 403

    label       = data.get('label', current['label']).strip()
    field_type  = data.get('field_type', current['field_type']).strip() or current['field_type']
    placeholder = data.get('placeholder', current['placeholder'])
    if placeholder is not None:
        placeholder = placeholder.strip() or None
    help_text   = data.get('help_text', current['help_text'])
    if help_text is not None:
        help_text = help_text.strip() or None
    options     = data.get('options', current['options'])
    if options is not None:
        options = options.strip() or None
    active      = int(data.get('active', current['active']))
    use_lookup  = int(data['use_lookup']) if 'use_lookup' in data else int(current['use_lookup'])

    if not label:
        return jsonify({'error': 'label is required'}), 400

    db.execute(
        '''UPDATE field_definitions
           SET label=?, field_type=?, placeholder=?, help_text=?, options=?, active=?, use_lookup=?
           WHERE id=?''',
        (label, field_type, placeholder, help_text, options, active, use_lookup, field_id),
    )
    db.commit()
    log_action('update_field_definition', 'field_definitions', field_id,
               {'label': label, 'active': active})
    row = db.execute(
        '''SELECT fd.*, (SELECT COUNT(*) FROM member_type_fields mtf WHERE mtf.field_id = fd.id) AS assigned_to
           FROM field_definitions fd WHERE fd.id = ?''', (field_id,)
    ).fetchone()
    return jsonify(dict(row))


@bp.route('/api/admin/field-definitions/<int:field_id>', methods=['DELETE'])
@permission_required('admin.settings')
def api_admin_field_definitions_delete(field_id):
    db  = get_db()
    row = db.execute('SELECT * FROM field_definitions WHERE id = ?', (field_id,)).fetchone()
    if not row:
        return jsonify({'error': 'Field definition not found'}), 404

    if row['system_field']:
        return jsonify({'error': 'System fields cannot be deleted'}), 403

    usage = db.execute(
        'SELECT COUNT(*) FROM member_type_fields WHERE field_id = ?', (field_id,)
    ).fetchone()[0]
    if usage:
        return jsonify({'error': f'Cannot delete — this field is assigned to {usage} member type(s)'}), 409

    db.execute('DELETE FROM field_definitions WHERE id = ?', (field_id,))
    db.commit()
    log_action('delete_field_definition', 'field_definitions', field_id, {'key': row['key']})
    return jsonify({'success': True})


# ── Type-field config ─────────────────────────────────────────────────────────

@bp.route('/api/admin/member-types/<int:type_id>/fields', methods=['GET'])
@permission_required('admin.settings')
def api_admin_type_fields_list(type_id):
    db = get_db()
    if not db.execute('SELECT id FROM member_types WHERE id = ?', (type_id,)).fetchone():
        return jsonify({'error': 'Member type not found'}), 404
    rows = db.execute('''
        SELECT  mtf.id AS assignment_id, mtf.sort_order, mtf.required,
                mtf.show_on_registration, mtf.show_on_list, mtf.show_on_card,
                mtf.show_on_detail, mtf.show_on_print, mtf.show_on_export,
                fd.id AS field_id, fd.key, fd.label, fd.field_type,
                fd.options, fd.help_text, fd.placeholder,
                fd.system_field, fd.column_name, fd.active
        FROM    member_type_fields mtf
        JOIN    field_definitions fd ON fd.id = mtf.field_id
        WHERE   mtf.member_type_id = ?
        ORDER   BY mtf.sort_order, fd.label
    ''', (type_id,)).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route('/api/admin/member-types/<int:type_id>/fields', methods=['POST'])
@permission_required('admin.settings')
def api_admin_type_fields_assign(type_id):
    db = get_db()
    if not db.execute('SELECT id FROM member_types WHERE id = ?', (type_id,)).fetchone():
        return jsonify({'error': 'Member type not found'}), 404

    data     = request.get_json() or {}
    field_id = data.get('field_id')
    if not field_id:
        return jsonify({'error': 'field_id is required'}), 400
    if not db.execute('SELECT id FROM field_definitions WHERE id = ?', (field_id,)).fetchone():
        return jsonify({'error': 'Field definition not found'}), 404

    max_order = db.execute(
        'SELECT COALESCE(MAX(sort_order), 0) FROM member_type_fields WHERE member_type_id = ?', (type_id,)
    ).fetchone()[0]

    try:
        cur = db.execute(
            '''INSERT INTO member_type_fields
               (member_type_id, field_id, sort_order, required,
                show_on_registration, show_on_list, show_on_card, show_on_detail, show_on_print, show_on_export)
               VALUES (?,?,?,0,1,0,0,1,1,0)''',
            (type_id, field_id, max_order + 1),
        )
        db.commit()
        log_action('assign_type_field', 'member_type_fields', cur.lastrowid,
                   {'member_type_id': type_id, 'field_id': field_id})
        row = db.execute('''
            SELECT  mtf.id AS assignment_id, mtf.sort_order, mtf.required,
                    mtf.show_on_registration, mtf.show_on_list, mtf.show_on_card,
                    mtf.show_on_detail, mtf.show_on_print, mtf.show_on_export,
                    fd.id AS field_id, fd.key, fd.label, fd.field_type,
                    fd.options, fd.help_text, fd.placeholder,
                    fd.system_field, fd.column_name, fd.active
            FROM    member_type_fields mtf
            JOIN    field_definitions fd ON fd.id = mtf.field_id
            WHERE   mtf.id = ?
        ''', (cur.lastrowid,)).fetchone()
        return jsonify(dict(row)), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'This field is already assigned to this member type'}), 409


@bp.route('/api/admin/member-types/<int:type_id>/fields/<int:field_id>', methods=['PUT'])
@permission_required('admin.settings')
def api_admin_type_fields_update(type_id, field_id):
    db  = get_db()
    row = db.execute(
        'SELECT * FROM member_type_fields WHERE member_type_id = ? AND field_id = ?',
        (type_id, field_id)
    ).fetchone()
    if not row:
        return jsonify({'error': 'Assignment not found'}), 404

    data    = request.get_json() or {}
    updates = {}
    for col in ('required', 'show_on_registration', 'show_on_list',
                'show_on_card', 'show_on_detail', 'show_on_print', 'show_on_export'):
        if col in data:
            updates[col] = int(data[col])

    if not updates:
        return jsonify({'error': 'No updatable fields provided'}), 400

    set_clause = ', '.join(f'{k} = ?' for k in updates)
    values     = list(updates.values()) + [type_id, field_id]
    db.execute(
        f'UPDATE member_type_fields SET {set_clause} WHERE member_type_id = ? AND field_id = ?', values
    )
    db.commit()

    updated = db.execute('''
        SELECT  mtf.id AS assignment_id, mtf.sort_order, mtf.required,
                mtf.show_on_registration, mtf.show_on_list, mtf.show_on_card,
                mtf.show_on_detail, mtf.show_on_print, mtf.show_on_export,
                fd.id AS field_id, fd.key, fd.label, fd.field_type,
                fd.options, fd.help_text, fd.placeholder,
                fd.system_field, fd.column_name, fd.active
        FROM    member_type_fields mtf
        JOIN    field_definitions fd ON fd.id = mtf.field_id
        WHERE   mtf.member_type_id = ? AND mtf.field_id = ?
    ''', (type_id, field_id)).fetchone()
    return jsonify(dict(updated))


@bp.route('/api/admin/member-types/<int:type_id>/fields/<int:field_id>', methods=['DELETE'])
@permission_required('admin.settings')
def api_admin_type_fields_remove(type_id, field_id):
    db = get_db()
    fd = db.execute('SELECT key FROM field_definitions WHERE id = ?', (field_id,)).fetchone()
    if fd and fd['key'] in ('first_name', 'surname'):
        return jsonify({'error': 'first_name and surname cannot be removed from a member type'}), 403

    row = db.execute(
        'SELECT id FROM member_type_fields WHERE member_type_id = ? AND field_id = ?',
        (type_id, field_id)
    ).fetchone()
    if not row:
        return jsonify({'error': 'Assignment not found'}), 404

    db.execute('DELETE FROM member_type_fields WHERE member_type_id = ? AND field_id = ?',
               (type_id, field_id))
    db.commit()
    log_action('remove_type_field', 'member_type_fields', row['id'],
               {'member_type_id': type_id, 'field_id': field_id})
    return jsonify({'success': True})


@bp.route('/api/admin/member-types/<int:type_id>/fields/reorder', methods=['POST'])
@permission_required('admin.settings')
def api_admin_type_fields_reorder(type_id):
    items = request.get_json() or []
    db    = get_db()
    for item in items:
        db.execute(
            'UPDATE member_type_fields SET sort_order = ? WHERE member_type_id = ? AND field_id = ?',
            (item.get('sort_order', 0), type_id, item.get('field_id')),
        )
    db.commit()
    return jsonify({'success': True})


# ── System log viewer ─────────────────────────────────────────────────────────

def _safe_log_path(filename: str):
    safe = os.path.basename(filename)
    full = os.path.join(LOG_DIR, safe)
    if not os.path.abspath(full).startswith(os.path.abspath(LOG_DIR) + os.sep):
        return None
    return full


@bp.route('/api/admin/logs')
@permission_required('admin.maintenance')
def api_logs_list():
    files = []
    for path in sorted(glob.glob(os.path.join(LOG_DIR, 'app.log*')),
                       key=os.path.getmtime, reverse=True):
        st = os.stat(path)
        files.append({
            'filename': os.path.basename(path),
            'size':     st.st_size,
            'modified': datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
        })
    return jsonify(files)


@bp.route('/api/admin/logs/tail')
@permission_required('admin.maintenance')
def api_logs_tail():
    filename = request.args.get('file', 'app.log')
    n_lines  = min(int(request.args.get('lines', 500)), 5000)
    path     = _safe_log_path(filename)
    if not path:
        return jsonify({'error': 'Invalid filename'}), 400
    if not os.path.exists(path):
        return jsonify({'lines': [], 'truncated': False})

    with open(path, 'rb') as f:
        f.seek(0, 2)
        size  = f.tell()
        chunk = min(size, 512 * 1024)
        f.seek(max(0, size - chunk))
        raw = f.read().decode('utf-8', errors='replace')

    all_lines = raw.splitlines()
    tail      = all_lines[-n_lines:]
    return jsonify({'lines': tail, 'truncated': len(all_lines) > n_lines,
                    'total_in_chunk': len(all_lines)})


@bp.route('/api/admin/logs/<path:filename>/download')
@permission_required('admin.maintenance')
def api_logs_download(filename):
    path = _safe_log_path(filename)
    if not path:
        return jsonify({'error': 'Invalid filename'}), 400
    if not os.path.exists(path):
        return jsonify({'error': 'File not found'}), 404
    return send_file(path, as_attachment=True,
                     download_name=os.path.basename(path),
                     mimetype='text/plain')


# ── Maintenance ───────────────────────────────────────────────────────────────

@bp.route('/api/admin/maintenance/counts')
@permission_required('admin.maintenance')
def api_maintenance_counts():
    db = get_db()
    return jsonify({
        'audit_log':       db.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0],
        'attendance':      db.execute('SELECT COUNT(*) FROM attendance').fetchone()[0],
        'mailshot_log':    db.execute('SELECT COUNT(*) FROM mailshot_log').fetchone()[0],
        'registrations':   db.execute('SELECT COUNT(*) FROM pending_registrations').fetchone()[0],
        'members':         db.execute('SELECT COUNT(*) FROM members').fetchone()[0],
        'member_contacts': db.execute('SELECT COUNT(*) FROM member_contacts').fetchone()[0],
        'dofe':            db.execute('SELECT COUNT(*) FROM dofe_participants').fetchone()[0],
    })


@bp.route('/api/admin/maintenance/audit-log', methods=['DELETE'])
@permission_required('admin.maintenance')
def api_maintenance_clear_audit():
    db = get_db()
    n  = db.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0]
    db.execute('DELETE FROM audit_log')
    db.commit()
    log_action('maintenance_clear', 'audit_log', None, {'cleared': n, 'by': session['username']})
    return jsonify({'success': True, 'deleted': n})


@bp.route('/api/admin/maintenance/attendance', methods=['DELETE'])
@permission_required('admin.maintenance')
def api_maintenance_clear_attendance():
    db = get_db()
    n  = db.execute('SELECT COUNT(*) FROM attendance').fetchone()[0]
    db.execute('DELETE FROM attendance')
    db.commit()
    log_action('maintenance_clear', 'attendance', None, {'cleared': n, 'by': session['username']})
    return jsonify({'success': True, 'deleted': n})


@bp.route('/api/admin/maintenance/mailshot-log', methods=['DELETE'])
@permission_required('admin.maintenance')
def api_maintenance_clear_mailshots():
    db = get_db()
    n  = db.execute('SELECT COUNT(*) FROM mailshot_log').fetchone()[0]
    db.execute('DELETE FROM mailshot_log')
    db.commit()
    log_action('maintenance_clear', 'mailshot_log', None, {'cleared': n, 'by': session['username']})
    return jsonify({'success': True, 'deleted': n})


@bp.route('/api/admin/maintenance/registrations', methods=['DELETE'])
@permission_required('admin.maintenance')
def api_maintenance_clear_registrations():
    db = get_db()
    n  = db.execute('SELECT COUNT(*) FROM pending_registrations').fetchone()[0]
    db.execute('DELETE FROM pending_registrations')
    db.commit()
    log_action('maintenance_clear', 'pending_registrations', None, {'cleared': n, 'by': session['username']})
    return jsonify({'success': True, 'deleted': n})


@bp.route('/api/admin/maintenance/members', methods=['DELETE'])
@permission_required('admin.maintenance')
def api_maintenance_clear_members():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Only the admin role can clear all members'}), 403

    body   = request.get_json(silent=True) or {}
    phrase = body.get('confirm', '')
    if phrase != 'DELETE ALL MEMBERS':
        return jsonify({'error': 'Confirmation phrase incorrect'}), 400

    db            = get_db()
    n_members     = db.execute('SELECT COUNT(*) FROM members').fetchone()[0]
    n_attendance  = db.execute('SELECT COUNT(*) FROM attendance').fetchone()[0]
    n_dofe        = db.execute('SELECT COUNT(*) FROM dofe_participants').fetchone()[0]

    db.execute('DELETE FROM attendance')
    db.execute('DELETE FROM dofe_participants')
    db.execute('DELETE FROM members')
    db.commit()

    log_action('maintenance_clear_members', 'members', None, {
        'members_deleted':    n_members,
        'attendance_deleted': n_attendance,
        'dofe_deleted':       n_dofe,
        'by':                 session['username'],
    })
    return jsonify({
        'success':            True,
        'members_deleted':    n_members,
        'attendance_deleted': n_attendance,
        'dofe_deleted':       n_dofe,
    })


@bp.route('/api/admin/maintenance/backup')
@permission_required('admin.maintenance')
def api_maintenance_backup():
    """Stream a hot backup of the SQLCipher database."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    slug      = CLUB_SHORT_NAME.lower().replace(' ', '_')
    filename  = f'{slug}_backup_{timestamp}.db'

    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
        tmp_path = tmp.name

    try:
        src  = _connect_db()
        import sqlcipher3 as _sqlite3_cipher
        dest = _sqlite3_cipher.connect(tmp_path)
        dest.execute(f"PRAGMA key='{os.environ.get('DB_ENCRYPTION_KEY', '')}'")
        src.backup(dest)
        dest.close()
        src.close()

        with open(tmp_path, 'rb') as f:
            data = f.read()
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass

    log_action('maintenance_backup', 'database', None,
               {'filename': filename, 'size_bytes': len(data), 'by': session['username']})

    return Response(
        data,
        mimetype='application/octet-stream',
        headers={
            'Content-Disposition': f'attachment; filename="{filename}"',
            'Content-Length':      str(len(data)),
        },
    )


@bp.route('/api/admin/maintenance/restore', methods=['POST'])
@permission_required('admin.maintenance')
def api_maintenance_restore():
    """Restore the database from an uploaded backup file."""
    import sqlcipher3 as _sqlite3_cipher

    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded.'}), 400
    upload = request.files['file']
    if not upload.filename:
        return jsonify({'error': 'Empty filename.'}), 400

    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
        tmp_path = tmp.name
        upload.save(tmp_path)

    try:
        # Step 1: validate
        try:
            check = _sqlite3_cipher.connect(tmp_path)
            check.execute(f"PRAGMA key='{os.environ.get('DB_ENCRYPTION_KEY', '')}'")
            check.execute('SELECT count(*) FROM sqlite_master')
        except Exception:
            return jsonify({
                'error': 'The uploaded file could not be opened. It may be corrupt '
                         'or was created with a different encryption key.'
            }), 400
        finally:
            try: check.close()
            except Exception: pass

        # Step 2: collect summary
        try:
            info_conn = _sqlite3_cipher.connect(tmp_path)
            info_conn.execute(f"PRAGMA key='{os.environ.get('DB_ENCRYPTION_KEY', '')}'")
            def _count(tbl):
                try:   return info_conn.execute(f'SELECT COUNT(*) FROM {tbl}').fetchone()[0]
                except: return None
            summary = {
                'members':    _count('members'),
                'users':      _count('users'),
                'audit_log':  _count('audit_log'),
                'attendance': _count('attendance'),
            }
            info_conn.close()
        except Exception:
            summary = {}

        # Step 3: auto-snapshot
        backups_dir   = os.path.join(INSTANCE_DIR, 'data', 'backups')
        os.makedirs(backups_dir, exist_ok=True)
        snapshot_ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
        snapshot_path = os.path.join(backups_dir, f'pre_restore_{snapshot_ts}.db')
        shutil.copy2(DATABASE, snapshot_path)

        # Step 4: atomic swap
        shutil.copy2(tmp_path, DATABASE)

        # Step 5: drop stale connection
        if hasattr(g, 'db'):
            try: g.db.close()
            except Exception: pass
            g.db = None

        # Step 6: run migrations on restored DB
        from db import ensure_tables
        with current_app.app_context():
            ensure_tables()

    finally:
        try: os.remove(tmp_path)
        except OSError: pass

    log_action('maintenance_restore', 'database', None, {
        'snapshot': snapshot_path,
        'summary':  summary,
        'by':       session['username'],
    })
    return jsonify({
        'success':  True,
        'summary':  summary,
        'snapshot': os.path.basename(snapshot_path),
    })


# ── Data import ───────────────────────────────────────────────────────────────

_IMPORT_CORE_FIELDS = [
    {'key': 'member_id',          'label': 'Member ID (existing)',      'field_type': 'text',     'required': False},
    {'key': 'first_name',         'label': 'First Name',                'field_type': 'text',     'required': True},
    {'key': 'surname',            'label': 'Surname',                   'field_type': 'text',     'required': True},
    {'key': 'date_of_birth',      'label': 'Date of Birth',             'field_type': 'date',     'required': False},
    {'key': 'status',             'label': 'Status',                    'field_type': 'select',   'required': False,
     'options': 'Active,Inactive,Leaver'},
    {'key': 'session',            'label': 'Session',                   'field_type': 'text',     'required': False},
    {'key': 'date_registered',    'label': 'Date Registered',           'field_type': 'date',     'required': False},
    {'key': 'staff_role',         'label': 'Staff Role',                'field_type': 'text',     'required': False},
    {'key': 'address',            'label': 'Address',                   'field_type': 'text',     'required': False},
    {'key': 'postcode',           'label': 'Postcode',                  'field_type': 'text',     'required': False},
    {'key': 'ethnicity_religion', 'label': 'Ethnicity / Religion',      'field_type': 'text',     'required': False},
    {'key': 'medical_sen',        'label': 'Medical / SEN',             'field_type': 'text',     'required': False},
    {'key': 'gp_contact',         'label': 'GP Contact',                'field_type': 'text',     'required': False},
    {'key': 'unattended_exit',    'label': 'Unattended Exit (Yes/No)',  'field_type': 'text',     'required': False},
    {'key': 'gdpr_consent',       'label': 'GDPR Consent (Yes/No)',     'field_type': 'text',     'required': False},
    {'key': 'comments',           'label': 'Notes / Comments',          'field_type': 'textarea', 'required': False},
    {'key': 'contact1_name',      'label': 'Contact 1 — Full Name',     'field_type': 'text',     'required': False},
    {'key': 'contact1_phone',     'label': 'Contact 1 — Phone',         'field_type': 'text',     'required': False},
    {'key': 'contact1_email',     'label': 'Contact 1 — Email',         'field_type': 'email',    'required': False},
    {'key': 'contact2_name',      'label': 'Contact 2 — Full Name',     'field_type': 'text',     'required': False},
    {'key': 'contact2_phone',     'label': 'Contact 2 — Phone',         'field_type': 'text',     'required': False},
    {'key': 'contact2_email',     'label': 'Contact 2 — Email',         'field_type': 'email',    'required': False},
]


def _bool_val(v):
    if isinstance(v, (int, float)):
        return 1 if v else 0
    return 1 if str(v).strip().lower() in ('yes', 'true', '1', 'y') else 0


def _fmt_cell(v):
    import datetime as _dt
    if v is None:
        return ''
    if isinstance(v, _dt.datetime):
        return v.strftime('%Y-%m-%d')
    if isinstance(v, _dt.date):
        return v.strftime('%Y-%m-%d')
    if isinstance(v, _dt.time):
        return ''
    if isinstance(v, float):
        return str(int(v)) if v == int(v) else str(v)
    return str(v).strip()


def _read_xlsx_file(path, sheet_name=None):
    ext = path.rsplit('.', 1)[-1].lower()
    if ext == 'xls':
        import xlrd
        wb          = xlrd.open_workbook(path)
        sheet_names = wb.sheet_names()
        ws          = wb.sheet_by_name(sheet_name) if (sheet_name and sheet_name in sheet_names) \
                      else wb.sheet_by_index(0)
        active      = ws.name
        rows        = [ws.row_values(i) for i in range(ws.nrows)]
    else:
        import openpyxl
        wb          = openpyxl.load_workbook(path, data_only=True)
        sheet_names = wb.sheetnames
        ws          = wb[sheet_name] if (sheet_name and sheet_name in wb.sheetnames) else wb.active
        active      = ws.title
        rows        = list(ws.iter_rows(values_only=True))

    if not rows:
        return sheet_names, active, [], []

    raw_headers = [str(c).strip() if c is not None else '' for c in rows[0]]
    last_col    = len(raw_headers)
    while last_col > 0 and not raw_headers[last_col - 1]:
        last_col -= 1
    headers   = raw_headers[:last_col]
    data_rows = []
    for row in rows[1:]:
        vals = [_fmt_cell(v) for v in row[:last_col]]
        if any(vals):
            data_rows.append(vals)
    return sheet_names, active, headers, data_rows


def _read_csv_file(path):
    with open(path, 'r', encoding='utf-8-sig', errors='replace') as fh:
        reader = list(_csv_mod.reader(fh))
    if not reader:
        return [], []
    headers   = [h.strip() for h in reader[0]]
    data_rows = [r for r in reader[1:] if any(c.strip() for c in r)]
    return headers, data_rows


@bp.route('/api/admin/import/analyse', methods=['POST'])
@csrf.exempt
@permission_required('admin.maintenance')
def api_import_analyse():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    f = request.files['file']
    if not f.filename:
        return jsonify({'error': 'No file selected'}), 400

    ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else ''
    if ext not in ('xlsx', 'xls', 'csv'):
        return jsonify({'error': 'Only .xlsx, .xls and .csv files are supported'}), 400

    imports_dir = os.path.join(INSTANCE_DIR, 'data', 'imports')
    os.makedirs(imports_dir, exist_ok=True)
    file_id   = str(_uuid_mod.uuid4())
    save_path = os.path.join(imports_dir, f'{file_id}.{ext}')
    f.save(save_path)

    sheet_name = (request.form.get('sheet_name') or '').strip() or None
    try:
        if ext in ('xlsx', 'xls'):
            sheet_names, active_sheet, headers, data_rows = _read_xlsx_file(save_path, sheet_name)
        else:
            sheet_names, active_sheet = [], ''
            headers, data_rows = _read_csv_file(save_path)
    except Exception as exc:
        try: os.remove(save_path)
        except OSError: pass
        return jsonify({'error': f'Could not read file: {exc}'}), 400

    return jsonify({
        'file_id':      file_id,
        'file_ext':     ext,
        'sheet_names':  sheet_names,
        'active_sheet': active_sheet,
        'columns':      headers,
        'preview':      data_rows[:5],
        'total_rows':   len(data_rows),
    })


@bp.route('/api/admin/import/fields/<int:type_id>')
@permission_required('admin.maintenance')
def api_import_fields(type_id):
    db = get_db()
    if not db.execute('SELECT id FROM member_types WHERE id = ?', (type_id,)).fetchone():
        return jsonify({'error': 'Member type not found'}), 404
    custom = db.execute('''
        SELECT  fd.id, fd.key, fd.label, fd.field_type, fd.options
        FROM    member_type_fields  mtf
        JOIN    field_definitions   fd  ON fd.id = mtf.field_id
        WHERE   mtf.member_type_id = ? AND fd.active = 1
        ORDER   BY mtf.sort_order, fd.label
    ''', (type_id,)).fetchall()
    return jsonify({
        'core_fields':   _IMPORT_CORE_FIELDS,
        'custom_fields': [dict(f) for f in custom],
    })


@bp.route('/api/admin/import/run', methods=['POST'])
@csrf.exempt
@permission_required('admin.maintenance')
def api_import_run():
    from helpers import _next_member_id, _save_id_format_from_import

    data       = request.get_json() or {}
    file_id    = (data.get('file_id') or '').strip()
    file_ext   = (data.get('file_ext') or '').strip()
    sheet_name = (data.get('sheet_name') or '').strip() or None
    type_id    = data.get('member_type_id')
    mapping    = data.get('mapping', {})
    skip_dupes = data.get('skip_duplicates', True)

    if not all([file_id, file_ext, type_id, mapping]):
        return jsonify({'error': 'Missing required parameters'}), 400

    imports_dir = os.path.join(INSTANCE_DIR, 'data', 'imports')
    save_path   = os.path.join(imports_dir, f'{file_id}.{file_ext}')
    if not os.path.exists(save_path):
        return jsonify({'error': 'Upload not found — please re-upload the file'}), 404

    db = get_db()
    mt = db.execute('SELECT * FROM member_types WHERE id = ?', (type_id,)).fetchone()
    if not mt:
        return jsonify({'error': 'Member type not found'}), 404

    custom_fields = {}
    for fd in db.execute('''
        SELECT fd.id, fd.key, fd.field_type
        FROM   member_type_fields mtf
        JOIN   field_definitions  fd ON fd.id = mtf.field_id
        WHERE  mtf.member_type_id = ?
    ''', (type_id,)).fetchall():
        custom_fields[fd['key']] = dict(fd)

    try:
        if file_ext in ('xlsx', 'xls'):
            _, _, file_headers, data_rows = _read_xlsx_file(save_path, sheet_name)
        else:
            file_headers, data_rows = _read_csv_file(save_path)
    except Exception as exc:
        return jsonify({'error': f'Could not read file: {exc}'}), 400

    CORE_KEYS = {
        'first_name', 'surname', 'date_of_birth', 'address', 'postcode',
        'session', 'ethnicity_religion', 'medical_sen', 'gp_contact',
        'unattended_exit', 'gdpr_consent', 'staff_role',
        'date_registered', 'comments', 'status',
    }
    SPECIAL_KEYS = {
        'email', 'member_id',
        'contact1_name', 'contact1_phone', 'contact1_email',
        'contact2_name', 'contact2_phone', 'contact2_email',
    }

    imported          = 0
    skipped           = 0
    errors            = []
    not_imported      = []
    imported_ids_used = []

    for row_num, row in enumerate(data_rows, start=2):
        try:
            core        = {}
            custom_vals = {}
            contacts    = {}
            email_val   = None
            provided_id = None

            for col_str, field_key in mapping.items():
                if field_key == '_skip':
                    continue
                col_idx = int(col_str)
                val     = row[col_idx] if col_idx < len(row) else ''
                if not val:
                    continue

                if field_key == 'email':
                    email_val = val
                elif field_key == 'member_id':
                    provided_id = str(val).strip()
                elif field_key in (
                    'contact1_name', 'contact1_phone', 'contact1_email',
                    'contact2_name', 'contact2_phone', 'contact2_email',
                ):
                    contacts[field_key] = str(val).strip()
                elif field_key in CORE_KEYS:
                    if field_key in ('unattended_exit', 'gdpr_consent'):
                        core[field_key] = _bool_val(val)
                    elif field_key == 'status':
                        _s = str(val).strip()
                        if _s:
                            _STATUS_MAP = {'active': 'Active', 'inactive': 'Inactive', 'leaver': 'Leaver'}
                            core[field_key] = _STATUS_MAP.get(_s.lower(), _s)
                    else:
                        core[field_key] = str(val).strip()
                elif field_key in custom_fields:
                    custom_vals[field_key] = val

            def _row_name():
                parts = [core.get('first_name', ''), core.get('surname', '')]
                return ' '.join(p for p in parts if p) or f'Row {row_num}'

            if not core.get('first_name') and not core.get('surname'):
                skipped += 1
                not_imported.append({'row': row_num, 'name': f'Row {row_num} (blank)',
                                     'reason': 'Blank row — no name data found'})
                continue

            if provided_id and db.execute(
                'SELECT id FROM members WHERE member_id = ?', (provided_id,)
            ).fetchone():
                skipped += 1
                not_imported.append({'row': row_num, 'name': _row_name(),
                                     'reason': f'Member ID {provided_id} already exists in the portal'})
                continue

            if skip_dupes and not provided_id and db.execute(
                'SELECT id FROM members WHERE first_name=? AND surname=? AND postcode=?',
                (core.get('first_name', ''), core.get('surname', ''), core.get('postcode', ''))
            ).fetchone():
                skipped += 1
                not_imported.append({'row': row_num, 'name': _row_name(),
                                     'reason': 'Duplicate — already exists in the portal (same name + postcode)'})
                continue

            member_id = provided_id if provided_id else _next_member_id(db)
            db.execute('''
                INSERT INTO members
                    (member_id, first_name, surname, date_of_birth, address,
                     postcode, session, ethnicity_religion, medical_sen,
                     gp_contact, unattended_exit, gdpr_consent, staff_role,
                     date_registered, comments, status, member_type)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ''', (
                member_id,
                core.get('first_name', ''), core.get('surname', ''),
                core.get('date_of_birth') or None, core.get('address') or None,
                core.get('postcode') or None, core.get('session') or None,
                core.get('ethnicity_religion') or None, core.get('medical_sen') or None,
                core.get('gp_contact') or None,
                core.get('unattended_exit', 0), core.get('gdpr_consent', 0),
                core.get('staff_role') or None, core.get('date_registered') or None,
                core.get('comments') or None, core.get('status', 'Active'),
                mt['slug'],
            ))
            new_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]

            if email_val and 'contact1_email' not in contacts:
                contacts['contact1_email'] = email_val

            for order, prefix in ((1, 'contact1'), (2, 'contact2')):
                name  = contacts.get(f'{prefix}_name',  '').strip()
                phone = contacts.get(f'{prefix}_phone', '').strip()
                email = contacts.get(f'{prefix}_email', '').strip()
                if name or phone or email:
                    db.execute(
                        '''INSERT INTO member_contacts
                               (member_id, contact_order, contact_name, contact_phone, contact_email)
                           VALUES (?,?,?,?,?)''',
                        (new_id, order, name or None, phone or None, email or None)
                    )

            for fkey, fval in custom_vals.items():
                fd = custom_fields[fkey]
                db.execute(
                    'INSERT OR REPLACE INTO member_field_values (member_id, field_id, value) VALUES (?,?,?)',
                    (new_id, fd['id'], str(fval))
                )

            db.commit()
            imported += 1
            if provided_id:
                imported_ids_used.append(member_id)

        except Exception as exc:
            errors.append({'row': row_num, 'error': str(exc)})
            not_imported.append({
                'row': row_num,
                'name': ' '.join(filter(None, [
                    (row[int(k)] if int(k) < len(row) else '') for k, v in mapping.items()
                    if v in ('first_name', 'surname')
                ])) or f'Row {row_num}',
                'reason': f'Error: {exc}',
            })
            try: db.rollback()
            except Exception: pass

    try: os.remove(save_path)
    except OSError: pass

    if imported_ids_used:
        _save_id_format_from_import(db, imported_ids_used)

    report_id = None
    if not_imported:
        report_id   = str(_uuid_mod.uuid4())
        report_path = os.path.join(imports_dir, f'{report_id}_report.csv')
        with open(report_path, 'w', newline='', encoding='utf-8') as fh:
            writer = _csv_mod.writer(fh)
            writer.writerow(['Row #', 'Name', 'Reason Not Imported'])
            for rec in not_imported:
                writer.writerow([rec['row'], rec['name'], rec['reason']])

    log_action('import.run', 'members', None, {
        'imported': imported, 'skipped': skipped,
        'errors':   len(errors), 'member_type': mt['slug'],
    })
    return jsonify({
        'imported':  imported,
        'skipped':   skipped,
        'errors':    errors,
        'report_id': report_id,
    })


@bp.route('/api/admin/import/report/<report_id>')
@permission_required('admin.maintenance')
def api_import_report(report_id):
    if not report_id or '/' in report_id or '..' in report_id:
        return jsonify({'error': 'Invalid report ID'}), 400
    imports_dir = os.path.join(INSTANCE_DIR, 'data', 'imports')
    report_path = os.path.join(imports_dir, f'{report_id}_report.csv')
    if not os.path.exists(report_path):
        return jsonify({'error': 'Report not found — it may have expired'}), 404
    return send_file(
        report_path,
        mimetype='text/csv',
        as_attachment=True,
        download_name='import_not_imported.csv',
    )
