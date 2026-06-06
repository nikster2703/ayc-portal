"""
AYC Portal — HTML page routes blueprint.
All routes that render templates — main portal sections and admin pages.
"""

import os
from datetime import datetime

from flask import Blueprint, redirect, render_template, request, send_from_directory, session

from config import APP_VERSION, BRANDING_DIR, CLUB_NAME, CLUB_SHORT_NAME
from helpers import (
    get_db, login_required, permission_required,
    tpl_ctx, get_brand_settings, get_session_types, get_valid_session_names,
    _is_register_locked, _ensure_qr_tokens_for_today, get_setting,
)

bp = Blueprint('pages', __name__)


@bp.route('/dashboard')
@login_required
def dashboard_page():
    db        = get_db()
    reg_types = db.execute(
        'SELECT slug, name, icon, colour, description, public_registration '
        'FROM member_types WHERE active = 1 ORDER BY sort_order'
    ).fetchall()
    return render_template('dashboard.html', active_page='dashboard',
                           reg_types=[dict(t) for t in reg_types],
                           **tpl_ctx())


@bp.route('/members')
@permission_required('members.view')
def members_page():
    return render_template('members.html', active_page='members', **tpl_ctx())


@bp.route('/approvals')
@permission_required('approvals.view')
def approvals_page():
    return render_template('approvals.html', active_page='approvals', **tpl_ctx())


@bp.route('/register')
@login_required
def register_page():
    _ensure_qr_tokens_for_today()
    return render_template('register.html', active_page='register', **tpl_ctx())


@bp.route('/register/print')
@permission_required('register.print')
def print_register_page():
    session_type = request.args.get('session', '').strip()
    date         = request.args.get('date', '').strip()
    type_slug    = request.args.get('type', 'member').strip() or 'member'

    if not session_type or not date:
        return 'Missing session or date parameter', 400

    valid_sessions = get_valid_session_names()
    if session_type not in valid_sessions:
        return 'Invalid session type', 400

    db = get_db()

    mtype = db.execute(
        'SELECT * FROM member_types WHERE slug = ? AND active = 1', (type_slug,)
    ).fetchone()
    if not mtype:
        mtype = db.execute(
            'SELECT * FROM member_types WHERE active = 1 ORDER BY sort_order LIMIT 1'
        ).fetchone()
    mtype_dict = dict(mtype) if mtype else {}

    print_fields_raw = []
    if mtype:
        pf_rows = db.execute('''
            SELECT  fd.id, fd.key, fd.label, fd.field_type,
                    fd.column_name, fd.system_field
            FROM    member_type_fields mtf
            JOIN    field_definitions fd ON fd.id = mtf.field_id
            WHERE   mtf.member_type_id = ? AND fd.active = 1 AND mtf.show_on_print = 1
            ORDER   BY mtf.sort_order
        ''', (mtype['id'],)).fetchall()
        print_fields_raw = [dict(r) for r in pf_rows]

    SKIP_PRINT_KEYS = {'first_name', 'surname'}
    dynamic_fields  = [f for f in print_fields_raw if f['key'] not in SKIP_PRINT_KEYS]

    members_raw = db.execute('''
        SELECT  m.*
        FROM    members m
        WHERE   EXISTS (SELECT 1 FROM member_statuses ms WHERE ms.name = m.status AND ms.behaviour = 'active')
          AND   m.member_type = ?
          AND   m.session     = ?
        ORDER   BY m.first_name, m.surname
    ''', (type_slug, session_type)).fetchall()
    members = [dict(r) for r in members_raw]

    has_custom = any(not f['system_field'] for f in dynamic_fields)
    if members and has_custom:
        member_ids   = [m['id'] for m in members]
        placeholders = ','.join('?' * len(member_ids))
        cfv_rows = db.execute(
            f'SELECT mfv.member_id, fd.key, mfv.value '
            f'FROM member_field_values mfv '
            f'JOIN field_definitions fd ON fd.id = mfv.field_id '
            f'WHERE mfv.member_id IN ({placeholders})',
            member_ids
        ).fetchall()
        custom_map = {}
        for cfv in cfv_rows:
            custom_map.setdefault(cfv['member_id'], {})[cfv['key']] = cfv['value']
        for m in members:
            m['custom_fields'] = custom_map.get(m['id'], {})
    else:
        for m in members:
            m['custom_fields'] = {}

    notes = db.execute('''
        SELECT  sn.id, sn.note_type, sn.title, sn.details, sn.created_at,
                u.username   AS added_by_name,
                m.first_name AS member_first, m.surname AS member_surname
        FROM    session_notes sn
        LEFT JOIN users   u ON u.id = sn.added_by
        LEFT JOIN members m ON m.id = sn.member_id
        WHERE   sn.session_date = ? AND sn.session_type = ?
        ORDER   BY sn.created_at
    ''', (date, session_type)).fetchall()

    try:
        display_date = datetime.strptime(date, '%Y-%m-%d').strftime('%d/%m/%Y')
    except ValueError:
        display_date = date

    return render_template(
        'print_register.html',
        session_type   = session_type,
        date           = date,
        display_date   = display_date,
        members        = members,
        notes          = [dict(r) for r in notes],
        dynamic_fields = dynamic_fields,
        mtype          = mtype_dict,
        club_name      = CLUB_NAME,
        club_short_name= CLUB_SHORT_NAME,
    )


@bp.route('/register/export')
@permission_required('register.export')
def export_register_page():
    session_type = request.args.get('session', '').strip()
    date         = request.args.get('date', '').strip()

    if not session_type or not date:
        return 'Missing session or date parameter', 400

    valid_sessions = get_valid_session_names()
    if session_type not in valid_sessions:
        return 'Invalid session type', 400

    db = get_db()

    completion = db.execute('''
        SELECT sc.completed_at, sc.auto_signout_count,
               u.username AS completed_by_name
        FROM   session_completions sc
        LEFT JOIN users u ON u.id = sc.completed_by
        WHERE  sc.session_date = ? AND sc.session_type = ?
    ''', (date, session_type)).fetchone()
    if not completion:
        return 'This register has not been completed yet.', 400

    member_mt = db.execute(
        '''SELECT mt.id FROM member_types mt
           JOIN members m ON m.member_type = mt.slug
           WHERE m.session = ? AND mt.registration_style != "staff" AND mt.active = 1
           LIMIT 1''',
        (session_type,)
    ).fetchone()
    export_fields = []
    if member_mt:
        ef_rows = db.execute('''
            SELECT  fd.key, fd.label, fd.field_type, fd.column_name, fd.system_field
            FROM    member_type_fields mtf
            JOIN    field_definitions fd ON fd.id = mtf.field_id
            WHERE   mtf.member_type_id = ? AND fd.active = 1 AND mtf.show_on_export = 1
              AND   fd.key NOT IN ('first_name', 'surname')
            ORDER   BY mtf.sort_order
        ''', (member_mt['id'],)).fetchall()
        export_fields = [dict(f) for f in ef_rows]

    members = db.execute('''
        SELECT  m.*,
                a.signed_in_at, a.signed_out_at
        FROM    members m
        JOIN    member_types mt ON mt.slug = m.member_type
        LEFT JOIN attendance a
               ON  a.member_id   = m.id
               AND a.session_date = ?
               AND a.session_type = ?
        WHERE   EXISTS (SELECT 1 FROM member_statuses ms WHERE ms.name = m.status AND ms.behaviour = 'active')
          AND   mt.registration_style != 'staff'
          AND   m.session     = ?
        ORDER   BY m.surname, m.first_name
    ''', (date, session_type, session_type)).fetchall()

    member_ids = [m['id'] for m in members]
    custom_fields_map = {}
    if member_ids and export_fields:
        placeholders = ','.join('?' * len(member_ids))
        cfv_rows = db.execute(
            f'SELECT mfv.member_id, fd.key, mfv.value '
            f'FROM member_field_values mfv '
            f'JOIN field_definitions fd ON fd.id = mfv.field_id '
            f'WHERE mfv.member_id IN ({placeholders})',
            member_ids
        ).fetchall()
        for cfv in cfv_rows:
            custom_fields_map.setdefault(cfv['member_id'], {})[cfv['key']] = cfv['value']

    members_out = []
    for m in members:
        md    = dict(m)
        extra = {}
        for f in export_fields:
            if f['system_field'] and f['column_name']:
                extra[f['key']] = md.get(f['column_name'], '') or ''
            else:
                extra[f['key']] = custom_fields_map.get(md['id'], {}).get(f['key'], '') or ''
        md['export_extra'] = extra
        members_out.append(md)
    members = members_out

    staff = db.execute('''
        SELECT  m.first_name, m.surname, m.staff_role,
                a.signed_in_at, a.signed_out_at
        FROM    members m
        LEFT JOIN attendance a
               ON  a.member_id   = m.id
               AND a.session_date = ?
               AND a.session_type = ?
        JOIN    member_types mt ON mt.slug = m.member_type
        WHERE   EXISTS (SELECT 1 FROM member_statuses ms WHERE ms.name = m.status AND ms.behaviour = 'active')
          AND   mt.registration_style = 'staff'
          AND   m.session     = ?
        ORDER   BY m.surname, m.first_name
    ''', (date, session_type, session_type)).fetchall()

    notes = db.execute('''
        SELECT  sn.note_type, sn.title, sn.details, sn.created_at,
                u.username   AS added_by_name,
                m.first_name AS member_first, m.surname AS member_surname
        FROM    session_notes sn
        LEFT JOIN users   u ON u.id = sn.added_by
        LEFT JOIN members m ON m.id = sn.member_id
        WHERE   sn.session_date = ? AND sn.session_type = ?
        ORDER   BY sn.created_at
    ''', (date, session_type)).fetchall()

    try:
        display_date = datetime.strptime(date, '%Y-%m-%d').strftime('%A %d %B %Y')
    except ValueError:
        display_date = date

    attended    = sum(1 for m in members if m['signed_in_at'])
    not_arrived = sum(1 for m in members if not m['signed_in_at'])

    return render_template(
        'register_export.html',
        session_type    = session_type,
        date            = date,
        display_date    = display_date,
        completion      = dict(completion),
        members         = members,
        staff           = [dict(s) for s in staff],
        notes           = [dict(n) for n in notes],
        export_fields   = export_fields,
        attended        = attended,
        not_arrived     = not_arrived,
        club_name       = CLUB_NAME,
        club_short_name = CLUB_SHORT_NAME,
        app_version     = APP_VERSION,
    )


@bp.route('/registration')
def registration_page():
    db    = get_db()
    types = db.execute(
        'SELECT * FROM member_types WHERE public_registration = 1 AND active = 1 ORDER BY sort_order'
    ).fetchall()
    return render_template('registration_landing.html',
                           reg_types=[dict(t) for t in types],
                           club_name=CLUB_NAME, club_short_name=CLUB_SHORT_NAME)


@bp.route('/registration/<slug>')
def registration_slug_page(slug):
    db    = get_db()
    mtype = db.execute(
        'SELECT * FROM member_types WHERE slug = ? AND active = 1', (slug,)
    ).fetchone()
    if not mtype:
        return redirect('/registration')
    return render_template('registration_dynamic.html',
                           type_slug=slug,
                           type_info=dict(mtype),
                           version=APP_VERSION,
                           club_name=CLUB_NAME, club_short_name=CLUB_SHORT_NAME)


@bp.route('/documents')
@permission_required('documents.view')
def documents_page():
    return render_template('documents.html', active_page='documents', **tpl_ctx())


@bp.route('/communications')
@permission_required('mailshots.send')
def communications_page():
    return render_template('communications.html', active_page='communications', **tpl_ctx())


@bp.route('/calendar')
@login_required
def calendar_page():
    return render_template('calendar.html', active_page='calendar', **tpl_ctx())


@bp.route('/display')
def display_page():
    brand = get_brand_settings()
    club  = brand.get('brand_club_name') or CLUB_NAME
    short = brand.get('brand_short_name') or CLUB_SHORT_NAME
    return render_template('display.html',
                           current_session=session.get('active_session', ''),
                           session_types=get_session_types(),
                           club_name=club, club_short_name=short,
                           brand=brand)


@bp.route('/quick-session')
def quick_session_page():
    return render_template('quick_session.html',
                           club_name=CLUB_NAME, club_short_name=CLUB_SHORT_NAME)


# ── Branding — public logo endpoint ──────────────────────────────────────────

@bp.route('/branding/logo')
def branding_logo():
    """Serve the organisation logo — publicly accessible, no auth needed."""
    brand    = get_brand_settings()
    filename = brand.get('brand_logo_file', '')
    if not filename:
        return '', 404
    safe = os.path.join(BRANDING_DIR, os.path.basename(filename))
    if not os.path.isfile(safe):
        return '', 404
    return send_from_directory(BRANDING_DIR, os.path.basename(filename))


# ── Admin HTML page routes ────────────────────────────────────────────────────

@bp.route('/admin/users')
@permission_required('users.view')
def users_page():
    return render_template('admin/users.html', active_page='users', **tpl_ctx())


@bp.route('/admin/audit')
@permission_required('audit.view')
def audit_page():
    return render_template('admin/audit.html', active_page='audit', **tpl_ctx())


@bp.route('/admin/logs')
@permission_required('admin.maintenance')
def system_logs_page():
    return render_template('admin/system_logs.html', active_page='settings', **tpl_ctx())


@bp.route('/admin/branding')
@permission_required('admin.settings')
def branding_page():
    return render_template('admin/branding.html', active_page='settings', **tpl_ctx())


@bp.route('/admin/settings')
@permission_required('admin.settings')
def settings_page():
    return render_template('admin/settings.html', active_page='settings', **tpl_ctx())


@bp.route('/admin/roles')
@permission_required('admin.settings')
def roles_page():
    return render_template('admin/roles.html', active_page='settings', **tpl_ctx())


@bp.route('/admin/staff-roles')
@permission_required('admin.settings')
def staff_roles_page():
    return render_template('admin/staff_roles.html', active_page='settings', **tpl_ctx())


@bp.route('/admin/tags')
@permission_required('admin.settings')
def tags_page():
    return render_template('admin/tags.html', active_page='settings', **tpl_ctx())


@bp.route('/admin/member-statuses')
@permission_required('admin.settings')
def member_statuses_page():
    return render_template('admin/member_statuses.html', active_page='settings', **tpl_ctx())


@bp.route('/admin/payments')
@permission_required('payments.manage')
def payments_admin_page():
    return render_template('admin/payments.html', active_page='settings', **tpl_ctx())


@bp.route('/admin/document-categories')
@permission_required('admin.settings')
def document_categories_page():
    return render_template('admin/document_categories.html', active_page='settings', **tpl_ctx())


@bp.route('/admin/document-fields/<int:cat_id>')
@permission_required('admin.settings')
def document_fields_page(cat_id):
    db  = get_db()
    cat = db.execute('SELECT * FROM document_categories WHERE id = ?', (cat_id,)).fetchone()
    return render_template('admin/document_fields.html',
                           cat_id=cat_id, active_page='settings', **tpl_ctx())


@bp.route('/admin/member-types')
@permission_required('admin.settings')
def member_types_page():
    return render_template('admin/member_types.html', active_page='settings', **tpl_ctx())


@bp.route('/admin/field-builder/<int:type_id>')
@permission_required('admin.settings')
def field_builder_page(type_id):
    db    = get_db()
    mtype = db.execute('SELECT * FROM member_types WHERE id = ?', (type_id,)).fetchone()
    if not mtype:
        return redirect('/admin/member-types')
    return render_template('admin/field_builder.html',
                           active_page='settings',
                           mtype=dict(mtype),
                           **tpl_ctx())


@bp.route('/admin/settings/attendance')
@permission_required('admin.settings')
def attendance_settings_page():
    return render_template('admin/attendance_settings.html', active_page='settings', **tpl_ctx())


@bp.route('/admin/settings/session-types')
@permission_required('admin.session_types')
def session_types_page():
    return render_template('admin/session_types.html', active_page='settings', **tpl_ctx())


@bp.route('/admin/settings/maintenance')
@permission_required('admin.maintenance')
def maintenance_page():
    return render_template('admin/maintenance.html', active_page='settings', **tpl_ctx())


@bp.route('/admin/settings/import')
@permission_required('admin.maintenance')
def import_page():
    return render_template('admin/import.html', active_page='settings', **tpl_ctx())


@bp.route('/admin/settings/import-history')
@permission_required('admin.maintenance')
def import_history_page():
    from helpers import get_db
    db           = get_db()
    session_types = db.execute('SELECT name FROM session_types ORDER BY sort_order, name').fetchall()
    payment_types = db.execute('SELECT name FROM payment_types ORDER BY sort_order, name').fetchall()
    payment_methods = db.execute('SELECT name FROM payment_methods ORDER BY sort_order, name').fetchall()
    return render_template(
        'admin/import_history.html',
        active_page='settings',
        session_types=session_types,
        payment_types=payment_types,
        payment_methods=payment_methods,
        **tpl_ctx()
    )


@bp.route('/admin/settings/export')
@permission_required('admin.maintenance')
def export_page():
    return render_template('admin/export.html', active_page='settings', **tpl_ctx())
