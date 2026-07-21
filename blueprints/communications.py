"""
AYC Portal — Communications blueprint.
Routes: /api/email-templates/*, /api/mailshots/*, /api/mailshots
"""

import html as _html
import json
import os
import re
import smtplib
from email import encoders
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from flask import Blueprint, current_app, jsonify, request, session

from config import BRANDING_DIR, CLUB_NAME, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM
from helpers import (
    get_db, log_action, permission_required, _assigned_session,
    decrypt_file, resolve_doc_path, user_can_access_doc, get_brand_settings,
)

bp = Blueprint('communications', __name__)


# ── Merge field helpers ───────────────────────────────────────────────────────

STANDARD_MERGE_FIELDS = [
    {'token': '{Forename}',    'label': 'Forename'},
    {'token': '{Surname}',     'label': 'Surname'},
    {'token': '{Full Name}',   'label': 'Full Name'},
    {'token': '{Email}',       'label': 'Email Address'},
    {'token': '{Member Type}', 'label': 'Member Type'},
]


# Maps first-class members table columns → field_definition labels used as merge tokens
_FC_LABELS = {
    'date_of_birth':      'Date of Birth',
    'address':            'Home Address',
    'postcode':           'Postcode',
    'ethnicity_religion': 'Ethnicity / Religion',
    'medical_sen':        'Medical Needs, Allergies or SEN',
    'gp_contact':         'GP / Doctor Surgery Contact',
    'unattended_exit':    'Unattended Exit',
    'gdpr_consent':       'Communications Consent',
    'status':             'Status',
    'session':            'Session',
    'staff_role':         'Staff Role',
    'mobile':             'Mobile Number',
    'date_registered':    'Date Registered',
    'comments':           'Internal Notes',
}


# v12.73: staff store their OWN mobile/email on the members row (see the approvals
# fix), so members.email is a legitimate mailshot destination for staff-style types.
# It is deliberately NOT one for youth types: a young person's own email may be on
# record, but club comms must reach their parent or guardian via contact 1. Any
# widening of this rule is a safeguarding decision, not a technical one.
_STAFF_TYPE_SQL = (
    "EXISTS (SELECT 1 FROM member_types mt_s "
    "WHERE mt_s.slug = m.member_type AND mt_s.registration_style = 'staff')"
)


def _build_member_lookup(emails):
    """
    Given a list of email addresses, return a dict keyed by email with member
    data and custom field values.  Used for per-recipient merge substitution.

    Covers three sources:
      1. Standard tokens  — first_name, surname, member_type, email (top-level keys)
      2. First-class cols — all columns in _FC_LABELS fetched directly from members
      3. Custom fields    — member_field_values rows for truly custom field_definitions
      4. Contacts         — primary and secondary contact details from member_contacts

    v12.73: matches on the contact-1 email OR, for staff-style types, the member's
    own members.email. A row can match on either, so the key this member is filed
    under is whichever address actually matched, not a fixed column.
    """
    if not emails:
        return {}
    db     = get_db()
    wanted = [e.lower() for e in emails]
    ph     = ','.join('?' * len(wanted))
    rows = db.execute(f'''
        SELECT  m.id, m.first_name, m.surname, m.member_type,
                m.date_of_birth, m.address, m.postcode, m.ethnicity_religion,
                m.medical_sen, m.gp_contact, m.unattended_exit, m.gdpr_consent,
                m.status, m.staff_role, m.mobile,
                COALESCE((SELECT group_concat(name, ', ') FROM (
                    SELECT st_s.name FROM member_sessions ms_s
                    JOIN session_types st_s ON st_s.id = ms_s.session_type_id
                    WHERE ms_s.member_id = m.id ORDER BY st_s.sort_order, st_s.name
                )), m.session) AS session,   -- v12.51: all sessions, comma-joined
                m.date_registered, m.comments,
                c.contact_email AS c1_email,
                m.email         AS own_email,
                {_STAFF_TYPE_SQL} AS is_staff_type,
                c.contact_name  AS c1_name,
                c.contact_phone AS c1_phone
        FROM    members m
        LEFT JOIN member_contacts c ON c.member_id = m.id AND c.contact_order = 1
        WHERE   lower(c.contact_email) IN ({ph})
           OR   ({_STAFF_TYPE_SQL} AND lower(m.email) IN ({ph}))
    ''', wanted * 2).fetchall()

    if not rows:
        return {}

    # Batch-fetch secondary contacts
    member_ids = [r['id'] for r in rows]
    c2_ph  = ','.join('?' * len(member_ids))
    c2_map = {}
    for c2 in db.execute(
        f'SELECT member_id, contact_name, contact_phone, contact_email '
        f'FROM member_contacts WHERE member_id IN ({c2_ph}) AND contact_order = 2',
        member_ids
    ).fetchall():
        c2_map[c2['member_id']] = c2

    lookup = {}
    for r in rows:
        # ── Custom (truly custom) field values from member_field_values ──
        field_rows = db.execute('''
            SELECT fd.label, mfv.value
            FROM   member_field_values mfv
            JOIN   field_definitions fd ON fd.id = mfv.field_id
            WHERE  mfv.member_id = ?
        ''', (r['id'],)).fetchall()
        custom = {fr['label']: (fr['value'] or '') for fr in field_rows}

        # ── First-class member columns ────────────────────────────────────
        for col, label in _FC_LABELS.items():
            val = r[col]
            if val is None:
                val = ''
            elif isinstance(val, int):
                val = 'Yes' if val else 'No'
            custom[label] = str(val)

        # ── Contact 1 ─────────────────────────────────────────────────────
        custom['Primary Contact — Full Name'] = r['c1_name']  or ''
        custom['Primary Contact — Phone']     = r['c1_phone'] or ''
        custom['Primary Contact — Email']     = r['c1_email'] or ''
        custom['Email Address']               = r['own_email'] or ''

        # ── Contact 2 ─────────────────────────────────────────────────────
        c2 = c2_map.get(r['id'])
        custom['Second Contact — Full Name'] = (c2['contact_name']  if c2 else '') or ''
        custom['Second Contact — Phone']     = (c2['contact_phone'] if c2 else '') or ''
        custom['Second Contact — Email']     = (c2['contact_email'] if c2 else '') or ''

        # v12.73: a member can be reachable at more than one of the matched
        # addresses (contact 1 and, for staff, their own). File the row under
        # every address that was actually asked for, so {Email} resolves to the
        # address THIS recipient was mailed at rather than a fixed column.
        matched = []
        if (r['c1_email'] or '').strip().lower() in wanted:
            matched.append(r['c1_email'].strip())
        if r['is_staff_type'] and (r['own_email'] or '').strip().lower() in wanted:
            matched.append(r['own_email'].strip())

        for addr in matched:
            lookup[addr.lower()] = {
                'first_name':  r['first_name']  or '',
                'surname':     r['surname']     or '',
                'member_type': r['member_type'] or '',
                'email':       addr,
                'custom':      custom,
            }
    return lookup


def _substitute_fields(body_html, member_data):
    """Replace {Token} placeholders with member-specific values."""
    replacements = {
        '{Forename}':    member_data.get('first_name', ''),
        '{Surname}':     member_data.get('surname', ''),
        '{Full Name}':   f"{member_data.get('first_name', '')} {member_data.get('surname', '')}".strip(),
        '{Email}':       member_data.get('email', ''),
        '{Member Type}': member_data.get('member_type', ''),
    }
    # Custom field tokens
    for label, value in member_data.get('custom', {}).items():
        replacements['{' + label + '}'] = value

    result = body_html
    for token, value in replacements.items():
        result = result.replace(token, value)
    return result


# ── Email templates ───────────────────────────────────────────────────────────

@bp.route('/api/email-templates')
@permission_required('mailshots.templates')
def api_email_templates_list():
    db   = get_db()
    rows = db.execute(
        'SELECT et.*, u.username AS created_by_name FROM email_templates et'
        ' LEFT JOIN users u ON u.id = et.created_by ORDER BY et.name'
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route('/api/email-templates', methods=['POST'])
@permission_required('mailshots.templates')
def api_email_templates_create():
    data    = request.get_json() or {}
    name    = data.get('name', '').strip()
    subject = data.get('subject', '').strip()
    body    = data.get('body_html', '').strip()
    if not name or not subject or not body:
        return jsonify({'error': 'Name, subject and body are required'}), 400
    db = get_db()
    db.execute(
        'INSERT INTO email_templates (name, subject, body_html, created_by) VALUES (?,?,?,?)',
        (name, subject, body, session['user_id'])
    )
    db.commit()
    log_action('create_email_template', 'email_templates', None, {'name': name})
    return jsonify({'success': True})


@bp.route('/api/email-templates/<int:tmpl_id>', methods=['PUT'])
@permission_required('mailshots.templates')
def api_email_templates_update(tmpl_id):
    data    = request.get_json() or {}
    name    = data.get('name', '').strip()
    subject = data.get('subject', '').strip()
    body    = data.get('body_html', '').strip()
    if not name or not subject or not body:
        return jsonify({'error': 'Name, subject and body are required'}), 400
    db = get_db()
    db.execute(
        'UPDATE email_templates SET name=?, subject=?, body_html=?, updated_at=datetime("now")'
        ' WHERE id=?',
        (name, subject, body, tmpl_id)
    )
    db.commit()
    log_action('edit_email_template', 'email_templates', tmpl_id, {'name': name})
    return jsonify({'success': True})


@bp.route('/api/email-templates/<int:tmpl_id>', methods=['DELETE'])
@permission_required('mailshots.templates')
def api_email_templates_delete(tmpl_id):
    db   = get_db()
    tmpl = db.execute('SELECT name FROM email_templates WHERE id = ?', (tmpl_id,)).fetchone()
    db.execute('DELETE FROM email_templates WHERE id = ?', (tmpl_id,))
    db.commit()
    log_action('delete_email_template', 'email_templates', tmpl_id,
               {'name': tmpl['name']} if tmpl else None)
    return jsonify({'success': True})


# ── Mailshots ─────────────────────────────────────────────────────────────────

@bp.route('/api/mailshots/merge-fields')
@permission_required('mailshots.send')
def api_mailshots_merge_fields():
    """Return merge fields (standard + custom) optionally filtered to a member type slug."""
    member_type = request.args.get('member_type', 'all')
    db = get_db()
    if member_type and member_type != 'all':
        rows = db.execute('''
            SELECT DISTINCT fd.key, fd.label
            FROM   field_definitions fd
            JOIN   member_type_fields mtf ON mtf.field_id = fd.id
            JOIN   member_types mt        ON mt.id = mtf.member_type_id
            WHERE  mt.slug = ?
            ORDER  BY fd.label
        ''', (member_type,)).fetchall()
    else:
        # Only return fields linked to at least one existing member type —
        # excludes orphaned fields from deleted member types
        rows = db.execute('''
            SELECT DISTINCT fd.key, fd.label
            FROM   field_definitions fd
            JOIN   member_type_fields mtf ON mtf.field_id = fd.id
            JOIN   member_types mt        ON mt.id = mtf.member_type_id
            ORDER  BY fd.label
        ''').fetchall()
    custom = [{'token': '{' + r['label'] + '}', 'label': r['label'], 'key': r['key']}
              for r in rows]
    return jsonify({'standard': STANDARD_MERGE_FIELDS, 'custom': custom})


_NO_VALUE_SPAN = (
    '<span style="background:#fef3c7;border:1px solid #f59e0b;border-radius:3px;'
    'padding:0 4px;color:#92400e;font-style:italic;font-size:.9em" '
    'title="No value set for this member">\\g<0> — no value</span>'
)


@bp.route('/api/mailshots/preview-substitute', methods=['POST'])
@permission_required('mailshots.send')
def api_mailshots_preview_substitute():
    """Server-side merge substitution for preview mode.
    After substitution any token that had no value is highlighted in amber
    with '— no value' so the composer can see exactly which fields are missing.
    Also substitutes the subject line (plain text) when provided."""
    data      = request.get_json() or {}
    body_html = data.get('body_html', '')
    subject   = data.get('subject', '')
    email     = (data.get('email') or '').strip().lower()

    if email:
        lookup = _build_member_lookup([email])
        member = lookup.get(email)
        if member:
            body_html = _substitute_fields(body_html, member)
            subject   = _substitute_fields(subject,   member)

    # Highlight unresolved body tokens in amber
    body_html = re.sub(r'\{[^}<>]+\}', _NO_VALUE_SPAN, body_html)
    # Mark unresolved subject tokens inline (plain text — no HTML spans)
    subject   = re.sub(r'\{[^}]+\}', lambda m: f'{m.group(0)} — no value', subject)
    return jsonify({'html': body_html, 'subject': subject})

def _get_recipients(session_filter, status_filter, flag_rule_ids=None, member_type_filter=None):
    """
    Return a deduplicated list of {email, name} dicts from member_contacts
    (contact_order=1) matching the given filters.
    Editors are automatically scoped to their own session.

    member_type_filter : slug string | 'all'  (default: all types)
    status_filter      : 'Active' | 'Inactive' | 'Leaver' | 'all'  (default: Active only)
    flag_rule_ids      : list of int alert-rule IDs — when provided, only members
                        with at least one active flag for ANY of those rules are included.
    """
    db         = get_db()
    conditions = []
    params     = []

    # Member type filter
    if member_type_filter and member_type_filter != 'all':
        conditions.append('m.member_type = ?')
        params.append(member_type_filter)

    # Status — use behaviour-based query throughout for consistency with dashboard
    if not status_filter or status_filter == 'all':
        pass  # no status restriction
    elif status_filter in ('Active', 'Inactive', 'Leaver'):
        # Map legacy display names to behaviour values
        _beh_map = {'Active': 'active', 'Inactive': 'inactive', 'Leaver': 'leaver'}
        conditions.append(
            "EXISTS (SELECT 1 FROM member_statuses ms WHERE ms.name = m.status AND ms.behaviour = ?)"
        )
        params.append(_beh_map[status_filter])
    else:
        # Exact status name (custom statuses, future use)
        conditions.append('m.status = ?')
        params.append(status_filter)

    # v12.51 Phase B: session matching via the member_sessions junction — a
    # member assigned to N sessions matches any of them. "No session assigned"
    # (no junction rows) keeps its historical meaning: reachable by everyone.
    _MS_ANY  = ('EXISTS (SELECT 1 FROM member_sessions ms_x '
                'JOIN session_types st_x ON st_x.id = ms_x.session_type_id '
                'WHERE ms_x.member_id = m.id AND st_x.name IN ({ph}))')
    _MS_NONE = 'NOT EXISTS (SELECT 1 FROM member_sessions ms_n WHERE ms_n.member_id = m.id)'

    scoped = _assigned_session()
    if scoped is not None:
        # scoped is a list of session names; non-admin users are restricted to their sessions.
        if scoped:
            conditions.append(f"({_MS_ANY.format(ph=','.join('?' * len(scoped)))} OR {_MS_NONE})")
            params.extend(scoped)
        # empty scoped list means the user has no sessions — return nothing
        else:
            conditions.append('1=0')
    elif session_filter and session_filter != 'all':
        conditions.append(f"({_MS_ANY.format(ph='?')} OR {_MS_NONE})")
        params.append(session_filter)

    # Flag filter — member must have an unresolved flag for one of the selected rules
    flag_join = ''
    if flag_rule_ids:
        valid_ids = [int(r) for r in flag_rule_ids if str(r).isdigit()]
        if valid_ids:
            placeholders = ','.join('?' * len(valid_ids))
            flag_join = (
                f'JOIN member_flags mf ON mf.member_id = m.id '
                f'AND mf.rule_id IN ({placeholders}) AND mf.resolved_at IS NULL'
            )
            params = valid_ids + params   # flag params come before WHERE params

    where = ' AND '.join(conditions) if conditions else '1=1'
    # v12.73: two sources, unioned — the contact-1 email for everyone, plus the
    # member's own members.email for staff-style types only (staff keep their own
    # details there since the approvals fix; youth comms must still go to the
    # guardian on contact 1). Both halves take the same filter params, hence
    # `params * 2`; flag_join params are already at the head of `params`.
    rows = db.execute(f'''
        SELECT DISTINCT email, member_name FROM (
            SELECT  c.contact_email AS email,
                    m.first_name || " " || m.surname AS member_name,
                    m.first_name AS sort_name
            FROM    members m
            {flag_join}
            JOIN    member_contacts c ON c.member_id = m.id AND c.contact_order = 1
            WHERE   {where}
              AND   c.contact_email IS NOT NULL
              AND   trim(c.contact_email) != ""
            UNION
            SELECT  m.email AS email,
                    m.first_name || " " || m.surname AS member_name,
                    m.first_name AS sort_name
            FROM    members m
            {flag_join}
            WHERE   {where}
              AND   {_STAFF_TYPE_SQL}
              AND   m.email IS NOT NULL
              AND   trim(m.email) != ""
        )
        ORDER BY sort_name
    ''', params * 2).fetchall()
    return [{'email': r['email'], 'name': r['member_name']} for r in rows]


@bp.route('/api/mailshots/preview', methods=['POST'])
@permission_required('mailshots.send')
def api_mailshots_preview():
    """Return how many unique recipient emails a mailshot would reach."""
    data       = request.get_json() or {}
    recipients = _get_recipients(
        data.get('session_filter'),
        data.get('status_filter'),
        data.get('flag_rule_ids'),
        data.get('member_type_filter'),
    )
    return jsonify({'count': len(recipients), 'recipients': recipients})


@bp.route('/api/mailshots/send', methods=['POST'])
@permission_required('mailshots.send')
def api_mailshots_send():
    """Send a mailshot via SMTP and log it."""
    data           = request.get_json() or {}
    subject        = (data.get('subject') or '').strip()
    body           = (data.get('body_html') or '').strip()
    template_id    = data.get('template_id')
    explicit_recip = data.get('recipients')        # list of {email, name} from frontend checklist
    document_ids   = data.get('document_ids', [])  # list of document IDs to attach
    profile_id     = data.get('smtp_profile_id')   # optional — falls back to default profile
    incident_note_id = data.get('incident_note_id')  # v12.56: stamps the session note on success

    if not subject or not body:
        return jsonify({'error': 'Subject and body are required'}), 400

    # v12.56: validate the incident note up front so a bad id fails before
    # any email goes out.
    _incident_note = None
    if incident_note_id:
        try:
            incident_note_id = int(incident_note_id)
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid incident note id'}), 400
        _incident_note = get_db().execute(
            'SELECT * FROM session_notes WHERE id = ? AND member_id IS NOT NULL',
            (incident_note_id,)
        ).fetchone()
        if not _incident_note:
            return jsonify({'error': 'Incident note not found or not linked to a member'}), 404
        _scoped = _assigned_session()
        if _scoped is not None and _incident_note['session_type'] not in (_scoped or []):
            return jsonify({'error': 'Forbidden'}), 403

    # ── Resolve SMTP credentials ──────────────────────────────────────────────
    # Prefer DB profile; fall back to .env values for backwards compatibility.
    db = get_db()
    _smtp_host = _smtp_port = _smtp_user = _smtp_pass = _smtp_from = None
    if profile_id:
        _prof = db.execute('SELECT * FROM smtp_profiles WHERE id = ?', (profile_id,)).fetchone()
    else:
        _prof = db.execute('SELECT * FROM smtp_profiles WHERE is_default = 1 LIMIT 1').fetchone()

    if _prof:
        try:
            _smtp_pass = decrypt_file(_prof['password_enc'].encode()).decode()
        except Exception:
            return jsonify({'error': 'Could not decrypt email sender password — re-save the profile in Settings → Email Senders'}), 503
        _smtp_host = _prof['host']
        _smtp_port = _prof['port']
        _smtp_user = _prof['username']
        _smtp_from = _prof['from_address']
    else:
        # .env fallback (no profiles configured yet)
        _smtp_host = SMTP_HOST
        _smtp_port = SMTP_PORT
        _smtp_user = SMTP_USER
        _smtp_pass = SMTP_PASS
        _smtp_from = SMTP_FROM

    if not _smtp_user or not _smtp_pass:
        return jsonify({'error': 'Email not configured — add a sender profile in Settings → Email Senders'}), 503

    # Use explicit selection from the frontend checklist; fall back to filter query.
    # v12.42: validate the explicit list against the member contacts this user is
    # actually allowed to reach (any status, scoped to their sessions) — previously
    # the endpoint accepted arbitrary addresses from the client, letting anyone
    # with mailshots.send use the club's SMTP account as an open relay.
    if explicit_recip and isinstance(explicit_recip, list):
        allowed_emails = {r['email'].lower() for r in _get_recipients('all', 'all')}
        recipients = [r for r in explicit_recip
                      if r.get('email') and r['email'].lower() in allowed_emails]
        dropped = len([r for r in explicit_recip if r.get('email')]) - len(recipients)
        if dropped:
            current_app.logger.warning(
                'Mailshot: dropped %d recipient(s) not in the allowed contact list', dropped)
    else:
        session_filter = data.get('session_filter', 'all')
        recipients = _get_recipients(session_filter, status_filter=None)  # defaults to active behaviour

    if not recipients:
        return jsonify({'error': 'No recipients selected'}), 400

    # v12.67 (audit fix #6): an incident notification must go to THAT member's
    # contacts. The UI pins the checklist correctly, but the API accepted any
    # in-scope recipient set alongside incident_note_id — stamping the note
    # "notified" while the email went to a different family.
    if _incident_note is not None:
        _member_emails = {
            (r['contact_email'] or '').strip().lower()
            for r in db.execute(
                'SELECT contact_email FROM member_contacts WHERE member_id = ?',
                (_incident_note['member_id'],)
            ).fetchall()
            if (r['contact_email'] or '').strip()
        }
        # v12.73: staff keep their own email on the members row, so an incident
        # concerning a staff member has no contact rows to validate against and
        # every recipient would be rejected. Their own address counts as theirs.
        # Youth members are deliberately NOT widened this way — an incident about
        # a young person must reach their guardian's contact email.
        _own = db.execute(
            f'SELECT m.email FROM members m WHERE m.id = ? AND {_STAFF_TYPE_SQL}',
            (_incident_note['member_id'],)
        ).fetchone()
        if _own and (_own['email'] or '').strip():
            _member_emails.add(_own['email'].strip().lower())
        _bad = [r['email'] for r in recipients
                if r['email'].lower() not in _member_emails]
        if _bad:
            return jsonify({'error': 'Incident notifications can only be sent to the '
                                     "member's own parent/guardian contacts"}), 400

    # Resolve and validate attachments from the document repository
    attachments = []   # list of {filename, mime_type, data (bytes)}
    if document_ids:
        for doc_id in document_ids:
            doc = db.execute(
                'SELECT * FROM documents WHERE id = ? AND active = 1', (doc_id,)
            ).fetchone()
            if not doc:
                return jsonify({'error': f'Document ID {doc_id} not found in repository'}), 400
            if not user_can_access_doc(doc):
                return jsonify({'error': f'Access denied to document: {doc["title"]}'}), 403
            file_path = resolve_doc_path(doc)
            if not os.path.exists(file_path):
                return jsonify({'error': f'File not found on server for: {doc["title"]}'}), 500
            with open(file_path, 'rb') as f:
                attachments.append({
                    'filename':  doc['filename'],
                    'mime_type': doc['mime_type'] or 'application/octet-stream',
                    'data':      decrypt_file(f.read()),
                })
            log_action('attach_to_mailshot', 'documents', doc_id,
                       {'title': doc['title'], 'subject': subject})

    # Pre-load member data for merge field substitution
    all_emails   = [r['email'] for r in recipients]
    member_lookup = _build_member_lookup(all_emails)

    # v12.70: optional branded header/footer wrapper (Admin → Branding).
    # The logo (raster formats only — SVG isn't reliably rendered by email
    # clients) is embedded inline via CID; without one, the header shows the
    # club name on the accent bar.
    _brand      = get_brand_settings()
    _brand_wrap = _brand.get('brand_email_branding', '0') == '1'
    _logo_bytes = _logo_subtype = None
    if _brand_wrap and _brand.get('brand_logo_file'):
        _lext = _brand['brand_logo_file'].rsplit('.', 1)[-1].lower()
        if _lext in ('png', 'jpg', 'jpeg', 'gif'):
            try:
                with open(os.path.join(BRANDING_DIR,
                                       os.path.basename(_brand['brand_logo_file'])), 'rb') as _fh:
                    _logo_bytes = _fh.read()
                _logo_subtype = 'jpeg' if _lext in ('jpg', 'jpeg') else _lext
            except OSError:
                pass

    def _apply_brand_wrap(inner_html):
        accent = _brand.get('brand_accent') or '#0096b4'
        club   = _html.escape(_brand.get('brand_club_name') or CLUB_NAME)
        header = (f'<img src="cid:brandlogo" alt="{club}" height="36" '
                  f'style="display:block;max-height:36px;height:36px">'
                  if _logo_bytes else
                  f'<span style="color:#ffffff;font-size:18px;font-weight:bold;'
                  f'font-family:Arial,sans-serif">{club}</span>')
        return (
            f'<table width="100%" cellpadding="0" cellspacing="0" role="presentation" '
            f'style="background:#f2f4f7;padding:24px 0"><tr><td align="center">'
            f'<table width="600" cellpadding="0" cellspacing="0" role="presentation" '
            f'style="max-width:600px;width:100%;background:#ffffff;border-radius:10px;overflow:hidden">'
            f'<tr><td style="background:{accent};padding:16px 28px" align="left">{header}</td></tr>'
            f'<tr><td style="padding:26px 28px;font-family:Arial,Helvetica,sans-serif;'
            f'font-size:14px;color:#1a202c;line-height:1.6">{inner_html}</td></tr>'
            f'<tr><td style="padding:14px 28px;background:#f2f4f7;font-size:12px;color:#6b7280;'
            f'font-family:Arial,Helvetica,sans-serif">{club}</td></tr>'
            f'</table></td></tr></table>'
        )

    emails_sent = 0
    errors      = []
    try:
        # Port 465 uses implicit SSL; all other ports (e.g. 587) use STARTTLS
        if _smtp_port == 465:
            ctx = smtplib.ssl.create_default_context()
            srv_cm = smtplib.SMTP_SSL(_smtp_host, _smtp_port, timeout=15, context=ctx)
        else:
            srv_cm = smtplib.SMTP(_smtp_host, _smtp_port, timeout=15)
        with srv_cm as srv:
            srv.ehlo()
            if _smtp_port != 465:
                srv.starttls()
                srv.ehlo()
            srv.login(_smtp_user, _smtp_pass)
            for r in recipients:
                try:
                    # Substitute merge fields per recipient
                    member_data = member_lookup.get(r['email'].lower(), {
                        'first_name':  r.get('name', '').split(' ')[0] if r.get('name') else '',
                        'surname':     ' '.join(r.get('name', '').split(' ')[1:]) if r.get('name') else '',
                        'email':       r['email'],
                        'member_type': '',
                        'custom':      {},
                    })
                    personalised_body    = _substitute_fields(body, member_data)
                    personalised_subject = _substitute_fields(subject, member_data)

                    # v12.70: branded wrapper + optional inline logo (multipart/related)
                    if _brand_wrap:
                        personalised_body = _apply_brand_wrap(personalised_body)
                    html_part = MIMEText(personalised_body, 'html', 'utf-8')
                    if _brand_wrap and _logo_bytes:
                        content = MIMEMultipart('related')
                        content.attach(html_part)
                        _img = MIMEImage(_logo_bytes, _subtype=_logo_subtype)
                        _img.add_header('Content-ID', '<brandlogo>')
                        _img.add_header('Content-Disposition', 'inline',
                                        filename=_brand['brand_logo_file'])
                        content.attach(_img)
                    else:
                        content = html_part

                    if attachments:
                        msg = MIMEMultipart('mixed')
                        msg.attach(content)
                    elif isinstance(content, MIMEMultipart):
                        msg = content
                    else:
                        msg = MIMEMultipart('alternative')
                        msg.attach(content)
                    msg['Subject'] = personalised_subject
                    msg['From']    = _smtp_from
                    msg['To']      = r['email']

                    for att in attachments:
                        part = MIMEBase('application', 'octet-stream')
                        part.set_payload(att['data'])
                        encoders.encode_base64(part)
                        part.add_header(
                            'Content-Disposition',
                            'attachment',
                            filename=att['filename'],
                        )
                        part.set_type(att['mime_type'])
                        msg.attach(part)

                    srv.sendmail(_smtp_from, [r['email']], msg.as_string())
                    emails_sent += 1
                except Exception as e:
                    errors.append({'email': r['email'], 'error': str(e)})
    except smtplib.SMTPAuthenticationError:
        return jsonify({'error': 'SMTP authentication failed — check the sender profile credentials in Settings → Email Senders'}), 503
    except Exception as e:
        current_app.logger.error(f'Mailshot SMTP error: {e}')
        return jsonify({'error': f'Failed to connect to the mail server: {e}'}), 503

    # v12.56: stamp the session note once at least one email actually went out
    if _incident_note is not None and emails_sent > 0:
        db.execute(
            "UPDATE session_notes SET notified_at = datetime('now'), notified_by = ? WHERE id = ?",
            (session['user_id'], incident_note_id)
        )
        log_action('incident_notified', 'session_notes', incident_note_id, {
            'member_id':    _incident_note['member_id'],
            'note_type':    _incident_note['note_type'],
            'session_type': _incident_note['session_type'],
            'session_date': _incident_note['session_date'],
            'recipients':   [r['email'] for r in recipients],
            'sent':         emails_sent,
        })

    # Log mailshot — store document IDs and profile used in filter_criteria for audit trail
    log_meta = {
        'recipients':       len(recipients),
        'manual_selection': bool(explicit_recip),
        'document_ids':     list(document_ids) if document_ids else [],
        'smtp_profile_id':  profile_id or (_prof['id'] if _prof else None),
        'incident_note_id': incident_note_id if _incident_note is not None else None,
    }
    db.execute(
        'INSERT INTO mailshot_log (template_id, subject, sent_by, recipient_count, filter_criteria, notes)'
        ' VALUES (?,?,?,?,?,?)',
        (
            template_id,
            subject,
            session['user_id'],
            emails_sent,
            json.dumps(log_meta),
            f'{len(errors)} error(s)' if errors else None,
        )
    )
    db.commit()
    log_action('send_mailshot', 'mailshot_log', None, {
        'subject': subject, 'sent': emails_sent, 'errors': len(errors),
        'attachments': len(attachments),
    })
    return jsonify({'success': True, 'sent': emails_sent, 'errors': errors})


# ── Incident notifications (v12.56) ───────────────────────────────────────────

@bp.route('/api/comms/incidents')
@permission_required('mailshots.send')
def api_comms_incidents():
    """Member-linked session notes for the incidents panel, newest first.

    ?days=N   window (default 30, clamped 1–365)
    ?note_id= fetch one specific note regardless of the window (deep links
              from the register may reference an older note)

    Each row carries the member's parent/guardian contacts (email holders
    only) and the notified_at/notified_by receipt. Session-scoped users only
    see notes from their own sessions."""
    db = get_db()
    try:
        days = max(1, min(365, int(request.args.get('days', 30))))
    except (ValueError, TypeError):
        days = 30
    note_id = request.args.get('note_id')

    conditions = ['sn.member_id IS NOT NULL']
    params     = []
    if note_id:
        # v12.68: cast before touching the conditions list (hygiene — the old
        # order appended the clause before the int() could raise).
        try:
            note_id = int(note_id)
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid note id'}), 400
        conditions.append('sn.id = ?')
        params.append(note_id)
    else:
        conditions.append("sn.created_at >= datetime('now', ?)")
        params.append(f'-{days} days')

    scoped = _assigned_session()
    if scoped is not None:
        if not scoped:
            return jsonify([])
        ph = ','.join('?' * len(scoped))
        conditions.append(f'sn.session_type IN ({ph})')
        params.extend(scoped)

    rows = db.execute(f'''
        SELECT  sn.id, sn.session_date, sn.session_type, sn.note_type,
                sn.title, sn.details, sn.created_at,
                sn.notified_at, sn.member_id,
                u.username  AS added_by_name,
                un.username AS notified_by_name,
                m.first_name || ' ' || m.surname AS member_name
        FROM    session_notes sn
        JOIN    members m  ON m.id  = sn.member_id
        LEFT JOIN users u  ON u.id  = sn.added_by
        LEFT JOIN users un ON un.id = sn.notified_by
        WHERE   {' AND '.join(conditions)}
        ORDER   BY sn.created_at DESC
        LIMIT   100
    ''', params).fetchall()

    # v12.68: batch the contact lookups (was one query per note row — N+1).
    contacts_map = {}
    member_ids = list({r['member_id'] for r in rows})
    if member_ids:
        ph = ','.join('?' * len(member_ids))
        for c in db.execute(
            f'SELECT member_id, contact_name, contact_email FROM member_contacts '
            f'WHERE member_id IN ({ph}) ORDER BY member_id, contact_order',
            member_ids
        ).fetchall():
            if (c['contact_email'] or '').strip():
                contacts_map.setdefault(c['member_id'], []).append(
                    {'name': c['contact_name'], 'email': c['contact_email'].strip()})

        # v12.73: staff have no contact rows — their own email is on the members
        # row — so the incident checklist rendered empty and nobody could be
        # notified about a staff incident. Mirrors the send-side validation.
        for s in db.execute(
            f'SELECT m.id, m.email, m.first_name || " " || m.surname AS nm '
            f'FROM members m WHERE m.id IN ({ph}) AND {_STAFF_TYPE_SQL} '
            f'AND m.email IS NOT NULL AND trim(m.email) != ""',
            member_ids
        ).fetchall():
            existing = {e['email'].lower() for e in contacts_map.get(s['id'], [])}
            if s['email'].strip().lower() not in existing:
                contacts_map.setdefault(s['id'], []).append(
                    {'name': s['nm'], 'email': s['email'].strip()})

    out = []
    for r in rows:
        d = dict(r)
        d['contacts'] = [{'name': c['name'] or d['member_name'], 'email': c['email']}
                         for c in contacts_map.get(r['member_id'], [])]
        out.append(d)
    return jsonify(out)


@bp.route('/api/mailshots')
@permission_required('mailshots.send')
def api_mailshots_history():
    db   = get_db()
    rows = db.execute('''
        SELECT  ml.*, u.username AS sent_by_name,
                et.name AS template_name
        FROM    mailshot_log ml
        LEFT JOIN users u ON u.id = ml.sent_by
        LEFT JOIN email_templates et ON et.id = ml.template_id
        ORDER   BY ml.sent_at DESC
        LIMIT   50
    ''').fetchall()
    return jsonify([dict(r) for r in rows])
