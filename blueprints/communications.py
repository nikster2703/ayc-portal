"""
AYC Portal — Communications blueprint.
Routes: /api/email-templates/*, /api/mailshots/*, /api/mailshots
"""

import json
import os
import re
import smtplib
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from flask import Blueprint, current_app, jsonify, request, session

from config import SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM
from helpers import (
    get_db, log_action, permission_required, _assigned_session,
    decrypt_file, resolve_doc_path, user_can_access_doc,
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


def _build_member_lookup(emails):
    """
    Given a list of email addresses, return a dict keyed by email with member
    data and custom field values.  Used for per-recipient merge substitution.

    Covers three sources:
      1. Standard tokens  — first_name, surname, member_type, email (top-level keys)
      2. First-class cols — all columns in _FC_LABELS fetched directly from members
      3. Custom fields    — member_field_values rows for truly custom field_definitions
      4. Contacts         — primary and secondary contact details from member_contacts
    """
    if not emails:
        return {}
    db = get_db()
    ph = ','.join('?' * len(emails))
    rows = db.execute(f'''
        SELECT  m.id, m.first_name, m.surname, m.member_type,
                m.date_of_birth, m.address, m.postcode, m.ethnicity_religion,
                m.medical_sen, m.gp_contact, m.unattended_exit, m.gdpr_consent,
                m.status, m.session, m.staff_role, m.mobile,
                m.date_registered, m.comments,
                c.contact_email AS email,
                c.contact_name  AS c1_name,
                c.contact_phone AS c1_phone
        FROM    members m
        JOIN    member_contacts c ON c.member_id = m.id AND c.contact_order = 1
        WHERE   lower(c.contact_email) IN ({ph})
    ''', [e.lower() for e in emails]).fetchall()

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
        custom['Primary Contact — Email']     = r['email']    or ''

        # ── Contact 2 ─────────────────────────────────────────────────────
        c2 = c2_map.get(r['id'])
        custom['Second Contact — Full Name'] = (c2['contact_name']  if c2 else '') or ''
        custom['Second Contact — Phone']     = (c2['contact_phone'] if c2 else '') or ''
        custom['Second Contact — Email']     = (c2['contact_email'] if c2 else '') or ''

        lookup[r['email'].lower()] = {
            'first_name':  r['first_name'] or '',
            'surname':     r['surname']    or '',
            'member_type': r['member_type'] or '',
            'email':       r['email']      or '',
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
            SELECT fd.key, fd.label
            FROM   field_definitions fd
            JOIN   member_type_fields mtf ON mtf.field_id = fd.id
            JOIN   member_types mt        ON mt.id = mtf.member_type_id
            WHERE  mt.slug = ?
            ORDER  BY fd.label
        ''', (member_type,)).fetchall()
    else:
        rows = db.execute('SELECT key, label FROM field_definitions ORDER BY label').fetchall()
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
    with '— no value' so the composer can see exactly which fields are missing."""
    data      = request.get_json() or {}
    body_html = data.get('body_html', '')
    email     = (data.get('email') or '').strip().lower()

    if email:
        lookup = _build_member_lookup([email])
        member = lookup.get(email)
        if member:
            body_html = _substitute_fields(body_html, member)

    # Highlight any tokens that were not substituted (field has no value for this member)
    body_html = re.sub(r'\{[^}<>]+\}', _NO_VALUE_SPAN, body_html)
    return jsonify({'html': body_html})

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

    scoped = _assigned_session()
    if scoped is not None:
        # scoped is a list of session names; non-admin users are restricted to their sessions.
        # Also include members with no session assigned (session IS NULL / '') so that
        # unassigned members are always reachable.
        if scoped:
            ph = ','.join('?' * len(scoped))
            conditions.append(f"(m.session IN ({ph}) OR m.session IS NULL OR m.session = '')")
            params.extend(scoped)
        # empty scoped list means the user has no sessions — return nothing
        else:
            conditions.append('1=0')
    elif session_filter and session_filter != 'all':
        # Include members explicitly assigned to this session, plus those with no session
        # set (NULL / empty) — unassigned members are treated as belonging to all sessions.
        conditions.append("(m.session = ? OR m.session IS NULL OR m.session = '')")
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
    rows  = db.execute(f'''
        SELECT  DISTINCT c.contact_email,
                m.first_name || " " || m.surname AS member_name
        FROM    members m
        {flag_join}
        JOIN    member_contacts c ON c.member_id = m.id AND c.contact_order = 1
        WHERE   {where}
          AND   c.contact_email IS NOT NULL
          AND   trim(c.contact_email) != ""
        ORDER   BY m.first_name
    ''', params).fetchall()
    return [{'email': r['contact_email'], 'name': r['member_name']} for r in rows]


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
    """Send a mailshot via Gmail SMTP and log it."""
    data           = request.get_json() or {}
    subject        = (data.get('subject') or '').strip()
    body           = (data.get('body_html') or '').strip()
    template_id    = data.get('template_id')
    explicit_recip = data.get('recipients')        # list of {email, name} from frontend checklist
    document_ids   = data.get('document_ids', [])  # list of document IDs to attach

    if not subject or not body:
        return jsonify({'error': 'Subject and body are required'}), 400
    if not SMTP_USER or not SMTP_PASS:
        return jsonify({'error': 'Email not configured — add MAIL_USERNAME and MAIL_PASSWORD to your .env file'}), 503

    # Use explicit selection from the frontend checklist; fall back to filter query
    if explicit_recip and isinstance(explicit_recip, list):
        recipients = [r for r in explicit_recip if r.get('email')]
    else:
        session_filter = data.get('session_filter', 'all')
        recipients = _get_recipients(session_filter, status_filter=None)  # defaults to active behaviour

    if not recipients:
        return jsonify({'error': 'No recipients selected'}), 400

    # Resolve and validate attachments from the document repository
    db          = get_db()
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

    emails_sent = 0
    errors      = []
    try:
        # Port 465 uses implicit SSL; all other ports (e.g. 587) use STARTTLS
        if SMTP_PORT == 465:
            ctx = smtplib.ssl.create_default_context()
            srv_cm = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15, context=ctx)
        else:
            srv_cm = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15)
        with srv_cm as srv:
            srv.ehlo()
            if SMTP_PORT != 465:
                srv.starttls()
                srv.ehlo()
            srv.login(SMTP_USER, SMTP_PASS)
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

                    msg = MIMEMultipart('mixed') if attachments else MIMEMultipart('alternative')
                    msg['Subject'] = personalised_subject
                    msg['From']    = SMTP_FROM
                    msg['To']      = r['email']
                    msg.attach(MIMEText(personalised_body, 'html', 'utf-8'))

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

                    srv.sendmail(SMTP_FROM, [r['email']], msg.as_string())
                    emails_sent += 1
                except Exception as e:
                    errors.append({'email': r['email'], 'error': str(e)})
    except smtplib.SMTPAuthenticationError:
        return jsonify({'error': 'Gmail authentication failed — check your App Password in .env'}), 503
    except Exception as e:
        current_app.logger.error(f'Mailshot SMTP error: {e}')
        return jsonify({'error': 'Failed to connect to the mail server. Check SMTP settings in .env.'}), 503

    # Log mailshot — store document IDs in filter_criteria for audit trail
    log_meta = {
        'recipients':       len(recipients),
        'manual_selection': bool(explicit_recip),
        'document_ids':     list(document_ids) if document_ids else [],
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
