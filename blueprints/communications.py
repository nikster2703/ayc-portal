"""
AYC Portal — Communications blueprint.
Routes: /api/email-templates/*, /api/mailshots/*, /api/mailshots
"""

import json
import os
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

def _get_recipients(session_filter, status_filter):
    """
    Return a deduplicated list of {email, name} dicts from member_contacts
    (contact_order=1) matching the given filters.
    Editors are automatically scoped to their own session.
    """
    db         = get_db()
    conditions = ["m.status != 'Leaver'"]
    params     = []

    if status_filter and status_filter != 'all':
        conditions.append('m.status = ?')
        params.append(status_filter)

    scoped = _assigned_session()
    if scoped is not None:
        conditions.append('m.session = ?')
        params.append(scoped)
    elif session_filter and session_filter != 'all':
        conditions.append('m.session = ?')
        params.append(session_filter)

    where = ' AND '.join(conditions)
    rows  = db.execute(f'''
        SELECT  DISTINCT c.contact_email,
                m.first_name || " " || m.surname AS member_name
        FROM    members m
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
    recipients = _get_recipients(data.get('session_filter'), data.get('status_filter'))
    return jsonify({'count': len(recipients), 'recipients': recipients})


@bp.route('/api/mailshots/send', methods=['POST'])
@permission_required('mailshots.send')
def api_mailshots_send():
    """Send a mailshot via Gmail SMTP and log it."""
    data           = request.get_json() or {}
    subject        = data.get('subject', '').strip()
    body           = data.get('body_html', '').strip()
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
        recipients = _get_recipients(session_filter, 'Active')

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

    emails_sent = 0
    errors      = []
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as srv:
            srv.ehlo()
            srv.starttls()
            srv.login(SMTP_USER, SMTP_PASS)
            for r in recipients:
                try:
                    msg = MIMEMultipart('mixed') if attachments else MIMEMultipart('alternative')
                    msg['Subject'] = subject
                    msg['From']    = SMTP_FROM
                    msg['To']      = r['email']
                    msg.attach(MIMEText(body, 'html', 'utf-8'))

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
