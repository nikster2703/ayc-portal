"""
AYC Portal — Documents blueprint.
Routes: /api/documents/*, /api/documents/categories, /api/documents/field-definitions
"""

import json
import os
import uuid as _uuid_mod
from datetime import date as _date, timedelta as _td

from flask import Blueprint, current_app, jsonify, request, session
from werkzeug.utils import secure_filename

from config import UPLOAD_DIR
from helpers import (
    get_db, log_action, login_required, permission_required,
    encrypt_file, decrypt_file,
    resolve_doc_path, user_can_access_doc, _user_can_access_from_group_concat,
    _fts5_available, _rebuild_doc_fts,
    allowed_file,
)

bp = Blueprint('documents', __name__)


# ── Document categories API ───────────────────────────────────────────────────

@bp.route('/api/documents/categories')
@login_required
def api_document_categories_list():
    db               = get_db()
    include_inactive = request.args.get('include_inactive') == '1' and \
                       'admin.settings' in (session.get('permissions') or [])
    where = '' if include_inactive else 'WHERE active = 1'
    rows  = db.execute(
        f'SELECT * FROM document_categories {where} ORDER BY sort_order, name'
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route('/api/documents/categories', methods=['POST'])
@permission_required('admin.settings')
def api_document_categories_create():
    data = request.get_json(force=True) or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'Name is required'}), 400
    db = get_db()
    if db.execute('SELECT id FROM document_categories WHERE name = ?', (name,)).fetchone():
        return jsonify({'error': 'A category with that name already exists'}), 409
    max_order = db.execute('SELECT COALESCE(MAX(sort_order),0) FROM document_categories').fetchone()[0]
    cur = db.execute(
        'INSERT INTO document_categories (name, description, icon, color, sort_order) VALUES (?,?,?,?,?)',
        (name, data.get('description', ''), data.get('icon', '📄'),
         data.get('color', '#64748b'), max_order + 1)
    )
    db.commit()
    log_action('create_document_category', 'document_categories', cur.lastrowid, {'name': name})
    return jsonify({'success': True, 'id': cur.lastrowid})


@bp.route('/api/documents/categories/<int:cat_id>', methods=['PUT'])
@permission_required('admin.settings')
def api_document_categories_update(cat_id):
    db  = get_db()
    cat = db.execute('SELECT * FROM document_categories WHERE id = ?', (cat_id,)).fetchone()
    if not cat:
        return jsonify({'error': 'Not found'}), 404
    data = request.get_json(force=True) or {}
    fields, vals = [], []
    for col in ('name', 'description', 'icon', 'color', 'sort_order', 'active'):
        if col in data:
            fields.append(f'{col} = ?')
            vals.append(data[col])
    if not fields:
        return jsonify({'error': 'Nothing to update'}), 400
    vals.append(cat_id)
    db.execute(f'UPDATE document_categories SET {", ".join(fields)} WHERE id = ?', vals)
    db.commit()
    log_action('update_document_category', 'document_categories', cat_id, data)
    return jsonify({'success': True})


@bp.route('/api/documents/categories/<int:cat_id>', methods=['DELETE'])
@permission_required('admin.settings')
def api_document_categories_delete(cat_id):
    db = get_db()
    if not db.execute('SELECT id FROM document_categories WHERE id = ?', (cat_id,)).fetchone():
        return jsonify({'error': 'Not found'}), 404
    # Soft-deactivate so existing documents retain their category reference
    db.execute('UPDATE document_categories SET active = 0 WHERE id = ?', (cat_id,))
    db.commit()
    log_action('deactivate_document_category', 'document_categories', cat_id, {})
    return jsonify({'success': True})


# ── Document field definitions API ───────────────────────────────────────────

@bp.route('/api/documents/field-definitions')
@login_required
def api_doc_field_definitions_list():
    """Return field definitions, optionally filtered by category_id.
    Pass include_inactive=1 (admin only) to include deactivated fields."""
    db               = get_db()
    category_id      = request.args.get('category_id')
    include_inactive = request.args.get('include_inactive') == '1' and \
                       'admin.settings' in (session.get('permissions') or [])
    active_clause    = '' if include_inactive else 'AND df.active = 1'

    if category_id:
        rows = db.execute(
            f'''SELECT df.*, dc.name AS category_name
               FROM document_field_definitions df
               JOIN document_categories dc ON dc.id = df.category_id
               WHERE df.category_id = ? {active_clause}
               ORDER BY df.sort_order, df.label''',
            (category_id,)
        ).fetchall()
    else:
        rows = db.execute(
            f'''SELECT df.*, dc.name AS category_name
               FROM document_field_definitions df
               JOIN document_categories dc ON dc.id = df.category_id
               WHERE 1=1 {active_clause}
               ORDER BY dc.sort_order, df.sort_order, df.label'''
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route('/api/documents/field-definitions', methods=['POST'])
@permission_required('admin.settings')
def api_doc_field_definitions_create():
    data        = request.get_json(force=True) or {}
    category_id = data.get('category_id')
    label       = (data.get('label') or '').strip()
    field_type  = data.get('field_type', 'text')

    if not category_id:
        return jsonify({'error': 'category_id is required'}), 400
    if not label:
        return jsonify({'error': 'label is required'}), 400
    if field_type not in ('text', 'date', 'number', 'boolean', 'member_ref'):
        return jsonify({'error': 'Invalid field_type'}), 400

    db = get_db()
    if not db.execute('SELECT id FROM document_categories WHERE id = ? AND active = 1',
                      (category_id,)).fetchone():
        return jsonify({'error': 'Category not found'}), 404

    max_order = db.execute(
        'SELECT COALESCE(MAX(sort_order),0) FROM document_field_definitions WHERE category_id = ?',
        (category_id,)
    ).fetchone()[0]

    cur = db.execute(
        '''INSERT INTO document_field_definitions
           (category_id, label, field_type, help_text, placeholder, required, sort_order)
           VALUES (?,?,?,?,?,?,?)''',
        (category_id, label, field_type,
         data.get('help_text', '') or None,
         data.get('placeholder', '') or None,
         1 if data.get('required') else 0,
         max_order + 1)
    )
    db.commit()
    log_action('create_doc_field', 'document_field_definitions', cur.lastrowid,
               {'label': label, 'category_id': category_id, 'field_type': field_type})
    return jsonify({'success': True, 'id': cur.lastrowid})


@bp.route('/api/documents/field-definitions/<int:field_id>', methods=['PUT'])
@permission_required('admin.settings')
def api_doc_field_definitions_update(field_id):
    db    = get_db()
    field = db.execute('SELECT * FROM document_field_definitions WHERE id = ?', (field_id,)).fetchone()
    if not field:
        return jsonify({'error': 'Not found'}), 404
    data       = request.get_json(force=True) or {}
    fields, vals = [], []
    for col in ('label', 'field_type', 'help_text', 'placeholder', 'required', 'sort_order', 'active'):
        if col in data:
            fields.append(f'{col} = ?')
            vals.append(data[col])
    if not fields:
        return jsonify({'error': 'Nothing to update'}), 400
    vals.append(field_id)
    db.execute(f'UPDATE document_field_definitions SET {", ".join(fields)} WHERE id = ?', vals)
    db.commit()
    log_action('update_doc_field', 'document_field_definitions', field_id, data)
    return jsonify({'success': True})


@bp.route('/api/documents/field-definitions/<int:field_id>', methods=['DELETE'])
@permission_required('admin.settings')
def api_doc_field_definitions_delete(field_id):
    db = get_db()
    if not db.execute('SELECT id FROM document_field_definitions WHERE id = ?', (field_id,)).fetchone():
        return jsonify({'error': 'Not found'}), 404
    meta_count = db.execute(
        'SELECT COUNT(*) FROM document_metadata WHERE field_id = ?', (field_id,)
    ).fetchone()[0]
    # Permanent delete — document_metadata.field_id has ON DELETE CASCADE
    db.execute('DELETE FROM document_field_definitions WHERE id = ?', (field_id,))
    db.commit()
    log_action('delete_doc_field', 'document_field_definitions', field_id,
               {'metadata_deleted': meta_count})
    return jsonify({'success': True, 'metadata_deleted': meta_count})


# ── Document list ─────────────────────────────────────────────────────────────

@bp.route('/api/documents')
@permission_required('documents.view')
def api_documents_list():
    db = get_db()

    # ── Collect filter params ─────────────────────────────────────────────────
    q           = (request.args.get('q') or '').strip()
    category_id = request.args.get('category_id') or None

    # Condition builder: cond_N_field / cond_N_op / cond_N_value  (N = 0..19)
    conditions = []
    for n in range(20):
        f_field = request.args.get(f'cond_{n}_field', '').strip()
        f_op    = request.args.get(f'cond_{n}_op',    '').strip()
        if not f_field or not f_op:
            continue
        f_val = request.args.get(f'cond_{n}_value', '').strip()
        conditions.append((f_field, f_op, f_val))

    # ── FTS5 full-text search → restrict to matching doc_ids ─────────────────
    fts_ids = None
    if q:
        if _fts5_available(db):
            try:
                safe_q = ' '.join(
                    f'"{t}"*' for t in q.replace('"', '').split() if t
                )
                fts_rows = db.execute(
                    'SELECT doc_id FROM documents_fts WHERE documents_fts MATCH ? ORDER BY rank',
                    (safe_q,)
                ).fetchall()
                fts_ids = {r['doc_id'] for r in fts_rows}
            except Exception:
                fts_ids = None  # FTS query error — fall through to LIKE

    # ── Build base SQL with filters ───────────────────────────────────────────
    where_clauses = ['d.active = 1']
    params        = []

    if fts_ids is not None:
        if not fts_ids:
            return jsonify([])   # FTS matched nothing
        placeholders = ','.join('?' * len(fts_ids))
        where_clauses.append(f'd.id IN ({placeholders})')
        params.extend(fts_ids)
    elif q:
        # FTS unavailable — LIKE fallback across title + description
        like = f'%{q}%'
        where_clauses.append('(d.title LIKE ? OR d.description LIKE ?)')
        params.extend([like, like])

    if category_id:
        where_clauses.append('d.category_id = ?')
        params.append(category_id)

    where_sql = ' AND '.join(where_clauses)

    rows = db.execute(f'''
        SELECT d.*,
               dc.name  AS category_name,
               dc.icon  AS category_icon,
               dc.color AS category_color,
               u.username AS uploaded_by_name,
               GROUP_CONCAT(dra.role_id) AS allowed_role_ids
        FROM   documents d
        LEFT JOIN document_categories dc   ON dc.id  = d.category_id
        LEFT JOIN users u                  ON u.id   = d.uploaded_by
        LEFT JOIN document_role_access dra ON dra.document_id = d.id
        WHERE  {where_sql}
        GROUP  BY d.id
        ORDER  BY COALESCE(dc.sort_order, 999), d.title
    ''', params).fetchall()

    docs = [dict(r) for r in rows if _user_can_access_from_group_concat(r['allowed_role_ids'])]

    # ── Apply condition filters (post-fetch) ──────────────────────────────────
    if conditions and docs:
        # Load raw metadata values for all candidate docs (keyed by field_id int)
        cond_doc_ids   = [d['id'] for d in docs]
        cond_meta_rows = db.execute(
            f'''SELECT dm.document_id, dm.field_id, dm.value
                FROM document_metadata dm
                WHERE dm.document_id IN ({",".join("?" * len(cond_doc_ids))})''',
            cond_doc_ids
        ).fetchall()
        cond_meta_by_doc: dict = {}
        for mr in cond_meta_rows:
            cond_meta_by_doc.setdefault(mr['document_id'], {})[mr['field_id']] = mr['value']

        def passes_conditions(doc):
            today     = _date.today()
            meta_vals = cond_meta_by_doc.get(doc['id'], {})
            for c_field, c_op, c_val in conditions:
                if c_field == 'title':
                    actual = doc.get('title') or ''
                elif c_field == 'description':
                    actual = doc.get('description') or ''
                elif c_field == 'uploader':
                    actual = doc.get('uploaded_by_name') or ''
                elif c_field == 'upload_date':
                    actual = (doc.get('created_at') or '')[:10]
                elif c_field == 'retain_until':
                    actual = doc.get('retain_until') or ''
                elif c_field.startswith('meta_'):
                    try:
                        fid = int(c_field[5:])
                    except ValueError:
                        continue
                    actual = meta_vals.get(fid) or ''
                else:
                    continue

                if c_op == 'is_empty':
                    if actual.strip():
                        return False
                elif c_op == 'is_filled':
                    if not actual.strip():
                        return False
                elif c_op == 'contains':
                    if c_val.lower() not in actual.lower():
                        return False
                elif c_op == 'eq':
                    if actual.lower() != c_val.lower():
                        return False
                elif c_op == 'before':
                    if not actual or actual > c_val:
                        return False
                elif c_op == 'after':
                    if not actual or actual < c_val:
                        return False
                elif c_op == 'older_than':
                    try:
                        days   = int(c_val)
                        cutoff = (today - _td(days=days)).isoformat()
                        if not actual or actual >= cutoff:
                            return False
                    except (ValueError, TypeError):
                        pass
                elif c_op == 'gt':
                    try:
                        if not actual or float(actual) <= float(c_val):
                            return False
                    except (ValueError, TypeError):
                        return False
                elif c_op == 'lt':
                    try:
                        if not actual or float(actual) >= float(c_val):
                            return False
                    except (ValueError, TypeError):
                        return False
                elif c_op == 'is_true':
                    if actual.lower() not in ('1', 'true', 'yes'):
                        return False
                elif c_op == 'is_false':
                    if actual.lower() in ('1', 'true', 'yes'):
                        return False
            return True

        docs = [d for d in docs if passes_conditions(d)]

    # ── Attach metadata summaries for card display ────────────────────────────
    if docs:
        doc_ids   = [d['id'] for d in docs]
        meta_rows = db.execute(
            f'''SELECT dm.document_id, df.label, df.field_type, df.sort_order, dm.value
                FROM document_metadata dm
                JOIN document_field_definitions df ON df.id = dm.field_id
                WHERE dm.document_id IN ({",".join("?" * len(doc_ids))})
                  AND dm.value IS NOT NULL AND dm.value != ''
                  AND df.active = 1
                ORDER BY dm.document_id, df.sort_order''',
            doc_ids
        ).fetchall()

        # Resolve member names
        member_ids   = {r['value'] for r in meta_rows if r['field_type'] == 'member_ref' and r['value']}
        member_names = {}
        if member_ids:
            mrows = db.execute(
                f'SELECT id, first_name, surname FROM members WHERE id IN ({",".join("?" * len(member_ids))})',
                list(member_ids)
            ).fetchall()
            member_names = {str(m['id']): f"{m['first_name']} {m['surname']}" for m in mrows}

        meta_by_doc = {}
        for mr in meta_rows:
            display = (member_names.get(mr['value'], mr['value'])
                       if mr['field_type'] == 'member_ref' else mr['value'])
            meta_by_doc.setdefault(mr['document_id'], []).append({
                'label':      mr['label'],
                'field_type': mr['field_type'],
                'value':      mr['value'],
                'display':    display,
            })

        for doc in docs:
            doc['metadata'] = meta_by_doc.get(doc['id'], [])

    return jsonify(docs)


# ── Document upload ───────────────────────────────────────────────────────────

@bp.route('/api/documents', methods=['POST'])
@permission_required('documents.upload')
def api_documents_upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    f = request.files['file']
    if not f.filename:
        return jsonify({'error': 'No file selected'}), 400
    if not allowed_file(f.filename):
        return jsonify({'error': 'File type not allowed'}), 400

    title            = request.form.get('title', '').strip() or secure_filename(f.filename)
    description      = request.form.get('description', '').strip()
    category_id      = request.form.get('category_id') or None
    retain_until     = request.form.get('retain_until', '').strip() or None
    retention_notes  = request.form.get('retention_notes', '').strip() or None

    # Role restriction — JSON array of role IDs; empty = no restriction
    try:
        role_ids = json.loads(request.form.get('role_ids', '[]'))
        role_ids = [int(r) for r in role_ids if str(r).strip().isdigit()]
    except (ValueError, TypeError):
        role_ids = []

    db = get_db()
    if category_id:
        if not db.execute('SELECT id FROM document_categories WHERE id = ? AND active = 1',
                          (category_id,)).fetchone():
            category_id = None

    # Generate UUID stored filename — no original name or extension on disk
    stored_filename = _uuid_mod.uuid4().hex
    bucket          = 'store'
    bucket_dir      = os.path.join(UPLOAD_DIR, bucket)
    os.makedirs(bucket_dir, exist_ok=True)

    raw_bytes      = f.read()
    file_size      = len(raw_bytes)
    encrypted_data = encrypt_file(raw_bytes)
    with open(os.path.join(bucket_dir, stored_filename), 'wb') as fh:
        fh.write(encrypted_data)

    mime      = f.mimetype or 'application/octet-stream'
    safe_name = secure_filename(f.filename)   # stored in DB for display/download only

    cur = db.execute(
        '''INSERT INTO documents
           (title, filename, file_path, stored_filename, bucket, mime_type, file_size,
            category_id, description, retain_until, retention_notes, uploaded_by)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
        (title, safe_name, '', stored_filename, bucket, mime, file_size,
         category_id, description or None, retain_until, retention_notes, session['user_id'])
    )
    # file_path is '' for v9.0+ rows — resolve_doc_path() uses stored_filename + bucket instead
    doc_id = cur.lastrowid

    for rid in role_ids:
        try:
            db.execute('INSERT OR IGNORE INTO document_role_access (document_id, role_id) VALUES (?,?)',
                       (doc_id, rid))
        except Exception:
            pass

    db.commit()
    _rebuild_doc_fts(db, doc_id)
    log_action('upload_document', 'documents', doc_id,
               {'title': title, 'category_id': category_id, 'restricted_to_roles': role_ids})
    return jsonify({'success': True, 'id': doc_id})


# ── Document update ───────────────────────────────────────────────────────────

@bp.route('/api/documents/<int:doc_id>', methods=['PUT'])
@permission_required('documents.upload')
def api_documents_update(doc_id):
    """Edit document metadata (title, description, category, retention, role access)."""
    db  = get_db()
    doc = db.execute('SELECT * FROM documents WHERE id = ? AND active = 1', (doc_id,)).fetchone()
    if not doc:
        return jsonify({'error': 'Not found'}), 404
    if not user_can_access_doc(doc):
        return jsonify({'error': 'Forbidden'}), 403

    data         = request.get_json(force=True) or {}
    fields, vals = [], []
    for col in ('title', 'description', 'category_id', 'retain_until', 'retention_notes'):
        if col in data:
            fields.append(f'{col} = ?')
            vals.append(data[col] or None)
    if fields:
        vals.append(doc_id)
        db.execute(f'UPDATE documents SET {", ".join(fields)} WHERE id = ?', vals)

    # Update role access if provided
    if 'role_ids' in data:
        try:
            role_ids = [int(r) for r in data['role_ids'] if str(r).strip().isdigit()]
        except (ValueError, TypeError):
            role_ids = []
        db.execute('DELETE FROM document_role_access WHERE document_id = ?', (doc_id,))
        for rid in role_ids:
            db.execute('INSERT OR IGNORE INTO document_role_access (document_id, role_id) VALUES (?,?)',
                       (doc_id, rid))
        log_action('update_document_access', 'documents', doc_id,
                   {'restricted_to_roles': role_ids})

    db.commit()
    _rebuild_doc_fts(db, doc_id)
    log_action('update_document', 'documents', doc_id, {k: data[k] for k in data if k != 'role_ids'})
    return jsonify({'success': True})


# ── Document access (role restrictions) ──────────────────────────────────────

@bp.route('/api/documents/<int:doc_id>/access')
@permission_required('documents.upload')
def api_documents_get_access(doc_id):
    """Return the role IDs that may access this document (empty = unrestricted)."""
    db = get_db()
    if not db.execute('SELECT id FROM documents WHERE id = ? AND active = 1', (doc_id,)).fetchone():
        return jsonify({'error': 'Not found'}), 404
    rows = db.execute(
        '''SELECT dra.role_id, r.name, r.display_name
           FROM document_role_access dra
           JOIN roles r ON r.id = dra.role_id
           WHERE dra.document_id = ?''', (doc_id,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ── Document metadata ─────────────────────────────────────────────────────────

@bp.route('/api/documents/<int:doc_id>/metadata')
@permission_required('documents.view')
def api_documents_get_metadata(doc_id):
    """Return all metadata values for a document, with field definitions."""
    db  = get_db()
    doc = db.execute('SELECT * FROM documents WHERE id = ? AND active = 1', (doc_id,)).fetchone()
    if not doc:
        return jsonify({'error': 'Not found'}), 404
    if not user_can_access_doc(doc):
        return jsonify({'error': 'Forbidden'}), 403

    rows = db.execute(
        '''SELECT df.id AS field_id, df.label, df.field_type, df.help_text,
                  df.placeholder, df.required, df.sort_order,
                  dm.value
           FROM document_field_definitions df
           LEFT JOIN document_metadata dm
                  ON dm.field_id = df.id AND dm.document_id = ?
           WHERE df.category_id = ? AND df.active = 1
           ORDER BY df.sort_order, df.label''',
        (doc_id, doc['category_id'])
    ).fetchall()

    result = []
    for row in rows:
        item = dict(row)
        if row['field_type'] == 'member_ref' and row['value']:
            m = db.execute(
                'SELECT id, first_name, surname FROM members WHERE id = ?', (row['value'],)
            ).fetchone()
            item['member'] = {'id': m['id'], 'name': f"{m['first_name']} {m['surname']}"} if m else None
        result.append(item)

    return jsonify(result)


@bp.route('/api/documents/<int:doc_id>/metadata', methods=['PUT'])
@permission_required('documents.upload')
def api_documents_put_metadata(doc_id):
    """Upsert metadata values for a document. Rebuilds FTS index afterwards."""
    db  = get_db()
    doc = db.execute('SELECT * FROM documents WHERE id = ? AND active = 1', (doc_id,)).fetchone()
    if not doc:
        return jsonify({'error': 'Not found'}), 404
    if not user_can_access_doc(doc):
        return jsonify({'error': 'Forbidden'}), 403

    items = request.get_json(force=True) or []
    if not isinstance(items, list):
        return jsonify({'error': 'Expected a JSON array'}), 400

    for item in items:
        field_id = item.get('field_id')
        value    = item.get('value')
        if field_id is None:
            continue
        field = db.execute(
            'SELECT * FROM document_field_definitions WHERE id = ? AND active = 1', (field_id,)
        ).fetchone()
        if not field or field['category_id'] != doc['category_id']:
            continue
        if value is None or str(value).strip() == '':
            db.execute('DELETE FROM document_metadata WHERE document_id = ? AND field_id = ?',
                       (doc_id, field_id))
        else:
            db.execute(
                '''INSERT INTO document_metadata (document_id, field_id, value, updated_at)
                   VALUES (?,?,?,datetime('now'))
                   ON CONFLICT(document_id, field_id) DO UPDATE SET value=excluded.value,
                   updated_at=excluded.updated_at''',
                (doc_id, field_id, str(value).strip())
            )

    db.commit()
    _rebuild_doc_fts(db, doc_id)
    log_action('update_doc_metadata', 'documents', doc_id, {})
    return jsonify({'success': True})


# ── Document download / view ──────────────────────────────────────────────────

@bp.route('/api/documents/<int:doc_id>/download')
@permission_required('documents.view')
def api_documents_download(doc_id):
    db  = get_db()
    doc = db.execute('SELECT * FROM documents WHERE id = ? AND active = 1', (doc_id,)).fetchone()
    if not doc:
        return jsonify({'error': 'Not found'}), 404
    if not user_can_access_doc(doc):
        return jsonify({'error': 'Forbidden'}), 403
    log_action('download_document', 'documents', doc_id, {'title': doc['title']})
    try:
        with open(resolve_doc_path(doc), 'rb') as fh:
            decrypted = decrypt_file(fh.read())
    except FileNotFoundError:
        return jsonify({'error': 'File not found on disk — it may have been lost during a server migration.'}), 404
    return current_app.response_class(
        decrypted,
        mimetype=doc['mime_type'] or 'application/octet-stream',
        headers={'Content-Disposition': f'attachment; filename="{doc["filename"]}"'},
    )


@bp.route('/api/documents/<int:doc_id>/view')
@permission_required('documents.view')
def api_documents_view(doc_id):
    """Serve the document inline so the browser can render it directly."""
    db  = get_db()
    doc = db.execute('SELECT * FROM documents WHERE id = ? AND active = 1', (doc_id,)).fetchone()
    if not doc:
        return jsonify({'error': 'Not found'}), 404
    if not user_can_access_doc(doc):
        return jsonify({'error': 'Forbidden'}), 403
    log_action('view_document', 'documents', doc_id, {'title': doc['title']})
    try:
        with open(resolve_doc_path(doc), 'rb') as fh:
            decrypted = decrypt_file(fh.read())
    except FileNotFoundError:
        return jsonify({'error': 'File not found on disk — it may have been lost during a server migration.'}), 404
    return current_app.response_class(
        decrypted,
        mimetype=doc['mime_type'] or 'application/octet-stream',
        headers={'Content-Disposition': f'inline; filename="{doc["filename"]}"'},
    )


# ── Document delete ───────────────────────────────────────────────────────────

@bp.route('/api/documents/<int:doc_id>', methods=['DELETE'])
@permission_required('documents.delete')
def api_documents_delete(doc_id):
    db  = get_db()
    doc = db.execute('SELECT * FROM documents WHERE id = ? AND active = 1', (doc_id,)).fetchone()
    if not doc:
        return jsonify({'error': 'Not found'}), 404
    # Hard-delete from disk immediately (GDPR right to erasure)
    try:
        file_path = resolve_doc_path(doc)
        if os.path.exists(file_path):
            os.remove(file_path)
    except OSError:
        pass  # File already gone — don't fail the request
    # Soft-delete the DB row so audit log retains the record
    db.execute('UPDATE documents SET active = 0 WHERE id = ?', (doc_id,))
    db.execute('DELETE FROM document_role_access WHERE document_id = ?', (doc_id,))
    db.commit()
    _rebuild_doc_fts(db, doc_id)   # removes from FTS index (active=0 triggers early return)
    log_action('delete_document', 'documents', doc_id, {'title': doc['title']})
    return jsonify({'success': True})
