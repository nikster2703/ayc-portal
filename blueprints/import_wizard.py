"""
AYC Portal — import wizard: scan a spreadsheet and show a person what is in it.

Routes: /api/admin/import/scan, /api/admin/import/profiles, /admin/import-wizard

Introduced in v12.87 (Phase 1b). This blueprint does not import anything. It
reads a file that has already been uploaded through the existing
/api/admin/import/analyse step and reports what it finds:

  * every column, its type mix, and — for date columns — the convention it
    inferred and the values it cannot resolve without help (dateparse);
  * every formatting convention: fill clusters, strikethrough, font colours,
    and the sheet's house style, which is excluded (sheetscan);
  * proposed households from all four signals, with evidence and the blind
    spots the signals could not reach (household_signals).

Nothing here decides what a marking MEANS. The scan reports that 105 rows are
grey; a person says whether grey means "removed from the mailing list" or
"lapsed" or something else, and that declaration is saved as a PROFILE. The
same colour means different things at different organisations, and inferring
the meaning from correlation is how I read the RA's own convention backwards on
the first pass. Storing it as configuration is what stops the next
organisation's yellow costing anybody a code change.
"""

import json
import os

from flask import Blueprint, jsonify, render_template, request

from config import INSTANCE_DIR
from helpers import get_db, log_action, permission_required, tpl_ctx

import dateparse
import household_signals as HS
import sheetscan

bp = Blueprint('import_wizard', __name__)

# Column roles a person can assign. The role decides how a column is READ, which
# is why the date parser needs it: a future date in a payment column is a
# finding, and in a renewal column it is the column doing its job.
COLUMN_ROLES = {
    'ignore':        'Ignore this column',
    'first_name':    'First name',
    'surname':       'Surname',
    'full_name':     'Full name (split into first/surname)',
    'road':          'Road name',
    'postcode':      'Postcode',
    'email':         'Email address',
    'mobile':        'Phone',
    'member_no':     'Member number',
    'joined':        'Date joined',
    'paid_date':     'Membership payment date',
    'renewal_date':  'Renewal / expiry date',
    'fee':           'Membership fee',
    'donation':      'Donation',
    'notes':         'Notes',
    'custom':        'Custom field',
}

# Roles where a date in the future is expected rather than suspicious.
_FUTURE_OK_ROLES = {'renewal_date'}


def _load_sheet(file_id, file_ext, sheet_name):
    """(values_ws, formats_ws) or (None, error). Two loads: openpyxl gives you
    values OR formulas-and-formatting, never both from one workbook object."""
    import openpyxl
    if not file_id or '/' in file_id or '..' in file_id:
        return None, 'Invalid file id'
    if file_ext not in ('xlsx', 'xlsm'):
        return None, 'Formatting can only be read from .xlsx files'
    path = os.path.join(INSTANCE_DIR, 'data', 'imports', f'{file_id}.{file_ext}')
    if not os.path.exists(path):
        return None, 'Uploaded file not found — please upload it again'
    try:
        wb_v = openpyxl.load_workbook(path, data_only=True)
        wb_f = openpyxl.load_workbook(path)
    except Exception as exc:
        return None, f'Could not read the workbook: {exc}'
    name = sheet_name or wb_v.sheetnames[0]
    if name not in wb_v.sheetnames:
        return None, f'Sheet {name!r} is not in this workbook'
    return (wb_v[name], wb_f[name]), None


def _rows_for_signals(ws, bounds, roles):
    """Turn the sheet into the dicts household_signals wants, using the roles
    a person assigned. Without roles we cannot know which column is a road."""
    col = {}
    for letter, role in (roles or {}).items():
        col.setdefault(role, letter)
    if not col.get('surname'):
        return [], 'Assign a Surname column before proposing households'

    first_row, last_row = bounds['first_row'], bounds['last_row']
    if not first_row or not last_row or last_row < first_row:
        return [], 'This sheet has no data rows'

    def val(r, role):
        letter = col.get(role)
        return ws[f'{letter}{r}'].value if letter else None

    rows = []
    for r in range(first_row, last_row + 1):
        if all(val(r, k) in (None, '') for k in ('first_name', 'surname', 'email')):
            continue
        rows.append({
            'row':        r,
            'first_name': val(r, 'first_name'),
            'surname':    val(r, 'surname'),
            'road':       val(r, 'road'),
            'postcode':   val(r, 'postcode'),
            'email':      val(r, 'email'),
            'paid':       val(r, 'paid_date'),
            'fee':        val(r, 'fee'),
            'notes':      val(r, 'notes'),
        })
    return rows, None


@bp.route('/api/admin/import/scan', methods=['POST'])
@permission_required('admin.maintenance')
def api_import_scan():
    """Structure and formatting of an already-uploaded workbook. Writes nothing.

    Deliberately does NOT take column roles. Scanning reads every cell twice —
    once for values, once for formatting — and the result does not depend on
    what a person has called the columns. Re-running it on every dropdown change
    made the page take a second per keystroke; roles go to /households instead.
    """
    data = request.get_json() or {}
    sheets, err = _load_sheet(
        (data.get('file_id') or '').strip(),
        (data.get('file_ext') or '').strip().lower(),
        (data.get('sheet_name') or '').strip() or None,
    )
    if err:
        return jsonify({'error': err}), 400
    _ws_values, ws_formats = sheets
    header_row = int(data.get('header_row') or 1)
    try:
        scan = sheetscan.scan_sheet(ws_formats, header_row=header_row)
    except Exception as exc:
        return jsonify({'error': f'Could not scan the sheet: {exc}'}), 400

    return jsonify({
        'sheet':        scan['sheet'],
        'data_rows':    scan['data_rows'],
        'header_row':   header_row,
        'first_row':    scan['first_row'],
        'last_row':     scan['last_row'],
        'columns':      scan['columns'],
        'markings': {
            'row_fills':     scan['row_fills'],
            'strikethrough': scan['strikethrough'],
            'font_colours':  scan['font_colours'],
            'house_style':   scan['house_style'],
        },
        'roles_available': COLUMN_ROLES,
    })


@bp.route('/api/admin/import/households', methods=['POST'])
@permission_required('admin.maintenance')
def api_import_households():
    """Propose households for the roles a person has assigned. Writes nothing.

    Separate from /scan because this is what changes as somebody works through
    the column dropdowns, and it needs only the values workbook.
    """
    data = request.get_json() or {}
    sheets, err = _load_sheet(
        (data.get('file_id') or '').strip(),
        (data.get('file_ext') or '').strip().lower(),
        (data.get('sheet_name') or '').strip() or None,
    )
    if err:
        return jsonify({'error': err}), 400
    ws_values, _ws_formats = sheets

    roles = data.get('roles') or {}
    bounds = {
        'first_row': int(data.get('first_row') or 2),
        'last_row':  int(data.get('last_row') or ws_values.max_row),
    }
    struck = [int(r) for r in (data.get('strikethrough') or []) if str(r).isdigit()]

    # Date columns re-read with the role applied, so a renewal column is not
    # reported as 167 suspicious future dates.
    dates = {}
    for letter, role in roles.items():
        if role not in ('paid_date', 'renewal_date', 'joined'):
            continue
        values = [ws_values[f'{letter}{r}'].value
                  for r in range(bounds['first_row'], bounds['last_row'] + 1)]
        _res, summary = dateparse.parse_column(
            values, future_ok=role in _FUTURE_OK_ROLES)
        summary['role_applied'] = role
        dates[letter] = summary

    rows, why = _rows_for_signals(ws_values, bounds, roles)
    if why:
        return jsonify({'proposals': [], 'blind_spots': {}, 'stats': {},
                        'dates': dates, 'note': why})

    props, blind, stats = HS.propose_households(rows, flagged_rows=set(struck))
    return jsonify({
        'proposals':   [p.as_dict() for p in props],
        'blind_spots': blind,
        'stats':       stats,
        'dates':       dates,
        'note':        None,
    })


# ── Marking profiles — the declared MEANING, stored as configuration ─────────

@bp.route('/api/admin/import/profiles')
@permission_required('admin.maintenance')
def api_profiles_list():
    db = get_db()
    rows = db.execute(
        'SELECT id, name, source_hint, config, updated_at FROM import_profiles '
        'ORDER BY name').fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d['config'] = json.loads(d['config'] or '{}')
        except ValueError:
            d['config'] = {}
        out.append(d)
    return jsonify(out)


@bp.route('/api/admin/import/profiles', methods=['POST'])
@permission_required('admin.maintenance')
def api_profile_save():
    """Create or update a profile by NAME, so re-saving next year updates it
    rather than leaving two profiles a person has to choose between."""
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'A name is required'}), 400
    config = data.get('config')
    if not isinstance(config, dict):
        return jsonify({'error': 'config must be an object'}), 400

    db = get_db()
    existing = db.execute(
        'SELECT id FROM import_profiles WHERE LOWER(name) = ?', (name.lower(),)
    ).fetchone()
    payload = json.dumps(config)
    hint = (data.get('source_hint') or '').strip() or None
    if existing:
        db.execute("UPDATE import_profiles SET config = ?, source_hint = ?, "
                   "updated_at = datetime('now') WHERE id = ?",
                   (payload, hint, existing['id']))
        pid = existing['id']
        action = 'update_import_profile'
    else:
        cur = db.execute('INSERT INTO import_profiles (name, source_hint, config) '
                         'VALUES (?,?,?)', (name, hint, payload))
        pid = cur.lastrowid
        action = 'create_import_profile'
    db.commit()
    log_action(action, 'import_profiles', pid, {'name': name})
    return jsonify({'id': pid, 'name': name, 'config': config}), (200 if existing else 201)


@bp.route('/api/admin/import/profiles/<int:profile_id>', methods=['DELETE'])
@permission_required('admin.maintenance')
def api_profile_delete(profile_id):
    db = get_db()
    row = db.execute('SELECT name FROM import_profiles WHERE id = ?',
                     (profile_id,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    db.execute('DELETE FROM import_profiles WHERE id = ?', (profile_id,))
    db.commit()
    log_action('delete_import_profile', 'import_profiles', profile_id,
               {'name': row['name']})
    return jsonify({'success': True})


@bp.route('/admin/import-wizard')
@permission_required('admin.maintenance')
def import_wizard_page():
    return render_template('admin/import_wizard.html', **tpl_ctx())
