"""
AYC Portal — Payments blueprint  v11.6
Routes:
  GET  /api/members/<id>/payments          — list payments for a member
  POST /api/members/<id>/payments          — record a payment
  PUT  /api/payments/<id>                  — edit a payment
  POST /api/payments/<id>/void             — void (soft-delete) a payment
  GET  /api/admin/payment-types            — list payment types
  POST /api/admin/payment-types            — create payment type
  PUT  /api/admin/payment-types/<id>       — edit payment type
  POST /api/admin/payment-types/<id>/deactivate  — deactivate a type
  GET  /api/admin/payment-methods          — list payment methods
  POST /api/admin/payment-methods          — create payment method
  PUT  /api/admin/payment-methods/<id>     — edit payment method
  POST /api/admin/payment-methods/<id>/deactivate — deactivate a method
  GET  /api/admin/payment-methods/<id>/reorder    — reorder (sort)
  GET  /api/payments/current-period        — return current_membership_period setting
  POST /api/payments/current-period        — update current_membership_period setting
"""

from datetime import datetime

import sqlcipher3 as sqlite3
from flask import Blueprint, jsonify, request, session

from helpers import (
    get_db, get_setting, log_action, permission_required,
)

bp = Blueprint('payments', __name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _payment_row(row):
    """Convert a sqlite3.Row from member_payments into a plain dict."""
    d = dict(row)
    return d


def _current_period():
    return get_setting('current_membership_period', '')


# ── Member payment endpoints ──────────────────────────────────────────────────

@bp.route('/api/members/<int:member_id>/payments')
@permission_required('payments.view')
def api_member_payments_list(member_id):
    db = get_db()
    member = db.execute('SELECT id, first_name, surname FROM members WHERE id = ?', (member_id,)).fetchone()
    if not member:
        return jsonify({'error': 'Member not found'}), 404

    include_voided = request.args.get('include_voided', '0') == '1'
    void_clause = '' if include_voided else 'AND mp.voided_at IS NULL'

    rows = db.execute(f'''
        SELECT  mp.id,
                mp.member_id,
                mp.period,
                mp.payment_date,
                mp.amount,
                mp.notes,
                mp.voided_at,
                mp.void_reason,
                mp.created_at,
                pt.name  AS payment_type,
                pm.name  AS payment_method,
                mp.payment_type_id,
                mp.method_id,
                u_rec.username  AS recorded_by,
                u_void.username AS voided_by_user
        FROM    member_payments mp
        JOIN    payment_types pt  ON pt.id = mp.payment_type_id
        LEFT JOIN payment_methods pm ON pm.id = mp.method_id
        LEFT JOIN users u_rec  ON u_rec.id = mp.recorded_by
        LEFT JOIN users u_void ON u_void.id = mp.voided_by
        WHERE   mp.member_id = ? {void_clause}
        ORDER   BY mp.created_at DESC
    ''', (member_id,)).fetchall()

    current = _current_period()
    payments = [_payment_row(r) for r in rows]

    # Determine whether this member has a valid (non-voided) membership payment
    # for the current period.
    paid_current = any(
        p for p in payments
        if p['payment_type'] == 'Membership'
        and p['period'] == current
        and not p['voided_at']
    )

    return jsonify({
        'payments':       payments,
        'current_period': current,
        'paid_current':   paid_current,
    })


@bp.route('/api/members/<int:member_id>/payments', methods=['POST'])
@permission_required('payments.record')
def api_member_payments_create(member_id):
    db = get_db()
    member = db.execute('SELECT id, first_name, surname FROM members WHERE id = ?', (member_id,)).fetchone()
    if not member:
        return jsonify({'error': 'Member not found'}), 404

    data = request.get_json() or {}
    payment_type_id = data.get('payment_type_id')
    period          = (data.get('period') or '').strip()
    payment_date    = (data.get('payment_date') or '').strip() or None
    amount_raw      = data.get('amount')
    method_id       = data.get('method_id') or None
    notes           = (data.get('notes') or '').strip() or None

    if not payment_type_id:
        return jsonify({'error': 'payment_type_id is required'}), 400
    if not period:
        return jsonify({'error': 'period is required'}), 400

    # Validate amount
    amount = None
    if amount_raw not in (None, ''):
        try:
            amount = float(amount_raw)
            if amount < 0:
                return jsonify({'error': 'Amount cannot be negative'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid amount'}), 400

    # Validate payment_type exists
    pt = db.execute('SELECT id FROM payment_types WHERE id = ? AND active = 1', (payment_type_id,)).fetchone()
    if not pt:
        return jsonify({'error': 'Invalid payment type'}), 400

    # Validate method if provided
    if method_id:
        pm = db.execute('SELECT id FROM payment_methods WHERE id = ? AND active = 1', (method_id,)).fetchone()
        if not pm:
            return jsonify({'error': 'Invalid payment method'}), 400

    user_id = session.get('user_id')
    db.execute(
        '''INSERT INTO member_payments
           (member_id, payment_type_id, period, payment_date, amount, method_id, notes, recorded_by)
           VALUES (?,?,?,?,?,?,?,?)''',
        (member_id, payment_type_id, period, payment_date, amount, method_id, notes, user_id)
    )
    db.commit()

    log_action('payment_record', 'member_payments', member_id, {
        'payment_type_id': payment_type_id, 'period': period,
        'amount': amount, 'payment_date': payment_date,
    })

    return jsonify({'ok': True})


@bp.route('/api/payments/<int:payment_id>', methods=['PUT'])
@permission_required('payments.record')
def api_payment_update(payment_id):
    db = get_db()
    pay = db.execute(
        'SELECT * FROM member_payments WHERE id = ? AND voided_at IS NULL', (payment_id,)
    ).fetchone()
    if not pay:
        return jsonify({'error': 'Payment not found or already voided'}), 404

    data = request.get_json() or {}
    payment_type_id = data.get('payment_type_id', pay['payment_type_id'])
    period          = (data.get('period') or pay['period']).strip()
    payment_date    = (data.get('payment_date') or '').strip() or None
    amount_raw      = data.get('amount')
    method_id       = data.get('method_id') or None
    notes           = (data.get('notes') or '').strip() or None

    amount = pay['amount']
    if amount_raw not in (None, ''):
        try:
            amount = float(amount_raw)
            if amount < 0:
                return jsonify({'error': 'Amount cannot be negative'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid amount'}), 400

    if not period:
        return jsonify({'error': 'period is required'}), 400

    pt = db.execute('SELECT id FROM payment_types WHERE id = ? AND active = 1', (payment_type_id,)).fetchone()
    if not pt:
        return jsonify({'error': 'Invalid payment type'}), 400

    if method_id:
        pm = db.execute('SELECT id FROM payment_methods WHERE id = ? AND active = 1', (method_id,)).fetchone()
        if not pm:
            return jsonify({'error': 'Invalid payment method'}), 400

    db.execute(
        '''UPDATE member_payments
           SET payment_type_id=?, period=?, payment_date=?, amount=?, method_id=?, notes=?
           WHERE id=?''',
        (payment_type_id, period, payment_date, amount, method_id, notes, payment_id)
    )
    db.commit()

    log_action('payment_edit', 'member_payments', payment_id, {
        'member_id': pay['member_id'], 'period': period,
    })

    return jsonify({'ok': True})


@bp.route('/api/payments/<int:payment_id>/void', methods=['POST'])
@permission_required('payments.manage')
def api_payment_void(payment_id):
    db = get_db()
    pay = db.execute(
        'SELECT * FROM member_payments WHERE id = ? AND voided_at IS NULL', (payment_id,)
    ).fetchone()
    if not pay:
        return jsonify({'error': 'Payment not found or already voided'}), 404

    data        = request.get_json() or {}
    void_reason = (data.get('reason') or '').strip() or None
    user_id     = session.get('user_id')
    now         = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

    db.execute(
        'UPDATE member_payments SET voided_at=?, voided_by=?, void_reason=? WHERE id=?',
        (now, user_id, void_reason, payment_id)
    )
    db.commit()

    log_action('payment_void', 'member_payments', payment_id, {
        'member_id': pay['member_id'], 'reason': void_reason,
    })

    return jsonify({'ok': True})


# ── Current period setting ────────────────────────────────────────────────────

@bp.route('/api/payments/current-period')
@permission_required('payments.view')
def api_current_period_get():
    return jsonify({'current_period': _current_period()})


@bp.route('/api/payments/current-period', methods=['POST'])
@permission_required('payments.manage')
def api_current_period_set():
    data   = request.get_json() or {}
    period = (data.get('period') or '').strip()
    if not period:
        return jsonify({'error': 'period is required'}), 400

    db      = get_db()
    user_id = session.get('user_id')
    now     = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    db.execute(
        'INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?,?,?,?) '
        'ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at, updated_by=excluded.updated_by',
        ('current_membership_period', period, now, user_id)
    )
    db.commit()

    log_action('setting_change', 'settings', None, {'key': 'current_membership_period', 'value': period})
    return jsonify({'ok': True, 'current_period': period})


# ── Payment types admin ───────────────────────────────────────────────────────

@bp.route('/api/admin/payment-types')
@permission_required('payments.view')
def api_payment_types_list():
    db   = get_db()
    rows = db.execute(
        'SELECT * FROM payment_types ORDER BY sort_order, name'
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route('/api/admin/payment-types', methods=['POST'])
@permission_required('payments.manage')
def api_payment_types_create():
    db   = get_db()
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    desc = (data.get('description') or '').strip() or None
    if not name:
        return jsonify({'error': 'name is required'}), 400

    max_sort = db.execute('SELECT COALESCE(MAX(sort_order),0) FROM payment_types').fetchone()[0]
    try:
        db.execute(
            'INSERT INTO payment_types (name, description, sort_order) VALUES (?,?,?)',
            (name, desc, max_sort + 1)
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({'error': 'A payment type with that name already exists'}), 409

    log_action('payment_type_create', 'payment_types', None, {'name': name})
    return jsonify({'ok': True})


@bp.route('/api/admin/payment-types/<int:type_id>', methods=['PUT'])
@permission_required('payments.manage')
def api_payment_types_update(type_id):
    db  = get_db()
    row = db.execute('SELECT id FROM payment_types WHERE id = ?', (type_id,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404

    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    desc = (data.get('description') or '').strip() or None
    if not name:
        return jsonify({'error': 'name is required'}), 400

    try:
        db.execute(
            'UPDATE payment_types SET name=?, description=? WHERE id=?',
            (name, desc, type_id)
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({'error': 'A payment type with that name already exists'}), 409

    log_action('payment_type_edit', 'payment_types', type_id, {'name': name})
    return jsonify({'ok': True})


@bp.route('/api/admin/payment-types/<int:type_id>/deactivate', methods=['POST'])
@permission_required('payments.manage')
def api_payment_types_deactivate(type_id):
    db  = get_db()
    row = db.execute('SELECT id FROM payment_types WHERE id = ?', (type_id,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404

    # Prevent deactivating a type that has existing payments (non-voided)
    in_use = db.execute(
        'SELECT COUNT(*) FROM member_payments WHERE payment_type_id = ? AND voided_at IS NULL',
        (type_id,)
    ).fetchone()[0]
    if in_use:
        return jsonify({'error': f'Cannot deactivate — {in_use} active payment(s) use this type'}), 409

    active_now = db.execute('SELECT active FROM payment_types WHERE id = ?', (type_id,)).fetchone()[0]
    db.execute('UPDATE payment_types SET active=? WHERE id=?', (0 if active_now else 1, type_id))
    db.commit()
    log_action('payment_type_toggle', 'payment_types', type_id, {'active': not active_now})
    return jsonify({'ok': True})


# ── Payment methods admin ─────────────────────────────────────────────────────

@bp.route('/api/admin/payment-methods')
@permission_required('payments.view')
def api_payment_methods_list():
    db   = get_db()
    rows = db.execute(
        'SELECT * FROM payment_methods ORDER BY sort_order, name'
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route('/api/admin/payment-methods', methods=['POST'])
@permission_required('payments.manage')
def api_payment_methods_create():
    db   = get_db()
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'name is required'}), 400

    max_sort = db.execute('SELECT COALESCE(MAX(sort_order),0) FROM payment_methods').fetchone()[0]
    try:
        db.execute(
            'INSERT INTO payment_methods (name, sort_order) VALUES (?,?)',
            (name, max_sort + 1)
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({'error': 'A payment method with that name already exists'}), 409

    log_action('payment_method_create', 'payment_methods', None, {'name': name})
    return jsonify({'ok': True})


@bp.route('/api/admin/payment-methods/<int:method_id>', methods=['PUT'])
@permission_required('payments.manage')
def api_payment_methods_update(method_id):
    db  = get_db()
    row = db.execute('SELECT id FROM payment_methods WHERE id = ?', (method_id,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404

    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'name is required'}), 400

    try:
        db.execute('UPDATE payment_methods SET name=? WHERE id=?', (name, method_id))
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({'error': 'A payment method with that name already exists'}), 409

    log_action('payment_method_edit', 'payment_methods', method_id, {'name': name})
    return jsonify({'ok': True})


@bp.route('/api/admin/payment-methods/<int:method_id>/deactivate', methods=['POST'])
@permission_required('payments.manage')
def api_payment_methods_deactivate(method_id):
    db  = get_db()
    row = db.execute('SELECT id FROM payment_methods WHERE id = ?', (method_id,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404

    active_now = db.execute('SELECT active FROM payment_methods WHERE id = ?', (method_id,)).fetchone()[0]
    db.execute('UPDATE payment_methods SET active=? WHERE id=?', (0 if active_now else 1, method_id))
    db.commit()
    log_action('payment_method_toggle', 'payment_methods', method_id, {'active': not active_now})
    return jsonify({'ok': True})
