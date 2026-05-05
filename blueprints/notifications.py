"""
AYC Portal — Notifications blueprint (v8.2).
Routes: /api/notifications/*
"""

from flask import Blueprint, jsonify, request, session

from helpers import (
    get_db, log_action, permission_required, send_notification,
)

bp = Blueprint('notifications', __name__)


@bp.route('/api/notifications')
@permission_required('notifications.view')
def get_notifications():
    """Return notifications relevant to the current user, newest first."""
    user_id = session.get('user_id')
    db      = get_db()
    user    = db.execute(
        'SELECT role, session_assigned FROM users WHERE id = ?', (user_id,)
    ).fetchone()
    user_role    = user['role']             if user else None
    user_session = user['session_assigned'] if user else None

    notifs = db.execute('''
        SELECT n.*,
               CASE WHEN nr.read_at IS NOT NULL THEN 1 ELSE 0 END AS is_read,
               u.username AS sender_name
        FROM notifications n
        LEFT JOIN notification_reads nr
            ON n.id = nr.notification_id AND nr.user_id = ?
        LEFT JOIN users u ON u.id = n.sender_id
        WHERE n.target_type = 'all'
           OR (n.target_type = 'role'    AND n.target_value = ?)
           OR (n.target_type = 'session' AND n.target_value = ?)
           OR (n.target_type = 'users'   AND EXISTS (
               SELECT 1 FROM json_each(n.target_value)
               WHERE CAST(json_each.value AS INTEGER) = ?
           ))
        ORDER BY n.created_at DESC
        LIMIT 100
    ''', (user_id, user_role, user_session, user_id)).fetchall()

    unread = sum(1 for n in notifs if not n['is_read'])
    return jsonify({
        'notifications': [dict(n) for n in notifs],
        'unread_count':  unread,
    })


@bp.route('/api/notifications/unread-count')
@permission_required('notifications.view')
def get_notifications_unread_count():
    """Lightweight endpoint for badge polling — returns just the unread count."""
    user_id = session.get('user_id')
    db      = get_db()
    user    = db.execute(
        'SELECT role, session_assigned FROM users WHERE id = ?', (user_id,)
    ).fetchone()
    user_role    = user['role']             if user else None
    user_session = user['session_assigned'] if user else None

    count = db.execute('''
        SELECT COUNT(*) AS n
        FROM notifications n
        WHERE (
            n.target_type = 'all'
            OR (n.target_type = 'role'    AND n.target_value = ?)
            OR (n.target_type = 'session' AND n.target_value = ?)
            OR (n.target_type = 'users'   AND EXISTS (
                SELECT 1 FROM json_each(n.target_value)
                WHERE CAST(json_each.value AS INTEGER) = ?
            ))
        )
        AND NOT EXISTS (
            SELECT 1 FROM notification_reads nr
            WHERE nr.notification_id = n.id AND nr.user_id = ?
        )
    ''', (user_role, user_session, user_id, user_id)).fetchone()['n']

    return jsonify({'unread_count': count})


@bp.route('/api/notifications/mark-read', methods=['POST'])
@permission_required('notifications.view')
def mark_notifications_read():
    """Mark a specific list of notification IDs as read for the current user."""
    data = request.get_json() or {}
    ids  = data.get('notification_ids', [])
    if not ids:
        return jsonify({'error': 'notification_ids required'}), 400

    user_id = session['user_id']
    db      = get_db()
    for nid in ids:
        db.execute(
            'INSERT OR IGNORE INTO notification_reads (notification_id, user_id) VALUES (?, ?)',
            (nid, user_id)
        )
    db.commit()
    return jsonify({'success': True})


@bp.route('/api/notifications/mark-all-read', methods=['POST'])
@permission_required('notifications.view')
def mark_all_notifications_read():
    """Mark every unread notification visible to the current user as read."""
    user_id = session['user_id']
    db      = get_db()
    user    = db.execute(
        'SELECT role, session_assigned FROM users WHERE id = ?', (user_id,)
    ).fetchone()
    user_role    = user['role']             if user else None
    user_session = user['session_assigned'] if user else None

    unread_ids = db.execute('''
        SELECT n.id
        FROM notifications n
        WHERE (
            n.target_type = 'all'
            OR (n.target_type = 'role'    AND n.target_value = ?)
            OR (n.target_type = 'session' AND n.target_value = ?)
            OR (n.target_type = 'users'   AND EXISTS (
                SELECT 1 FROM json_each(n.target_value)
                WHERE CAST(json_each.value AS INTEGER) = ?
            ))
        )
        AND NOT EXISTS (
            SELECT 1 FROM notification_reads nr
            WHERE nr.notification_id = n.id AND nr.user_id = ?
        )
    ''', (user_role, user_session, user_id, user_id)).fetchall()

    for row in unread_ids:
        db.execute(
            'INSERT OR IGNORE INTO notification_reads (notification_id, user_id) VALUES (?, ?)',
            (row['id'], user_id)
        )
    db.commit()
    return jsonify({'success': True, 'marked': len(unread_ids)})


@bp.route('/api/notifications/send', methods=['POST'])
@permission_required('notifications.send')
def send_custom_notification():
    """Send a custom notification to a targeted audience."""
    data         = request.get_json() or {}
    title        = (data.get('title') or '').strip()
    body         = (data.get('body')  or '').strip()
    ntype        = data.get('notification_type', 'Info')
    target_type  = data.get('target_type')
    target_value = data.get('target_value')

    if not title or not body or not target_type:
        return jsonify({'error': 'title, body and target_type are required'}), 400
    if ntype not in ('Info', 'Reminder', 'Urgent', 'Announcement'):
        return jsonify({'error': 'Invalid notification_type'}), 400
    if target_type not in ('all', 'role', 'users', 'session'):
        return jsonify({'error': 'Invalid target_type'}), 400

    send_notification(
        sender_id=session['user_id'],
        title=title,
        body=body,
        notification_type=ntype,
        target_type=target_type,
        target_value=target_value,
        is_system=0,
    )
    return jsonify({'success': True})


@bp.route('/api/notifications/<int:notification_id>', methods=['DELETE'])
@permission_required('notifications.manage')
def delete_notification(notification_id):
    """Permanently delete a notification (admin / manage permission only)."""
    db    = get_db()
    notif = db.execute(
        'SELECT id FROM notifications WHERE id = ?', (notification_id,)
    ).fetchone()
    if not notif:
        return jsonify({'error': 'Notification not found'}), 404
    db.execute('DELETE FROM notifications WHERE id = ?', (notification_id,))
    db.commit()
    log_action('notification.deleted', 'notifications', notification_id, {})
    return jsonify({'success': True})
