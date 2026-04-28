#!/usr/bin/env python3
"""
migrate_to_alert_rules.py — v8.0 data migration
================================================
Run once on any existing AYC Portal install to migrate from the hardcoded
At Risk status to the new Member Alert Rules system.

What this script does:
  1. Creates alert_rules and member_flags tables if they don't yet exist.
  2. Reads existing at_risk_threshold_* settings and seeds one attendance
     alert rule per session type.
  3. Finds all members with status = 'At Risk', creates a member_flags row
     for each (flagged_by = 'migration'), then sets their status to 'Active'.
  4. Removes the old at_risk_threshold_* settings keys (optional).

Usage:
  cd ayc-portal
  python scripts/migrate_to_alert_rules.py [--db PATH_TO_DB]

The script is idempotent — safe to run more than once.
"""

import argparse
import json
import os
import sys
from datetime import datetime

# ── Path setup ────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR   = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, BASE_DIR)

try:
    import sqlcipher3 as sqlite3
    _cipher = True
except ImportError:
    import sqlite3
    _cipher = False

from dotenv import load_dotenv
load_dotenv(os.path.join(BASE_DIR, '.env'))

DEFAULT_DB = os.path.join(BASE_DIR, 'data', 'ayc.db')


def get_db(db_path):
    key = os.environ.get('DB_ENCRYPTION_KEY', '')
    if _cipher:
        if not key:
            print('[migrate] ERROR: DB_ENCRYPTION_KEY is not set in .env — cannot open encrypted database.')
            sys.exit(1)
        if "'" in key:
            print("[migrate] ERROR: DB_ENCRYPTION_KEY contains a single-quote character — invalid key.")
            sys.exit(1)
    con = sqlite3.connect(db_path)
    if _cipher:
        con.execute(f"PRAGMA key='{key}'")
        try:
            con.execute('SELECT count(*) FROM sqlite_master')  # verify key immediately
        except Exception:
            print('[migrate] ERROR: Could not decrypt the database — check DB_ENCRYPTION_KEY in .env matches the key used when the portal was started.')
            sys.exit(1)
    con.row_factory = sqlite3.Row
    return con


def migrate(db_path, dry_run=False):
    print(f'[migrate] Database: {db_path}')
    if not os.path.exists(db_path):
        print('[migrate] ERROR: database file not found — run the portal once first to initialise it.')
        sys.exit(1)

    db = get_db(db_path)
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # ── 1. Create tables if missing ───────────────────────────────────────────
    print('[migrate] Step 1 — ensuring alert_rules and member_flags tables exist…')
    db.execute('''
        CREATE TABLE IF NOT EXISTS alert_rules (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            name                TEXT    NOT NULL,
            rule_type           TEXT    NOT NULL,
            target_field        TEXT,
            condition           TEXT,
            threshold_value     INTEGER,
            threshold_unit      TEXT,
            applies_to_session  TEXT,
            flag_label          TEXT    NOT NULL,
            flag_colour         TEXT    NOT NULL DEFAULT '#f59e0b',
            auto_resolve        INTEGER NOT NULL DEFAULT 1,
            resolve_field       TEXT,
            is_active           INTEGER NOT NULL DEFAULT 1,
            created_at          TEXT    DEFAULT (datetime('now')),
            created_by          INTEGER
        )
    ''')
    db.execute('''
        CREATE TABLE IF NOT EXISTS member_flags (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id    INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
            rule_id      INTEGER NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
            flagged_at   TEXT    NOT NULL DEFAULT (datetime('now')),
            flagged_by   TEXT    NOT NULL DEFAULT 'auto',
            resolved_at  TEXT,
            resolved_by  TEXT,
            note         TEXT
        )
    ''')
    db.execute('CREATE INDEX IF NOT EXISTS idx_member_flags_member ON member_flags(member_id)')
    db.execute('CREATE INDEX IF NOT EXISTS idx_member_flags_rule   ON member_flags(rule_id)')
    if not dry_run:
        db.commit()
    print('    Done.')

    # ── 2. Seed attendance rules from existing thresholds ─────────────────────
    print('[migrate] Step 2 — seeding attendance alert rules from existing thresholds…')
    session_types = db.execute(
        "SELECT name FROM session_types WHERE active = 1 ORDER BY sort_order"
    ).fetchall()

    for st in session_types:
        name = st['name']
        key  = f'at_risk_threshold_{name.lower().replace(" ", "_")}'
        row  = db.execute('SELECT value FROM settings WHERE key = ?', (key,)).fetchone()
        threshold = int(row['value']) if row else 5

        # Check if a rule already exists for this session
        existing = db.execute(
            "SELECT id FROM alert_rules WHERE rule_type = 'attendance' "
            "AND applies_to_session = ? AND is_active = 1",
            (name,)
        ).fetchone()
        if existing:
            print(f'    {name}: attendance rule already exists (id={existing["id"]}), skipping.')
            continue

        rule_name  = f'Missed {name} Sessions'
        flag_label = 'Missed Sessions'
        flag_colour = '#f59e0b'  # amber
        print(f'    {name}: creating attendance rule — threshold={threshold} sessions.')
        if not dry_run:
            db.execute(
                'INSERT INTO alert_rules '
                '(name, rule_type, threshold_value, threshold_unit, applies_to_session, '
                'flag_label, flag_colour, auto_resolve, is_active, created_at) '
                'VALUES (?, "attendance", ?, "sessions", ?, ?, ?, 1, 1, ?)',
                (rule_name, threshold, name, flag_label, flag_colour, now)
            )
    if not dry_run:
        db.commit()
    print('    Done.')

    # ── 3. Migrate existing At Risk members → member_flags ────────────────────
    print('[migrate] Step 3 — migrating existing At Risk members…')
    at_risk_members = db.execute(
        "SELECT id, first_name, surname, session FROM members WHERE status = 'At Risk'"
    ).fetchall()
    print(f'    Found {len(at_risk_members)} At Risk member(s).')

    migrated = 0
    for m in at_risk_members:
        # Find the attendance rule for this member's session
        rule = db.execute(
            "SELECT id FROM alert_rules WHERE rule_type = 'attendance' "
            "AND applies_to_session = ? AND is_active = 1",
            (m['session'],)
        ).fetchone()

        if not rule:
            # Fallback: any active attendance rule (handles edge cases)
            rule = db.execute(
                "SELECT id FROM alert_rules WHERE rule_type = 'attendance' AND is_active = 1 LIMIT 1"
            ).fetchone()

        if not rule:
            print(f'    WARNING: No attendance rule found for {m["first_name"]} {m["surname"]} '
                  f'(session={m["session"]}) — skipping flag creation.')
            continue

        # Check for duplicate
        dup = db.execute(
            'SELECT id FROM member_flags WHERE member_id = ? AND rule_id = ? AND resolved_at IS NULL',
            (m['id'], rule['id'])
        ).fetchone()
        if dup:
            print(f'    {m["first_name"]} {m["surname"]}: flag already exists, will still set status to Active.')
        else:
            if not dry_run:
                db.execute(
                    'INSERT INTO member_flags (member_id, rule_id, flagged_at, flagged_by, note) '
                    'VALUES (?, ?, ?, "migration", "Migrated from At Risk status on v8.0 upgrade")',
                    (m['id'], rule['id'], now)
                )

        # Set status to Active
        if not dry_run:
            db.execute(
                "UPDATE members SET status = 'Active', updated_at = ? WHERE id = ?",
                (now, m['id'])
            )
        migrated += 1
        print(f'    ✓ {m["first_name"]} {m["surname"]} — flag created, status → Active')

    if not dry_run:
        db.commit()
    print(f'    {migrated} member(s) migrated.')

    # ── 4. Seed new permissions into the permissions catalogue ───────────────
    print('[migrate] Step 4 — seeding alert permissions into permissions table…')
    new_perms = [
        ('alerts.view',    'View Alerts',          'See member flags and the alert rules list',   'alerts'),
        ('alerts.manage',  'Manage Alert Rules',   'Create and edit alert rules',                 'alerts'),
        ('alerts.run',     'Run Alert Checks',     'Trigger an alert rule evaluation manually',   'alerts'),
        ('alerts.dismiss', 'Dismiss Flags',        'Manually clear a flag from a member record',  'alerts'),
    ]
    for code, name, desc, cat in new_perms:
        exists = db.execute('SELECT code FROM permissions WHERE code = ?', (code,)).fetchone()
        if not exists:
            if not dry_run:
                db.execute(
                    'INSERT INTO permissions (code, name, description, category) VALUES (?,?,?,?)',
                    (code, name, desc, cat)
                )
            print(f'    + {code}')
        else:
            print(f'    {code} already exists — skipping.')
    if not dry_run:
        db.commit()
    print('    Done.')

    # ── 5. Patch existing roles to include the new alert permissions ──────────
    print('[migrate] Step 5 — patching existing roles with alert permissions…')
    # Which permissions each built-in role should receive
    ROLE_ALERT_PERMS = {
        'admin':    ['alerts.view', 'alerts.manage', 'alerts.run', 'alerts.dismiss'],
        'editor':   ['alerts.view', 'alerts.manage', 'alerts.run', 'alerts.dismiss'],
        'leader':   ['alerts.view'],
        'readonly': [],
    }
    roles = db.execute('SELECT id, name, permissions FROM roles').fetchall()
    for role in roles:
        role_name  = role['name']
        to_add     = ROLE_ALERT_PERMS.get(role_name, [])
        if not to_add:
            print(f'    {role_name}: no alert permissions to add.')
            continue
        try:
            current = json.loads(role['permissions'])
        except (ValueError, TypeError):
            current = []
        added = []
        for perm in to_add:
            if perm not in current:
                current.append(perm)
                added.append(perm)
        if added:
            if not dry_run:
                db.execute(
                    'UPDATE roles SET permissions = ? WHERE id = ?',
                    (json.dumps(current), role['id'])
                )
            print(f'    {role_name}: added {", ".join(added)}')
        else:
            print(f'    {role_name}: already has all alert permissions.')
    if not dry_run:
        db.commit()
    print('    Done.')

    # ── 6. Seed alerts_last_run setting ───────────────────────────────────────
    print('[migrate] Step 6 — seeding alerts_last_run setting…')
    existing_lr = db.execute(
        "SELECT key FROM settings WHERE key = 'alerts_last_run'"
    ).fetchone()
    if not existing_lr:
        if not dry_run:
            db.execute("INSERT INTO settings (key, value) VALUES ('alerts_last_run', '')")
            db.commit()
        print('    Inserted.')
    else:
        print('    Already exists — skipping.')

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    if dry_run:
        print('[migrate] DRY RUN complete — no changes written to database.')
    else:
        print('[migrate] Migration complete. You can now restart the portal.')
        print()
        print('  Note: the old at_risk_threshold_* settings keys have been left in place.')
        print('  They are no longer used by the portal. You may delete them from the')
        print('  settings table manually if you wish, but it is not required.')

    db.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Migrate AYC Portal to v8.0 alert rules system')
    parser.add_argument('--db',      default=DEFAULT_DB, help='Path to ayc.db')
    parser.add_argument('--dry-run', action='store_true', help='Preview changes without writing')
    args = parser.parse_args()
    migrate(args.db, dry_run=args.dry_run)
