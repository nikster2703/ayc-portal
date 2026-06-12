#!/usr/bin/env python3
"""
migrate_to_user_sessions.py — v10.3 data migration
===================================================
Run once on any existing AYC Portal install to migrate from the legacy
users.session_assigned TEXT column to the new user_sessions junction table.

What this script does:
  1. Creates the user_sessions table if it doesn't yet exist.
  2. Makes session_types.weekday nullable and adds session_types.description
     if those columns aren't already in the right shape.
  3. Adds users.active_session_id if it doesn't exist.
  4. For every user that has a non-empty session_assigned value:
       a. Finds the matching session_types row by name.
       b. Inserts a row into user_sessions (INSERT OR IGNORE — idempotent).
       c. Sets users.active_session_id to that session type's ID (if not already set).
  5. Reports a summary of what was migrated.

Usage:
  cd ayc-portal
  python scripts/migrate_to_user_sessions.py [--db PATH_TO_DB]

The script is idempotent — safe to run more than once.
"""

import argparse
import os
import sys

# ── Path setup ────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(SCRIPT_DIR))

from config import DATABASE, INSTANCE_DIR  # noqa: E402

try:
    import sqlcipher3 as sqlite3
except ImportError:
    import sqlite3


def get_db_key():
    key = os.environ.get('DB_KEY', '')
    if not key:
        key_file = os.path.join(INSTANCE_DIR, '.db_key')
        if os.path.isfile(key_file):
            with open(key_file) as f:
                key = f.read().strip()
    return key


def connect(db_path):
    conn = sqlite3.connect(db_path)
    key  = get_db_key()
    if key:
        conn.execute(f"PRAGMA key = '{key}'")
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.row_factory = sqlite3.Row
    return conn


def run(db_path):
    print(f'\nMigrating: {db_path}')
    conn = connect(db_path)

    # ── Step 1: Create user_sessions table ────────────────────────────────────
    conn.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            session_type_id INTEGER NOT NULL REFERENCES session_types(id) ON DELETE CASCADE,
            UNIQUE(user_id, session_type_id)
        )
    ''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_user_sessions_user    ON user_sessions(user_id)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_user_sessions_session ON user_sessions(session_type_id)')
    print('  ✓ user_sessions table ready')

    # ── Step 2: Make session_types.weekday nullable ────────────────────────────
    schema_row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='session_types'"
    ).fetchone()
    schema_sql = schema_row[0] if schema_row else ''
    weekday_line = ''
    for part in schema_sql.split('\n'):
        if 'weekday' in part.lower():
            weekday_line = part
            break

    if 'NOT NULL' in weekday_line:
        print('  Rebuilding session_types to make weekday nullable...')
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS session_types_v2 (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT    NOT NULL UNIQUE,
                weekday     INTEGER,
                description TEXT,
                active      INTEGER NOT NULL DEFAULT 1,
                sort_order  INTEGER NOT NULL DEFAULT 0
            );
            INSERT OR IGNORE INTO session_types_v2 (id, name, weekday, active, sort_order)
                SELECT id, name, weekday, active, sort_order FROM session_types;
            DROP TABLE session_types;
            ALTER TABLE session_types_v2 RENAME TO session_types;
        ''')
        print('  ✓ session_types.weekday is now nullable')
    else:
        # Add description column if missing
        existing_cols = [r[1] for r in conn.execute('PRAGMA table_info(session_types)').fetchall()]
        if 'description' not in existing_cols:
            conn.execute('ALTER TABLE session_types ADD COLUMN description TEXT')
            print('  ✓ Added session_types.description')
        else:
            print('  ✓ session_types already up to date')

    # ── Step 3: Add users.active_session_id ───────────────────────────────────
    existing_user_cols = [r[1] for r in conn.execute('PRAGMA table_info(users)').fetchall()]
    if 'active_session_id' not in existing_user_cols:
        conn.execute('ALTER TABLE users ADD COLUMN active_session_id INTEGER REFERENCES session_types(id)')
        print('  ✓ Added users.active_session_id')
    else:
        print('  ✓ users.active_session_id already exists')

    # ── Step 4: Populate user_sessions from session_assigned ──────────────────
    users = conn.execute(
        "SELECT id, username, session_assigned FROM users "
        "WHERE session_assigned IS NOT NULL AND TRIM(session_assigned) != ''"
    ).fetchall()

    migrated   = 0
    skipped    = 0
    not_found  = []

    for user in users:
        sess_name = (user['session_assigned'] or '').strip()
        if not sess_name:
            continue

        st = conn.execute(
            'SELECT id FROM session_types WHERE name = ?', (sess_name,)
        ).fetchone()

        if not st:
            not_found.append((user['username'], sess_name))
            skipped += 1
            continue

        conn.execute(
            'INSERT OR IGNORE INTO user_sessions (user_id, session_type_id) VALUES (?,?)',
            (user['id'], st['id'])
        )
        conn.execute(
            'UPDATE users SET active_session_id = ? WHERE id = ? AND active_session_id IS NULL',
            (st['id'], user['id'])
        )
        migrated += 1

    conn.execute('PRAGMA foreign_keys = ON')
    conn.commit()
    conn.close()

    # ── Step 5: Summary ───────────────────────────────────────────────────────
    print('\n  Migration complete:')
    print(f'    Users migrated:       {migrated}')
    print(f'    Users skipped:        {skipped}')
    if not_found:
        print('\n  WARNING — session name not found for these users:')
        for username, sess in not_found:
            print(f'    {username!r:20s} → session_assigned={sess!r} (no matching session_types row)')
        print('  These users will have no session access until manually assigned in the portal.')
    print()


def main():
    parser = argparse.ArgumentParser(description='AYC Portal v10.3 user_sessions migration')
    parser.add_argument('--db', default=DATABASE, help=f'Path to database (default: {DATABASE})')
    args = parser.parse_args()

    if not os.path.isfile(args.db):
        print(f'ERROR: Database not found: {args.db}')
        sys.exit(1)

    run(args.db)


if __name__ == '__main__':
    main()
