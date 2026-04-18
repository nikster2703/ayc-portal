"""
AYC Portal — Staff Roles Migration
====================================
Adds the `staff_roles` table and seeds it with the three roles that were
previously hardcoded across the codebase (Volunteer, Youth Volunteer, Leader).

Run ONCE on the live server before deploying the new code:
    python scripts/migrate_add_staff_roles.py

Safe to run multiple times — uses INSERT OR IGNORE and IF NOT EXISTS.
"""

import os
import sys

try:
    import sqlcipher3 as sqlite3
except ImportError:
    sys.exit('sqlcipher3 not found. Run: pip3 install sqlcipher3')

try:
    from dotenv import load_dotenv
except ImportError:
    sys.exit('python-dotenv not found. Run: pip3 install python-dotenv')

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'ayc.db')
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))


def connect():
    key = os.environ.get('DB_ENCRYPTION_KEY')
    if not key:
        sys.exit('ERROR: DB_ENCRYPTION_KEY not set in .env')
    conn = sqlite3.connect(DB_PATH)
    conn.execute(f"PRAGMA key='{key}'")
    conn.execute('SELECT count(*) FROM sqlite_master')   # verify key
    conn.row_factory = sqlite3.Row
    return conn


def run():
    print('Connecting to database…')
    conn = connect()

    print('Creating staff_roles table…')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS staff_roles (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT    NOT NULL UNIQUE,
            active        INTEGER NOT NULL DEFAULT 1,
            display_order INTEGER NOT NULL DEFAULT 0,
            created_at    TEXT    DEFAULT (datetime('now'))
        )
    ''')

    print('Seeding default roles…')
    default_roles = [
        ('Volunteer',       1, 0),
        ('Youth Volunteer', 1, 1),
        ('Leader',          1, 2),
    ]
    for name, active, order in default_roles:
        conn.execute(
            'INSERT OR IGNORE INTO staff_roles (name, active, display_order) VALUES (?,?,?)',
            (name, active, order)
        )
        print(f'  → {name}')

    conn.commit()
    conn.close()
    print('\nMigration complete. ✓')


if __name__ == '__main__':
    run()
