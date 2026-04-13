"""
seed_admin.py — Create the first admin user interactively.

Run from inside the ayc-portal directory:
    python3 scripts/seed_admin.py

You can also add additional users through the portal's User Management page
once you're logged in as admin.
"""

import getpass
import os
import sqlite3
import sys

try:
    import bcrypt
except ImportError:
    sys.exit('bcrypt not found. Run: pip3 install bcrypt')

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR   = os.path.dirname(SCRIPT_DIR)
DB_PATH    = os.path.join(BASE_DIR, 'data', 'ayc.db')


SCHEMA_PATH = os.path.join(BASE_DIR, 'schema.sql')


def ensure_db():
    """Create or repair the database if it's missing or uninitialised."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
    ).fetchone()
    if not tables:
        print('Database not initialised — running schema now…')
        with open(SCHEMA_PATH, 'r') as f:
            conn.executescript(f.read())
        conn.commit()
        print('Schema applied.\n')
    conn.close()


def seed():
    ensure_db()

    print('=== AYC Portal — Create Admin User ===\n')

    username = input('Username: ').strip()
    if not username:
        sys.exit('Username cannot be empty.')

    email = input('Email (optional, press Enter to skip): ').strip()

    while True:
        password = getpass.getpass('Password (min 8 characters): ')
        if len(password) < 8:
            print('Password must be at least 8 characters. Try again.')
            continue
        confirm = getpass.getpass('Confirm password: ')
        if password != confirm:
            print('Passwords do not match. Try again.')
            continue
        break

    pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            'INSERT INTO users (username, email, password_hash, role) VALUES (?,?,?,?)',
            (username, email, pw_hash, 'admin')
        )
        conn.commit()
        print(f"\nAdmin user '{username}' created successfully.")
        print('You can now log in at http://localhost:5001')
    except sqlite3.IntegrityError:
        print(f"\nA user named '{username}' already exists.")
    finally:
        conn.close()


if __name__ == '__main__':
    seed()
