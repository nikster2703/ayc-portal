"""
seed_admin.py — Create the first admin user interactively.

Run from inside the ayc-portal directory:
    python3 scripts/seed_admin.py

You can also add additional users through the portal's User Management page
once you're logged in as admin.
"""

import getpass
import os
import sys

import sqlcipher3 as sqlite3  # SQLCipher — transparent AES-256 encryption at rest

try:
    import bcrypt
except ImportError:
    sys.exit('bcrypt not found. Run: pip3 install bcrypt')

try:
    from dotenv import load_dotenv
except ImportError:
    sys.exit('python-dotenv not found. Run: pip3 install python-dotenv')

import re

SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
APP_DIR      = os.path.dirname(SCRIPT_DIR)
# INSTANCE_DIR separates runtime data from code — used in Docker deployments.
# Falls back to APP_DIR for direct (non-Docker) installs.
INSTANCE_DIR = os.environ.get('INSTANCE_DIR', APP_DIR)
DB_PATH      = os.path.join(INSTANCE_DIR, 'data', 'ayc.db')

# Schema lives with the code, not the instance data
SCHEMA_PATH  = os.path.join(APP_DIR, 'schema.sql')

# Load .env — try instance dir first (Docker passes vars via env, so this is
# a no-op there), then fall back to app dir for direct installs.
load_dotenv(os.path.join(INSTANCE_DIR, '.env'))
load_dotenv(os.path.join(APP_DIR, '.env'))


def _connect_db(path):
    """Open a SQLCipher-encrypted DB connection. Raises if key is missing."""
    key = os.environ.get('DB_ENCRYPTION_KEY')
    if not key:
        sys.exit('ERROR: DB_ENCRYPTION_KEY is not set in .env — cannot open the database.')
    conn = sqlite3.connect(path)
    conn.execute(f"PRAGMA key='{key}'")
    conn.execute('SELECT count(*) FROM sqlite_master')  # verify key immediately
    return conn




def validate_password(password):
    """Enforce the portal password policy. Returns error string or None if valid."""
    if len(password) < 8:
        return 'Password must be at least 8 characters'
    if not re.search(r'[A-Z]', password):
        return 'Password must contain at least one uppercase letter'
    if not re.search(r'[0-9]', password):
        return 'Password must contain at least one number'
    if not re.search(r'[^A-Za-z0-9]', password):
        return 'Password must contain at least one special character'
    return None


def ensure_db():
    """Create or repair the database if it's missing or uninitialised."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = _connect_db(DB_PATH)
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
        password = getpass.getpass('Password (min 8 chars, 1 uppercase, 1 number, 1 special): ')
        error = validate_password(password)
        if error:
            print(f'{error}. Try again.')
            continue
        confirm = getpass.getpass('Confirm password: ')
        if password != confirm:
            print('Passwords do not match. Try again.')
            continue
        break

    pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = _connect_db(DB_PATH)
    try:
        conn.execute(
            'INSERT INTO users (username, email, password_hash, role) VALUES (?,?,?,?)',
            (username, email, pw_hash, 'admin')
        )
        conn.commit()
        print(f"\nAdmin user '{username}' created successfully.")
        # Note: this one-off container can't know the host-facing port (Docker
        # maps it externally), so we don't print a specific URL here. The
        # installer prints the correct address when it starts the portal.
        print('You can now log in once the portal is running.')
    except sqlite3.IntegrityError:
        print(f"\nA user named '{username}' already exists.")
    finally:
        conn.close()


if __name__ == '__main__':
    seed()
