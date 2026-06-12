#!/usr/bin/env python3
"""
AYC Portal — One-time migration to SQLCipher-encrypted database.

Run this ONCE, while the portal is stopped, after:
  1. Adding DB_ENCRYPTION_KEY to .env
  2. Installing sqlcipher3-binary (pip install -r requirements.txt)
  3. Applying the code changes to app.py, seed_admin.py, migrate_members.py

Usage:
    cd ayc-portal
    source venv/bin/activate
    python3 scripts/migrate_to_encrypted.py

The script will:
  - Verify DB_ENCRYPTION_KEY is set
  - Create a timestamped backup of the existing plaintext database
  - Export all data into a new encrypted database file
  - Atomically replace the original with the encrypted version

The original plaintext backup is kept until you are confident everything works.
"""

import os
import shutil
import sys

import sqlcipher3

try:
    from dotenv import load_dotenv
except ImportError:
    sys.exit('python-dotenv not found. Run: pip3 install python-dotenv')

# ── Paths ──────────────────────────────────────────────────────────────────────

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
BASE_DIR    = os.path.dirname(SCRIPT_DIR)
DB_PATH     = os.path.join(BASE_DIR, 'data', 'ayc.db')
BACKUP_PATH = DB_PATH + f'.backup-{int(os.path.getmtime(DB_PATH))}'

# Load .env
load_dotenv(os.path.join(BASE_DIR, '.env'))

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print('=== AYC Portal — Database Encryption Migration ===\n')

    # 1. Safety checks
    if not os.path.exists(DB_PATH):
        sys.exit('ERROR: ayc.db not found — nothing to migrate.')

    key = os.environ.get('DB_ENCRYPTION_KEY')
    if not key:
        sys.exit('ERROR: DB_ENCRYPTION_KEY is not set in .env — add the key and retry.')

    # 2. Backup the existing plaintext database
    print(f'Backing up current database to:\n  {BACKUP_PATH}')
    shutil.copy2(DB_PATH, BACKUP_PATH)
    print('Backup created.\n')

    # 3. Open the plaintext source WITHOUT setting a key.
    #    SQLCipher can read a plain SQLite file when no PRAGMA key is applied.
    #    Setting a key here would cause SQLCipher to treat the file as already
    #    encrypted and fail to read it — this is the corrected approach.
    print('Creating encrypted database...')
    temp_encrypted = DB_PATH + '.encrypted'

    source = sqlcipher3.connect(DB_PATH)  # no PRAGMA key — source is plaintext

    # 4. Attach a new encrypted file and export everything into it
    source.execute('ATTACH DATABASE ? AS encrypted KEY ?', (temp_encrypted, key))
    source.execute("SELECT sqlcipher_export('encrypted');")
    source.execute('DETACH DATABASE encrypted;')
    source.close()

    # 5. Verify the encrypted file can actually be opened with the key
    print('Verifying encrypted database...')
    try:
        check = sqlcipher3.connect(temp_encrypted)
        check.execute(f"PRAGMA key='{key}'")
        check.execute('SELECT count(*) FROM sqlite_master')
        check.close()
    except Exception as e:
        os.remove(temp_encrypted)
        sys.exit(f'ERROR: Encrypted database verification failed — {e}\n'
                 f'The original database has NOT been replaced. Restore from backup if needed.')

    # 6. Atomic swap — replace the plaintext file with the encrypted one
    os.replace(temp_encrypted, DB_PATH)

    print('\n✅ Migration complete!')
    print(f'  • Original (plaintext) backed up at : {BACKUP_PATH}')
    print(f'  • Encrypted database now at          : {DB_PATH}')
    print('\nKeep the backup until you have fully tested the portal.')
    print('You can now restart the portal.')


if __name__ == '__main__':
    main()
