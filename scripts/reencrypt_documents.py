#!/usr/bin/env python3
"""
AYC Portal — Document re-encryption script.

Run this script ONCE after adding DOCUMENT_ENCRYPTION_KEY to .env.
It re-encrypts every stored document from the old derived key
(SHA-256 of DB_ENCRYPTION_KEY) to the new dedicated DOCUMENT_ENCRYPTION_KEY.

Usage:
    1. Set both DB_ENCRYPTION_KEY and DOCUMENT_ENCRYPTION_KEY in your .env
    2. Take a backup of data/documents/ first (cp -r data/documents data/documents.bak)
    3. Run from the ayc-portal directory:
           python scripts/reencrypt_documents.py

The script is idempotent — if interrupted, re-run it.  Already-converted
files are detected via a dry-read with the new key and skipped safely.
"""

import base64
import hashlib
import os
import sys

# ── Load environment from .env ────────────────────────────────────────────────
script_dir  = os.path.dirname(os.path.abspath(__file__))
portal_dir  = os.path.dirname(script_dir)
dotenv_path = os.path.join(os.environ.get('INSTANCE_DIR', portal_dir), '.env')

try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path)
except ImportError:
    # Parse .env manually if python-dotenv is not available
    if os.path.exists(dotenv_path):
        with open(dotenv_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, _, v = line.partition('=')
                    os.environ.setdefault(k.strip(), v.strip())

DB_KEY  = os.environ.get('DB_ENCRYPTION_KEY', '').strip()
DOC_KEY = os.environ.get('DOCUMENT_ENCRYPTION_KEY', '').strip()

if not DB_KEY:
    print('ERROR: DB_ENCRYPTION_KEY is not set in .env')
    sys.exit(1)
if not DOC_KEY:
    print('ERROR: DOCUMENT_ENCRYPTION_KEY is not set in .env')
    print('Generate one with:')
    print('  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"')
    sys.exit(1)

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    print('ERROR: cryptography package not installed.  pip install cryptography')
    sys.exit(1)

# ── Build old and new Fernet instances ────────────────────────────────────────
old_fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(DB_KEY.encode()).digest()))
new_fernet = Fernet(DOC_KEY.encode())

# ── Locate document directory ─────────────────────────────────────────────────
upload_dir = os.path.join(os.environ.get('INSTANCE_DIR', portal_dir), 'data', 'documents')
if not os.path.isdir(upload_dir):
    print(f'ERROR: Document directory not found: {upload_dir}')
    sys.exit(1)

# ── Re-encrypt each file ──────────────────────────────────────────────────────
files       = [f for f in os.listdir(upload_dir)
               if os.path.isfile(os.path.join(upload_dir, f))]
total       = len(files)
converted   = 0
already_new = 0
errors      = 0

print(f'Found {total} files in {upload_dir}')
print('Starting re-encryption...')
print()

for filename in files:
    path = os.path.join(upload_dir, filename)
    try:
        with open(path, 'rb') as fh:
            ciphertext = fh.read()

        # Try decrypting with the new key first — if it works, already converted
        try:
            new_fernet.decrypt(ciphertext)
            already_new += 1
            print(f'  SKIP  {filename} (already encrypted with new key)')
            continue
        except (InvalidToken, Exception):
            pass

        # Decrypt with old key
        try:
            plaintext = old_fernet.decrypt(ciphertext)
        except (InvalidToken, Exception) as e:
            print(f'  ERROR {filename} — cannot decrypt with old key: {e}')
            errors += 1
            continue

        # Re-encrypt with new key and write back
        new_ciphertext = new_fernet.encrypt(plaintext)
        with open(path, 'wb') as fh:
            fh.write(new_ciphertext)

        converted += 1
        print(f'  OK    {filename}')

    except Exception as e:
        print(f'  ERROR {filename} — unexpected error: {e}')
        errors += 1

print()
print('─' * 50)
print(f'Complete: {converted} converted, {already_new} already converted, {errors} errors')
if errors:
    print()
    print('WARNING: Some files could not be re-encrypted.')
    print('Check the errors above.  Do NOT remove data/documents.bak until all files are verified.')
    sys.exit(1)
else:
    print()
    print('All documents successfully re-encrypted with DOCUMENT_ENCRYPTION_KEY.')
    print('You can now safely delete data/documents.bak if you made a backup.')
