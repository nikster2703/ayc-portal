#!/usr/bin/env python3
"""
migrate_documents_phase_a.py — v9.0 Document Repository migration
==================================================================
Safe, idempotent migration for existing deployments.

What it does:
  1. Creates document_categories and document_role_access tables (if absent).
  2. Seeds the default document categories (if absent).
  3. Adds new columns to the documents table (stored_filename, bucket,
     category_id, description, retain_until, retention_notes, file_size).
  4. For any existing document rows that still use the old file_path scheme,
     generates a UUID stored_filename, moves the file into the store/ bucket,
     and maps the old text category to the closest document_categories row.

Run once after deploying v9.0 code.  Safe to re-run — all operations check
before acting.

Usage:
    python scripts/migrate_documents_phase_a.py
    python scripts/migrate_documents_phase_a.py --db /path/to/ayc.db
"""

import argparse
import os
import shutil
import sqlite3
import uuid
import sys

# ── Defaults ──────────────────────────────────────────────────────────────────
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PORTAL_DIR  = os.path.dirname(SCRIPT_DIR)
DEFAULT_DB  = os.path.join(PORTAL_DIR, 'data', 'ayc.db')
DOCS_DIR    = os.path.join(PORTAL_DIR, 'data', 'documents')

DEFAULT_CATEGORIES = [
    ('Policy',       'Organisational policies and procedures',  '📜', '#3b82f6', 0),
    ('Form',         'Fillable forms and templates',            '📋', '#10b981', 1),
    ('Template',     'Document templates for staff use',        '✉️', '#8b5cf6', 2),
    ('Register',     'Session registers and attendance sheets', '📝', '#f59e0b', 3),
    ('Safeguarding', 'Safeguarding records and incident notes', '🔒', '#ef4444', 4),
    ('Finance',      'Financial records, invoices and budgets', '💰', '#06b6d4', 5),
    ('General',      'General documents and miscellaneous',     '📄', '#64748b', 6),
]

# Map old hardcoded category text values → new category names
CATEGORY_MAP = {
    'policy':    'Policy',
    'form':      'Form',
    'template':  'Template',
    'registers': 'Register',
    'general':   'General',
}


def get_db(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


def column_exists(conn, table, column):
    rows = conn.execute(f'PRAGMA table_info({table})').fetchall()
    return any(r['name'] == column for r in rows)


def table_exists(conn, table):
    return conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone() is not None


def run(db_path, docs_dir):
    print(f'Database : {db_path}')
    print(f'Docs dir : {docs_dir}')
    print()

    if not os.path.exists(db_path):
        print('ERROR: Database not found. Check --db path.')
        sys.exit(1)

    conn = get_db(db_path)

    # ── 1. Create new tables ──────────────────────────────────────────────────
    print('[1/4] Creating new tables (if absent)…')
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS document_categories (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL UNIQUE,
            description TEXT,
            icon        TEXT    DEFAULT '📄',
            color       TEXT    DEFAULT '#64748b',
            sort_order  INTEGER DEFAULT 0,
            active      INTEGER NOT NULL DEFAULT 1,
            created_at  TEXT    DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS document_role_access (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
            role_id     INTEGER NOT NULL REFERENCES roles(id)     ON DELETE CASCADE,
            UNIQUE(document_id, role_id)
        );
        CREATE INDEX IF NOT EXISTS idx_doc_role_access_doc  ON document_role_access(document_id);
        CREATE INDEX IF NOT EXISTS idx_doc_role_access_role ON document_role_access(role_id);
    ''')
    conn.commit()
    print('   ✓ Tables ready.')

    # ── 2. Seed default categories ────────────────────────────────────────────
    print('[2/4] Seeding default document categories…')
    seeded = 0
    for name, desc, icon, color, sort_order in DEFAULT_CATEGORIES:
        existing = conn.execute(
            'SELECT id FROM document_categories WHERE name = ?', (name,)
        ).fetchone()
        if not existing:
            conn.execute(
                'INSERT INTO document_categories (name, description, icon, color, sort_order) '
                'VALUES (?,?,?,?,?)',
                (name, desc, icon, color, sort_order)
            )
            seeded += 1
    conn.commit()
    print(f'   ✓ {seeded} categor{"y" if seeded==1 else "ies"} seeded '
          f'(existing ones untouched).')

    # ── 3. Add new columns to documents ──────────────────────────────────────
    print('[3/4] Adding new columns to documents table…')
    new_cols = [
        ('stored_filename', 'TEXT'),
        ('bucket',          "TEXT NOT NULL DEFAULT 'store'"),
        ('category_id',     'INTEGER REFERENCES document_categories(id)'),
        ('description',     'TEXT'),
        ('retain_until',    'TEXT'),
        ('retention_notes', 'TEXT'),
        ('file_size',       'INTEGER'),
    ]
    added = 0
    for col, col_def in new_cols:
        if not column_exists(conn, 'documents', col):
            conn.execute(f'ALTER TABLE documents ADD COLUMN {col} {col_def}')
            added += 1
    conn.commit()
    print(f'   ✓ {added} column(s) added.')

    # ── 4. Migrate existing document rows ─────────────────────────────────────
    print('[4/4] Migrating existing document rows…')

    # Build category name→id lookup
    cat_rows = conn.execute('SELECT id, name FROM document_categories').fetchall()
    cat_lookup = {r['name']: r['id'] for r in cat_rows}

    old_docs = conn.execute(
        'SELECT * FROM documents WHERE stored_filename IS NULL AND active = 1'
    ).fetchall()

    if not old_docs:
        print('   ✓ No legacy document rows found — nothing to migrate.')
    else:
        store_dir = os.path.join(docs_dir, 'store')
        os.makedirs(store_dir, exist_ok=True)
        migrated = 0
        errors   = 0

        for doc in old_docs:
            old_path = os.path.join(docs_dir, doc['file_path'])
            new_fname = uuid.uuid4().hex
            new_path  = os.path.join(store_dir, new_fname)

            # Resolve category_id from old text category
            old_cat    = (doc['category'] or 'general').lower().strip()
            cat_name   = CATEGORY_MAP.get(old_cat, 'General')
            category_id = cat_lookup.get(cat_name, cat_lookup.get('General'))

            # Move the file
            if os.path.exists(old_path):
                try:
                    shutil.move(old_path, new_path)
                    conn.execute(
                        '''UPDATE documents
                           SET stored_filename = ?, bucket = 'store', category_id = ?
                           WHERE id = ?''',
                        (new_fname, category_id, doc['id'])
                    )
                    migrated += 1
                except Exception as e:
                    print(f'   ⚠ Doc ID {doc["id"]} ("{doc["title"]}"): {e}')
                    errors += 1
            else:
                # File missing on disk — update DB only so the row isn't re-attempted
                print(f'   ⚠ Doc ID {doc["id"]}: file not found at {old_path} — DB updated, no file moved.')
                conn.execute(
                    '''UPDATE documents
                       SET stored_filename = ?, bucket = 'store', category_id = ?
                       WHERE id = ?''',
                    (new_fname, category_id, doc['id'])
                )
                migrated += 1

        conn.commit()
        print(f'   ✓ {migrated} row(s) migrated, {errors} error(s).')

    conn.close()
    print()
    print('Migration complete.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='AYC Portal v9.0 document migration')
    parser.add_argument('--db', default=DEFAULT_DB, help='Path to ayc.db')
    parser.add_argument('--docs', default=DOCS_DIR, help='Path to data/documents directory')
    args = parser.parse_args()
    run(args.db, args.docs)
