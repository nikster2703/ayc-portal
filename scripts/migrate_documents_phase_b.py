#!/usr/bin/env python3
"""
migrate_documents_phase_b.py — v9.2 Document Repository Phase B migration
=========================================================================
Safe, idempotent migration for existing deployments.

What it does:
  1. Creates document_field_definitions and document_metadata tables (if absent).
  2. Creates the documents_fts FTS5 virtual table (if absent and FTS5 is
     available).  Prints a warning and skips gracefully if the SQLCipher
     build does not include FTS5.
  3. Populates the FTS index for every active document already in the DB
     (title + description + category name + metadata label/value pairs).

Run once after deploying v9.2 code.  Safe to re-run — all operations check
before acting; FTS entries are deleted and rebuilt so re-running is clean.

Usage:
    python scripts/migrate_documents_phase_b.py
    python scripts/migrate_documents_phase_b.py --db /path/to/ayc.db
"""

import argparse
import os
import sys

try:
    import sqlcipher3 as sqlite3      # production — encrypted DB
except ImportError:
    import sqlite3                    # fallback for plain SQLite test DBs

# ── Defaults ──────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PORTAL_DIR = os.path.dirname(SCRIPT_DIR)
DEFAULT_DB = os.path.join(PORTAL_DIR, 'data', 'ayc.db')


def get_db(path, key=None):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    if key:
        conn.execute(f"PRAGMA key='{key}'")
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


def table_exists(conn, table):
    return conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone() is not None


def vtable_exists(conn, table):
    return conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone() is not None


def fts5_available(conn):
    """Return True if this SQLite/SQLCipher build includes FTS5."""
    try:
        conn.execute('CREATE VIRTUAL TABLE IF NOT EXISTS _fts5_probe USING fts5(x)')
        conn.execute('DROP TABLE IF EXISTS _fts5_probe')
        return True
    except Exception:
        return False


def run(db_path, db_key=None):
    print(f'Database : {db_path}')
    print()

    if not os.path.exists(db_path):
        print('ERROR: Database not found. Check --db path.')
        sys.exit(1)

    conn = get_db(db_path, key=db_key)

    # ── 1. Create document_field_definitions ─────────────────────────────────
    print('[1/3] Creating document_field_definitions table (if absent)…')
    if not table_exists(conn, 'document_field_definitions'):
        conn.executescript('''
            CREATE TABLE document_field_definitions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                category_id INTEGER NOT NULL REFERENCES document_categories(id) ON DELETE CASCADE,
                label       TEXT    NOT NULL,
                field_type  TEXT    NOT NULL DEFAULT 'text',
                help_text   TEXT,
                placeholder TEXT,
                required    INTEGER NOT NULL DEFAULT 0,
                sort_order  INTEGER NOT NULL DEFAULT 0,
                active      INTEGER NOT NULL DEFAULT 1,
                created_at  TEXT    DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_doc_field_defs_cat
                ON document_field_definitions(category_id);
        ''')
        conn.commit()
        print('   ✓ document_field_definitions created.')
    else:
        print('   ✓ document_field_definitions already exists — skipped.')

    # ── 2. Create document_metadata ──────────────────────────────────────────
    print('[2/3] Creating document_metadata table (if absent)…')
    if not table_exists(conn, 'document_metadata'):
        conn.executescript('''
            CREATE TABLE document_metadata (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER NOT NULL REFERENCES documents(id)                    ON DELETE CASCADE,
                field_id    INTEGER NOT NULL REFERENCES document_field_definitions(id)   ON DELETE CASCADE,
                value       TEXT,
                updated_at  TEXT    DEFAULT (datetime('now')),
                UNIQUE(document_id, field_id)
            );
            CREATE INDEX IF NOT EXISTS idx_doc_metadata_doc
                ON document_metadata(document_id);
            CREATE INDEX IF NOT EXISTS idx_doc_metadata_field
                ON document_metadata(field_id);
        ''')
        conn.commit()
        print('   ✓ document_metadata created.')
    else:
        print('   ✓ document_metadata already exists — skipped.')

    # ── 3. Create + populate FTS5 index ──────────────────────────────────────
    print('[3/3] Setting up FTS5 full-text search index…')
    if not fts5_available(conn):
        print('   ⚠ FTS5 is not available in this SQLite/SQLCipher build.')
        print('     Skipping FTS index creation.  The portal will fall back')
        print('     to LIKE-based search automatically.')
    else:
        # Create table if absent
        if not vtable_exists(conn, 'documents_fts'):
            conn.executescript('''
                CREATE VIRTUAL TABLE documents_fts USING fts5(
                    doc_id   UNINDEXED,
                    content,
                    tokenize = 'porter unicode61'
                );
            ''')
            conn.commit()
            print('   ✓ documents_fts virtual table created.')
        else:
            print('   ✓ documents_fts already exists — will rebuild entries.')

        # Rebuild FTS entries for all active documents
        docs = conn.execute(
            '''SELECT d.id, d.title, d.description, dc.name AS cat_name
               FROM documents d
               LEFT JOIN document_categories dc ON dc.id = d.category_id
               WHERE d.active = 1'''
        ).fetchall()

        # Load all metadata values in one query
        meta_rows = conn.execute(
            '''SELECT dm.document_id, df.label, df.field_type, dm.value
               FROM document_metadata dm
               JOIN document_field_definitions df ON df.id = dm.field_id
               WHERE dm.value IS NOT NULL AND dm.value != ''
               ORDER BY dm.document_id'''
        ).fetchall()

        # Load members for member_ref resolution
        members = conn.execute('SELECT id, first_name, surname FROM members').fetchall()
        member_map = {str(m['id']): f"{m['first_name']} {m['surname']}" for m in members}

        # Group metadata by doc_id
        meta_by_doc = {}
        for mr in meta_rows:
            doc_id = mr['document_id']
            if doc_id not in meta_by_doc:
                meta_by_doc[doc_id] = []
            val = mr['value']
            if mr['field_type'] == 'member_ref' and val in member_map:
                val = member_map[val]
            meta_by_doc[doc_id].append(f"{mr['label']} {val}")

        rebuilt = 0
        for doc in docs:
            doc_id = doc['id']
            # Delete any existing FTS entry for this doc
            conn.execute('DELETE FROM documents_fts WHERE doc_id = ?', (doc_id,))
            # Build content string
            parts = [doc['title'] or '']
            if doc['description']:
                parts.append(doc['description'])
            if doc['cat_name']:
                parts.append(doc['cat_name'])
            parts.extend(meta_by_doc.get(doc_id, []))
            content = ' '.join(filter(None, parts))
            conn.execute(
                'INSERT INTO documents_fts (doc_id, content) VALUES (?, ?)',
                (doc_id, content)
            )
            rebuilt += 1

        conn.commit()
        print(f'   ✓ FTS index rebuilt for {rebuilt} document(s).')

    conn.close()
    print()
    print('Migration complete.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='AYC Portal v9.2 Phase B migration')
    parser.add_argument('--db',  default=DEFAULT_DB, help='Path to ayc.db')
    parser.add_argument('--key', default=None,       help='SQLCipher passphrase (if DB is encrypted)')
    args = parser.parse_args()
    run(args.db, db_key=args.key)
