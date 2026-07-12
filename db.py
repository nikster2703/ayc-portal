"""
AYC Portal — Database initialisation and migration utilities.
Called at app startup (ensure_tables) and via the Flask CLI (init-db).

Imported by:
  - app.py  (startup + CLI command)
  - blueprints/admin.py  (restore endpoint runs ensure_tables after swap)
"""

import json
import logging
import os

import sqlcipher3 as sqlite3  # noqa: F401 — Row factory type used implicitly

logger = logging.getLogger(__name__)

from config import (
    BASE_DIR, DATABASE, BRAND_KEYS,
    ALL_PERMISSIONS, DEFAULT_ROLE_PERMISSIONS, ROLE_DISPLAY_NAMES,
)
from helpers import _connect_db


def init_db():
    """Initialise the database from schema.sql. Safe to run multiple times."""
    os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
    db = _connect_db()
    with open(os.path.join(BASE_DIR, 'schema.sql'), 'r') as f:
        db.executescript(f.read())
    db.commit()
    db.close()
    print(f'Database initialised at {DATABASE}')


def sync_default_roles():
    """Sync default role permissions and display names from config to the DB.

    Called on every startup (not just fresh installs) so Docker/gunicorn
    instances stay up to date when config changes between deploys.

    Rules:
    - Default roles (is_default=1) always have their permissions replaced
      from DEFAULT_ROLE_PERMISSIONS — this prevents stale permissions
      accumulating across upgrades.
    - Custom roles (is_default=0) are never touched.
    - The retired 'leader' role is migrated to 'readonly' and deleted.
    """
    import sqlcipher3 as _sc3
    db = _connect_db()
    db.row_factory = _sc3.Row

    # ── Retire legacy 'leader' role ────────────────────────────────────────────
    readonly_row = db.execute("SELECT id FROM roles WHERE name = 'readonly'").fetchone()
    leader_row   = db.execute("SELECT id FROM roles WHERE name = 'leader'").fetchone()
    if leader_row:
        if readonly_row:
            db.execute(
                "UPDATE users SET role = 'readonly', role_id = ? WHERE role = 'leader'",
                (readonly_row['id'],),
            )
        else:
            db.execute("UPDATE users SET role = 'readonly' WHERE role = 'leader'")
        db.execute("DELETE FROM roles WHERE name = 'leader'")
        logger.info("sync_default_roles: retired 'leader' role, users moved to 'readonly'.")

    # ── Sync permissions and display name for every default role ───────────────
    for role_name, perms in DEFAULT_ROLE_PERMISSIONS.items():
        display = ROLE_DISPLAY_NAMES.get(role_name, role_name)
        # Ensure the row exists (idempotent insert)
        db.execute(
            'INSERT OR IGNORE INTO roles (name, permissions, is_default, display_name) VALUES (?,?,1,?)',
            (role_name, json.dumps(perms), display),
        )
        # Always overwrite permissions and display name for system-managed roles
        db.execute(
            'UPDATE roles SET permissions = ?, display_name = ? WHERE name = ? AND is_default = 1',
            (json.dumps(perms), display, role_name),
        )

    db.commit()
    db.close()


def ensure_tables():
    """Create any tables added after initial deploy without requiring a full init-db.
    Safe to run on every startup — all operations are idempotent."""
    db = _connect_db()

    # ── Tables ────────────────────────────────────────────────────────────────
    db.executescript('''
        CREATE TABLE IF NOT EXISTS session_activities (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            session_type TEXT    NOT NULL,
            activity     TEXT    NOT NULL,
            added_by     INTEGER REFERENCES users(id),
            created_at   TEXT    DEFAULT (datetime('now')),
            active       INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS term_sessions (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            session_date TEXT    NOT NULL,
            session_type TEXT    NOT NULL,
            term_name    TEXT,
            status       TEXT    NOT NULL DEFAULT 'planned',
            notes        TEXT,
            created_by   INTEGER REFERENCES users(id),
            created_at   TEXT    DEFAULT (datetime('now')),
            UNIQUE(session_date, session_type)
        );
        CREATE INDEX IF NOT EXISTS idx_term_sessions_date ON term_sessions(session_date);
        CREATE INDEX IF NOT EXISTS idx_audit_timestamp    ON audit_log(timestamp);
        CREATE TABLE IF NOT EXISTS session_completions (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            session_date       TEXT    NOT NULL,
            session_type       TEXT    NOT NULL,
            completed_by       INTEGER REFERENCES users(id),
            completed_at       TEXT    DEFAULT (datetime('now')),
            auto_signout_count INTEGER DEFAULT 0,
            UNIQUE(session_date, session_type)
        );
        CREATE TABLE IF NOT EXISTS session_types (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL UNIQUE,
            weekday     INTEGER,
            description TEXT,
            active      INTEGER NOT NULL DEFAULT 1,
            sort_order  INTEGER NOT NULL DEFAULT 0
        );
        -- v10.3: user-to-session junction table (replaces users.session_assigned)
        CREATE TABLE IF NOT EXISTS user_sessions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            session_type_id INTEGER NOT NULL REFERENCES session_types(id) ON DELETE CASCADE,
            UNIQUE(user_id, session_type_id)
        );
        CREATE INDEX IF NOT EXISTS idx_user_sessions_user    ON user_sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_user_sessions_session ON user_sessions(session_type_id);
        -- v12.50 Phase A (multi-session membership): member-to-session junction
        -- table, mirroring user_sessions. members.session remains as a read-only
        -- echo (first assigned session by sort_order) until Phases B–D convert
        -- the remaining readers, then it will be dropped from all queries.
        CREATE TABLE IF NOT EXISTS member_sessions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id       INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
            session_type_id INTEGER NOT NULL REFERENCES session_types(id) ON DELETE CASCADE,
            created_at      TEXT    DEFAULT (datetime('now')),
            UNIQUE(member_id, session_type_id)
        );
        CREATE INDEX IF NOT EXISTS idx_member_sessions_member  ON member_sessions(member_id);
        CREATE INDEX IF NOT EXISTS idx_member_sessions_session ON member_sessions(session_type_id);
        CREATE TABLE IF NOT EXISTS settings (
            key        TEXT PRIMARY KEY,
            value      TEXT NOT NULL,
            updated_at TEXT,
            updated_by INTEGER REFERENCES users(id)
        );
        -- v6.0: permissions catalogue and configurable roles
        CREATE TABLE IF NOT EXISTS permissions (
            code        TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            description TEXT,
            category    TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS roles (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    UNIQUE NOT NULL,
            is_default  INTEGER DEFAULT 0,
            permissions TEXT    NOT NULL,
            created_at  TEXT    DEFAULT (datetime('now'))
        );
        -- v7.1: member skills & badge tags
        CREATE TABLE IF NOT EXISTS tag_definitions (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL UNIQUE,
            category   TEXT    NOT NULL DEFAULT 'General',
            icon       TEXT    DEFAULT '🏷',
            colour     TEXT    NOT NULL DEFAULT '#3b82f6',
            active     INTEGER NOT NULL DEFAULT 1,
            sort_order INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS member_tags (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id  INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
            tag_id     INTEGER NOT NULL REFERENCES tag_definitions(id) ON DELETE CASCADE,
            expires_at TEXT,
            notes      TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            UNIQUE(member_id, tag_id)
        );
        CREATE INDEX IF NOT EXISTS idx_member_tags_member ON member_tags(member_id);
        -- v7.1: session notes & incidents
        CREATE TABLE IF NOT EXISTS session_notes (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            session_date TEXT    NOT NULL,
            session_type TEXT    NOT NULL,
            member_id    INTEGER REFERENCES members(id),
            note_type    TEXT    NOT NULL DEFAULT 'General',
            title        TEXT,
            details      TEXT,
            added_by     INTEGER REFERENCES users(id),
            created_at   TEXT    DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_session_notes_date_type ON session_notes(session_date, session_type);
        CREATE INDEX IF NOT EXISTS idx_session_notes_member    ON session_notes(member_id);
        -- v8.0: configurable member field system
        CREATE TABLE IF NOT EXISTS member_types (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            name                TEXT    NOT NULL UNIQUE,
            slug                TEXT    NOT NULL UNIQUE,
            icon                TEXT    NOT NULL DEFAULT '👤',
            colour              TEXT    NOT NULL DEFAULT '#1b2d4f',
            description         TEXT,
            public_registration INTEGER NOT NULL DEFAULT 0,
            active              INTEGER NOT NULL DEFAULT 1,
            sort_order          INTEGER NOT NULL DEFAULT 0,
            created_at          TEXT    DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS field_definitions (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            key          TEXT    NOT NULL UNIQUE,
            label        TEXT    NOT NULL,
            field_type   TEXT    NOT NULL DEFAULT 'text',
            options      TEXT,
            help_text    TEXT,
            placeholder  TEXT,
            system_field INTEGER NOT NULL DEFAULT 0,
            column_name  TEXT,
            active       INTEGER NOT NULL DEFAULT 1,
            sort_order   INTEGER NOT NULL DEFAULT 0,
            created_at   TEXT    DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS member_type_fields (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            member_type_id       INTEGER NOT NULL REFERENCES member_types(id) ON DELETE CASCADE,
            field_id             INTEGER NOT NULL REFERENCES field_definitions(id) ON DELETE CASCADE,
            sort_order           INTEGER NOT NULL DEFAULT 0,
            required             INTEGER NOT NULL DEFAULT 0,
            show_on_registration INTEGER NOT NULL DEFAULT 1,
            show_on_list         INTEGER NOT NULL DEFAULT 0,
            show_on_attendance   INTEGER NOT NULL DEFAULT 0,
            show_on_card         INTEGER NOT NULL DEFAULT 0,
            show_on_detail       INTEGER NOT NULL DEFAULT 1,
            show_on_print        INTEGER NOT NULL DEFAULT 1,
            show_on_export       INTEGER NOT NULL DEFAULT 0,
            UNIQUE(member_type_id, field_id)
        );
        CREATE TABLE IF NOT EXISTS member_field_values (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id  INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
            field_id   INTEGER NOT NULL REFERENCES field_definitions(id) ON DELETE CASCADE,
            value      TEXT,
            updated_at TEXT    DEFAULT (datetime('now')),
            UNIQUE(member_id, field_id)
        );
        CREATE INDEX IF NOT EXISTS idx_mfv_member ON member_field_values(member_id);
        CREATE INDEX IF NOT EXISTS idx_mtf_type   ON member_type_fields(member_type_id);
        -- v8.0: Member Alert Rules — configurable multi-rule flag engine
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
            created_by          INTEGER REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS member_flags (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id    INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
            rule_id      INTEGER NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
            flagged_at   TEXT    NOT NULL DEFAULT (datetime('now')),
            flagged_by   TEXT    NOT NULL DEFAULT 'auto',
            resolved_at  TEXT,
            resolved_by  TEXT,
            note         TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_member_flags_member ON member_flags(member_id);
        CREATE INDEX IF NOT EXISTS idx_member_flags_rule   ON member_flags(rule_id);
        -- v8.2: Notifications system
        CREATE TABLE IF NOT EXISTS notifications (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id         INTEGER REFERENCES users(id),
            title             TEXT    NOT NULL,
            body              TEXT    NOT NULL,
            notification_type TEXT    NOT NULL DEFAULT 'Info',
            target_type       TEXT    NOT NULL DEFAULT 'all',
            target_value      TEXT,
            is_system         INTEGER NOT NULL DEFAULT 0,
            related_table     TEXT,
            related_id        INTEGER,
            created_at        TEXT    DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS notification_reads (
            notification_id   INTEGER NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
            user_id           INTEGER NOT NULL REFERENCES users(id),
            read_at           TEXT    DEFAULT (datetime('now')),
            PRIMARY KEY (notification_id, user_id)
        );
        CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_notifications_sender  ON notifications(sender_id);
        CREATE INDEX IF NOT EXISTS idx_notification_reads    ON notification_reads(user_id);
        -- v11.6: payments system
        CREATE TABLE IF NOT EXISTS payment_types (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL UNIQUE,
            description TEXT,
            active      INTEGER NOT NULL DEFAULT 1,
            sort_order  INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT    DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS payment_methods (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL UNIQUE,
            active      INTEGER NOT NULL DEFAULT 1,
            sort_order  INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT    DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS member_payments (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id       INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
            payment_type_id INTEGER NOT NULL REFERENCES payment_types(id),
            session_type_id INTEGER REFERENCES session_types(id),  -- v12.53: NULL = whole-club payment
            period          TEXT    NOT NULL,
            payment_date    TEXT,
            amount          REAL,
            method_id       INTEGER REFERENCES payment_methods(id),
            notes           TEXT,
            voided_at       TEXT,
            voided_by       INTEGER REFERENCES users(id),
            void_reason     TEXT,
            recorded_by     INTEGER REFERENCES users(id),
            created_at      TEXT    DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_member_payments_member ON member_payments(member_id);
        CREATE INDEX IF NOT EXISTS idx_member_payments_period ON member_payments(period);
        -- v10.4: configurable member statuses
        CREATE TABLE IF NOT EXISTS member_statuses (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT    NOT NULL UNIQUE,
            behaviour    TEXT    NOT NULL DEFAULT 'active',
            colour       TEXT    NOT NULL DEFAULT '#22c55e',
            sort_order   INTEGER NOT NULL DEFAULT 0,
            is_default   INTEGER NOT NULL DEFAULT 0,
            is_protected INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_member_statuses_name ON member_statuses(name);
        CREATE INDEX IF NOT EXISTS idx_member_statuses_beh  ON member_statuses(behaviour);
        -- v8.3: QR quick-session tokens
        CREATE TABLE IF NOT EXISTS quick_signin_tokens (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            token          TEXT    NOT NULL UNIQUE,
            session_type   TEXT    NOT NULL,
            session_date   TEXT    NOT NULL,
            created_at     TEXT    NOT NULL DEFAULT (datetime('now')),
            invalidated_at TEXT    NULL
        );
        CREATE INDEX IF NOT EXISTS idx_qst_token   ON quick_signin_tokens(token);
        CREATE INDEX IF NOT EXISTS idx_qst_session ON quick_signin_tokens(session_type, session_date);
        -- v9.0: Document repository — configurable categories, secure storage, role-based access
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
        -- v9.2: per-category metadata fields + FTS5 search
        CREATE TABLE IF NOT EXISTS document_field_definitions (
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
        CREATE INDEX IF NOT EXISTS idx_doc_field_defs_cat ON document_field_definitions(category_id);
        CREATE TABLE IF NOT EXISTS document_metadata (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL REFERENCES documents(id)                  ON DELETE CASCADE,
            field_id    INTEGER NOT NULL REFERENCES document_field_definitions(id) ON DELETE CASCADE,
            value       TEXT,
            updated_at  TEXT    DEFAULT (datetime('now')),
            UNIQUE(document_id, field_id)
        );
        CREATE INDEX IF NOT EXISTS idx_doc_metadata_doc   ON document_metadata(document_id);
        CREATE INDEX IF NOT EXISTS idx_doc_metadata_field ON document_metadata(field_id);
        -- v11.7: SMTP sender profiles (replaces hard-coded .env SMTP settings)
        CREATE TABLE IF NOT EXISTS smtp_profiles (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT    NOT NULL UNIQUE,
            host         TEXT    NOT NULL,
            port         INTEGER NOT NULL DEFAULT 587,
            username     TEXT    NOT NULL,
            password_enc TEXT    NOT NULL,
            from_address TEXT    NOT NULL,
            is_default   INTEGER NOT NULL DEFAULT 0,
            created_by   INTEGER REFERENCES users(id),
            created_at   TEXT    DEFAULT (datetime('now')),
            updated_at   TEXT
        );
        -- v11.29: DB-backed rate limiting (shared across gunicorn workers).
        -- Replaces the per-process in-memory limiters for login, public
        -- registration and QR sign-in so limits stay accurate with >1 worker.
        CREATE TABLE IF NOT EXISTS rate_limits (
            bucket_key   TEXT    PRIMARY KEY,   -- e.g. 'login:1.2.3.4', 'register:1.2.3.4', 'qr:qr_search:1.2.3.4'
            window_start REAL    NOT NULL,      -- unix epoch when the current window began
            count        INTEGER NOT NULL DEFAULT 0,
            locked_until REAL    NOT NULL DEFAULT 0,  -- unix epoch; > now means locked out
            updated_at   TEXT
        );
    ''')

    # FTS5 must be created separately — not all SQLite builds support it.
    _fts_db = _connect_db()
    try:
        _fts_db.execute('''
            CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
                doc_id   UNINDEXED,
                content,
                tokenize = 'porter unicode61'
            )
        ''')
        _fts_db.commit()
    except Exception as _fts_exc:
        logger.warning('FTS5 not available — document search will use LIKE fallback: %s', _fts_exc)
    finally:
        _fts_db.close()

    # ── ALTER TABLE migrations (idempotent) ────────────────────────────────────
    alter_stmts = [
        "ALTER TABLE members ADD COLUMN member_type TEXT NOT NULL DEFAULT 'member'",
        "ALTER TABLE members ADD COLUMN staff_role TEXT",
        "ALTER TABLE pending_registrations ADD COLUMN registration_type TEXT NOT NULL DEFAULT 'member'",
        "ALTER TABLE pending_registrations ADD COLUMN applicant_role TEXT",
        "ALTER TABLE pending_registrations ADD COLUMN mobile TEXT",
        "ALTER TABLE pending_registrations ADD COLUMN email TEXT",
        "ALTER TABLE members ADD COLUMN status_note TEXT",
        "ALTER TABLE member_types ADD COLUMN registration_style TEXT NOT NULL DEFAULT 'member'",
        "ALTER TABLE pending_registrations ADD COLUMN custom_fields TEXT",
        "ALTER TABLE pending_registrations ADD COLUMN member_type_slug TEXT NOT NULL DEFAULT 'member'",
        "ALTER TABLE users ADD COLUMN role_id INTEGER REFERENCES roles(id)",
        "ALTER TABLE roles ADD COLUMN display_name TEXT",
        "ALTER TABLE session_completions ADD COLUMN exported_at TEXT",
        "ALTER TABLE session_completions ADD COLUMN exported_by INTEGER REFERENCES users(id)",
        "ALTER TABLE member_type_fields ADD COLUMN show_on_export INTEGER NOT NULL DEFAULT 0",
        # v11.2: split show_on_card into show_on_attendance (register page) and show_on_card (member profile)
        "ALTER TABLE member_type_fields ADD COLUMN show_on_attendance INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE attendance ADD COLUMN source TEXT NOT NULL DEFAULT 'web'",
        "ALTER TABLE field_definitions ADD COLUMN use_lookup INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE documents ADD COLUMN stored_filename TEXT",
        "ALTER TABLE documents ADD COLUMN bucket TEXT NOT NULL DEFAULT 'store'",
        "ALTER TABLE documents ADD COLUMN category_id INTEGER REFERENCES document_categories(id)",
        "ALTER TABLE documents ADD COLUMN description TEXT",
        "ALTER TABLE documents ADD COLUMN retain_until TEXT",
        "ALTER TABLE documents ADD COLUMN retention_notes TEXT",
        "ALTER TABLE documents ADD COLUMN file_size INTEGER",
        "ALTER TABLE documents ADD COLUMN file_path TEXT NOT NULL DEFAULT ''",
        # v10.13: mobile + email as first-class columns on members (mirroring field_definitions)
        "ALTER TABLE members ADD COLUMN mobile TEXT",
        "ALTER TABLE members ADD COLUMN email TEXT",
        # v10.3: Phase A — session type description
        "ALTER TABLE session_types ADD COLUMN description TEXT",
        # v10.3: Phase B — persisted active session selection per user
        "ALTER TABLE users ADD COLUMN active_session_id INTEGER REFERENCES session_types(id)",
        # v12.41: flag the membership payment type so queries stop matching on
        # name = 'Membership' (which broke silently if the type was renamed)
        "ALTER TABLE payment_types ADD COLUMN is_membership INTEGER NOT NULL DEFAULT 0",
        # v12.53 (multi-session Phase C): per-session payments. NULL means a
        # whole-club payment covering every session — the meaning of all rows
        # recorded before this migration, so nobody's paid status changes.
        "ALTER TABLE member_payments ADD COLUMN session_type_id INTEGER REFERENCES session_types(id)",
    ]
    for stmt in alter_stmts:
        try:
            db.execute(stmt)
        except sqlite3.OperationalError as e:
            # Swallow "duplicate column name" — that means the migration already ran.
            # Re-raise anything else (e.g. disk full, schema errors, lock failures).
            err = str(e).lower()
            if 'duplicate column name' in err or 'already exists' in err:
                logger.debug('Migration skipped (already applied): %s', stmt[:80])
            else:
                logger.error('Migration failed — stmt: %s — error: %s', stmt, e)
                raise

    db.commit()

    # v10.3 Phase A: make session_types.weekday nullable (was NOT NULL in older schemas).
    # SQLite can't ALTER COLUMN, so we rebuild the table if the schema still has the constraint.
    try:
        schema_row = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='session_types'"
        ).fetchone()
        schema_sql = schema_row[0] if schema_row else ''
        if 'weekday' in schema_sql and 'NOT NULL' in schema_sql.split('weekday')[1].split('\n')[0]:
            db.executescript('''
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
            db.commit()
            logger.info('Migration: session_types.weekday made nullable (v10.3)')
    except Exception as _e:
        logger.warning('session_types weekday migration skipped: %s', _e)

    # v10.3 Phase B: populate user_sessions from legacy users.session_assigned column.
    # Safe to run repeatedly — INSERT OR IGNORE is idempotent.
    try:
        legacy_users = db.execute(
            "SELECT id, session_assigned FROM users "
            "WHERE session_assigned IS NOT NULL AND session_assigned != ''"
        ).fetchall()
        for _u in legacy_users:
            _st = db.execute(
                "SELECT id FROM session_types WHERE name = ?", (_u[1],)
            ).fetchone()
            if _st:
                db.execute(
                    "INSERT OR IGNORE INTO user_sessions (user_id, session_type_id) VALUES (?,?)",
                    (_u[0], _st[0])
                )
                db.execute(
                    "UPDATE users SET active_session_id = ? "
                    "WHERE id = ? AND active_session_id IS NULL",
                    (_st[0], _u[0])
                )
        db.commit()
        logger.info('Migration: user_sessions populated from session_assigned (v10.3)')
    except Exception as _e:
        logger.warning('user_sessions data migration skipped: %s', _e)

    # v12.50 Phase A: reconcile member_sessions from members.session.
    # Set-based INSERT OR IGNORE — idempotent AND self-healing: it runs on every
    # startup so members created by not-yet-converted write paths (approvals,
    # import) still get their junction row from the members.session value those
    # paths write. Members whose session is blank or doesn't match a session
    # type are counted and logged rather than silently skipped.
    try:
        db.execute('''
            INSERT OR IGNORE INTO member_sessions (member_id, session_type_id)
            SELECT m.id, st.id
            FROM   members m
            JOIN   session_types st ON st.name = m.session
            WHERE  m.session IS NOT NULL AND m.session != ''
        ''')
        _orphans = db.execute('''
            SELECT COUNT(*) FROM members m
            WHERE  NOT EXISTS (SELECT 1 FROM member_sessions ms WHERE ms.member_id = m.id)
        ''').fetchone()[0]
        db.commit()
        if _orphans:
            logger.warning('member_sessions reconcile: %d member(s) have no session '
                           'assignment (blank or unknown session value)', _orphans)
    except Exception as _e:
        logger.warning('member_sessions reconcile skipped: %s', _e)

    # v8.3: unique guard on attendance
    try:
        db.execute('''
            DELETE FROM attendance
            WHERE rowid NOT IN (
                SELECT MIN(rowid)
                FROM attendance
                GROUP BY member_id, session_date, session_type
            )
        ''')
        db.execute('''
            CREATE UNIQUE INDEX IF NOT EXISTS idx_attendance_unique
                ON attendance(member_id, session_date, session_type)
        ''')
    except Exception:
        pass

    # v8.15+: normalise member status values
    try:
        db.execute(
            "UPDATE members SET status = 'Active' WHERE status IS NULL OR TRIM(status) = ''"
        )
        for dirty, clean in [('active', 'Active'), ('inactive', 'Inactive'), ('leaver', 'Leaver')]:
            db.execute(
                "UPDATE members SET status = ? WHERE LOWER(TRIM(status)) = ? AND status != ?",
                (clean, dirty, clean)
            )
    except Exception:
        pass

    # v11.2: split show_on_card into show_on_attendance + show_on_card (member profile).
    # One-time data migration for pre-v11.2 databases ONLY — copy old show_on_card →
    # show_on_attendance, then set show_on_card = OR(card, detail).
    #
    # RULE: if any member field already has at least one "Show On" flag set, an admin
    # has configured the fields and we must not seed or change anything.
    #
    # This guard is required because the UPDATE is NOT idempotent: it rewrites
    # show_on_card = MAX(show_on_card, show_on_detail), which feeds back into the WHERE
    # clause on the next startup and re-flips show_on_attendance = 1. Since nearly every
    # field has show_on_detail = 1, without this guard every field ends up populated on
    # the attendance card after a couple of restarts.
    try:
        already_configured = db.execute('''
            SELECT 1 FROM member_type_fields
            WHERE  show_on_registration = 1 OR show_on_list = 1
               OR  show_on_attendance   = 1 OR show_on_card = 1
               OR  show_on_detail       = 1 OR show_on_print = 1
               OR  show_on_export       = 1
            LIMIT 1
        ''').fetchone()
        if already_configured:
            logger.info('show_on_attendance migration skipped: member fields already configured')
        else:
            db.execute('''
                UPDATE member_type_fields
                SET    show_on_attendance = show_on_card,
                       show_on_card      = MAX(show_on_card, show_on_detail)
                WHERE  show_on_attendance = 0 AND (show_on_card = 1 OR show_on_detail = 1)
            ''')
            logger.info('Migration: show_on_attendance populated from show_on_card (v11.2)')
    except Exception as _e:
        logger.warning('show_on_attendance data migration skipped: %s', _e)

    db.commit()
    db.close()

    # ── Seeding — one shared connection (v12.42) ──────────────────────────────
    # Previously every seed section below opened and closed its own connection
    # (9 per startup), and the payment-field migration leaked its connection if
    # an error fired before its close(). All sections now share `seed`, closed
    # once in the finally block at the end of this function.
    import sqlcipher3 as _sc3
    seed = _connect_db()
    seed.row_factory = _sc3.Row
    try:

        # ── Seed default settings ─────────────────────────────────────────────────
        if not seed.execute("SELECT key FROM settings WHERE key = 'alerts_last_run'").fetchone():
            seed.execute("INSERT INTO settings (key, value) VALUES ('alerts_last_run', '')")
        _qr_defaults = [
            ('quick_signin_enabled',      'true'),
            ('quick_signout_enabled',     'false'),
            ('quick_signin_welcome_msg',  'Welcome, {name}! Great to see you tonight! 🎉'),
            ('quick_signin_already_msg',  "You're already signed in, {name}! See you inside 👋"),
            ('quick_signout_goodbye_msg', 'Goodbye, {name}! See you next time 👋'),
            ('quick_signout_already_msg', "You're already signed out, {name}. Safe journey home!"),
        ]
        for key, val in _qr_defaults:
            if not seed.execute('SELECT key FROM settings WHERE key = ?', (key,)).fetchone():
                seed.execute('INSERT INTO settings (key, value) VALUES (?, ?)', (key, val))
        for key, val in BRAND_KEYS.items():
            if not seed.execute('SELECT key FROM settings WHERE key = ?', (key,)).fetchone():
                seed.execute('INSERT INTO settings (key, value) VALUES (?, ?)', (key, val))
        # v11.6: current membership period (admin-configurable)
        if not seed.execute("SELECT key FROM settings WHERE key = 'current_membership_period'").fetchone():
            from datetime import date as _date
            _yr = _date.today().year
            _period = f'{_yr}/{str(_yr + 1)[-2:]}'
            seed.execute("INSERT INTO settings (key, value) VALUES ('current_membership_period', ?)", (_period,))
        seed.commit()

        # ── Seed default session types (fresh install only) ───────────────────────
        # Only runs when the table is completely empty — never overwrites deliberate deletions.
        if not seed.execute('SELECT id FROM session_types LIMIT 1').fetchone():
            for sort_order, (name, weekday) in enumerate([('Tuesday', 1), ('Thursday', 3)]):
                seed.execute(
                    'INSERT INTO session_types (name, weekday, active, sort_order, description) VALUES (?,?,1,?,?)',
                    (name, weekday, sort_order, f'{name} evening session'),
                )
            seed.commit()
            logger.info('Seeded default session types (fresh install)')

        # ── Seed default document categories ──────────────────────────────────────
        _default_categories = [
            ('Policy',        'Organisational policies and procedures',  '📜', '#3b82f6', 0),
            ('Form',          'Fillable forms and templates',            '📋', '#10b981', 1),
            ('Template',      'Document templates for staff use',        '✉️', '#8b5cf6', 2),
            ('Register',      'Session registers and attendance sheets', '📝', '#f59e0b', 3),
            ('Safeguarding',  'Safeguarding records and incident notes', '🔒', '#ef4444', 4),
            ('Finance',       'Financial records, invoices and budgets', '💰', '#06b6d4', 5),
            ('General',       'General documents and miscellaneous',     '📄', '#64748b', 6),
        ]
        for name, desc, icon, color, sort_order in _default_categories:
            if not seed.execute('SELECT id FROM document_categories WHERE name = ?', (name,)).fetchone():
                seed.execute(
                    'INSERT INTO document_categories (name, description, icon, color, sort_order) VALUES (?,?,?,?,?)',
                    (name, desc, icon, color, sort_order),
                )
        seed.commit()

        # ── Seed member statuses ──────────────────────────────────────────────────
        # Protected statuses (Active, Leaver) cannot be deleted; Active is the default.
        _default_statuses = [
            # name,       behaviour,  colour,    sort, is_default, is_protected
            ('Active',   'active',   '#22c55e', 0,    1,          1),
            ('Inactive', 'inactive', '#f59e0b', 1,    0,          0),
            ('Leaver',   'leaver',   '#ef4444', 2,    0,          1),
        ]
        for name, behaviour, colour, sort_order, is_default, is_protected in _default_statuses:
            # INSERT OR IGNORE so the loop is idempotent on repeated startups
            seed.execute(
                'INSERT OR IGNORE INTO member_statuses '
                '(name, behaviour, colour, sort_order, is_default, is_protected) '
                'VALUES (?,?,?,?,?,?)',
                (name, behaviour, colour, sort_order, is_default, is_protected),
            )
            # Always enforce correct behaviour + protected flag on existing rows
            seed.execute(
                'UPDATE member_statuses SET behaviour = ?, is_protected = ? WHERE name = ?',
                (behaviour, is_protected, name),
            )
        seed.commit()

        # ── Seed permissions catalogue ─────────────────────────────────────────────
        for code, name, desc, cat in ALL_PERMISSIONS:
            seed.execute(
                'INSERT OR IGNORE INTO permissions (code, name, description, category) VALUES (?,?,?,?)',
                (code, name, desc, cat),
            )
        seed.commit()

        # ── Seed / sync default roles ──────────────────────────────────────────────
        # Delegated to sync_default_roles() which also runs on every startup,
        # ensuring Docker/gunicorn instances stay current without a full init-db.
        sync_default_roles()

        # ── Migrate existing users → role_id ───────────────────────────────────────
        users_needing_migration = seed.execute(
            'SELECT id, role FROM users WHERE role_id IS NULL'
        ).fetchall()
        for user in users_needing_migration:
            role_row = seed.execute(
                'SELECT id FROM roles WHERE name = ?', (user['role'],)
            ).fetchone()
            if role_row:
                seed.execute(
                    'UPDATE users SET role_id = ? WHERE id = ?',
                    (role_row['id'], user['id']),
                )
        seed.commit()

        # ── Seed member types (fresh install only) ────────────────────────────────
        # Only runs when the table is completely empty — never overwrites deliberate
        # additions, renames, or deletions made by the club admin.
        if not seed.execute('SELECT id FROM member_types LIMIT 1').fetchone():
            for slug, name, icon, colour, description, public_registration, sort_order in [
                ('member', 'Member', '👦', '#1b2d4f', 'Young people attending club sessions', 1, 0),
                ('staff',  'Staff',  '🧑', '#0f766e', 'Leaders, coaches and volunteers',      0, 1),
            ]:
                seed.execute(
                    '''INSERT OR IGNORE INTO member_types
                       (slug, name, icon, colour, description, public_registration, sort_order)
                       VALUES (?,?,?,?,?,?,?)''',
                    (slug, name, icon, colour, description, public_registration, sort_order),
                )
            seed.execute(
                "UPDATE member_types SET registration_style = 'staff' "
                "WHERE slug = 'staff' AND (registration_style IS NULL OR registration_style = 'member')"
            )
            seed.commit()
            logger.info('Seeded default member types (fresh install)')

        # ── Seed system field definitions ──────────────────────────────────────────
        for key, label, field_type, column_name, placeholder, help_text, sort_order in [
            ('first_name',            'First Name',                      'text',      'first_name',         'e.g. Isabella',                             None,  1),
            ('surname',               'Surname',                         'text',      'surname',            'e.g. Fitzpatrick',                          None,  2),
            ('date_of_birth',         'Date of Birth',                   'date',      'date_of_birth',      None,                                        None,  3),
            ('address',               'Home Address',                    'text',      'address',            'Start typing or use the postcode finder',    None,  4),
            ('postcode',              'Postcode',                        'postcode',  'postcode',           'e.g. TW15 3EL',                             None,  5),
            ('ethnicity_religion',    'Ethnicity / Religion',            'text',      'ethnicity_religion', 'e.g. English / Christian',                  None,  6),
            ('medical_sen',           'Medical Needs, Allergies or SEN', 'textarea',  'medical_sen',        None,                                        'Describe any medical conditions, allergies or special educational needs.', 7),
            ('gp_contact',            'GP / Doctor Surgery Contact',     'text',      'gp_contact',         'e.g. Stanwell Road Surgery — 01784 123456', None,  8),
            ('unattended_exit',       'Unattended Exit',                 'boolean',   'unattended_exit',    None,                                        'Will make their own way home unaccompanied at the end of the session.',    9),
            ('gdpr_consent',          'Communications Consent',          'boolean',   'gdpr_consent',       None,                                        'Happy to be contacted about upcoming events and club information.',        10),
            ('session',               'Session',                         'text',      'session',            None,                                        'Which session this person attends.',                                       11),
            ('staff_role',            'Staff Role',                      'text',      'staff_role',         None,                                        None, 12),
            ('comments',              'Internal Notes',                  'textarea',  'comments',           None,                                        'Internal notes — not visible to members or parents.',                      13),
            ('status',                'Status',                          'select',    'status',             None,                                        None, 14),
            ('date_registered',       'Date Registered',                 'date',      'date_registered',    None,                                        None, 15),
            ('contact1_name',         'Primary Contact — Full Name',     'text',      'contact1_name',      'e.g. Charlotte Day',                        None, 30),
            ('contact1_phone',        'Primary Contact — Phone',         'phone',     'contact1_phone',     'e.g. 07590 118098',                         None, 31),
            ('contact1_email',        'Primary Contact — Email',         'email',     'contact1_email',     'e.g. charlotte.day@email.com',              None, 32),
            ('contact2_name',         'Second Contact — Full Name',      'text',      'contact2_name',      'e.g. James Day',                            None, 33),
            ('contact2_phone',        'Second Contact — Phone',          'phone',     'contact2_phone',     'e.g. 07700 900000',                         None, 34),
            ('contact2_email',        'Second Contact — Email',          'email',     'contact2_email',     'e.g. james.day@email.com',                  None, 35),
            ('mobile',                'Mobile Number',                   'phone',     'mobile',             'e.g. 07700 900000',                         None, 36),
            ('email',                 'Email Address',                   'email',     'email',              'e.g. you@email.com',                        None, 37),
            ('guardian_confirmation', 'Guardian Confirmation',           'signature', None,                 None,                                        'Parent or guardian types their full name to confirm the registration.',   38),
        ]:
            seed.execute(
                '''INSERT OR IGNORE INTO field_definitions
                   (key, label, field_type, column_name, placeholder, help_text, sort_order, system_field)
                   VALUES (?,?,?,?,?,?,?,1)''',
                (key, label, field_type, column_name, placeholder, help_text, sort_order),
            )
        seed.execute("""
            UPDATE field_definitions
            SET system_field  = 1,
                column_name   = 'status',
                field_type    = 'select',
                options       = CASE WHEN options IS NULL OR options = '' THEN 'Active\nInactive\nLeaver' ELSE options END
            WHERE key = 'status'
        """)
        seed.execute("""
            UPDATE field_definitions
            SET system_field = 1,
                column_name  = 'date_registered',
                field_type   = 'date'
            WHERE key = 'date_registered'
        """)

        # ── Seed declaration field definitions ─────────────────────────────────────
        for key, label, sort_order in [
            ('consent_attend',
             'I am the parent / guardian of the young person named above and I give '
             'consent for them to attend activities organised by {club}.',
             20),
            ('consent_photos',
             "I agree that photos and videos can be taken of my child to publicise "
             "the group's activities.",
             21),
            ('consent_comms',
             'I am happy to be emailed or texted with up-and-coming events or '
             'important information regarding {club}.',
             22),
            ('consent_belongings',
             'I understand that {club} is NOT responsible for personal belongings.',
             23),
            ('consent_medical',
             'I give consent for my child to be taken for medical treatment in the '
             'event of an emergency.',
             24),
        ]:
            seed.execute(
                '''INSERT OR IGNORE INTO field_definitions
                   (key, label, field_type, column_name, placeholder, help_text, sort_order, system_field)
                   VALUES (?,?,'declaration',NULL,NULL,NULL,?,0)''',
                (key, label, sort_order),
            )
        seed.commit()

        # ── Seed default member_type_fields (fresh install only per member type) ───
        # Only seeds show_on values for a member type that has no existing field
        # configurations — once an admin has configured fields for a type, we never
        # overwrite their choices (even for fields not yet linked to that type).
        _default_fields = {
            'member': [
                # key,                   req, reg, list, card, detail, print, sort
                ('first_name',           1,   1,   1,    1,    1,      1,     1),
                ('surname',              1,   1,   1,    1,    1,      1,     2),
                ('date_of_birth',        1,   1,   0,    0,    1,      1,     3),
                ('address',              1,   1,   0,    0,    1,      1,     4),
                ('postcode',             1,   1,   0,    0,    1,      0,     5),
                ('ethnicity_religion',   0,   1,   0,    0,    1,      0,     6),
                ('medical_sen',          0,   1,   0,    0,    1,      1,     7),
                ('gp_contact',           1,   1,   0,    0,    1,      1,     8),
                ('unattended_exit',      0,   1,   0,    1,    1,      1,     9),
                ('gdpr_consent',         0,   1,   0,    0,    1,      0,     10),
                ('session',              1,   0,   0,    0,    1,      1,     11),
                ('comments',             0,   0,   0,    0,    1,      0,     12),
                ('status',               0,   0,   0,    1,    1,      1,     13),
                ('date_registered',      0,   0,   0,    0,    1,      0,     14),
                ('contact1_name',        1,   1,   0,    0,    1,      1,     30),
                ('contact1_phone',       1,   1,   0,    0,    1,      1,     31),
                ('contact1_email',       0,   1,   0,    0,    1,      0,     32),
                ('contact2_name',        0,   1,   0,    0,    1,      0,     33),
                ('contact2_phone',       0,   1,   0,    0,    1,      0,     34),
                ('contact2_email',       0,   1,   0,    0,    1,      0,     35),
                ('consent_attend',       1,   1,   0,    0,    1,      0,     20),
                ('consent_photos',       0,   1,   0,    0,    1,      0,     21),
                ('consent_comms',        0,   1,   0,    0,    1,      0,     22),
                ('consent_belongings',   0,   1,   0,    0,    1,      0,     23),
                ('consent_medical',      1,   1,   0,    0,    1,      0,     24),
                ('guardian_confirmation',1,   1,   0,    0,    0,      0,     38),
            ],
            'staff': [
                ('first_name',   1, 1, 1, 1, 1, 1, 1),
                ('surname',      1, 1, 1, 1, 1, 1, 2),
                ('date_of_birth',0, 1, 0, 0, 1, 0, 3),
                ('mobile',       0, 1, 0, 0, 1, 0, 36),
                ('email',        0, 1, 0, 0, 1, 0, 37),
                ('staff_role',   0, 1, 1, 1, 1, 1, 12),
                ('session',      1, 0, 0, 0, 1, 1, 11),
                ('status',       0, 0, 0, 1, 1, 1, 13),
                ('comments',     0, 0, 0, 0, 1, 0, 99),
            ],
        }
        for type_slug, fields in _default_fields.items():
            type_row = seed.execute(
                'SELECT id FROM member_types WHERE slug = ?', (type_slug,)
            ).fetchone()
            if not type_row:
                continue
            type_id = type_row['id']
            # Skip entirely if this member type already has any field configurations
            already_configured = seed.execute(
                'SELECT id FROM member_type_fields WHERE member_type_id = ? LIMIT 1',
                (type_id,)
            ).fetchone()
            if already_configured:
                continue
            for field_key, req, reg, lst, card, detail, prnt, sort in fields:
                fd = seed.execute(
                    'SELECT id FROM field_definitions WHERE key = ?', (field_key,)
                ).fetchone()
                if not fd:
                    continue
                field_id = fd['id']
                seed.execute(
                    '''INSERT OR IGNORE INTO member_type_fields
                       (member_type_id, field_id, required, show_on_registration, show_on_list,
                        show_on_card, show_on_detail, show_on_print, sort_order)
                       VALUES (?,?,?,?,?,?,?,?,?)''',
                    (type_id, field_id, req, reg, lst, card, detail, prnt, sort),
                )
        seed.commit()

        # ── Seed default payment types ─────────────────────────────────────────────
        _default_payment_types = [
            ('Membership', 'Annual membership fee',          0),
            ('Trip',       'Day trip or residential outing', 1),
            ('Equipment',  'Equipment or kit purchase',      2),
            ('Event',      'One-off event or activity fee',  3),
            ('Other',      'Miscellaneous payment',          4),
        ]
        for name, desc, sort_order in _default_payment_types:
            seed.execute(
                'INSERT OR IGNORE INTO payment_types (name, description, sort_order) VALUES (?,?,?)',
                (name, desc, sort_order),
            )
        _default_payment_methods = [
            ('Cash',            0),
            ('Bank Transfer',   1),
            ('Standing Order',  2),
            ('Online',          3),
            ('Other',           4),
        ]
        for name, sort_order in _default_payment_methods:
            seed.execute(
                'INSERT OR IGNORE INTO payment_methods (name, sort_order) VALUES (?,?)',
                (name, sort_order),
            )
        # v12.41: one-time flag of the membership type. Guarded so a club that
        # renamed its flagged type and later created a new type called 'Membership'
        # doesn't get the flag silently moved.
        if not seed.execute('SELECT id FROM payment_types WHERE is_membership = 1 LIMIT 1').fetchone():
            seed.execute("UPDATE payment_types SET is_membership = 1 WHERE name = 'Membership'")
        seed.commit()

        # ── Migrate legacy boolean "paid" fields → member_payments rows ────────────
        # Finds any field_definitions with a key matching *_paid_* or *_membership_paid*
        # (e.g. "membership_paid_2526", "ara_membership_paid_2526") that store a
        # boolean value. For each member with value '1' or 'true', inserts a
        # member_payments row (amount=NULL, payment_date=NULL) so the history is
        # preserved.  Original field values are left untouched.
        try:
            paid_fields = seed.execute(
                "SELECT id, key, label FROM field_definitions "
                "WHERE (key LIKE '%_paid_%' OR key LIKE '%membership_paid%') "
                "  AND field_type = 'boolean' AND active = 1"
            ).fetchall()
            membership_type = seed.execute(
                "SELECT id FROM payment_types WHERE is_membership = 1"
            ).fetchone()
            if not membership_type:
                membership_type = seed.execute(
                    "SELECT id FROM payment_types WHERE name = 'Membership'"
                ).fetchone()
            if paid_fields and membership_type:
                mt_id = membership_type['id']
                for pf in paid_fields:
                    # Derive period from label: e.g. "2025/26 Membership Paid" → "2025/26"
                    import re as _re
                    period_match = _re.search(r'(\d{4}/\d{2,4})', pf['label'])
                    period = period_match.group(1) if period_match else pf['key']

                    truthy_members = seed.execute(
                        "SELECT member_id FROM member_field_values "
                        "WHERE field_id = ? AND LOWER(TRIM(value)) IN ('1','true','yes')",
                        (pf['id'],)
                    ).fetchall()
                    for row in truthy_members:
                        existing = seed.execute(
                            "SELECT id FROM member_payments "
                            "WHERE member_id = ? AND payment_type_id = ? AND period = ? AND voided_at IS NULL",
                            (row['member_id'], mt_id, period)
                        ).fetchone()
                        if not existing:
                            seed.execute(
                                "INSERT INTO member_payments "
                                "(member_id, payment_type_id, period, recorded_by) "
                                "VALUES (?,?,?,NULL)",
                                (row['member_id'], mt_id, period)
                            )
                            logger.info(
                                'Migration: inserted payment for member_id=%s period=%s from field %s',
                                row['member_id'], period, pf['key']
                            )
                seed.commit()
        except Exception as _mig_exc:
            logger.warning('Payment field migration skipped: %s', _mig_exc)
    finally:
        seed.close()
