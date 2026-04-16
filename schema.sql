-- ============================================================
-- AYC Portal — Database Schema
-- SQLite, Phase 1
--
-- Tables are created for ALL planned phases now so future
-- features slot in without migrations breaking existing data.
-- ============================================================

-- ── Staff logins ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    username         TEXT    UNIQUE NOT NULL,
    email            TEXT,
    password_hash    TEXT    NOT NULL,
    role             TEXT    NOT NULL DEFAULT 'readonly',
    -- roles: admin | editor | leader | readonly
    session_assigned TEXT,
    -- Tuesday | Thursday | Both  (used by 'leader' role to scope their view)
    active           INTEGER NOT NULL DEFAULT 1,
    created_at       TEXT    DEFAULT (datetime('now')),
    last_login       TEXT
);

-- ── Members ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS members (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id         TEXT    UNIQUE NOT NULL,   -- AYC001, AYC002 …
    first_name        TEXT    NOT NULL,
    surname           TEXT    NOT NULL,
    date_of_birth     TEXT,
    address           TEXT,
    postcode          TEXT,
    ethnicity_religion TEXT,
    medical_sen       TEXT,
    gp_contact        TEXT,
    unattended_exit   INTEGER NOT NULL DEFAULT 0,  -- 0=No 1=Yes
    gdpr_consent      INTEGER NOT NULL DEFAULT 0,
    status            TEXT    NOT NULL DEFAULT 'Active',  -- Active | Inactive | Leaver
    session           TEXT,                               -- Tuesday | Thursday | Both
    member_type       TEXT    NOT NULL DEFAULT 'member',  -- member | staff
    staff_role        TEXT,                               -- Volunteer | Youth Volunteer | Leader (staff only)
    date_registered   TEXT,
    comments          TEXT,
    created_at        TEXT    DEFAULT (datetime('now')),
    updated_at        TEXT    DEFAULT (datetime('now')),
    updated_by        INTEGER REFERENCES users(id)
);

-- ── Member contacts (replaces Contact 1/2 columns) ────────
CREATE TABLE IF NOT EXISTS member_contacts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id     INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    contact_order INTEGER NOT NULL DEFAULT 1,   -- 1 = primary, 2 = secondary
    contact_name  TEXT,
    contact_phone TEXT,
    contact_email TEXT
);

-- ── Pending registrations (public self-reg awaiting approval)
CREATE TABLE IF NOT EXISTS pending_registrations (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name         TEXT    NOT NULL,
    surname            TEXT    NOT NULL,
    date_of_birth      TEXT,
    address            TEXT,
    postcode           TEXT,
    ethnicity_religion TEXT,
    medical_sen        TEXT,
    gp_contact         TEXT,
    unattended_exit    INTEGER DEFAULT 0,
    gdpr_consent       INTEGER DEFAULT 0,
    comms_consent      INTEGER DEFAULT 0,
    contact1_name      TEXT,
    contact1_phone     TEXT,
    contact1_email     TEXT,
    contact2_name      TEXT,
    contact2_phone     TEXT,
    contact2_email     TEXT,
    declarations       TEXT,   -- JSON blob of all declaration answers
    submitted_at       TEXT    DEFAULT (datetime('now')),
    status             TEXT    NOT NULL DEFAULT 'pending', -- pending | approved | rejected
    assigned_session   TEXT,
    reviewed_by        INTEGER REFERENCES users(id),
    reviewed_at        TEXT,
    notes              TEXT,
    registration_type  TEXT    NOT NULL DEFAULT 'member', -- member | staff
    applicant_role     TEXT,    -- Volunteer | Youth Volunteer | Leader (staff registrations)
    mobile             TEXT,    -- staff contact mobile
    email              TEXT     -- staff contact email
);

-- ── Document repository (Phase 4) ─────────────────────────
CREATE TABLE IF NOT EXISTS documents (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    title         TEXT    NOT NULL,
    filename      TEXT    NOT NULL,
    file_path     TEXT    NOT NULL,
    mime_type     TEXT,
    category      TEXT,        -- policy | template | form | general
    access_role   TEXT    NOT NULL DEFAULT 'readonly',  -- min role to access
    uploaded_by   INTEGER REFERENCES users(id),
    created_at    TEXT    DEFAULT (datetime('now')),
    active        INTEGER NOT NULL DEFAULT 1
);

-- ── Email templates (Phase 4) ─────────────────────────────
CREATE TABLE IF NOT EXISTS email_templates (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    subject     TEXT    NOT NULL,
    body_html   TEXT    NOT NULL,
    created_by  INTEGER REFERENCES users(id),
    created_at  TEXT    DEFAULT (datetime('now')),
    updated_at  TEXT    DEFAULT (datetime('now'))
);

-- ── Mailshot log (Phase 4) ────────────────────────────────
CREATE TABLE IF NOT EXISTS mailshot_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id      INTEGER REFERENCES email_templates(id),
    subject          TEXT    NOT NULL,
    sent_by          INTEGER REFERENCES users(id),
    recipient_count  INTEGER,
    filter_criteria  TEXT,   -- JSON — what filter was used to select recipients
    sent_at          TEXT    DEFAULT (datetime('now')),
    notes            TEXT
);

-- ── Session attendance register (Phase 3) ─────────────────
CREATE TABLE IF NOT EXISTS attendance (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id     INTEGER NOT NULL REFERENCES members(id),
    session_date  TEXT    NOT NULL,
    session_type  TEXT    NOT NULL,   -- Tuesday | Thursday
    signed_in_at  TEXT,
    signed_out_at TEXT,
    recorded_by   INTEGER REFERENCES users(id)
);

-- ── Session types (configurable) ────────────────────────
CREATE TABLE IF NOT EXISTS session_types (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL UNIQUE,
    weekday    INTEGER NOT NULL,  -- Python weekday(): Mon=0 … Sun=6
    active     INTEGER NOT NULL DEFAULT 1,
    sort_order INTEGER NOT NULL DEFAULT 0
);

-- ── Session register completions ────────────────────────
CREATE TABLE IF NOT EXISTS session_completions (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    session_date       TEXT    NOT NULL,
    session_type       TEXT    NOT NULL,   -- Tuesday | Thursday
    completed_by       INTEGER REFERENCES users(id),
    completed_at       TEXT    DEFAULT (datetime('now')),
    auto_signout_count INTEGER DEFAULT 0,
    UNIQUE(session_date, session_type)
);

-- ── Term calendar (Phase 5) ───────────────────────────────
CREATE TABLE IF NOT EXISTS term_sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_date TEXT    NOT NULL,
    session_type TEXT    NOT NULL,   -- Tuesday | Thursday
    term_name    TEXT,               -- e.g. "Autumn 2026"
    status       TEXT    NOT NULL DEFAULT 'planned',  -- planned | cancelled | special
    notes        TEXT,
    created_by   INTEGER REFERENCES users(id),
    created_at   TEXT    DEFAULT (datetime('now')),
    UNIQUE(session_date, session_type)
);

CREATE INDEX IF NOT EXISTS idx_term_sessions_date ON term_sessions(session_date);

-- ── Session activities board (display screen) ────────────
CREATE TABLE IF NOT EXISTS session_activities (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_type TEXT    NOT NULL,   -- Tuesday | Thursday
    activity     TEXT    NOT NULL,
    added_by     INTEGER REFERENCES users(id),
    created_at   TEXT    DEFAULT (datetime('now')),
    active       INTEGER NOT NULL DEFAULT 1
);

-- ── Duke of Edinburgh (future phase) ─────────────────────
CREATE TABLE IF NOT EXISTS dofe_participants (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id   INTEGER NOT NULL REFERENCES members(id),
    level       TEXT    NOT NULL,   -- Bronze | Silver | Gold
    start_date  TEXT,
    assessor    TEXT,
    status      TEXT    DEFAULT 'active',  -- active | completed | withdrawn
    notes       TEXT,
    created_at  TEXT    DEFAULT (datetime('now'))
);

-- ── Audit log ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER REFERENCES users(id),
    action     TEXT    NOT NULL,
    table_name TEXT,
    record_id  INTEGER,
    details    TEXT,   -- JSON
    ip_address TEXT,
    timestamp  TEXT    DEFAULT (datetime('now'))
);

-- ── Indexes ───────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_members_status   ON members(status);
CREATE INDEX IF NOT EXISTS idx_members_session  ON members(session);
CREATE INDEX IF NOT EXISTS idx_contacts_member  ON member_contacts(member_id);
CREATE INDEX IF NOT EXISTS idx_pending_status   ON pending_registrations(status);
CREATE INDEX IF NOT EXISTS idx_attendance_member ON attendance(member_id);
CREATE INDEX IF NOT EXISTS idx_audit_user       ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp  ON audit_log(timestamp);
