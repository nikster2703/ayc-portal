-- ============================================================
-- AYC Portal — Permissions Schema Extension
-- Run via migrate_to_role_permissions.py (or automatically
-- on startup via ensure_tables() in app.py).
-- ============================================================

-- Master list of every permission the app supports.
-- Codes are dotted strings: "<area>.<action>"
CREATE TABLE IF NOT EXISTS permissions (
    code        TEXT PRIMARY KEY,   -- e.g. "members.view", "register.signin"
    name        TEXT NOT NULL,
    description TEXT,
    category    TEXT NOT NULL       -- members | register | approvals | documents |
                                    -- calendar | users | admin | audit | communications | display
);

-- Configurable roles (replaces the hard-coded role TEXT values).
-- permissions column is a JSON array of permission codes.
CREATE TABLE IF NOT EXISTS roles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    UNIQUE NOT NULL,
    is_default  INTEGER DEFAULT 0,  -- 1 = one of the original built-in roles
    permissions TEXT    NOT NULL,   -- JSON: ["members.view", "register.signin", ...]
    created_at  TEXT    DEFAULT (datetime('now'))
);
