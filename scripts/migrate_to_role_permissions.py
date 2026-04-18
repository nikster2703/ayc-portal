"""
AYC Portal — v6.0 Migration Script
===================================
Migrates the database from hard-coded role strings to the new
Roles + Permissions system.

Run this ONCE on the live server before deploying v6.0 code:
    python scripts/migrate_to_role_permissions.py

Safe to run multiple times — all inserts use INSERT OR IGNORE.
The old `role` column on users is preserved for one release cycle
as a safety net.
"""

import json
import os
import sys

import sqlcipher3 as sqlite3  # SQLCipher — transparent AES-256 encryption at rest

try:
    from dotenv import load_dotenv
except ImportError:
    sys.exit('python-dotenv not found. Run: pip3 install python-dotenv')

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'ayc.db')

# Load .env so DB_ENCRYPTION_KEY is available
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))


def _connect_db(path):
    """Open a SQLCipher-encrypted DB connection. Exits if key is missing."""
    key = os.environ.get('DB_ENCRYPTION_KEY')
    if not key:
        sys.exit('ERROR: DB_ENCRYPTION_KEY is not set in .env — cannot open the database.')
    conn = sqlite3.connect(path)
    conn.execute(f"PRAGMA key='{key}'")
    conn.execute('SELECT count(*) FROM sqlite_master')  # verify key immediately
    return conn
SQL_PATH = os.path.join(os.path.dirname(__file__), 'schema_permissions.sql')


# ── Permission catalogue ───────────────────────────────────────────────────────

ALL_PERMISSIONS = [
    # Members
    ('members.view',        'View Members',           'View member list and full detail cards',          'members'),
    ('members.edit',        'Edit Members',            'Edit member records',                              'members'),
    ('members.delete',      'Soft Delete Members',     'Mark a member as Leaver (reversible)',             'members'),
    ('members.hard_delete', 'Permanent Delete Members','Permanently and irreversibly delete a member',     'members'),
    # Register / attendance
    ('register.signin',     'Sign In',                 'Sign members in on the session register',          'register'),
    ('register.signout',    'Sign Out',                'Sign members out on the session register',          'register'),
    ('register.complete',   'Complete Register',       'Lock the register at end of session',              'register'),
    ('register.reset',      'Reset Register',          'Wipe all sign-in/out data for a session',         'register'),
    ('register.at_risk',    'Mark At Risk',            'Run the at-risk check and flag members',           'register'),
    # Approvals
    ('approvals.view',      'View Approvals',          'View pending self-registration submissions',       'approvals'),
    ('approvals.approve',   'Approve Registrations',   'Approve a pending registration',                   'approvals'),
    ('approvals.reject',    'Reject Registrations',    'Reject a pending registration',                    'approvals'),
    # Documents
    ('documents.view',      'View Documents',          'Browse the document repository (rank check still applies per doc)', 'documents'),
    ('documents.upload',    'Upload Documents',        'Upload new files to the repository',               'documents'),
    ('documents.delete',    'Delete Documents',        'Soft-delete documents from the repository',        'documents'),
    # Calendar
    ('calendar.create',     'Create Calendar Sessions','Add sessions to the term calendar',                'calendar'),
    ('calendar.edit',       'Edit Calendar',           'Update session status, notes and term name',       'calendar'),
    ('calendar.delete',     'Delete Calendar Sessions','Remove sessions from the term calendar',           'calendar'),
    # Users
    ('users.view',          'View Users',              'View the portal user list',                        'users'),
    ('users.create',        'Create Users',            'Create new portal staff accounts',                 'users'),
    ('users.edit',          'Edit Users',              'Edit existing portal accounts',                    'users'),
    ('users.create.admin',  'Create Admin Users',      'Assign roles that carry admin-level permissions',  'users'),
    ('users.delete',        'Delete Users',            'Permanently delete a portal user account',         'users'),
    # Admin / settings
    ('admin.settings',      'Manage Settings',         'Access and change club settings and roles',        'admin'),
    ('admin.session_types', 'Manage Session Types',    'Create, edit and reorder session types',           'admin'),
    ('admin.maintenance',   'Maintenance Tools',       'Clear audit logs, attendance and registration data','admin'),
    # Audit
    ('audit.view',          'View Audit Log',          'View the full system audit log',                   'audit'),
    # Communications
    ('mailshots.send',      'Send Mailshots',          'Send bulk emails to member contacts',              'communications'),
    ('mailshots.templates', 'Manage Email Templates',  'Create, edit and delete email templates',          'communications'),
    # Display board
    ('activities.manage',   'Manage Activities Board', 'Add and remove activities from the TV display',    'display'),
]


# ── Default role permission sets (exact match to current behaviour) ────────────

DEFAULT_ROLES = {
    'admin': [
        'members.view', 'members.edit', 'members.delete', 'members.hard_delete',
        'register.signin', 'register.signout', 'register.complete', 'register.reset',
        'register.at_risk',
        'approvals.view', 'approvals.approve', 'approvals.reject',
        'documents.view', 'documents.upload', 'documents.delete',
        'calendar.create', 'calendar.edit', 'calendar.delete',
        'users.view', 'users.create', 'users.edit', 'users.create.admin', 'users.delete',
        'admin.settings', 'admin.session_types', 'admin.maintenance',
        'audit.view',
        'mailshots.send', 'mailshots.templates',
        'activities.manage',
    ],
    'editor': [   # Core Leader
        'members.view', 'members.edit', 'members.delete',
        'register.signin', 'register.signout', 'register.complete', 'register.at_risk',
        'approvals.view', 'approvals.approve', 'approvals.reject',
        'documents.view', 'documents.upload', 'documents.delete',
        'calendar.create', 'calendar.edit', 'calendar.delete',
        'users.view', 'users.create', 'users.edit',
        'admin.settings',
        'audit.view',
        'mailshots.send', 'mailshots.templates',
        'activities.manage',
    ],
    'leader': [   # Session Leader
        'members.view',
        'register.signin', 'register.signout',
        'activities.manage',
    ],
    'readonly': [  # Youth Worker / read-only
        'register.signout',
        'documents.view',
        'activities.manage',
    ],
}


def migrate():
    if not os.path.exists(DB_PATH):
        print(f'✗  Database not found at {DB_PATH}')
        sys.exit(1)

    db = _connect_db(DB_PATH)
    db.row_factory = sqlite3.Row

    print('AYC Portal — v6.0 permissions migration')
    print('─' * 42)

    # 1. Create new tables
    print('1. Creating permissions and roles tables…')
    with open(SQL_PATH, 'r') as f:
        db.executescript(f.read())

    # 2. Add role_id column to users (idempotent)
    print('2. Adding role_id column to users table…')
    try:
        db.execute('ALTER TABLE users ADD COLUMN role_id INTEGER REFERENCES roles(id)')
        db.commit()
        print('   role_id column added.')
    except Exception:
        print('   role_id column already exists — skipped.')

    # 3. Seed all permission codes
    print(f'3. Seeding {len(ALL_PERMISSIONS)} permission codes…')
    for code, name, desc, cat in ALL_PERMISSIONS:
        db.execute(
            'INSERT OR IGNORE INTO permissions (code, name, description, category) VALUES (?,?,?,?)',
            (code, name, desc, cat),
        )
    db.commit()
    print('   Done.')

    # 4. Seed default roles
    print('4. Seeding default roles…')
    for role_name, perms in DEFAULT_ROLES.items():
        db.execute(
            'INSERT OR IGNORE INTO roles (name, permissions, is_default) VALUES (?,?,1)',
            (role_name, json.dumps(perms)),
        )
    db.commit()
    print('   Done.')

    # 5. Migrate existing users: set role_id from the old role column
    print('5. Migrating existing users to role_id…')
    users = db.execute('SELECT id, role, role_id FROM users').fetchall()
    migrated = 0
    skipped  = 0
    missing  = 0
    for user in users:
        if user['role_id'] is not None:
            skipped += 1
            continue
        role_row = db.execute(
            'SELECT id FROM roles WHERE name = ?', (user['role'],)
        ).fetchone()
        if role_row:
            db.execute(
                'UPDATE users SET role_id = ? WHERE id = ?',
                (role_row['id'], user['id']),
            )
            migrated += 1
        else:
            print(f'   ⚠️  User id={user["id"]} has unknown role "{user["role"]}" — role_id left NULL')
            missing += 1
    db.commit()
    print(f'   Migrated: {migrated}  Already done: {skipped}  Unknown role: {missing}')

    # 6. Verify
    role_counts = db.execute(
        'SELECT r.name, COUNT(u.id) AS n FROM roles r '
        'LEFT JOIN users u ON u.role_id = r.id '
        'GROUP BY r.id ORDER BY r.id'
    ).fetchall()
    print('\n   Role summary after migration:')
    for row in role_counts:
        print(f'   {row["name"]:12s}  {row["n"]} user(s)')

    null_count = db.execute('SELECT COUNT(*) FROM users WHERE role_id IS NULL').fetchone()[0]
    if null_count:
        print(f'\n   ⚠️  {null_count} user(s) have no role_id — check their role values.')
    else:
        print('\n   ✅ All users have a valid role_id.')

    db.close()
    print('\n✅ Migration complete — deploy v6.0 code and restart the portal.')


if __name__ == '__main__':
    migrate()
