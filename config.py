"""
AYC Portal — Application constants and configuration.
Imported by helpers.py, app.py, and every blueprint.
No Flask objects live here — plain Python only.
"""

import os
from dotenv import load_dotenv

# ── Instance directory (multi-tenant) ─────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.environ.get('INSTANCE_DIR', BASE_DIR)

# Load .env from the instance directory before anything reads os.environ
load_dotenv(os.path.join(INSTANCE_DIR, '.env'))

# ── Paths ──────────────────────────────────────────────────────────────────────
DATABASE     = os.path.join(INSTANCE_DIR, 'data', 'ayc.db')
UPLOAD_DIR   = os.path.join(INSTANCE_DIR, 'data', 'documents')
LOG_DIR      = os.path.join(INSTANCE_DIR, 'data', 'logs')
BRANDING_DIR = os.path.join(INSTANCE_DIR, 'data', 'branding')

# ── Version ────────────────────────────────────────────────────────────────────
APP_VERSION = 'v12.74'  # Incidents can be closed off as resolved in person (no email). Plus v12.73 mobile/email PUT whitelist + staff contact model. See CHANGELOG.md.

# ── Upload settings ────────────────────────────────────────────────────────────
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'doc', 'jpg', 'jpeg', 'png', 'xlsx', 'xls'}

# ── Club identity (multi-tenant) ──────────────────────────────────────────────
CLUB_NAME       = os.environ.get('CLUB_NAME',       'Ashford Youth Club')
CLUB_SHORT_NAME = os.environ.get('CLUB_SHORT_NAME', 'AYC')

# ── SMTP config (set in .env) ─────────────────────────────────────────────────
SMTP_HOST = os.environ.get('MAIL_HOST',     'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('MAIL_PORT', 587))
SMTP_USER = os.environ.get('MAIL_USERNAME', '')
SMTP_PASS = os.environ.get('MAIL_PASSWORD', '')
SMTP_FROM = os.environ.get('MAIL_FROM',     SMTP_USER)

# ── Postcode lookup (getaddress.io) ──────────────────────────────────────────
GETADDRESS_KEY = os.environ.get('GETADDRESS_KEY', '')

# ── Branding defaults ──────────────────────────────────────────────────────────
# Colour/enum values: '' means "use the theme default" throughout.
BRAND_KEYS = {
    'brand_accent':      '#0096b4',
    'brand_nav_style':   'dark',    # 'dark' | 'accent' | 'white'
    'brand_logo_file':   '',
    'brand_club_name':   '',
    'brand_short_name':  '',
    # v12.70 Branding v2
    'brand_accent_dark':      '',       # separate accent for dark mode ('' = use brand_accent)
    'brand_bg_light':         '',       # page background (light theme)
    'brand_surface_light':    '',       # card surface (light theme)
    'brand_heading_light':    '',       # heading colour / --navy (light theme)
    'brand_bg_dark':          '',
    'brand_surface_dark':     '',
    'brand_heading_dark':     '',
    'brand_font':             '',       # '' = skin default | key of BRAND_FONT_STACKS
    'brand_default_theme':    'light',  # 'light' | 'dark' | 'system' — for users with no saved choice
    'brand_login_image_file': '',       # login page background image
    'brand_favicon_file':     '',
    'brand_email_branding':   '0',      # '1' = wrap mailshots in a branded header/footer
}

# Curated font stacks — all either vendored (fonts.css) or system fonts, so no
# CDN/CSP implications. '' (skin default) keeps Inter/Nunito per skin.
BRAND_FONT_STACKS = {
    'inter':   "'Inter', system-ui, sans-serif",
    'nunito':  "'Nunito', system-ui, sans-serif",
    'system':  "system-ui, -apple-system, 'Segoe UI', sans-serif",
    'georgia': "Georgia, 'Times New Roman', serif",
}

# ── Role slug constants ────────────────────────────────────────────────────────
ROLE_ADMIN    = 'admin'
ROLE_EDITOR   = 'editor'
ROLE_READONLY = 'readonly'

ROLE_DISPLAY_NAMES = {
    'admin':    'Admin',
    'editor':   'Editor',
    'readonly': 'Read Only',
}

# ── Permission catalogue ───────────────────────────────────────────────────────
ALL_PERMISSIONS = [
    # Members
    ('members.view',        'View Members',            'View member list and full detail cards',               'members'),
    ('members.edit',        'Edit Members',             'Edit member records',                                  'members'),
    ('members.delete',      'Soft Delete Members',      'Mark a member as Leaver (reversible)',                 'members'),
    ('members.hard_delete', 'Permanent Delete Members', 'Permanently and irreversibly delete a member',         'members'),
    # Register / attendance
    ('register.signin',     'Sign In',                  'Sign members in on the session register',              'register'),
    ('register.signout',    'Sign Out',                 'Sign members out on the session register',              'register'),
    ('register.complete',   'Complete Register',        'Lock the register at end of session',                  'register'),
    ('register.reset',      'Reset Register',           'Wipe all sign-in/out data for a session',             'register'),
    # Alert rules
    ('alerts.view',        'View Alerts',               'See member flags and the alert rules list',            'alerts'),
    ('alerts.manage',      'Manage Alert Rules',        'Create and edit alert rules',                         'alerts'),
    ('alerts.run',         'Run Alert Checks',          'Trigger an alert rule evaluation manually',           'alerts'),
    ('alerts.dismiss',     'Dismiss Flags',             'Manually clear a flag from a member record',          'alerts'),
    ('register.print',      'Print Register',           'Print a paper copy of the session register',           'register'),
    ('members.tags',        'Manage Member Tags',        'Add and remove skill/badge tags on member records',    'members'),
    ('register.notes',      'Session Notes',            'Add and manage session incident and general notes',    'register'),
    ('register.export',     'Export Complete Register', 'Open print-ready export with attendance and notes',    'register'),
    ('register.qr_manage',  'Manage QR Code',           'Regenerate the QR quick sign-in code on the register', 'register'),
    # Approvals
    ('approvals.view',      'View Approvals',           'View pending self-registration submissions',           'approvals'),
    ('approvals.approve',   'Approve Registrations',    'Approve a pending registration',                       'approvals'),
    ('approvals.reject',    'Reject Registrations',     'Reject a pending registration',                        'approvals'),
    # Documents
    ('documents.view',      'View Documents',           'Browse the document repository (per-doc rank still applies)', 'documents'),
    ('documents.upload',    'Upload Documents',         'Upload new files to the repository',                   'documents'),
    ('documents.delete',    'Delete Documents',         'Soft-delete documents from the repository',            'documents'),
    # Calendar
    ('calendar.create',     'Create Calendar Sessions', 'Add sessions to the term calendar',                    'calendar'),
    ('calendar.edit',       'Edit Calendar',            'Update session status, notes and term name',           'calendar'),
    ('calendar.delete',     'Delete Calendar Sessions', 'Remove sessions from the term calendar',               'calendar'),
    # Users
    ('users.view',          'View Users',               'View the portal user list',                            'users'),
    ('users.create',        'Create Users',             'Create new portal staff accounts',                     'users'),
    ('users.edit',          'Edit Users',               'Edit existing portal accounts',                        'users'),
    ('users.create.admin',  'Create Admin Users',       'Assign roles that carry admin-level permissions',      'users'),
    ('users.delete',        'Delete Users',             'Permanently delete a portal user account',             'users'),
    # Admin / settings
    ('admin.settings',      'Manage Settings',          'Access and change club settings and roles',            'admin'),
    ('admin.session_types', 'Manage Session Types',     'Create, edit and reorder session types',               'admin'),
    ('admin.maintenance',   'Maintenance Tools',        'Clear audit logs, attendance and registration data',   'admin'),
    # Audit
    ('audit.view',          'View Audit Log',           'View the full system audit log',                       'audit'),
    # Communications
    ('mailshots.send',      'Send Mailshots',           'Send bulk emails to member contacts',                  'communications'),
    ('mailshots.templates', 'Manage Email Templates',   'Create, edit and delete email templates',              'communications'),
    # Notifications
    ('notifications.view',   'View Notifications',       'View personal and system notifications',               'communications'),
    ('notifications.send',   'Send Notifications',       'Send targeted notifications to users, roles or sessions', 'communications'),
    ('notifications.manage', 'Manage Notifications',     'Delete old notifications (admin only)',                'admin'),
    # Display board
    ('activities.manage',   'Manage Activities Board',  'Add and remove activities from the TV display',        'display'),
    # Payments
    ('payments.view',       'View Payments',            'View payment history on member cards',                  'payments'),
    ('payments.record',     'Record Payments',          'Add and edit payment entries on member records',        'payments'),
    ('payments.manage',     'Manage Payments',          'Void payments, manage payment types and methods, set current period', 'payments'),
    # Admin — granular settings
    ('admin.branding',      'Manage Branding',          'Customise club name, logo, colours and nav style',      'admin'),
    ('admin.roles',         'Manage Roles & Permissions', 'Create and edit portal roles and their permission sets', 'admin'),
    ('admin.smtp_profiles', 'Manage Email Senders',     'Add, edit and delete SMTP sender profiles for mailshots', 'admin'),
]

# ── Default role permissions ───────────────────────────────────────────────────
DEFAULT_ROLE_PERMISSIONS = {
    'admin': [
        'members.view', 'members.edit', 'members.delete', 'members.hard_delete', 'members.tags',
        'register.signin', 'register.signout', 'register.complete', 'register.reset',
        'register.print', 'register.notes', 'register.export', 'register.qr_manage',
        'approvals.view', 'approvals.approve', 'approvals.reject',
        'documents.view', 'documents.upload', 'documents.delete',
        'calendar.create', 'calendar.edit', 'calendar.delete',
        'users.view', 'users.create', 'users.edit', 'users.create.admin', 'users.delete',
        'admin.settings', 'admin.session_types', 'admin.maintenance',
        'admin.branding', 'admin.roles', 'admin.smtp_profiles',
        'audit.view',
        'mailshots.send', 'mailshots.templates',
        'activities.manage',
        'alerts.view', 'alerts.manage', 'alerts.run', 'alerts.dismiss',
        'notifications.view', 'notifications.send', 'notifications.manage',
        'payments.view', 'payments.record', 'payments.manage',
    ],
    'editor': [
        'members.view', 'members.edit', 'members.delete', 'members.tags',
        'register.signin', 'register.signout', 'register.complete', 'register.print',
        'register.notes', 'register.export', 'register.qr_manage',
        'approvals.view', 'approvals.approve', 'approvals.reject',
        'documents.view', 'documents.upload', 'documents.delete',
        'calendar.create', 'calendar.edit', 'calendar.delete',
        'users.view', 'users.create', 'users.edit',
        'admin.settings', 'admin.branding', 'admin.smtp_profiles',
        'audit.view',
        'mailshots.send', 'mailshots.templates',
        'activities.manage',
        'alerts.view', 'alerts.manage', 'alerts.run', 'alerts.dismiss',
        'notifications.view', 'notifications.send',
        'payments.view', 'payments.record', 'payments.manage',
    ],
    'readonly': [
        'register.signout',
        'documents.view',
        'activities.manage',
        'notifications.view',
        'payments.view',
    ],
}

# ── Auth rate-limit constants ──────────────────────────────────────────────────
SESSION_IDLE_TIMEOUT   = 30 * 60   # 30 minutes inactivity
LOGIN_MAX_FAILURES     = 10
LOGIN_LOCKOUT_SECONDS  = 15 * 60   # 15 minutes
