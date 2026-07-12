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
APP_VERSION = 'v12.50'  # v12.50: multi-session membership Phase A — members can belong to N sessions. (1) New member_sessions junction table (member_id, session_type_id, UNIQUE pair) mirroring user_sessions, with indexes. (2) Startup reconcile: set-based INSERT OR IGNORE seeds member_sessions from members.session on EVERY boot (idempotent + self-healing while approvals/import still write the old column; orphan members with blank/unknown session are logged). (3) members.session kept as read-only echo (first assigned session by sort_order) for not-yet-converted readers (register, comms, dashboard, alerts read it until Phases B–D); set_member_sessions() maintains the echo. (4) helpers: get_member_session_names, get_sessions_for_members (batch), set_member_sessions (validates against session_types, dedupes, echo sync), member_in_scope (any-session intersection with echo fallback). (5) members API: list/session filter + scope via EXISTS on junction; every member payload gains sessions[]; PUT accepts sessions[] (legacy single 'session' still accepted, converted); all six member-endpoint scope checks switched to intersection; scoped editors can't save a session set that removes the member from all their sessions. (6) members UI: edit modal session dropdown replaced with checkbox chips (.sess-chip, :has(:checked) styling); card subline lists all sessions ('Tuesday · Friday'); client-side session filter matches any assigned session. SQL logic verified by idempotency/intersection test run twice against fixture data. Phases B (register/QR/approvals/comms/dashboard), C (per-session payments), D (import/export/alerts + drop echo) to follow per AYC_MultiSession_Plan.docx.  # v12.43: mobile responsiveness pass (fixes shipped in the v12.42 tree; this bump documents them and cache-busts the CSS) — (1) .data-table mobile column-hiding (<768px) now exempts the last column, so Actions stays reachable on Manage Users / Comms templates; td gains overflow-wrap:anywhere for long emails (shared.css + skin-casual.css). (2) form controls (search-input, session-select, form-group inputs/selects/textareas, form-input) bump to 16px font below 768px to stop iOS Safari focus-zoom. (3) auto-fill card grids use minmax(min(Xpx,100%),1fr) so 260–330px minimums can't overflow narrow phones (members grid-f, documents, roles, member_types, settings, approvals, dashboard). (4) dashboard .dash-grid forced to 1 column below 768px (was repeat(2,1fr)) per Nik — stat cards and today-cards stack full-width. (5) session pill ellipsizes at 42vw <480px; toast spans viewport width <480px. (6) calendar day cells tightened <480px (58px cells, 8.5px pills) so the 7-column month stays usable. (7) horizontal-scroll wrappers on field_builder assigned-fields table, both admin payments tables, and the member-card payments table.  # v12.42: audit smaller-observations pass — (1) db.py ensure_tables seeding refactored from 9 per-section connections to one shared `seed` connection wrapped in try/finally (the payment-field migration previously leaked its connection on error); verified with a 13-check seed test run twice for idempotency. (2) session.permanent set at login so permanent_session_lifetime (8h) actually applies. (3) requirements.txt duplicate flask-wtf range dropped (pinned Flask-WTF==1.2.2 stays). (4) gunicorn timeout 60→120s for synchronous mailshot sends. (5) new helpers.client_ip() (X-Forwarded-For gated on TRUST_PROXY_HEADERS, default trust for the Caddy topology) used by login lockout, registration + QR + postcode rate limits and audit-log IPs — behind Caddy all users previously shared ONE rate bucket, so 10 failed logins by anyone locked everyone out and audit entries logged the proxy IP. (6) mailshot explicit recipients validated against the sender's scoped member contacts (endpoint previously accepted arbitrary addresses — open-relay risk). (7) members flag_rule_id join parameterised. (8) session-scope checks added to member tags GET and permanent delete. (9) helpers.club_slug(): all export/backup filenames now use the branded short name consistently.  # v12.41: audit fixes — (1) register session picker: admins are never locked to active_session and options are filtered server-side to the user's sessions; onSessionChange persists for admins too. (2) /admin/settings/import-history 500 fixed (duplicate session_types kwarg vs tpl_ctx). (3) XSS: register card data-name attribute now esc()'d. (4) session-type rename cascade extended to session_notes, quick_signin_tokens, alert_rules.applies_to_session, pending_registrations.assigned_session. (5) APScheduler guarded by flock so only one gunicorn worker runs the nightly alert check; RUN_SCHEDULER=0 disables. (6) payments PUT no longer wipes omitted payment_date/method_id/notes. (7) payment_types.is_membership flag replaces name='Membership' matching (members paid filter, member payments paid_current, import). (8) staff approval resolves the staff member-type slug instead of hardcoding 'staff'. (9) /api/postcode rate-limited 20/min/IP. (10) DB restore: connection closed before swap, WAL checkpoint before snapshot, stale -wal/-shm removed before copy. (11) session grants (role/permissions/session_names) re-synced from DB every 60s — role edits, session reassignments and deactivation now apply without re-login. (12) audit/calendar numeric query params validated (400 instead of 500).  # v12.40: register summary tiles (Signed In / Not Arrived / Signed Out) are now clickable filter views — keep their counts but filter the grid to that state so signing members out no longer means scrolling to the bottom; click the active tile again to show everyone. Default register sort changed to First Name. Both the active state filter and the sort order are persisted per user in localStorage (key ayc-register-<username>) so they survive refreshes, session changes and page navigation. (Members tab only; staff tab unchanged.)  # v12.39: filtered staff out of all remaining dashboard attendance counts — api_dashboard today_att (Today's Sessions headcount), and api_stat_trends att_by_type (Today's Sessions sparklines) + att_rows (Attendance last-session % and sparkline) now JOIN members→member_types and filter registration_style != 'staff', consistent with v12.38.  # v12.38: fixed the attendance trend chart to exclude staff — api_attendance_trend joins attendance→members→member_types so only the selected cohort is counted (previously counted members + staff); accepts ?view=members (default) or ?view=staff; dashboard trend card gains a Members/Staff pill toggle that switches view, retitles the card and rebuilds the chart; staff view with no data keeps the card visible.  # v12.37: replaced the print register's in-page Print button (which mis-rendered on some browsers — v12.36 image-wait attempt did not fix it) with an Export to Excel button. New /register/print.xlsx route builds an .xlsx mirroring the print layout: embedded logo header, title/subtitle, the member type's show_on_print fields, boolean YES/NO, and blank Tick on Arrival / Tick When Leaving columns plus 5 walk-in rows. Uses the resolved member-type slug (not hardcoded 'member'). Logo embedding needs Pillow (added to requirements) and degrades gracefully if absent. Printing is now via the browser menu / Cmd+P. Removed the now-unused printPage() from print_register.html (kept on register_export.html).  # v12.36: print register/export Print button now waits for all images (notably the cache-busted /branding/logo) to finish loading before calling window.print(). Printing mid-load made Chrome re-render the preview when the logo arrived seconds later, blanking the large fixed-layout table and the on-screen page; Cmd+P was unaffected because the logo had already settled. printPage() added to print_register.html and register_export.html with a single-print guard and 3s safety timeout.  # v12.35: removed remaining hardcoded 'member' slug fallbacks on write paths — member import and public registration now default to the club's primary active non-staff member type (first by sort_order) instead of 'member', and resolve unknown/blank slugs to it, so clubs with a renamed type slug (e.g. ara-members) no longer create orphaned members/registrations invisible to every mt.slug = m.member_type join.  # v12.34: print register now filters members by the resolved member-type slug instead of the hardcoded 'member' default (clubs with a renamed type slug, e.g. ara-members, were getting 0 rows on the printable register); guarded the v11.2 show_on_attendance data migration so it is skipped whenever any member field already has a Show On flag set — the UPDATE was not idempotent (rewrote show_on_card = MAX(card, detail), which fed back in and re-flipped show_on_attendance = 1 each startup), so every field was ending up on the attendance card.  # v12.33: approval modal — initial status picker; defaults Active, supports Provisional workflow  # v12.22: sticky footer — body flex column, page-content flex:1 + width:100%, app-footer margin-top removed. Footer now always at viewport bottom on short pages, natural scroll position on long pages. v12.21: search bar height — explicit height:44px on .search-input and .session-select in shared.css (formal light/dark + casual dark) and skin-casual.css (casual light). Previous padding-only approach had no effect because inter 14px + 1px border + box-sizing:border-box = 40px regardless of padding. v12.19: dashboard — zero-count card hiding; per-user layout prefs (drag-to-reorder, hide/restore cards, hide sections); global trends toggle; reset layout; localStorage keyed by username. v12.18: final sweep — register.html (7 hardcoded navy→token), members.html (badge colours→token). v12.15: display.html — drop Google Fonts CDN→vendor/fonts.css (CSP fix); add ?mode=light support via html.light-mode CSS override block (body bg #f1f5f9, navy text, white cards). v12.14: batch 7 — remaining admin sub-pages. attendance_settings: tokenize casual amber overrides (#fef3c7→var(--amber-bg), #fcd34d→color-mix, #78350f→var(--amber)), white→var(--cream) for qr-toggle-card, dual-render ⚠️ in safeguarding note. member_types: rgba box-shadow→color-mix(accent). smtp_profiles: #dc2626→var(--red). system_logs: outer border #1e293b→var(--border), dual-render ⚠️/🔴 level-btn icons. session_types/payments/staff_roles: clean.

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
BRAND_KEYS = {
    'brand_accent':      '#0096b4',
    'brand_nav_style':   'dark',    # 'dark' | 'accent' | 'white'
    'brand_logo_file':   '',
    'brand_club_name':   '',
    'brand_short_name':  '',
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
