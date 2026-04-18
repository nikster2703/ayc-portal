# AYC Portal — Permissions Audit (v5.0)

Planning reference. Lists every route and the permission mechanism(s) it uses.

---

## Permission Mechanisms in Use

There are currently **6 distinct mechanisms** for controlling access:

1. **`@login_required`** — any authenticated user, any role
2. **`@role_required(roles...)`** — hard-coded role list in the decorator
3. **No auth (public)** — no decorator, open to anyone
4. **Session scoping (`_assigned_session()`)** — additional within-route restriction: non-admin roles are always restricted to their assigned session (Tuesday/Thursday). Enforced inline in individual routes.
5. **Settings-driven** — two keys in the `settings` table: `register_can_signin` and `register_can_signout`. Currently the only configurable permissions.
6. **Document rank system** — `ROLE_RANK = {readonly:0, leader:1, editor:2, admin:3}` + `user_can_access_doc()`. Each document has its own `access_role` column. User rank must meet or exceed document's required rank to list/view/download it.
7. **Register lock** — `_is_register_locked()`. Once a register is marked complete, sign-in and sign-out are blocked for everyone regardless of role.

---

## Pages (HTML routes)

| Route | Auth | Roles | Notes |
|-------|------|-------|-------|
| `/` | Public | — | Login page |
| `/dashboard` | login_required | all | |
| `/members` | role_required | admin, editor, leader | |
| `/approvals` | role_required | admin, editor | |
| `/register` | login_required | all | Sign-in/out actions governed by settings |
| `/registration` | Public | — | Landing page — choose member or staff form |
| `/registration/member` | Public | — | Public self-reg form |
| `/registration/staff` | Public | — | Simplified staff/volunteer form |
| `/documents` | role_required | admin, editor, leader, readonly | Individual doc visibility filtered by rank |
| `/communications` | role_required | admin, editor | |
| `/admin/users` | role_required | admin, editor | |
| `/admin/audit` | role_required | admin, editor | |
| `/admin/settings` | role_required | admin, editor | |
| `/display` | Public | — | Reception TV screen (names only, no sensitive data) |
| `/calendar` | login_required | all | |

---

## API — Authentication

| Endpoint | Auth | Notes |
|----------|------|-------|
| POST `/api/auth/login` | Public | |
| POST `/api/auth/logout` | Public | |
| GET `/api/auth/me` | login_required | |
| POST `/api/auth/change-password` | login_required | Own account only |

---

## API — Settings

| Endpoint | Auth | Notes |
|----------|------|-------|
| GET `/api/settings` | admin, editor | Returns all settings |
| POST `/api/settings` | admin, editor | Editors scoped: can only update threshold for their own session |

**Currently stored settings:**
- `at_risk_threshold_tuesday` / `at_risk_threshold_thursday`
- `register_can_signin` (default: `admin,editor,leader`)
- `register_can_signout` (default: `admin,editor,leader,readonly`)
- `last_attendance_change` (internal, not user-facing)

---

## API — Members

| Endpoint | Auth | Notes |
|----------|------|-------|
| GET `/api/members` | admin, editor, leader | Session-scoped; leaders cannot see staff/volunteer records |
| GET `/api/members/<id>` | admin, editor, leader | Session-scoped |
| POST `/api/members/<id>/viewed` | admin, editor, leader | Session-scoped; audit log only, no data returned |
| PUT `/api/members/<id>` | admin, editor | Session-scoped |
| DELETE `/api/members/<id>` | admin, editor | Soft delete (marks as Leaver); session-scoped; requires reason |
| DELETE `/api/members/<id>/permanent` | **admin only** | Hard delete; requires full name confirmation |

---

## API — Dashboard

| Endpoint | Auth | Notes |
|----------|------|-------|
| GET `/api/dashboard` | login_required | All roles; session-scoped counts for non-admin |

---

## API — Audit Log

| Endpoint | Auth | Notes |
|----------|------|-------|
| GET `/api/admin/audit` | admin, editor | Full log; not session-scoped (editors see all entries) |

---

## API — Registration (public submissions)

| Endpoint | Auth | Notes |
|----------|------|-------|
| POST `/api/registration` | Public | Stores member or staff self-reg as pending |
| GET `/api/postcode/<postcode>` | Public | Proxy to getaddress.io; no auth required |

---

## API — Session Types

| Endpoint | Auth | Notes |
|----------|------|-------|
| GET `/api/session-types` | login_required | Active session types only (for dropdowns/JS) |
| GET `/api/admin/session-types` | **admin only** | All types including inactive |
| POST `/api/admin/session-types` | **admin only** | Create new session type |
| PUT `/api/admin/session-types/<id>` | **admin only** | Update name/weekday/active status |
| DELETE `/api/admin/session-types/<id>` | **admin only** | Delete (blocked if members assigned) |
| POST `/api/admin/session-types/reorder` | **admin only** | Update sort order |

---

## API — Users

| Endpoint | Auth | Notes |
|----------|------|-------|
| GET `/api/admin/users` | admin, editor | Editors: own session non-admin users only |
| POST `/api/admin/users` | admin, editor | Editors: own session only; **only admin can create admin accounts** (inline check) |
| PUT `/api/admin/users/<id>` | admin, editor | Editors: own session only; **cannot assign admin role** (inline check); cannot deactivate own account |
| DELETE `/api/admin/users/<id>/permanent` | **admin only** | Requires username confirmation; cannot delete own account |

---

## API — Approvals

| Endpoint | Auth | Notes |
|----------|------|-------|
| GET `/api/approvals` | admin, editor | Session-scoped: editors see unassigned + their session |
| POST `/api/approvals/<id>/approve` | admin, editor | Session-scoped: editors can only approve into their session |
| POST `/api/approvals/<id>/reject` | admin, editor | Session-scoped |

---

## API — Attendance / Session Register

| Endpoint | Auth | Notes |
|----------|------|-------|
| GET `/api/attendance/<type>/<date>` | login_required | Session-scoped |
| GET `/api/attendance/staff/<type>/<date>` | login_required | Session-scoped |
| POST `/api/attendance/signin` | login_required | **Settings-driven** (`register_can_signin`); session-scoped; blocked if register locked |
| POST `/api/attendance/signout` | login_required | **Settings-driven** (`register_can_signout`); session-scoped; blocked if register locked |
| GET `/api/attendance/complete/<type>/<date>` | login_required | Status check only; no write |
| POST `/api/attendance/complete` | admin, editor | Session-scoped; locks the register |
| POST `/api/attendance/reset` | **admin only** | Wipes all attendance + unlocks; no session scope |
| GET `/api/attendance/check-at-risk` | admin, editor | Session-scoped |
| POST `/api/attendance/mark-at-risk` | admin, editor | Session-scoped |
| GET `/api/attendance/history/<member_id>` | login_required | Session-scoped |

---

## API — Display (public read-only)

| Endpoint | Auth | Notes |
|----------|------|-------|
| GET `/api/display/stream` | Public | SSE event stream for live display refresh |
| GET `/api/display/<session_type>` | Public | Returns first name + surname only; no sensitive data |

---

## API — Activities (display board)

| Endpoint | Auth | Notes |
|----------|------|-------|
| GET `/api/activities/<session_type>` | login_required | |
| POST `/api/activities` | login_required | Any logged-in user can add activities |
| DELETE `/api/activities/<id>` | login_required | Any logged-in user can remove activities |

---

## API — Calendar

| Endpoint | Auth | Notes |
|----------|------|-------|
| GET `/api/calendar` | login_required | Read; all roles |
| GET `/api/calendar/terms` | login_required | Distinct term names; all roles |
| POST `/api/calendar` | admin, editor | Session-scoped; date must match session's weekday |
| POST `/api/calendar/bulk` | admin, editor | Session-scoped; max 365-day range |
| PUT `/api/calendar/<id>` | admin, editor | Session-scoped |
| DELETE `/api/calendar/<id>` | admin, editor | Session-scoped |
| GET `/api/calendar/upcoming` | login_required | Next N planned sessions; all roles |

---

## API — Documents

| Endpoint | Auth | Notes |
|----------|------|-------|
| GET `/api/documents` | login_required | **Rank-filtered per document** — each doc has its own `access_role`; user must meet or exceed it |
| POST `/api/documents` | admin, editor | Upload; uploader sets `access_role` on the document |
| GET `/api/documents/<id>/download` | login_required | **Per-doc rank check** |
| GET `/api/documents/<id>/view` | login_required | **Per-doc rank check** |
| DELETE `/api/documents/<id>` | admin, editor | Soft delete (sets `active = 0`) |

---

## API — Email Templates

| Endpoint | Auth | Notes |
|----------|------|-------|
| GET `/api/email-templates` | admin, editor | |
| POST `/api/email-templates` | admin, editor | |
| PUT `/api/email-templates/<id>` | admin, editor | |
| DELETE `/api/email-templates/<id>` | admin, editor | |

---

## API — Mailshots

| Endpoint | Auth | Notes |
|----------|------|-------|
| POST `/api/mailshots/preview` | admin, editor | Session-scoped recipient list |
| POST `/api/mailshots/send` | admin, editor | Session-scoped; logs to mailshot_log |
| GET `/api/mailshots` | admin, editor | History; not session-scoped |

---

## API — Maintenance

| Endpoint | Auth | Notes |
|----------|------|-------|
| GET `/api/admin/maintenance/counts` | **admin only** | Row counts per table |
| DELETE `/api/admin/maintenance/audit-log` | **admin only** | Wipes audit log |
| DELETE `/api/admin/maintenance/attendance` | **admin only** | Wipes all attendance |
| DELETE `/api/admin/maintenance/mailshot-log` | **admin only** | Wipes mailshot history |
| DELETE `/api/admin/maintenance/registrations` | **admin only** | Wipes pending registrations |

---

## Summary: What's Currently Configurable vs Hard-coded

### Configurable (settings table)
- Who can **sign in** on the register (`register_can_signin`)
- Who can **sign out** on the register (`register_can_signout`)
- At-risk absence threshold per session (`at_risk_threshold_*`)

### Hard-coded (role_required decorator or inline checks)
Everything else — which roles can access members, approvals, documents, communications, calendar write, user management, audit log, maintenance, etc.

### Other access control mechanisms (not role-based, not configurable)
- **Document access_role** — per-document minimum rank, set at upload time
- **Session scoping** — all non-admin roles are always restricted to their assigned session; this is architectural, not configurable
- **Register lock** — completed registers block all sign-in/out regardless of role
