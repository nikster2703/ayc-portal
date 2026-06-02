# Session & Access Redesign
## Analysis of Current System + Plan for Configurable Multi-Session Access

---

## Part 1 — How the Current System Works

### The core concept: "session assignment"

Every non-admin user has a single `session_assigned` TEXT field in the `users` table. This is the entire access control mechanism for session scoping. A user is assigned to exactly one session (e.g., `"Tuesday"`) or nothing at all.

The function `_assigned_session()` in `helpers.py` is the central decision point:

```python
def _assigned_session():
    if session.get('role') == ROLE_ADMIN:
        return None          # unscoped — sees everything
    return session.get('session_assigned') or ''  # '' = locked out, sees nothing
```

The return value has three possible states:

| Return value | Meaning |
|---|---|
| `None` | Admin — no filter applied, full visibility |
| `"Tuesday"` (or any session name) | Scoped — sees only that session's data |
| `""` (empty string) | Broken/misconfigured — sees zero members/attendance |

### Where scoping is enforced

Every data-bearing blueprint calls `_assigned_session()` and applies it:

**`members.py`** — member list and detail endpoints:
- If scoped: adds `WHERE m.session = scoped` to all member queries
- A member not in the user's session is a 403 on detail/edit/view

**`attendance.py`** — sign-in/out, register completion, session notes:
- If scoped: rejects any request where the URL's `session_type` doesn't exactly match `scoped`
- Empty scope (`''`) returns an empty list immediately

**`admin.py`** — user creation and editing:
- If scoped: a user can only create/edit users who are assigned to the *same* session as themselves
- Non-admin users without `admin.maintenance` permission *must* have a session assigned

**`alerts.py`** — member flags and alert rule evaluation:
- Alert rules have their own `applies_to_session` field (used during rule evaluation)
- Scoping applied to flag dismissal and member flag views

### How sessions themselves are defined

The `session_types` table stores the available sessions:

```sql
CREATE TABLE session_types (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL UNIQUE,   -- "Tuesday", "Thursday", etc.
    weekday    INTEGER NOT NULL,          -- Python weekday 0=Mon … 6=Sun
    active     INTEGER NOT NULL DEFAULT 1,
    sort_order INTEGER NOT NULL DEFAULT 0
);
```

Seeded at first run with `('Tuesday', 1)` and `('Thursday', 3)`.

The `weekday` column is used in two ways:
1. `weekday_to_session_map()` — to auto-determine which session is "today's" session on the register/display board
2. `session_to_weekday_map()` — reverse lookup for calendar generation

### How members are assigned to sessions

Members have a single `session TEXT` field (e.g., `"Tuesday"`, `"Thursday"`). The schema comment mentions `"Both"` as a valid value, but the Python scoping logic uses exact string equality (`m.session = ?`), so `"Both"` would only match a user whose `session_assigned` is literally `"Both"` — it is effectively unused.

### The "Both" problem

The original design had a concept of members attending "Both" sessions, but this was never properly implemented at the scoping layer. A member with `session = 'Both'` is currently *invisible* to any scoped (non-admin) user, because no user has `session_assigned = 'Both'`. This is a latent bug.

---

## Part 2 — Problems With the Current System

### 1. One session per user, hard limit

`session_assigned` is a single TEXT field. There is no way to give a non-admin user access to two specific sessions without making them a full admin. For multi-org use cases (e.g., a volunteer who covers Monday and Wednesday but not Friday), this is a blocker.

### 2. Sessions are semantically tied to days

The `weekday` column bakes a weekday number into every session. This made sense for "Tuesday club" and "Thursday club", but is wrong for:
- Sessions named after locations ("East Site", "West Site")
- Sessions named after age groups ("Juniors", "Seniors")
- Organisations that run sessions fortnightly, monthly, or ad-hoc
- Any session that doesn't map to a fixed weekday

The weekday is used as a scheduling *hint* (auto-suggesting session dates), but its presence as a `NOT NULL` column implies it is structurally required.

### 3. Members can only belong to one session

`members.session` is a single TEXT field. A member who genuinely attends two sessions has no proper representation. The `"Both"` workaround in the schema comment is broken.

### 4. Binary access model

The access model is all-or-nothing: either you're admin (everything) or you see exactly one session. There's no way to express "this user can see sessions A and B but not C" without granting full admin rights.

### 5. Session names used as identifiers everywhere

The `session_type` column in `attendance`, `session_completions`, `term_sessions`, `session_activities`, `quick_signin_tokens`, and `alert_rules` stores the session **name** as a string (e.g., `"Tuesday"`), not the `session_types.id`. This means renaming a session type would require updating every one of those tables — a significant data integrity risk.

### 6. No concept of "unscoped non-admin"

The only way to have a non-admin who can see all sessions is to give them the `admin` role. There's no permission like `sessions.view_all` that a regular user could be granted.

---

## Part 3 — Redesign Plan

The goal is: **a user can be granted access to any subset of sessions, with no upper limit and no requirement to be an admin to access more than one.**

The redesign is broken into four phases to allow incremental delivery without a big-bang rewrite.

---

### Phase A — Decouple session names from weekdays

**Scope:** `session_types` table + calendar/register logic only.

**Changes:**
- Make `weekday` nullable (`INTEGER DEFAULT NULL`) — it becomes an *optional scheduling hint*, not a structural requirement
- Add a `description TEXT` column to `session_types` for admin-defined context (e.g., "For members aged 10–14")
- Update the admin "Manage Session Types" UI to make weekday optional and show the description field
- Calendar generation: when `weekday` is NULL, the session doesn't auto-populate into the term calendar; admin must add dates manually

**Migration:** No data migration needed — existing Tuesday/Thursday records keep their weekday values.

**Risk:** Low. Purely additive.

---

### Phase B — Introduce a `user_sessions` junction table

**Scope:** User-to-session mapping. The core access control change.

**New table:**
```sql
CREATE TABLE user_sessions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_type_id INTEGER NOT NULL REFERENCES session_types(id) ON DELETE CASCADE,
    UNIQUE(user_id, session_type_id)
);
```

**`users.session_assigned` becomes deprecated** — kept for one release as a migration source, then removed.

**`_assigned_session()` rewritten:**
```python
def _assigned_session():
    if session.get('role') == ROLE_ADMIN:
        return None  # unscoped
    # Returns a list of session names, or empty list if none assigned
    return session.get('session_names', [])
```

All scoping checks that currently do `scoped != session_type` become `session_type not in scoped`. Member queries that do `WHERE m.session = ?` become `WHERE m.session IN (?, ?, ...)`.

**Login** stores the list of session names into the Flask session at login time, exactly as permissions are stored today.

**Admin UI changes:**
- User create/edit form: replace single dropdown with a multi-select checklist of active session types
- User list: show session access as tags rather than a single value
- An editor-scoped user managing other users can only assign sessions they themselves have access to

**Migration script:** Reads `users.session_assigned` and inserts one row per user into `user_sessions`.

**Risk:** Medium. Touches auth, admin, and all scoping checks. Needs careful testing. The three-state return value (`None` / `[names]` / `[]`) must be handled consistently everywhere.

---

### Phase C — Introduce a `member_sessions` junction table

**Scope:** How members are assigned to sessions.

**New table:**
```sql
CREATE TABLE member_sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id       INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    session_type_id INTEGER NOT NULL REFERENCES session_types(id) ON DELETE CASCADE,
    UNIQUE(member_id, session_type_id)
);
```

**`members.session` becomes deprecated** — kept for one release, then removed.

**Scoping queries** join through `member_sessions`:
```sql
-- Before:
WHERE m.session = ?

-- After:
WHERE EXISTS (
    SELECT 1 FROM member_sessions ms
    WHERE ms.member_id = m.id
    AND ms.session_type_id IN (?, ?, ...)
)
```

**Member create/edit UI:** Replace single session dropdown with a multi-select checklist.

**Migration script:** Reads `members.session`, splits on `','` or `'/'` for any compound values, inserts into `member_sessions`.

**Risk:** Medium-high. The member list query is used everywhere — it'll need index support on `member_sessions`. Add `CREATE INDEX idx_member_sessions_member ON member_sessions(member_id)` and `idx_member_sessions_session ON member_sessions(session_type_id)`.

---

### Phase D — Replace session name strings with IDs in data tables

**Scope:** All tables that store `session_type TEXT` as a name string.

Affected tables:
- `attendance.session_type`
- `session_completions.session_type`
- `term_sessions.session_type`
- `session_activities.session_type`
- `quick_signin_tokens.session_type`
- `alert_rules.applies_to_session`
- `members.session` (already handled in Phase C)

**Change:** Add a `session_type_id INTEGER REFERENCES session_types(id)` column alongside the existing `session_type TEXT`, backfill via a migration, then deprecate the TEXT column. Keep both during transition for rollback safety.

**Why this matters:** Currently renaming "Tuesday" to anything else requires manually updating six tables. After this phase, a rename is a single row update on `session_types`.

**Risk:** High — touches the most tables. Should be done last, after Phases B and C are stable. The TEXT columns can stay in place indefinitely as read-only legacy fields; the ID columns become the source of truth.

---

## Part 4 — Suggested Delivery Order

| Phase | Description | Complexity | Risk | Prerequisite |
|---|---|---|---|---|
| A | Weekday optional + description field | Low | Low | None |
| B | `user_sessions` junction table | Medium | Medium | A |
| C | `member_sessions` junction table | Medium | Medium-High | B |
| D | Replace name strings with IDs | High | High | B + C |

Phase A can be shipped in isolation and immediately unblocks other orgs from using non-day-named sessions. Phases B and C are the structural heart of the work and should be built together or in quick succession. Phase D is a clean-up/hardening phase and can be deferred without blocking functionality.

---

## Part 5 — Design Decisions (Confirmed 2026-05-17)

**1. Filtered view, not merged.**
When a user has access to multiple sessions, the UI shows a session picker (as today) and the user chooses which session's register/members they are working in. Data is never merged across sessions in a single view. The current register page pattern is preserved — just the session selector changes from a fixed single value to a chooser limited to the user's allowed sessions.

**2. Session assignment is mandatory at user creation; validated server-side.**
A non-admin user with no session assigned is an error state, not a valid configuration. The user creation API (`POST /api/admin/users`) already has a check for this (via `admin.maintenance` permission gate); this stays and is made explicit in the UI — the session picker on the create/edit user form is required for any non-admin role, and the save button remains disabled until at least one session is selected.

**3. Single role per user — no session-scoped permissions.**
Role stays on the user, not on the session assignment. If a person genuinely needs different permissions for different sessions, the answer is to create them as two separate user accounts. This keeps `_assigned_session()` and the permission system completely independent of each other.

**4. Alert rules join through `member_sessions` after Phase C.**
`alert_rules.applies_to_session` will migrate from a name string to a `session_type_id` foreign key as part of Phase D. The rule evaluation query in `alerts.py` (currently `m.session = ?`) becomes a join through `member_sessions` — matching any member who has *any* of their sessions matching the rule's target session. This means a member assigned to two sessions could be caught by rules from either.

---

## Part 6 — Implementation Consequences of the Decisions

### Session picker behaviour (Decision 1)

The active session selection needs to move from being implicit (one stored value, automatically applied) to explicit (user picks from their allowed list at the start of a session, or it's remembered from their last use).

Proposed approach: store `active_session` in the Flask session (the server-side cookie session, not the DB sessions table) — set when the user picks a session on the register/dashboard. `_assigned_session()` returns the *active* session when a user has multiple options, falling back to their only assigned session if they have just one. The session picker appears in the nav for multi-session users.

### `_assigned_session()` return type change (Decision 3)

Currently returns `None | str`. After Phase B it returns `None | list[str]`. Every caller must be updated. The pattern changes from:

```python
# Before
scoped = _assigned_session()
if scoped is not None and scoped != session_type:
    return 403

# After — checking the active selection
scoped = _assigned_session()           # None or list
active = get_active_session()          # the currently selected session
if scoped is not None and active != session_type:
    return 403
```

For member list queries (which filter by what a user *can* see, not what they're actively working in), the full list is used:

```python
# Member list: show members from any of the user's sessions
if scoped is not None:
    placeholders = ','.join('?' * len(scoped))
    conditions.append(f'session_type_id IN ({placeholders})')
    params.extend(scoped)
```

### Mandatory session validation (Decision 2)

User creation and editing must enforce: if the role does not carry `admin.maintenance`, at least one session must be selected. This is already partially done but becomes the primary guard rather than a secondary check.

---

*Document produced: 2026-05-17*
*Decisions confirmed: 2026-05-17*
*Status: Ready for Phase A implementation*
