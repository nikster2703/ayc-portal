# Member Alert Rules — Design Specification

**Status:** Design locked, not yet implemented  
**Replaces:** At Risk attendance check (hardcoded)  
**Version:** 1.0 — April 2026

---

## Overview

The Member Alert Rules system replaces the hardcoded "At Risk" attendance flag with a configurable, multi-rule engine. Any number of rules can be defined by an admin; each rule independently evaluates members and raises a coloured flag badge. Members can carry multiple concurrent flags. The `status` field on the `members` table is simplified to `Active` or `Leaver` only — flagging is handled entirely by this system.

---

## Confirmed Design Decisions

| Decision | Choice |
|---|---|
| Member status values | `Active` and `Leaver` only — "At Risk" retired |
| Flag model | Multiple concurrent flags per member, each tied to a rule |
| Auto-resolve | Yes where the condition is machine-verifiable (see per rule type below) |
| Field picker source | Shared with existing Field Builder (member_fields / custom fields registry) |
| Where checks live | Alerts section in Settings + Dashboard card — not buried in Register |

---

## Database Schema

### New table: `alert_rules`

```sql
CREATE TABLE alert_rules (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    name                TEXT NOT NULL,                  -- admin-facing label, e.g. "Overdue Payment"
    rule_type           TEXT NOT NULL,                  -- attendance | date_field | empty_field | numeric
    target_field        TEXT,                           -- field key from member_fields; NULL for attendance
    condition           TEXT,                           -- older_than | before_today | blank | below | above
    threshold_value     INTEGER,                        -- e.g. 5 (sessions), 365 (days), 0 (numeric)
    threshold_unit      TEXT,                           -- days | sessions | NULL
    applies_to_session  TEXT,                           -- NULL = all sessions; 'Tuesday' = scoped
    flag_label          TEXT NOT NULL,                  -- shown as badge on member, e.g. "Payment Overdue"
    flag_colour         TEXT NOT NULL DEFAULT '#d97706',-- hex colour for badge
    auto_resolve        INTEGER NOT NULL DEFAULT 1,     -- 1 = auto-clear when condition no longer met
    resolve_field       TEXT,                           -- field to watch for auto-resolve (date/numeric rules)
    is_active           INTEGER NOT NULL DEFAULT 1,
    created_at          DATETIME DEFAULT (datetime('now')),
    created_by          INTEGER REFERENCES users(id)
);
```

### New table: `member_flags`

```sql
CREATE TABLE member_flags (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id     INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    rule_id       INTEGER NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    flagged_at    DATETIME NOT NULL DEFAULT (datetime('now')),
    flagged_by    TEXT NOT NULL,                        -- 'auto' or user_id as text
    resolved_at   DATETIME,
    resolved_by   TEXT,                                 -- 'auto' or user_id as text
    note          TEXT,
    UNIQUE (member_id, rule_id)                         -- only one active flag per member per rule
                                                        -- (enforced in app layer: WHERE resolved_at IS NULL)
);
```

### Changed: `members` table

- Remove `'At Risk'` as a valid `status` value
- `status` column now only ever holds `'Active'` or `'Leaver'`
- `status_note` column remains (used for leaver notes)

---

## Rule Types

### 1. Attendance
Flags a member who has missed N or more consecutive sessions of their assigned session type.

- `target_field`: NULL (uses attendance table directly)
- `condition`: `consecutive_misses`
- `threshold_value`: number of sessions (e.g. 5)
- `threshold_unit`: `sessions`
- **Auto-resolve:** Yes — flag clears automatically when the member signs in to a session
- **Migrates from:** existing `at_risk_threshold_tuesday` / `at_risk_threshold_thursday` settings

### 2. Date Field
Flags a member when a date field is older than N days, or falls before today.

- `target_field`: field key (e.g. `last_payment_date`, `membership_renewal_date`)
- `condition`: `older_than` | `before_today`
- `threshold_value`: number of days (for `older_than`); NULL (for `before_today`)
- `threshold_unit`: `days` | NULL
- **Auto-resolve:** Yes — re-evaluated on next check run; flag clears if condition no longer true
- `resolve_field`: same as `target_field`

### 3. Empty Field
Flags a member when a specified field has no value recorded.

- `target_field`: field key (e.g. `emergency_contact`, `medical_notes`)
- `condition`: `blank`
- `threshold_value`: NULL
- **Auto-resolve:** Yes — re-evaluated on next check; flag clears when field is populated
- Note: "auto-resolve" here means the check detects the field is now filled — there is no field-update trigger; it clears on next run

### 4. Numeric
Flags a member when a numeric field falls above or below a threshold value.

- `target_field`: field key (e.g. `outstanding_balance`)
- `condition`: `above` | `below`
- `threshold_value`: numeric threshold (e.g. 0)
- **Auto-resolve:** Yes — re-evaluated on next check run

---

## Flag Lifecycle

```
Rule defined (admin)
        ↓
Check runs (manual trigger or nightly)
        ↓
Each active rule evaluated against eligible members
        ↓
New flags inserted into member_flags (deduped — skip if active flag already exists for that member+rule)
        ↓
Flag badge visible on member list / member detail
        ↓
Resolved automatically (condition clears on next check) OR manually dismissed with optional note
        ↓
resolved_at + resolved_by recorded — flag no longer shown
```

---

## API Endpoints (to be built)

| Method | Path | Permission | Description |
|---|---|---|---|
| GET | `/api/alert-rules` | `alerts.view` | List all rules |
| POST | `/api/alert-rules` | `alerts.manage` | Create rule |
| PUT | `/api/alert-rules/<id>` | `alerts.manage` | Update rule |
| DELETE | `/api/alert-rules/<id>` | `alerts.manage` | Deactivate rule |
| POST | `/api/alert-rules/run` | `alerts.run` | Run all active rules now |
| GET | `/api/members/<id>/flags` | `members.view` | Get active flags for a member |
| POST | `/api/members/<id>/flags/<flag_id>/dismiss` | `alerts.dismiss` | Manually dismiss a flag |
| GET | `/api/alerts/summary` | `alerts.view` | Dashboard summary (count per rule) |

### New permissions to seed

```python
('alerts.view',    'View Alerts',    'See member flags and alert rules',       'alerts'),
('alerts.manage',  'Manage Rules',   'Create and edit alert rules',            'alerts'),
('alerts.run',     'Run Checks',     'Trigger an alert rule evaluation',       'alerts'),
('alerts.dismiss', 'Dismiss Flags',  'Manually clear a flag from a member',    'alerts'),
```

---

## UI Touchpoints

### Settings → Alerts (new page)
- List of configured rules with toggle (active/inactive), label, type, and flag count
- "New Rule" button opens rule builder form:
  - Rule name
  - Rule type selector → dynamically shows relevant fields
  - Target field picker (drawn from Field Builder registry)
  - Condition + threshold inputs
  - Session scope (all / specific session)
  - Flag label + colour picker
  - Auto-resolve toggle
- Edit / delete existing rules

### Dashboard card — Member Alerts
- Replaces existing "At Risk" count
- Shows count per active rule with coloured badge labels
- Each row links through to member list filtered by that flag

### Member List
- Flag badges shown inline per member row (stacked if multiple)
- New filter: "Flagged" tab / dropdown showing all flagged members, or filter by specific rule
- Replaces existing "At Risk" filter

### Member Detail
- Flags panel: all active flags listed with date raised, raised by, and Dismiss button
- Dismiss opens a small modal for optional note
- Flag history (resolved flags) collapsible below active flags

### Audit Log
- All flag raises and dismissals logged:
  - `raise_flag` — member, rule name, flagged_by
  - `dismiss_flag` — member, rule name, dismissed_by, note

---

## Migration Plan

1. **Schema migration script** (`scripts/migrate_to_alert_rules.py`):
   - Create `alert_rules` and `member_flags` tables
   - Read existing `at_risk_threshold_tuesday` / `at_risk_threshold_thursday` from settings
   - Insert one attendance rule per session type using those thresholds
   - Find all members where `status = 'At Risk'`
   - Insert a `member_flags` row for each, linked to the matching attendance rule, `flagged_by = 'migration'`
   - Update those members to `status = 'Active'`
   - Leave old settings keys in place temporarily (remove in a follow-up cleanup)

2. **app.py changes**:
   - Remove all `status = 'At Risk'` references from queries
   - Remove `api_attendance_check_at_risk` and `api_attendance_mark_at_risk` endpoints (replaced by generic rules endpoints)
   - Remove `register.at_risk` permission (replaced by `alerts.*` permissions)
   - Update dashboard counts query — "at risk" count becomes per-rule flag counts
   - Member list query joins `member_flags` to attach active flags

3. **Templates**:
   - `dashboard.html` — replace at-risk card with alerts summary widget
   - `members.html` — add flag badges, update filter tabs
   - `member_detail.html` — add flags panel
   - `admin/settings.html` — add Alerts card
   - Add `admin/alerts.html` — rule builder page
   - Remove `admin/attendance_settings.html` (superseded)

---

## Open Questions

- **Nightly auto-check:** Implement as a scheduled background task (APScheduler) or keep manual-only for now and add scheduling later? Recommendation: manual-only first, schedule as a follow-on.
- **Flag colour palette:** Define a small set of preset colours (red, amber, blue, purple) for the picker, or allow full hex input?
- **Notification on flag raise:** Out of scope for now, but the flag system is the right hook for future email alerts to leaders when new flags are raised.
