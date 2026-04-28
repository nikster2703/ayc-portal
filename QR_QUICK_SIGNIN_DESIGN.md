# QR Quick Sign-In / Sign-Out — Design Specification

**Feature:** Mobile self-sign-in (and optional sign-out) via QR code on the reception display  
**Status:** Design — not yet implemented  
**Fits into:** Phase 3 (Digital Register) extension

---

## Overview

When there is a queue at the iPad, kids can scan a QR code on the reception display with their phone, search for their first name, and sign themselves into the session — all without a login. The same QR code can also be configured to offer a **Sign Out** option, controlled by org-wide settings. For AYC, sign-out via QR is disabled by default because guardians must be present to collect members; other organisations may enable it freely.

The QR code is tied to the current session token and becomes invalid the moment the register is completed or a leader regenerates it.

---

## One QR Code — Adaptive Flow

A single QR code handles everything. The landing page detects which modes are enabled and adapts:

| Setting state | Landing page behaviour |
|--------------|----------------------|
| Sign-in only (default) | Skips the choice screen entirely — goes straight to name search |
| Both enabled | Shows two large buttons: **Sign In** and **Sign Out** |
| Sign-out only | Skips the choice screen — goes straight to sign-out name search |

This avoids the confusion of two QR codes and means the leader never has to "prepare" a second code. The QR on the display is always the same URL; the behaviour is controlled entirely by settings.

---

## User Flows

### Sign-In Flow
```
Reception display shows QR code (top-right, left of clock)
        ↓
Kid scans with phone camera — no app needed
        ↓
/quick-session?t=<token> loads
        ↓
[If both modes enabled] → choice screen: big "Sign In" | "Sign Out" buttons
[If sign-in only]       → goes straight to search (no extra tap)
        ↓
"What's your first name?" — large search field, big tap targets
        ↓
Kid types name → results show matching active members (first name + surname initial)
Already-signed-in members show ✓ and are un-tappable
        ↓
Kid taps their name → confirmation:
  "Is this you?  Jamie B."
  [Yes, sign me in]  [No, go back]
        ↓
Server signs them in — duplicate check runs server-side
        ↓
Success: "Welcome, Jamie! 🎉 Great to see you tonight!"
        ↓
Page auto-resets after 8 seconds
```

### Sign-Out Flow (when enabled)
```
Kid scans same QR code
        ↓
Choice screen → taps "Sign Out"
        ↓
"What's your first name?" — same search UI
        ↓
Results show only members currently signed IN (signed_out_at IS NULL)
Members not yet arrived, or already signed out, are hidden entirely
        ↓
Kid taps their name → confirmation:
  "Leaving now?  Jamie B."
  [Yes, sign me out]  [No, go back]
        ↓
Server records sign-out time — same duplicate protection
        ↓
Success: "Goodbye, Jamie! See you next time 👋"
        ↓
Page auto-resets after 8 seconds
```

---

## Token Design

A **session token** is the only gate on the entire flow. It is embedded in the QR URL and validated server-side on every request.

### Rules
- One active token per `(session_type, session_date)` at any time.
- Token is a `secrets.token_urlsafe(32)` — 43 URL-safe random characters.
- Auto-created when the register page is first opened for the day.
- Immediately invalid if any of these are true:
  - `session_date` ≠ today's date (tokens do not carry over between sessions)
  - The register has been completed/locked (`session_completions` row exists)
  - `invalidated_at` is set (leader regenerated or session completed)
- Token is never reused; regeneration creates a new row and stamps `invalidated_at` on the old one.

### New database table
```sql
CREATE TABLE IF NOT EXISTS quick_signin_tokens (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    token          TEXT    NOT NULL UNIQUE,
    session_type   TEXT    NOT NULL,
    session_date   TEXT    NOT NULL,   -- YYYY-MM-DD
    created_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    invalidated_at TEXT    NULL        -- set on regenerate or register complete
);
CREATE INDEX IF NOT EXISTS idx_qst_token   ON quick_signin_tokens(token);
CREATE INDEX IF NOT EXISTS idx_qst_session ON quick_signin_tokens(session_type, session_date);
```

---

## New Routes

### Public (no login required)

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/quick-session` | Mobile landing page (`?t=<token>` required) |
| `GET`  | `/api/quick-signin/verify` | Validate token → return session info + enabled modes |
| `GET`  | `/api/quick-signin/search` | Search members by first name |
| `POST` | `/api/quick-signin/signin` | Sign a member in |
| `POST` | `/api/quick-signin/signout` | Sign a member out (only if `quick_signout_enabled = true`) |

### Authenticated (logged-in leader/admin)

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/api/quick-signin/token/<session_type>` | Get (or create) today's token + QR URL |
| `POST` | `/api/quick-signin/token/<session_type>/regenerate` | Invalidate + issue new token |

### Display page (public)

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/api/quick-signin/display-token/<session_type>` | QR URL for the TV display (public, returns URL or null) |

---

## API Endpoint Details

### `GET /api/quick-signin/verify?t=<token>`
Called on page load. Returns session info and which modes are currently enabled, so the mobile page knows whether to show the choice screen.

**Response (valid):**
```json
{
  "valid": true,
  "session_type": "Tuesday",
  "session_date": "2026-04-29",
  "signin_enabled": true,
  "signout_enabled": false
}
```
**Response (invalid/expired/locked):**
```json
{ "valid": false, "reason": "Session register is locked." }
```

---

### `GET /api/quick-signin/search?t=<token>&q=<name>&mode=signin`
Returns matching active members, filtered to the token's session.

**Behaviour:**
- `q` must be ≥ 2 characters.
- `mode` = `signin` or `signout`.
- For `signin`: returns all active members for the session; flags those already signed in.
- For `signout`: returns only members currently signed in (`signed_in_at NOT NULL AND signed_out_at IS NULL`).
- Returns first name + surname initial only (no full surnames on a public endpoint).

**Response:**
```json
[
  { "id": 42, "first_name": "Jamie", "surname_initial": "B", "already_signed_in": false },
  { "id": 71, "first_name": "Jamie", "surname_initial": "O", "already_signed_in": true }
]
```
For sign-out search, `already_signed_in` is always `true` (only currently-present members are returned).

---

### `POST /api/quick-signin/signin`
**Server-side checks (in order):**
1. Token valid, today's date, not invalidated → else 403.
2. Register not locked → else 403.
3. `quick_signin_enabled` setting is true → else 403.
4. `member_id` is active and belongs to this session → else 403.
5. Check for existing attendance row:
   - Already signed in → return success with `already_signed_in: true`. Do not double-record.
   - Not signed in → `INSERT OR IGNORE`; if 0 rows affected (race), treat as already-signed-in.
6. Auto-resolve attendance alert flags (same logic as `api_attendance_signin`).
7. Set `recorded_by = 'qr-self'`.

**Response (new sign-in):**
```json
{
  "success": true,
  "already_signed_in": false,
  "first_name": "Jamie",
  "welcome_message": "Welcome, Jamie! 🎉 Great to see you tonight!"
}
```
**Response (already signed in):**
```json
{
  "success": true,
  "already_signed_in": true,
  "first_name": "Jamie",
  "welcome_message": "You're already signed in, Jamie! See you inside 👋"
}
```

---

### `POST /api/quick-signin/signout`
Only callable if `quick_signout_enabled = true` in settings — otherwise returns 403 immediately.

**Server-side checks:**
1. Token valid, today's date, not invalidated → else 403.
2. Register not locked → else 403.
3. `quick_signout_enabled` setting is true → else 403.
4. `member_id` is active and belongs to this session → else 403.
5. Fetch attendance row. If `signed_out_at` already set → return `already_signed_out: true` (friendly message, no error).
6. `UPDATE attendance SET signed_out_at = ?, recorded_by = 'qr-self' WHERE id = ? AND signed_out_at IS NULL`. If 0 rows updated (race condition), treat as already-signed-out.

**Response:**
```json
{
  "success": true,
  "already_signed_out": false,
  "first_name": "Jamie",
  "goodbye_message": "Goodbye, Jamie! See you next time 👋"
}
```

---

## Mobile Page (`/quick-session`)

A standalone, mobile-optimised HTML page — no login, no navigation, no `base.html` inheritance.

**Design principles:**
- Very large text and tap targets (kids, small screens, bright conditions).
- Maximum three taps from scan to "Welcome/Goodbye".
- Auto-focus the search field on load.
- Page auto-resets to start after 8 seconds.

**Page states:**
1. **Invalid token** — "This sign-in link has expired. Ask a leader for help."
2. **Mode choice** *(only when both sign-in and sign-out are enabled)* — two large buttons.
3. **Search** — text field + Search button, results below.
4. **Confirm sign-in** — "Is this you? [Name I.]" + Yes / No.
5. **Confirm sign-out** — "Leaving now? [Name I.]" + Yes / No.
6. **Welcome** — personalised sign-in success message + countdown.
7. **Goodbye** — personalised sign-out success message + countdown.
8. **Already signed in / out** — friendly variant message.

**Styling:** Uses `shared.css` for visual consistency. No header or sidebar.

---

## Reception Display Changes (`display.html`)

The display polls `/api/display/<session_type>` every 10 seconds. Add:

1. **QR code panel** — top-right corner of the display, positioned **to the left of the clock/date**.
   - Rendered with [qrcode.js](https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js) (CDN).
   - Polls `/api/quick-signin/display-token/<session_type>` every 30 seconds.
   - Valid token → render QR + label (see below).
   - No valid token / register locked → panel hidden entirely.

2. **Panel label** adapts to enabled modes:
   - Sign-in only → "Queue? Scan to sign in"
   - Both enabled → "Scan to sign in or out"
   - Sign-out only → "Scan to sign out"

3. **Visual treatment** — QR kept compact (≈120 px on the display); label text small and subdued. The scrolling names remain the hero element.

---

## Register Page Changes (`register.html`)

Add a "QR Sign-in" info panel visible to logged-in leaders:

- Thumbnail of the current QR code.
- "Regenerate QR" button — invalidates old token, issues new one (useful if QR was photographed and shared).
- Counter badge: "X signed in via QR · Y signed out via QR" (counts of `recorded_by = 'qr-self'` rows, split by whether `signed_out_at` is set).
- When register is completed: panel shows "QR session access disabled — register is locked."

---

## Settings Changes

All new keys live in the `settings` table and are exposed in **Admin → Settings → Attendance**.

| Key | Default | Description |
|-----|---------|-------------|
| `quick_signin_enabled` | `true` | Allow members to sign **in** via QR |
| `quick_signout_enabled` | `false` | Allow members to sign **out** via QR. Disabled by default — orgs where a guardian must collect the child should leave this off. |
| `quick_signin_welcome_msg` | `Welcome, {name}! Great to see you tonight!` | Sign-in success message. `{name}` = first name. |
| `quick_signin_already_msg` | `You're already signed in, {name}! See you inside 👋` | Shown if member scans again after sign-in. |
| `quick_signout_goodbye_msg` | `Goodbye, {name}! See you next time 👋` | Sign-out success message. |
| `quick_signout_already_msg` | `You're already signed out, {name}. Safe journey home!` | Shown if member scans again after sign-out. |

> **Settings UI note:** Show `quick_signout_enabled` with an inline warning: *"Only enable this if you do not require a guardian to be present at sign-out. For safeguarding reasons this is off by default."*

---

## Rate Limiting

Simple in-memory rate limiting — no new dependencies:

- **Search:** max 15 requests / minute / IP → 429 if exceeded.
- **Sign-in / Sign-out:** max 10 requests / minute / IP → 429 if exceeded.
- Implemented as a dict keyed by `(ip, endpoint, minute_bucket)`, cleared each new minute.

---

## Security Summary

| Risk | Mitigation |
|------|------------|
| Token shared outside the room | Leader can regenerate instantly; old token is invalidated server-side |
| Token carried over from previous session | Token always validated against today's date |
| Kid signing in/out as another kid | First name + surname initial confirmation; same exposure as the iPad kiosk |
| QR in camera roll after session ends | Completed register check runs server-side on every request |
| Double-tap race condition | `INSERT OR IGNORE` / `UPDATE … WHERE signed_out_at IS NULL`; SQLite serialises writes |
| Scraping the member list | Search requires ≥ 2 chars; rate limited by IP; no full surnames returned |
| Sign-out enabled unintentionally | Default is `false`; settings UI shows safeguarding warning |

---

## Implementation Checklist

### Database
- [ ] Add `quick_signin_tokens` table to `_ensure_schema()` migration block
- [ ] Verify `attendance` has `UNIQUE (member_id, session_date, session_type)` — add if missing
- [ ] Seed all six new settings keys with defaults

### Backend (`app.py`)
- [ ] Helper `_get_or_create_qr_token(session_type)`
- [ ] Helper `_validate_qr_token(token)` → row or None
- [ ] `GET /api/quick-signin/token/<session_type>` — authenticated
- [ ] `POST /api/quick-signin/token/<session_type>/regenerate` — authenticated
- [ ] `GET /api/quick-signin/display-token/<session_type>` — public
- [ ] `GET /api/quick-signin/verify` — public; returns modes enabled
- [ ] `GET /api/quick-signin/search` — public, rate-limited, mode-aware
- [ ] `POST /api/quick-signin/signin` — public, rate-limited, bulletproof upsert
- [ ] `POST /api/quick-signin/signout` — public, rate-limited, setting-gated
- [ ] Auto-invalidate token in `api_attendance_complete()`
- [ ] Auto-create token when `register.html` is served
- [ ] `GET /quick-session` — public route → `quick_session.html`

### Frontend
- [ ] `templates/quick_session.html` — adaptive mobile page (sign-in + optional sign-out)
- [ ] `display.html` — QR panel top-right, left of clock; adaptive label; 30 s poll
- [ ] `register.html` — QR panel with thumbnail, regenerate button, QR count badges

### Settings UI
- [ ] Expose all six keys in Admin → Settings → Attendance
- [ ] Safeguarding warning next to `quick_signout_enabled` toggle

---

## Out of Scope (for now)
- Staff signing in/out via QR
- Analytics dashboard for QR vs iPad ratios
- Push notification to leaders on QR sign-in/out
- Time-window restriction (e.g. sign-out only available in last 30 mins of session)
