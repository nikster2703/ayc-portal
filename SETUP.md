# AYC Portal — Setup & Reference Guide

Full-stack member management portal for Ashford Youth Club.
Built with Python / Flask / SQLite. Runs on a Mac Mini M1, accessible over the internet via DuckDNS + Caddy.

---

## What's in the portal

| Phase | Features |
|-------|----------|
| 1 | Login, member lookup, edit/soft-delete, audit log, user management |
| 2 | Public self-registration form + staff approval workflow |
| 3 | Digital session register (sign-in/out), attendance history, auto-leaver (35-day rule) |
| 4 | Document repository, email templates, mailshots via Gmail |
| 5 | Duke of Edinburgh module *(coming soon)* |

**Special pages**
- `/registration` — public self-registration form (no login required, share with parents)
- `/display` — reception TV display showing who's currently signed in (no login required)

---

## Prerequisites

- Python 3.11 or later (`python3 --version`)
- The `ayc-portal` folder on your Mac Mini

---

## Step 1 — Create a virtual environment

Modern Macs won't let you install Python packages system-wide. Create a virtual environment inside the project folder once:

```bash
cd ayc-portal
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

You'll see `(venv)` at the start of your prompt. After the first time, just activate it when you want to work on the project:

```bash
source venv/bin/activate
```

---

## Step 2 — Create your .env file

```bash
cp .env.example .env
```

Open `.env` and fill in two things:

**SECRET_KEY** — a long random string Flask uses to sign session cookies:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```
Paste the output as the value for `SECRET_KEY`.

**Gmail SMTP** (needed for mailshots):
1. Make sure 2-Step Verification is on for your Gmail account
2. Go to **Google Account → Security → App passwords**
3. Create one named "AYC Portal" — Google gives you a 16-character code
4. Fill in your Gmail address as `MAIL_USERNAME` and the App Password as `MAIL_PASSWORD`

The `.env.example` file has all the variable names with comments.

---

## Step 3 — First run

```bash
python3 app.py
```

On first run the database is created automatically:
```
First run — initialising database…
Database initialised at /path/to/ayc-portal/data/ayc.db
 * Running on http://0.0.0.0:5001
```

Visit `http://localhost:5001` to confirm it's working. You won't be able to log in yet — do that next.

> **Note:** Port 5001 is used because AirPlay Receiver occupies port 5000 on Mac.

---

## Step 4 — Create your admin user

With the app running, open a **second Terminal** in the same folder and run:

```bash
source venv/bin/activate
python3 scripts/seed_admin.py
```

Follow the prompts to set a username and password. This creates the first admin account.

---

## Step 5 — Import existing member data

Still in the second Terminal:

```bash
python3 scripts/migrate_members.py
```

This reads `SYC Member Details-2.xlsx` (in the `AYC Member Lookup` folder one level above `ayc-portal/`) and imports all members into SQLite. Safe to re-run — it won't duplicate records.

---

## Step 6 — Test the login

Go to `http://localhost:5001` and log in with your admin credentials. You should land on the Dashboard.

---

## Step 7 — Run as a background service (Mac Mini)

So the portal keeps running after you close Terminal, create a launch agent.

Create `~/Library/LaunchAgents/com.ayc.portal.plist`, replacing `YOUR_USERNAME` and the path to match where `ayc-portal` actually lives:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.ayc.portal</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/YOUR_USERNAME/path/to/ayc-portal/venv/bin/python3</string>
    <string>/Users/YOUR_USERNAME/path/to/ayc-portal/app.py</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PYTHONDONTWRITEBYTECODE</key>
    <string>1</string>
  </dict>
  <key>WorkingDirectory</key>
  <string>/Users/YOUR_USERNAME/path/to/ayc-portal</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/tmp/ayc-portal.log</string>
  <key>StandardErrorPath</key>
  <string>/tmp/ayc-portal-error.log</string>
</dict>
</plist>
```

Load it:
```bash
launchctl load ~/Library/LaunchAgents/com.ayc.portal.plist
```

Stop/restart it:
```bash
launchctl unload ~/Library/LaunchAgents/com.ayc.portal.plist
launchctl load   ~/Library/LaunchAgents/com.ayc.portal.plist
```

Check the logs:
```bash
tail -f /tmp/ayc-portal.log
tail -f /tmp/ayc-portal-error.log
```

---

## Step 8 — Expose via DuckDNS + Caddy

### DuckDNS

1. Go to https://www.duckdns.org and sign in
2. Create a subdomain (e.g. `ayc-portal.duckdns.org`)
3. Set it to point to your Mac Mini's public IP
4. Add a cron job to keep it updated (replace `YOUR_TOKEN` and `YOUR_SUBDOMAIN`):
   ```bash
   crontab -e
   ```
   ```
   */5 * * * * curl -s "https://www.duckdns.org/update?domains=YOUR_SUBDOMAIN&token=YOUR_TOKEN&ip=" > /dev/null
   ```

### Caddy

Install Caddy from https://caddyserver.com/docs/install.

Create a `Caddyfile`:
```
ayc-portal.duckdns.org {
    reverse_proxy localhost:5001
}
```

Caddy handles HTTPS certificates automatically. Start it:
```bash
sudo caddy run --config /path/to/Caddyfile
```

Your portal will then be live at `https://ayc-portal.duckdns.org`.

---

## Managing staff users

Log in as admin → **⚙️ Users** in the nav. You can:

- Add staff accounts (username, email, role, optional session assignment)
- **Roles:**
  - **Admin** — full access including user management and audit log
  - **Editor** — view/edit all members, approve registrations, send mailshots
  - **Leader** — view and sign-in/out members for their assigned session only
  - **Read-only** — view only, scoped to their assigned session
- Assign a **session** to Leader and Read-only accounts so they only see Tuesday or Thursday members
- Deactivate accounts when someone leaves
- Reset passwords via the Edit button

Staff can also change their own password at any time by clicking their username in the top-right header.

---

## Reception TV display

Navigate to `/display` on any browser and use AirPlay (or a cable) to put it on the TV. The page:

- Auto-detects the current session based on the day of the week
- Shows all members currently **signed in and not yet signed out**
- Refreshes automatically every 30 seconds
- Shows a live clock and "X signed in" headcount
- Requires no login — safe to leave on screen permanently

For a clean full-screen view, press **Cmd+Ctrl+F** in Safari or **F11** in Chrome.

---

## Public self-registration

Share the URL `https://ayc-portal.duckdns.org/registration` (or your local equivalent) with parents. The form collects all required details and places the submission in the **Approvals** queue for staff to review.

Staff with Admin or Editor role go to **📋 Approvals** in the nav to approve (assigning a session) or reject (with optional notes) each submission. Approved submissions automatically create a member record with the next AYC### ID.

---

## File & folder reference

```
ayc-portal/
├── app.py                    Main Flask app — all routes and API endpoints
├── schema.sql                SQLite schema (all tables, all phases)
├── requirements.txt          Python dependencies
├── .env                      Your secrets — never share or commit this file
├── .env.example              Template showing all available config variables
├── SETUP.md                  This file
│
├── data/
│   ├── ayc.db                SQLite database (all member/attendance data)
│   └── documents/            Uploaded documents (PDFs, Word files, etc.)
│
├── scripts/
│   ├── seed_admin.py         Create the first admin user interactively
│   └── migrate_members.py    Import members from the original spreadsheet
│
├── static/
│   ├── css/shared.css        All shared styles
│   └── js/utils.js           Shared JS helpers (apiFetch, showToast, etc.)
│
└── templates/
    ├── base.html             Shared layout — header, nav, password-change modal
    ├── index.html            Login page
    ├── dashboard.html        Home — member stats, pending approvals, activity feed
    ├── members.html          Member lookup, edit, soft-delete, attendance history
    ├── approvals.html        Review & approve/reject self-registration submissions
    ├── register.html         Digital session sign-in/out register
    ├── registration.html     Public self-registration form (no login required)
    ├── display.html          Reception TV display (no login required)
    ├── documents.html        Document repository — upload, browse, download
    ├── communications.html   Email templates + send mailshots + sent history
    └── admin/
        ├── users.html        User management (admin only)
        └── audit.html        Security audit log (admin only)
```

---

## Backing up the database

Everything is in one file: `data/ayc.db`. Back it up with:

```bash
cp data/ayc.db data/ayc-backup-$(date +%Y%m%d).db
```

Set this up as a daily cron job:
```bash
crontab -e
```
```
0 2 * * * cp /path/to/ayc-portal/data/ayc.db /path/to/ayc-portal/data/backups/ayc-$(date +\%Y\%m\%d).db
```

Also back up `data/documents/` periodically — this contains all uploaded files.

When you move to D9 hosting, copy both `data/ayc.db` and `data/documents/` across and the portal will work immediately.

---

## Troubleshooting

**Port already in use** — The app runs on port 5001. If that's also in use, change `port=5001` near the bottom of `app.py` and update your Caddyfile to match.

**Can't find the spreadsheet** — `migrate_members.py` looks for `SYC Member Details-2.xlsx` one level above `ayc-portal/`. Make sure it's in the `AYC Member Lookup` folder.

**Session expires too quickly** — The default is 8 hours. Change `timedelta(hours=8)` in `app.py` to suit, e.g. `timedelta(days=1)`.

**Forgot admin password** — Run `python3 scripts/seed_admin.py` to create a new admin account, log in, then go to Users to reset the old account's password from there.

**Mailshot says "Email not configured"** — Add `MAIL_USERNAME` and `MAIL_PASSWORD` to your `.env` file (see Step 2 above). Restart the app after editing `.env`.

**Gmail App Password rejected** — Make sure 2-Step Verification is enabled on the sending Gmail account. Standard passwords don't work with SMTP — it must be an App Password generated from Google Account → Security → App passwords.

**Uploaded documents not appearing** — The `data/documents/` folder is created automatically on startup. If it's missing permissions, run `chmod 755 data/documents` from inside `ayc-portal/`.

**Times showing 1 hour behind** — Make sure your Mac Mini's System Settings → General → Date & Time is set to the correct timezone (Europe/London) and "Set time zone automatically" is on.
