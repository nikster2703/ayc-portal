# AYC Portal — Setup & Reference Guide

Full-stack member management portal for Ashford Youth Club.
Built with Python / Flask / SQLite. Can run directly on a Mac Mini (development) or in Docker containers on a QNAP NAS or any Linux server (production).

---

## What's in the portal

| Phase | Features |
|-------|----------|
| 1 | Login, member lookup, edit/soft-delete, audit log, user management |
| 2 | Public self-registration form + staff approval workflow |
| 3 | Digital session register (sign-in/out), attendance history, At Risk tracking |
| 4 | Document repository, email templates, mailshots via Gmail |
| 5 | Term calendar, staff registrations, permanent record delete |
| 6 | Configurable Roles & Permissions — fully database-driven, customisable per-role |
| 7 | Duke of Edinburgh module *(coming soon)* |

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
- Roles are fully configurable — see the **Roles & Permissions** section below for details
- Assign a **session** to accounts that need to be scoped to a single session (e.g. Tuesday or Thursday only). Accounts with the `admin.maintenance` permission are automatically unscoped.
- Deactivate accounts when someone leaves
- Reset passwords via the Edit button

Staff can also change their own password at any time by clicking their username in the top-right header.

---

## Roles & Permissions

From Phase 6 onwards, roles are fully database-driven. There are no hard-coded role names in the application — any role with the right permissions will automatically gain access to the corresponding features.

### Default roles

Four roles are created on first run and cannot be deleted:

| Role | Description |
|------|-------------|
| **Admin** | Full access — user management, audit log, settings, all member data |
| **Core Leader** | Edit members, approve registrations, send mailshots, manage documents |
| **Leader** | Sign members in/out for their assigned session; view attendance |
| **Read-only** | View member list and attendance for their assigned session only |

### Managing roles

Log in as admin → **⚙️ Settings** → **Manage Roles & Permissions**. From here you can:

- Create custom roles with any combination of permissions
- Edit existing role names and permissions
- Delete custom roles (only if no users are currently assigned to them)

### Permission reference

Permissions are grouped into categories. The full list is visible in the role editor UI. Key ones to know:

| Permission | What it unlocks |
|------------|-----------------|
| `admin.maintenance` | Full admin access; marks the role as unscoped (no session required) |
| `users.create.admin` | Ability to create/assign admin-level roles |
| `members.edit` | Edit member records |
| `members.delete` | Soft-delete (mark as leaver) |
| `members.hard_delete` | Permanent delete of member records |
| `approvals.view` | See and action the self-registration queue |
| `register.signin` / `register.signout` | Sign members in or out on the register |
| `register.at_risk` | Mark/unmark members as At Risk |
| `documents.upload` | Upload new documents to the repository |
| `mailshots.send` | Compose and send mailshots |
| `calendar.create` | Add / generate term calendar entries |
| `audit.view` | View the security audit log |

### Session scoping

Any role **without** the `admin.maintenance` permission must be assigned a session (e.g. Tuesday or Thursday). Users with a scoped role can only see members registered to that session. Admins see all sessions.

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

Staff with the `approvals.view` permission go to **📋 Approvals** in the nav to approve (assigning a session and portal role) or reject (with optional notes) each submission. Approved submissions automatically create a member record with the next AYC### ID. The portal role dropdown in the approval form is populated dynamically from the roles table, so any custom roles you've created will appear automatically.

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
├── PERMISSIONS_AUDIT.md      Full list of every permission code and which routes/features it guards
│
├── data/
│   ├── ayc.db                SQLite database (all member/attendance/roles data)
│   └── documents/            Uploaded documents (PDFs, Word files, etc.)
│
├── scripts/
│   ├── seed_admin.py         Create the first admin user interactively
│   ├── migrate_members.py    Import members from the original spreadsheet
│   └── schema_permissions.sql  Standalone SQL to seed the roles/permissions tables
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
        ├── users.html        User management
        ├── roles.html        Roles & Permissions editor
        ├── audit.html        Security audit log
        └── settings.html     Portal settings (session types, etc.)
```

---

## Code vs data — where things live (Docker)

This is important to understand when running in Docker on the QNAP.

**The `ara-portal` folder** (visible via SMB in the Container share) contains only the **code** — `app.py`, templates, static files etc. You will not find a `data/` folder here and that is normal.

**The database and uploaded documents** live in a Docker named volume (`ara-portal_portal-live-data`) which Docker manages in its own internal storage area, separate from the code folder. This is intentional — it means you can update the code (git pull + rebuild) without ever touching your data.

To see exactly where Docker keeps the volume on disk:
```bash
docker volume inspect ara-portal_portal-live-data
```

The golden rule:
- **Code update** → `git pull` + `docker compose build` + `docker compose up -d` — your data is untouched
- **Data lives** in the Docker volume — back it up with the `docker run ... tar` command in the Docker section above, or via Settings → Maintenance in the portal

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

When you move to D9 hosting, copy both `data/ayc.db` and `data/documents/` across and the portal will work immediately — your roles, permissions, members, and all settings are all stored in the database.

### Upgrading from v5 to v6 (Roles & Permissions)

If you have an existing database from before Phase 6 (i.e. no `roles` or `permissions` tables), the app will create them automatically on first run using the default role set. Existing users will be migrated to the matching default role. No manual SQL is required.

If you need to migrate manually or inspect the schema, see `scripts/schema_permissions.sql`.

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

---

## Docker deployment (QNAP / Linux server)

The portal ships with a `Dockerfile` and `docker-compose.yml` that run two fully isolated instances — **live** (port 5001) and **dev** (port 5002) — side by side on the same host. All runtime data (database, uploaded documents, backups) is stored in named Docker volumes so it survives container rebuilds.

### Prerequisites

- Docker Engine 24+ and Docker Compose V2
- On QNAP: install **Container Station** from the App Center (this provides both)

### First-time setup on a new machine

**1. Clone the repo**
```bash
git clone https://github.com/nikster2703/ayc-portal.git
cd ayc-portal
```

**2. Create your instance .env files**

Each instance needs its own secrets file. Start from the provided templates:
```bash
cp instances/live/.env.example instances/live/.env
cp instances/dev/.env.example  instances/dev/.env
```

Edit each file and fill in at minimum:
- `SECRET_KEY` — generate with `python3 -c "import secrets; print(secrets.token_hex(32))"`
- `DB_ENCRYPTION_KEY` — generate with `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`
- `CLUB_NAME` / `CLUB_SHORT_NAME`
- Gmail SMTP credentials (for mailshots)

**3. Build the Docker image**
```bash
docker compose build
```
This compiles pysqlcipher3 and installs all Python dependencies. Takes a few minutes the first time; subsequent builds are fast due to layer caching.

**4. Create the first admin user**
```bash
# For the live instance:
docker compose run --rm ayc-live python scripts/seed_admin.py

# For the dev instance:
docker compose run --rm ayc-dev python scripts/seed_admin.py
```

**5. Import existing member data (live instance only)**

Copy your `SYC Member Details-2.xlsx` into the project folder first, then:
```bash
docker compose run --rm -v "$(pwd)/SYC Member Details-2.xlsx:/SYC Member Details-2.xlsx" \
  ayc-live python scripts/migrate_members.py
```

**6. Start both instances**
```bash
docker compose up -d
```

Visit `http://<QNAP-IP>:5001` for live and `http://<QNAP-IP>:5002` for dev.

---

### Deploying an update

```bash
git pull
docker compose build
docker compose up -d
```

Docker Compose restarts each container with the new image. Downtime is typically under 5 seconds per service.

---

### Caddy reverse proxy (HTTPS)

Run Caddy on the QNAP host (or as a third Docker service) to handle HTTPS and route traffic.

**Install Caddy on the QNAP** (via the Entware package manager or a Caddy container):

Example `Caddyfile` routing two subdomains to the two instances:
```
ayc-portal.duckdns.org {
    reverse_proxy localhost:5001
}

dev.ayc-portal.duckdns.org {
    reverse_proxy localhost:5002
}
```

Start Caddy:
```bash
sudo caddy run --config /path/to/Caddyfile
```

Caddy handles TLS certificates automatically via Let's Encrypt.

---

### Managing volumes (backup & restore)

All instance data lives in named Docker volumes. To back up:
```bash
# Backup live database
docker run --rm \
  -v ayc-portal_ayc-live-data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/ayc-live-backup-$(date +%Y%m%d).tar.gz -C /data .
```

To restore on a new machine:
```bash
docker volume create ayc-portal_ayc-live-data
docker run --rm \
  -v ayc-portal_ayc-live-data:/data \
  -v $(pwd):/backup \
  alpine tar xzf /backup/ayc-live-backup-YYYYMMDD.tar.gz -C /data
```

Then run `docker compose up -d` as normal.

---

### Useful Docker commands

| Task | Command |
|------|---------|
| View live logs | `docker compose logs -f ayc-live` |
| View dev logs | `docker compose logs -f ayc-dev` |
| Restart live only | `docker compose restart ayc-live` |
| Open a shell in live container | `docker compose exec ayc-live bash` |
| Stop everything | `docker compose down` |
| Stop and remove volumes (destructive!) | `docker compose down -v` |
| Check container health | `docker compose ps` |

---

### Troubleshooting (Docker)

**Build fails on pysqlcipher3** — The Dockerfile installs `libsqlcipher-dev` in the builder stage. If you see a compilation error, make sure your Docker Engine is up to date (24+).

**Container starts then immediately exits** — Check logs with `docker compose logs ayc-live`. Most likely cause is a missing or malformed `instances/live/.env` — particularly `DB_ENCRYPTION_KEY` or `SECRET_KEY` not set.

**Port already in use** — Change the host-side ports in `docker-compose.yml` (e.g. `"5011:5001"` for live). Update your Caddyfile to match.

**Times showing 1 hour behind in Docker** — Add `TZ=Europe/London` to the `environment:` block for each service in `docker-compose.yml`.

**Uploaded documents not persisting** — Make sure the named volumes exist (`docker volume ls`). If you used `docker compose down -v` at any point, the volumes were deleted.
