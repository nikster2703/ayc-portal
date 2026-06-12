# AYC Portal — Setup & Reference Guide

Full-stack member management portal for Ashford Youth Club.
Built with Python / Flask / SQLite. Can run directly on a Mac Mini (development) or in Docker containers on a QNAP NAS or any Linux server (production).

---

## What's in the portal

| Phase | Features |
|-------|----------|
| 1 | Login, member lookup, edit/soft-delete, audit log, user management |
| 2 | Public self-registration form + staff approval workflow |
| 3 | Digital session register (sign-in/out), attendance history, configurable member alert flags |
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

Open `.env` and fill in the following:

**SECRET_KEY** — a long random string Flask uses to sign session cookies:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```
Paste the output as the value for `SECRET_KEY`.

**DB_ENCRYPTION_KEY** — the key that encrypts the database. Generate a *different* random value:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```
**Keep this safe — if you lose it, the database is permanently unreadable.**

**DOCUMENT_ENCRYPTION_KEY** — a dedicated key that encrypts uploaded documents, kept separate from the database key. On a fresh install, generate one now:
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```
Keep this safe too. If you leave it blank the portal still works (it falls back to deriving a key from `DB_ENCRYPTION_KEY`), but setting a dedicated key is the recommended best practice. **Do not change this value once documents have been uploaded, or those files become unreadable** — to switch keys later you must run `scripts/reencrypt_documents.py` (see "Rotating the document key" below).

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

Three roles are created on first run and cannot be deleted:

| Role | Description |
|------|-------------|
| **Admin** | Full access — user management, audit log, settings, all member data (unscoped — sees every session) |
| **Editor** | Day-to-day staff role — edit members, approve registrations, run the register, send mailshots, manage documents and alert rules (scoped to assigned session) |
| **Read Only** | Limited access for the assigned session — sign members out, view documents, payments and notifications |

> An earlier "Leader" role was retired and its users were automatically migrated to **Read Only**. Custom roles with any mix of permissions can still be created (see below).

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
| `alerts.view` / `alerts.manage` | View member flags; create and edit alert rules |
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

The portal runs as a single Docker container. All runtime data (database, uploaded documents, backups) is stored in a named Docker volume so it survives container rebuilds completely untouched.

The Docker project name is taken from the folder you clone into — so cloning into `ara-portal` gives you container `portal` and volume `ara-portal_portal-data`. Every club gets its own cleanly namespaced setup.

### Prerequisites

- Docker Engine 24+ and Docker Compose V2
- On QNAP: install **Container Station** from the App Center (this provides both)
- A DuckDNS domain pointed at your public IP
- Ports 80 and 443 forwarded on your router to the machine running Caddy

---

### First-time setup on a new machine

**1. Clone the repo into a club-named folder**

Since the QNAP doesn't have git installed, use a temporary Docker container:
```bash
cd /share/Container
docker run --rm -v /share/Container:/output \
  alpine sh -c "apk add --no-cache git && \
    git clone git@github.com:nikster2703/ayc-portal.git /output/ara-portal"
```
Replace `ara-portal` with your club's folder name (e.g. `burnham-portal`).

**2. Set up the SSH deploy key**

The repo uses an SSH deploy key instead of a password or token. On first install on a new machine:
```bash
# Create the SSH directory
mkdir -p /share/Container/.ssh

# Generate the deploy key pair
docker run --rm -v /share/Container/.ssh:/root/.ssh \
  alpine sh -c "apk add --no-cache openssh && \
    ssh-keygen -t ed25519 -f /root/.ssh/ara-portal-deploy -N '' -C 'ara-portal-qnap-deploy'"

# Set correct permissions
chmod 600 /share/Container/.ssh/ara-portal-deploy

# Fetch GitHub's host key
docker run --rm -v /share/Container/.ssh:/root/.ssh \
  alpine sh -c "apk add --no-cache openssh && \
    ssh-keyscan github.com > /root/.ssh/known_hosts"

# Show the public key — copy this to GitHub
cat /share/Container/.ssh/ara-portal-deploy.pub
```

Add the public key to GitHub: **repo → Settings → Deploy keys → Add deploy key** (read-only, no write access needed).

Then update the git remote to use SSH:
```bash
cd /share/Container/ara-portal
docker run --rm \
  -v /share/Container/ara-portal:/repo \
  -v /share/Container/.ssh:/root/.ssh:ro \
  alpine sh -c "apk add --no-cache git openssh && \
    git -C /repo remote set-url origin git@github.com:nikster2703/ayc-portal.git"
```

**3. Create your .env file**

```bash
cd /share/Container/ara-portal
cp .env.example .env
vi .env
```

Fill in at minimum:
- `PORT` — the port you want (e.g. `5005`). This is the port in your browser and Caddyfile.
- `CLUB_NAME` / `CLUB_SHORT_NAME` — full name and member ID prefix
- `SECRET_KEY` — generate with: `docker run --rm python:3.11-slim python3 -c "import secrets; print(secrets.token_hex(32))"`
- `DB_ENCRYPTION_KEY` — run the same command again for a second unique value. **Keep this safe — losing it means losing the database.**
- `DOCUMENT_ENCRYPTION_KEY` — a dedicated key for uploaded documents, unique to this server. Generate with: `docker run --rm python:3.11-slim sh -c "pip install -q cryptography && python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"`. Optional (a blank value falls back to deriving from `DB_ENCRYPTION_KEY`), but recommended on a fresh install. **Keep it safe and never change it once documents exist.**
- `FLASK_ENV` — set to `production`
- Gmail credentials — can be added later

**4. Build the Docker image**
```bash
docker compose build
```
Takes a few minutes the first time (compiles pysqlcipher3). Subsequent builds are fast.

**5. Create the first admin user**
```bash
docker compose run --rm portal python scripts/seed_admin.py
```

**6. Start the portal**
```bash
docker compose up -d
```

Visit `http://<server-IP>:<PORT>` to confirm it's running.

**7. Add to Caddy for HTTPS**

On the machine running Caddy (e.g. Mac Mini), add a block to the Caddyfile:
```
your-domain.duckdns.org {
    reverse_proxy <QNAP-IP>:<PORT>
}
```

Reload Caddy:
```bash
sudo caddy reload --config /path/to/Caddyfile
```

The portal will then be live at `https://your-domain.duckdns.org`.

---

### Deploying an update

A single script handles everything — pull, rebuild, restart:
```bash
cd /share/Container/ara-portal
./update.sh
```

Downtime is typically under 10 seconds. Your data is never touched.

> **Note — updates never modify your `.env`.** `update.sh` only pulls code and rebuilds; it does not change the server's `.env`. So when a new config variable is introduced (for example `DOCUMENT_ENCRYPTION_KEY`), `git pull` updates `.env.example` but **not** your live `.env` — you must add the new line to `.env` by hand and then `docker compose up -d --force-recreate`. Compare the two after an update with `diff <(sed -E 's/=.*//' .env | sort) <(sed -E 's/=.*//' .env.example | sort)` to spot any new variables you're missing.

#### Adding the document key to an existing server

If a server has been running **without** `DOCUMENT_ENCRYPTION_KEY`, its existing documents are encrypted with a key derived from `DB_ENCRYPTION_KEY`. You have two safe choices:

- **Leave it blank** — everything keeps working on the derived key. No action needed.
- **Switch to a dedicated key** — add `DOCUMENT_ENCRYPTION_KEY` to `.env`, then re-encrypt the existing files (see "Rotating the document key" below). Do **not** add the key without re-encrypting, or previously uploaded documents will fail to open.

A brand-new server with no documents yet can simply set a fresh key from the start — nothing to migrate.

#### Rotating the document key

To move existing documents from the old (derived) key to a new dedicated key, or to rotate to a brand-new key:

1. **Back up the documents first:** `cp -r data/documents data/documents.bak` (or, in Docker, snapshot the volume — see "Backing up and restoring data").
2. Add the new `DOCUMENT_ENCRYPTION_KEY` to `.env` (keep `DB_ENCRYPTION_KEY` unchanged so the script can read the old files).
3. Run the re-encryption script from the portal folder:
   - Local: `python3 scripts/reencrypt_documents.py`
   - Docker: `docker compose run --rm portal python scripts/reencrypt_documents.py`
4. The script decrypts each file with the old key and re-encrypts it with the new one. It's idempotent — safe to re-run if interrupted — and reports any errors. Only delete `data/documents.bak` once it reports success.

---

### Backing up and restoring data

All data lives in the Docker volume `<folder-name>_portal-data`. Back it up with:
```bash
docker run --rm \
  -v ara-portal_portal-data:/data \
  -v /share/Container/ara-portal:/backup \
  alpine tar czf /backup/portal-backup-$(date +%Y%m%d).tar.gz -C /data .
```

To restore on a new machine:
```bash
docker volume create ara-portal_portal-data
docker run --rm \
  -v ara-portal_portal-data:/data \
  -v /share/Container/ara-portal:/backup \
  alpine tar xzf /backup/portal-backup-YYYYMMDD.tar.gz -C /data
docker compose up -d
```

---

### Useful Docker commands

| Task | Command |
|------|---------|
| View logs | `docker compose logs -f portal` |
| Restart portal | `docker compose restart portal` |
| Open a shell in the container | `docker compose exec portal bash` |
| Check status | `docker compose ps` |
| Stop portal | `docker compose down` |
| Stop and delete all data (destructive!) | `docker compose down -v` |

---

### Troubleshooting (Docker)

**Build fails on pysqlcipher3** — The Dockerfile installs `libsqlcipher-dev` in the builder stage. Make sure Docker Engine is 24+.

**Container starts then immediately exits** — Check logs with `docker compose logs portal`. Most likely cause is a missing or malformed `.env` — check `DB_ENCRYPTION_KEY` and `SECRET_KEY` are set.

**Port already in use** — Change `PORT=` in `.env` to a free port, then run `docker compose up -d --force-recreate`. Update your Caddyfile to match.

**Times showing 1 hour behind** — Add `TZ=Europe/London` to the `environment:` block in `docker-compose.yml` and force-recreate.

**Uploaded documents not persisting** — Run `docker volume ls` to confirm the volume exists. If you ran `docker compose down -v` at any point, the volume was deleted.
