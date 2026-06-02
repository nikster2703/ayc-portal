# Secrets Rotation Guide

> **URGENT** — The `.env` file was committed to Git, exposing three secrets.
> Follow this guide in order. Do not skip steps.

---

## What was exposed

| Secret | Used for | Risk |
|--------|----------|------|
| `SECRET_KEY` | Flask session signing | Session forgery, CSRF bypass |
| `DB_ENCRYPTION_KEY` | SQLCipher database encryption | Offline database decryption |
| `GETADDRESS_KEY` | Postcode lookup API | Unauthorised API usage / billing |

---

## Step 1 — Remove the secrets from Git history

The `.gitignore` already excludes `.env`, but Git still tracks the already-committed
version. You must un-track it AND purge the history.

```bash
# From the ayc-portal directory:

# Un-track the file (stops future commits including it)
git rm --cached .env

# Commit the removal
git commit -m "Remove .env from tracking (should never have been committed)"

# Push
git push

# ── Purge from history ────────────────────────────────────────────────────────
# Install git-filter-repo if not already installed:
#   pip install git-filter-repo
#
# Remove .env from all historical commits:
git filter-repo --path .env --invert-paths

# Force-push the rewritten history (coordinate with anyone else with a clone):
git push --force-with-lease
```

> If you can't rewrite history (e.g. the repo is shared and clones exist),
> **rotate the secrets anyway** — assume the old values are compromised.

---

## Step 2 — Rotate SECRET_KEY

This logs all users out immediately. Do it during a low-traffic period.

Generate a new key:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Update `.env`:
```
SECRET_KEY=<new value from above>
```

Restart the portal:
```bash
docker compose up -d --force-recreate
```

---

## Step 3 — Rotate GETADDRESS_KEY

1. Log into your getAddress.io account at https://getaddress.io/
2. Revoke the existing API key
3. Generate a new key
4. Update `.env`:
   ```
   GETADDRESS_KEY=<new key>
   ```

---

## Step 4 — Add DOCUMENT_ENCRYPTION_KEY (NEW — decouples document encryption)

Generate a dedicated Fernet key for document encryption:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Add to `.env`:
```
DOCUMENT_ENCRYPTION_KEY=<new Fernet key from above>
```

Back up your documents directory:
```bash
cp -r data/documents data/documents.bak
```

Run the re-encryption script to convert existing files to the new key:
```bash
python scripts/reencrypt_documents.py
```

This is idempotent — safe to re-run if interrupted.

---

## Step 5 — Rotate DB_ENCRYPTION_KEY (most complex — plan carefully)

Rotating the SQLCipher key requires re-encrypting the entire database.
**Do not do this in production without a tested backup and restore plan.**

```bash
# 1. Stop the portal
docker compose stop

# 2. Back up the database
cp data/ayc.db data/ayc.db.backup-$(date +%Y%m%d)

# 3. Generate a new key
python -c "import secrets; print(secrets.token_hex(32))"
# Copy this value — you'll need it in step 5

# 4. Re-encrypt the database with the new key
# (Run from ayc-portal directory with OLD key still in .env)
python3 - <<'EOF'
import os, sqlcipher3 as sqlite3
from dotenv import load_dotenv
load_dotenv()

old_key = os.environ['DB_ENCRYPTION_KEY']
new_key = input("Enter NEW DB_ENCRYPTION_KEY: ").strip()

db = sqlite3.connect('data/ayc.db')
db.execute(f"PRAGMA key='{old_key}'")
db.execute('SELECT count(*) FROM sqlite_master')  # verify old key works
db.execute(f"PRAGMA rekey='{new_key}'")
db.close()
print("Database re-keyed successfully.")
EOF

# 5. Update .env with the new DB_ENCRYPTION_KEY

# 6. Restart and verify
docker compose up -d
# Check logs: docker compose logs -f portal
```

---

## Step 6 — Verify everything works

```bash
# Check the portal starts cleanly
docker compose logs portal | grep -E "ERROR|WARNING|started"

# Confirm health endpoint returns 200
curl http://localhost:5001/api/health
# Expected: {"status": "ok", "version": "v10.1"}

# Log in and confirm sessions work
# Upload and download a test document to verify encryption
```

---

## New .env reference

After rotation, your `.env` should contain:

```env
# Flask
SECRET_KEY=<rotated value>
FLASK_DEBUG=0
SESSION_COOKIE_SECURE=1   # set to 1 only when serving over HTTPS; omit or set to 0 for local HTTP dev

# Database
DB_ENCRYPTION_KEY=<rotated value>

# Documents (NEW — separate from DB key)
DOCUMENT_ENCRYPTION_KEY=<new Fernet key>

# Email
MAIL_HOST=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=<your gmail>
MAIL_PASSWORD=<app password>
MAIL_FROM=<your gmail>

# Postcode lookup
GETADDRESS_KEY=<rotated value>

# Club identity
CLUB_NAME=Ashford Youth Club
CLUB_SHORT_NAME=AYC
```
