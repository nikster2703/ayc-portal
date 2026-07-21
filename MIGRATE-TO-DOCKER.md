# Migrating the live club from bare Python to the prebuilt Docker image

One-off runbook for moving the live instance off `venv + gunicorn` onto the
published GHCR image, so it updates by pulling a version rather than by copying
files across.

**Applies to:** an ARM (aarch64) host currently running the portal from source
at v12.57. After this it runs the prebuilt image, and future updates are two
commands with no source code on the box.

> **Read this first.** The container reads its database from `/data/data/ayc.db`
> — note the **nested** `data` directory, because `INSTANCE_DIR=/data` and the
> app appends `data/`. Seed the volume at the wrong depth and the portal starts
> up with a brand-new empty database and *looks* like it worked.

---

## 0. Prerequisites

- Docker Engine + Compose v2 on the live host (`docker compose version`).
- The **arm64 image must be published first.** The publish workflow was
  amd64-only until now; `linux/arm64` was added in this release. Push to `main`
  (or run the workflow manually), wait for it to finish, then confirm:

  ```sh
  docker manifest inspect ghcr.io/nikster2703/ayc-portal:v12.74 \
    | grep -A2 '"platform"'
  ```

  You want to see `"architecture": "arm64"` in the output. **Do not start the
  migration until this is true** — the arm64 leg cross-builds under QEMU and
  takes noticeably longer than the amd64 one.

---

## 1. Note the current version and stop the service

```sh
# Whatever your service is called
sudo systemctl stop ayc-portal        # or: pkill gunicorn
sudo systemctl disable ayc-portal     # prevent it racing the container on boot
```

Leave the old folder in place — it is the rollback.

---

## 2. Back up the database and secrets

```sh
cd /path/to/old/ayc-portal
tar czf ~/ayc-live-backup-$(date +%F).tar.gz data/ .env
```

Copy that archive **off the host** before continuing.

---

## 3. Create the deploy folder

The host only needs two files. The folder name becomes the Docker project name,
so give it a club-specific name.

```sh
mkdir -p ~/ayc-live && cd ~/ayc-live
# copy docker-compose.deploy.yml from the repo, then:
cp /path/to/old/ayc-portal/.env .
```

**Carry the existing `.env` across verbatim.** These three keys must match the
old install exactly or the data is unreadable:

| Key | Consequence if wrong |
|-----|----------------------|
| `DB_ENCRYPTION_KEY` | SQLCipher cannot open the database at all |
| `DOCUMENT_ENCRYPTION_KEY` | Uploaded documents fail to decrypt |
| `SECRET_KEY` | All existing login sessions are invalidated (cosmetic) |

Pin the version rather than tracking `:latest` — add to `.env`:

```sh
echo 'PORTAL_IMAGE=ghcr.io/nikster2703/ayc-portal:v12.74' >> .env
```

---

## 4. Create the volume (and throw away the empty database it makes)

```sh
docker compose -f docker-compose.deploy.yml pull
docker compose -f docker-compose.deploy.yml up -d
sleep 15
docker compose -f docker-compose.deploy.yml down
```

That first boot creates the named volume and an empty database. The next step
overwrites it with the real data. Find the volume's real name (Compose prefixes
it with the folder name):

```sh
docker volume ls | grep portal-data      # e.g. ayc-live_portal-data
```

---

## 5. Seed the volume with the live data

Set `VOL` to the name from the previous step and `OLD` to the old install path:

```sh
VOL=ayc-live_portal-data
OLD=/path/to/old/ayc-portal

# Work out the uid the container runs as (non-root user 'ayc')
UID_IN=$(docker run --rm ghcr.io/nikster2703/ayc-portal:v12.74 id -u)

docker run --rm \
  -v "$VOL":/dest \
  -v "$OLD/data":/src:ro \
  alpine sh -c "rm -rf /dest/data && mkdir -p /dest/data && \
                cp -a /src/. /dest/data/ && chown -R $UID_IN:$UID_IN /dest"
```

Verify the database landed at the right depth **before** starting:

```sh
docker run --rm -v "$VOL":/data alpine ls -l /data/data/ayc.db
```

If that errors, stop and fix the path — do not start the portal.

---

## 6. Start and verify

```sh
docker compose -f docker-compose.deploy.yml up -d
docker compose -f docker-compose.deploy.yml logs -f
```

This boot also jumps the data from v12.57 to v12.74, which runs two one-time
migrations. Watch the log for both:

- **Staff contact relocation** — look for `staff contact` and the
  `(N skipped for manual review)` count. If N is not 0, those staff records need
  their mobile/email reconciled by hand.
- **Declaration backfill** — only logs if it *failed*
  (`Declaration backfill migration skipped:`).

Both are wrapped in try/except so a failure cannot block boot — which means a
failure is quiet. Actually read the log rather than assuming success.

Then check in the browser:

- [ ] Login works
- [ ] Member count matches the old install
- [ ] A register loads with the right members
- [ ] An uploaded document opens (proves `DOCUMENT_ENCRYPTION_KEY` carried over)
- [ ] The logo and branding appear (proves `data/branding/` came across)
- [ ] `/api/health` returns ok

---

## 7. Point the reverse proxy at it

The container publishes `${PORT:-5001}` on the host, same as before. If Caddy
pointed at the old gunicorn port, either keep `PORT` identical in `.env` (no
proxy change needed) or update the Caddyfile.

> Remember the live Caddyfile is `/opt/homebrew/etc/Caddyfile`, not `~/Caddyfile`.

---

## 8. Decommission the old install

Only after a full session has run cleanly on the container:

```sh
sudo systemctl disable --now ayc-portal
```

Keep the old folder and the backup archive for a few weeks.

---

## Updating from here on

No file copying, no git, no build:

```sh
cd ~/ayc-live
# bump the pinned version in .env, then:
docker compose -f docker-compose.deploy.yml pull
docker compose -f docker-compose.deploy.yml up -d --force-recreate
```

To publish a new version to pull: tag the release so a pinned image is built.

```sh
git tag v12.75 && git push origin v12.75
```

---

## Rollback

The old install is untouched, and the container never writes to it.

```sh
docker compose -f docker-compose.deploy.yml down
sudo systemctl enable --now ayc-portal
```

The only caveat: any data entered *while the container was live* exists solely
in the Docker volume. If you roll back after real use, export from the volume
first:

```sh
docker run --rm -v ayc-live_portal-data:/src:ro -v "$PWD":/out \
  alpine tar czf /out/volume-backup.tar.gz -C /src .
```
