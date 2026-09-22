# mt-backup

Cloudflare Worker that gives RouterOS devices a short-lived, pre-signed R2
upload URL for their backup files, without ever handing a router your R2
credentials. Each router has its own revocable identity, tracked in D1.

## How it works

RouterOS's `/tool fetch` can only ever hand a file to an HTTP PUT by first
reading it into a script variable - and both that read and the PUT body are
hard-capped at tens of KB (see the companion `.rsc` script's header for the
exact limits). So files are uploaded in small chunks, each its own
temporary R2 object, and reassembled by the Worker where none of those
router-side limits apply:

1. For each chunk, the router sends `GET /presign?ext=<backup|rsc>&base=<name>&part=<n>`
   with header `X-Router-Auth: <device_id>:<secret>`. `ext` picks the file
   extension, `base` names the file (matches the router's own local
   basename), and `part` is that chunk's zero-based index.
2. The Worker looks up `device_id` in D1, checks it isn't disabled, and
   verifies the secret against its stored hash.
3. It asks R2's S3-compatible API to sign a short-lived `PUT` URL for a
   temporary part object (`<device_id>/<date>/<base>.<ext>/parts/<n>`).
4. It returns `{ "url": "...", "key": "...", "expiresIn": 120 }`.
5. The router `PUT`s that one chunk's bytes straight to that URL, and
   repeats steps 1-5 for every remaining chunk - one presign per chunk,
   requested right before it's needed, so a slow multi-chunk upload can
   never outlive `PRESIGN_TTL_SECONDS`.
6. Once every chunk has uploaded, the router sends
   `POST /finalize {"ext", "base", "parts": <count>}`. The Worker checks
   every expected part object actually exists (never assembling a
   truncated file), streams them together in order into the final object
   at `<device_id>/<date>/<base>.<ext>`, and best-effort deletes the parts.

R2 never sees the router's secret, and the Worker never sees a chunk's
contents at PUT time (only when it reassembles them, entirely inside
Cloudflare). An R2 lifecycle rule on the `.../parts/` prefix (set this up
once in the dashboard) cleans up any leftover parts from a run that died
before calling `/finalize`.

A presigned URL can't be revoked early - disabling a router in D1 blocks
new presigns immediately, but a URL already handed out keeps working until
it expires - so `PRESIGN_TTL_SECONDS` is the real "one-shot" mechanism here.
Keep it short.

`X-Router-Auth` is used instead of HTTP Basic auth because RouterOS's
`/tool fetch` `user=`/`password=` params aren't confirmed to send
credentials preemptively over HTTP(S) (only FTP/SFTP) - a plain header
sidesteps that and needs no base64 support on the router.

## Admin API

Call these yourself (curl, Postman, etc.) - never from a router. All admin
routes require `Authorization: Bearer <ADMIN_SECRET>`.

| Route | Method | Purpose |
| --- | --- | --- |
| `/admin/routers` | GET | List routers (no secrets returned) |
| `/admin/routers` | POST | Register a new router, or rotate an existing one's secret. Body: `{"device_id": "...", "label": "..."}`. Returns the new secret once. |
| `/admin/routers/:id/disable` | POST | Revoke a router |
| `/admin/routers/:id/enable` | POST | Re-enable a router |

Example - register a router:

```sh
curl -X POST https://<worker-url>/admin/routers \
  -H "Authorization: Bearer <ADMIN_SECRET>" \
  -H "Content-Type: application/json" \
  -d '{"device_id":"home-router","label":"Home router"}'
```

Store the returned secret on the matching router (see the companion
RouterOS scripts below).

## Setup

```sh
npm install
wrangler secret put ADMIN_SECRET           # long random string, used only for the admin API above
wrangler secret put R2_ACCOUNT_ID          # Cloudflare account id
wrangler secret put R2_ACCESS_KEY_ID       # R2 API token - scope it to ONLY this bucket, Object Read & Write
wrangler secret put R2_SECRET_ACCESS_KEY
wrangler secret put R2_BUCKET_NAME
```

Then create the D1 database and point `wrangler.toml` at it:

```sh
wrangler d1 create mt-backup
# paste the returned database_id into wrangler.toml's [[d1_databases]] block
wrangler d1 execute mt-backup --remote --file=schema.sql
wrangler deploy
```

`PRESIGN_TTL_SECONDS` is not sensitive, so it's set as a plain var in
`wrangler.toml` (defaults to `120`). The D1 `database_id`, and the
`[[r2_buckets]]` `bucket_name` used by `/finalize`, are likewise not
sensitive and are fine to commit - just fill in your actual bucket name
(same bucket as the `R2_BUCKET_NAME` secret) before deploying.

Finally, add an R2 lifecycle rule on your bucket (dashboard: your bucket >
Settings > Object lifecycle rules) that deletes objects under the
`parts/` path segment after a day or so. That's the backstop for temporary
chunk objects left behind by a run that fails before calling `/finalize` -
harmless either way, since `/finalize` only ever assembles from parts it
confirms exist, but there's no reason to keep them around.

## Requirements

- A [Cloudflare account](https://dash.cloudflare.com/) with R2 and D1
  enabled, and an R2 bucket created for backups.
- [`wrangler`](https://developers.cloudflare.com/workers/wrangler/) installed
  and authenticated (`wrangler login`).
- An R2 API token scoped to only the backup bucket, with Object Read & Write
  permission.

## RouterOS side

This repo includes two companion RouterOS scripts (not deployed to
Cloudflare - see `.wranglerignore` - but kept here for version control):

- `secret-vault.rsc` - defines a `$SECRET` helper that keeps credentials
  out of script text and off-router backups. Deploy and schedule this
  first; see its header for setup.
- `routeros-delayed-update.rsc` - the delayed-update-with-backup logic
  described below.

### What `routeros-delayed-update.rsc` does

Run it on a schedule (e.g. once a day, via RouterOS's own scheduler). Each
run:

1. **Checks for a RouterOS update** on the configured channel
   (`stable` by default).
2. **Delays installing it** until the release has been publicly available
   for at least `$MinDaysSinceRelease` days (30 by default) - release age
   is read from MikroTik's own CHANGELOG file, since RouterOS itself
   doesn't expose a release date. If the changelog can't be fetched or
   parsed, the script fails safe and skips installing that run rather than
   guessing.
3. **Backs up before doing anything else.** By default, a backup only
   happens right before installing an update; set `$AlwaysBackup=true` to
   also back up (and upload) on every run, update or not, so there's
   always a recent backup on R2. Each backup run creates and uploads
   *both* a binary `.backup` (full config, restorable in one step) and a
   plain-text `.rsc` export (`/export`, easy to read/diff), each uploaded
   in small chunks via this repo's Worker (see "How it works" above) so
   file size is never limited by RouterOS's own read/PUT-body ceilings.
   The `.rsc` export masks `$SECRET`-vault passwords by default - set
   `$ExportShowSensitive=true` only if you understand and accept a
   plaintext-secrets export. Every chunk's read is re-checked against the
   chunk size the script asked for, and the Worker re-checks every part
   object exists before assembling the final file, so a short/empty read
   or a chunk that never arrives never silently produces a truncated
   backup. By default (`RequireBackupBeforeUpdate=true`), an update is
   skipped for that run unless both files uploaded successfully.
4. **Installs the update.** `/system/package/update/install` reboots the
   router automatically once the download finishes.
5. **Upgrades RouterBOARD firmware after reboot, if needed.** The script
   self-provisions a `start-time=startup` scheduler task that checks for a
   pending RouterBOARD firmware upgrade and reboots once more to apply it.

**Authentication**: each router authenticates to the Worker as
`X-Router-Auth: <device_id>:<secret>` - the router's identity
(`/system/identity`) paired with a per-router secret. The Worker checks
that pair against D1 before signing anything, so a compromised router can
be revoked individually (see Admin API above) without affecting others or
rotating anything shared.

**Where secrets live**: nothing sensitive is hardcoded in the script.
- On the **router**, this router's own R2 credential (and, optionally, a
  backup-encryption password) live in the `$SECRET` vault provided by
  `secret-vault.rsc`, not in script text.
- On **Cloudflare**, the Worker's own secrets (`ADMIN_SECRET`,
  R2 account id/access key/secret key/bucket name) are `wrangler secret`
  env vars - see Setup above. The router never sees these; it only ever
  gets a presigned URL back.

Each router needs its own credential registered with the Worker (see
Admin API above) before it can back anything up; the registered
`device_id` must match the router's identity. See the header of
`routeros-delayed-update.rsc` for exact setup steps.
