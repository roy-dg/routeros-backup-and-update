# mt-backup

Cloudflare Worker that gives RouterOS devices a short-lived, pre-signed R2
upload URL for their backup files, without ever handing a router your R2
credentials. Each router has its own revocable identity, tracked in D1.

## How it works

1. The router sends `GET /presign` with header
   `X-Router-Auth: <device_id>:<secret>`.
2. The Worker looks up `device_id` in D1, checks it isn't disabled, and
   verifies the secret against its stored hash.
3. It asks R2's S3-compatible API to sign a short-lived `PUT` URL for a
   fresh object key (`<device_id>/<date>/<ts>.backup`).
4. It returns `{ "url": "...", "key": "...", "expiresIn": 120 }`.
5. The router `PUT`s the backup bytes straight to that URL. R2 never sees
   the router's secret, and the Worker never sees the backup bytes.

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
`wrangler.toml` (defaults to `120`). The D1 `database_id` is likewise not
sensitive and is fine to commit.

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
- `routeros-delayed-update.rsc` - checks for a RouterOS update, waits for
  it to have been publicly available for a configurable number of days,
  takes a pre-update backup and uploads it via this Worker's presigned URL,
  installs the update, and upgrades RouterBOARD firmware if needed.

Each router needs its own credential registered with the Worker (see
Admin API above) before it can back anything up; the registered
`device_id` must match the router's identity. See the header of
`routeros-delayed-update.rsc` for exact setup steps.
