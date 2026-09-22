# mt-backup

Cloudflare Worker that gives a RouterOS device a short-lived, pre-signed R2
upload URL for its backup file, without ever handing the router your R2
credentials.

## How it works

1. The router sends `GET /presign?device=<name>` with header
   `Authorization: Bearer <ROUTER_SHARED_SECRET>`.
2. The Worker validates the secret, then asks R2's S3-compatible API to sign
   a short-lived `PUT` URL for a fresh object key (`<device>/<date>/<ts>.backup`).
3. It returns `{ "url": "...", "key": "...", "expiresIn": 120 }`.
4. The router `PUT`s the backup bytes straight to that URL. R2 never sees the
   shared secret, and the Worker never sees the backup bytes.

A presigned URL can't be revoked early without rotating the whole R2 key
(which would break every other outstanding URL too), so `PRESIGN_TTL_SECONDS`
is the real "one-shot" mechanism here — keep it short.

## Setup

```sh
npm install
wrangler secret put ROUTER_SHARED_SECRET   # long random string, must match the router's config
wrangler secret put R2_ACCOUNT_ID          # Cloudflare account id
wrangler secret put R2_ACCESS_KEY_ID       # R2 API token - scope it to ONLY this bucket, Object Read & Write
wrangler secret put R2_SECRET_ACCESS_KEY
wrangler secret put R2_BUCKET_NAME
wrangler deploy
```

`PRESIGN_TTL_SECONDS` is not sensitive, so it's set as a plain var in
`wrangler.toml` (defaults to `120`).

## Requirements

- A [Cloudflare account](https://dash.cloudflare.com/) with R2 enabled and a
  bucket created for backups.
- [`wrangler`](https://developers.cloudflare.com/workers/wrangler/) installed
  and authenticated (`wrangler login`).
- An R2 API token scoped to only the backup bucket, with Object Read & Write
  permission.

## RouterOS side

Configure the router to:

1. `GET https://<worker-url>/presign?device=<name>` with the
   `Authorization: Bearer <ROUTER_SHARED_SECRET>` header.
2. `PUT` the backup file to the returned `url` before `expiresIn` seconds
   elapse.
