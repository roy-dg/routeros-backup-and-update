// Cloudflare Worker: R2 pre-signed backup-upload gateway for a RouterOS script.
//
// Flow:
//   1. The router sends  GET /presign?device=<name>
//      with header  Authorization: Bearer <ROUTER_SHARED_SECRET>
//   2. This Worker checks the secret, then asks R2's S3-compatible API to
//      sign a short-lived PUT URL for a fresh object key.
//   3. It returns { "url": "...", "key": "...", "expiresIn": 120 }.
//   4. The router PUTs the backup bytes straight to that URL. R2 never sees
//      the shared secret, and the Worker never sees the backup bytes.
//
// A presigned URL can't be revoked early without rotating the whole R2 key
// (which would break every other outstanding URL too) - so PRESIGN_TTL_SECONDS
// is the real "one-shot" mechanism here. Keep it short.
//
// SETUP
//   npm install aws4fetch
//   wrangler secret put ROUTER_SHARED_SECRET   # long random string, must match the router's config
//   wrangler secret put R2_ACCOUNT_ID          # Cloudflare account id
//   wrangler secret put R2_ACCESS_KEY_ID       # R2 API token - scope it to ONLY this bucket, Object Read & Write
//   wrangler secret put R2_SECRET_ACCESS_KEY
//   wrangler secret put R2_BUCKET_NAME
//   wrangler deploy
//
// (PRESIGN_TTL_SECONDS can be a plain var in wrangler.toml since it isn't sensitive.)

import { AwsClient } from "aws4fetch";

const DEFAULT_TTL_SECONDS = 120;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname !== "/presign") {
      return new Response("Not found", { status: 404 });
    }
    if (request.method !== "GET" && request.method !== "POST") {
      return new Response("Method not allowed", { status: 405 });
    }

    const auth = request.headers.get("Authorization") || "";
    if (auth !== `Bearer ${env.ROUTER_SHARED_SECRET}`) {
      return new Response("Unauthorized", { status: 401 });
    }

    const device = (url.searchParams.get("device") || "router").replace(/[^a-zA-Z0-9._-]/g, "_");
    const now = new Date();
    const day = now.toISOString().slice(0, 10);
    const key = `${device}/${day}/${now.getTime()}.backup`;

    const ttl = Number(env.PRESIGN_TTL_SECONDS || DEFAULT_TTL_SECONDS);

    const client = new AwsClient({
      service: "s3",
      region: "auto",
      accessKeyId: env.R2_ACCESS_KEY_ID,
      secretAccessKey: env.R2_SECRET_ACCESS_KEY,
    });

    const objectUrl =
      `https://${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com/` +
      `${env.R2_BUCKET_NAME}/${key}?X-Amz-Expires=${ttl}`;

    // signQuery: true => a presigned URL (signature lives in the query string),
    // not a request the Worker executes itself. Only "host" ends up signed,
    // so the router doesn't need to send any special headers on the PUT.
    const signed = await client.sign(new Request(objectUrl, { method: "PUT" }), {
      aws: { signQuery: true },
    });

    return new Response(JSON.stringify({ url: signed.url, key, expiresIn: ttl }), {
      headers: { "content-type": "application/json" },
    });
  },
};
