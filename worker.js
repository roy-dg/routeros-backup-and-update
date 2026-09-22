// Cloudflare Worker: R2 pre-signed backup-upload gateway for RouterOS scripts.
// Per-router identity + revocation via D1, presigned R2 PUT URLs via aws4fetch.
//
// ROUTER-FACING
//   GET or POST /presign
//   Header:  X-Router-Auth: <device_id>:<secret>
//   -> 200 { "url": "...", "key": "...", "expiresIn": 120 }
//   -> 401 if the device is unknown, disabled, or the secret doesn't match
//
//   This is NOT real HTTP Basic auth. RouterOS's /tool fetch user=/password=
//   params are only confirmed to work for FTP/SFTP - there's a long-standing
//   report of them not sending credentials preemptively for HTTP(S), which
//   would just come back as a silent 401. A single plain header sidesteps
//   that (and needs no base64 support on the router side).
//
// ADMIN-FACING (call from curl, Postman, etc. - never from a router)
//   Header: Authorization: Bearer <ADMIN_SECRET>
//   GET  /admin/routers                     -> list routers (no secrets returned)
//   POST /admin/routers {device_id, label}  -> create, or rotate an existing
//                                              device's secret; returns the
//                                              new secret ONCE
//   POST /admin/routers/:id/disable         -> revoke. Blocks new presigns
//                                              immediately; a presigned URL
//                                              already handed out in the last
//                                              PRESIGN_TTL_SECONDS still works
//                                              until it expires - R2 doesn't
//                                              re-check D1 at PUT time.
//   POST /admin/routers/:id/enable          -> re-enable
//
// D1: one "routers" table, see schema.sql. secret_hash is SHA-256 of the
// router's secret - the plaintext is never stored, only ever returned once
// at creation/rotation time.
//
// SETUP (in addition to the original single-secret setup)
//   1. Create a D1 database (dashboard: Storage & databases > D1 > Create
//      database, or `wrangler d1 create <name>`), then put its database_id
//      into wrangler.toml's [[d1_databases]] block.
//   2. Run schema.sql against it: the D1 dashboard's Console/Query tab, or
//      `wrangler d1 execute <name> --remote --file=schema.sql`.
//   3. wrangler secret put ADMIN_SECRET   (new - keep this OFF every router;
//      it's not the same as any router's own secret)
//   4. Register each router:
//        curl -X POST https://<worker-url>/admin/routers \
//          -H "Authorization: Bearer <ADMIN_SECRET>" \
//          -H "Content-Type: application/json" \
//          -d '{"device_id":"home-router","label":"Home router"}'
//      -> returns {"device_id":"home-router","secret":"...",...} once. Store
//      that secret on the matching router with:
//        $SECRET "set" "R2_BACKUP_SECRET" password="<the secret>"
//
// ROUTER_SHARED_SECRET is gone - there is no single shared secret anymore.
// Every router has its own row in D1 instead.

import { AwsClient } from "aws4fetch";

const PRESIGN_TTL_DEFAULT = 120;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/presign") {
      return handlePresign(request, env);
    }

    if (url.pathname.startsWith("/admin/")) {
      const authHeader = request.headers.get("Authorization") || "";
      if (authHeader !== `Bearer ${env.ADMIN_SECRET}`) {
        return new Response("Unauthorized", { status: 401 });
      }
      return handleAdmin(request, env, url);
    }

    return new Response("Not found", { status: 404 });
  },
};

// ---------------------------------------------------------------- presign --

async function handlePresign(request, env) {
  if (request.method !== "GET" && request.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  const creds = parseRouterAuth(request);
  if (!creds) {
    return new Response("Unauthorized", { status: 401 });
  }

  const row = await env.DB.prepare(
    "SELECT secret_hash, disabled_at FROM routers WHERE device_id = ?"
  ).bind(creds.deviceId).first();

  if (!row || row.disabled_at) {
    return new Response("Unauthorized", { status: 401 });
  }

  const suppliedHash = await sha256Hex(creds.secret);
  if (!timingSafeEqualHex(suppliedHash, row.secret_hash)) {
    return new Response("Unauthorized", { status: 401 });
  }

  // Best-effort - a failed write here shouldn't block the backup itself.
  try {
    await env.DB.prepare(
      "UPDATE routers SET last_seen_at = ? WHERE device_id = ?"
    ).bind(new Date().toISOString(), creds.deviceId).run();
  } catch (e) {
    // ignore
  }

  // The key is built from the AUTHENTICATED device_id, never from anything
  // client-supplied - a router can only ever get a presigned URL under its
  // own prefix. ext picks the file extension (backup or rsc) so the router
  // can request a presigned URL for either its binary backup or its plain
  // config export; unset ext defaults to "backup" for old callers.
  const requestedExt = url.searchParams.get("ext") || "backup";
  const allowedExts = ["backup", "rsc"];
  if (!allowedExts.includes(requestedExt)) {
    return new Response("Bad request: ext must be one of " + allowedExts.join(", "), { status: 400 });
  }

  const safeDeviceId = creds.deviceId.replace(/[^a-zA-Z0-9._-]/g, "_");
  const now = new Date();
  const key = `${safeDeviceId}/${now.toISOString().slice(0, 10)}/${now.getTime()}.${requestedExt}`;
  const ttl = Number(env.PRESIGN_TTL_SECONDS || PRESIGN_TTL_DEFAULT);

  const client = new AwsClient({
    service: "s3",
    region: "auto",
    accessKeyId: env.R2_ACCESS_KEY_ID,
    secretAccessKey: env.R2_SECRET_ACCESS_KEY,
  });

  const objectUrl =
    `https://${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com/` +
    `${env.R2_BUCKET_NAME}/${key}?X-Amz-Expires=${ttl}`;

  const signed = await client.sign(new Request(objectUrl, { method: "PUT" }), {
    aws: { signQuery: true },
  });

  return new Response(JSON.stringify({ url: signed.url, key, expiresIn: ttl }), {
    headers: { "content-type": "application/json" },
  });
}

function parseRouterAuth(request) {
  const header = request.headers.get("X-Router-Auth") || "";
  const sep = header.indexOf(":");
  if (sep === -1) return null;
  const deviceId = header.slice(0, sep);
  const secret = header.slice(sep + 1);
  if (!deviceId || !secret) return null;
  return { deviceId, secret };
}

// ------------------------------------------------------------------ admin --

async function handleAdmin(request, env, url) {
  if (url.pathname === "/admin/routers" && request.method === "GET") {
    return listRouters(env);
  }
  if (url.pathname === "/admin/routers" && request.method === "POST") {
    return addOrRotateRouter(request, env);
  }
  const disableMatch = url.pathname.match(/^\/admin\/routers\/([^/]+)\/disable$/);
  if (disableMatch && request.method === "POST") {
    return setDisabled(env, decodeURIComponent(disableMatch[1]), true);
  }
  const enableMatch = url.pathname.match(/^\/admin\/routers\/([^/]+)\/enable$/);
  if (enableMatch && request.method === "POST") {
    return setDisabled(env, decodeURIComponent(enableMatch[1]), false);
  }
  return new Response("Not found", { status: 404 });
}

async function listRouters(env) {
  const { results } = await env.DB.prepare(
    "SELECT device_id, label, created_at, disabled_at, last_seen_at FROM routers ORDER BY device_id"
  ).all();
  return new Response(JSON.stringify(results), { headers: { "content-type": "application/json" } });
}

async function addOrRotateRouter(request, env) {
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return new Response("Bad request: expected a JSON body", { status: 400 });
  }

  const deviceId = body && body.device_id ? String(body.device_id).trim() : "";
  if (!deviceId) {
    return new Response("Bad request: device_id is required", { status: 400 });
  }
  const label = body && body.label ? String(body.label) : null;

  const secret = randomHex(32);
  const secretHash = await sha256Hex(secret);
  const now = new Date().toISOString();

  await env.DB.prepare(
    `INSERT INTO routers (device_id, secret_hash, label, created_at, disabled_at, last_seen_at)
     VALUES (?, ?, ?, ?, NULL, NULL)
     ON CONFLICT(device_id) DO UPDATE SET
       secret_hash = excluded.secret_hash,
       label = excluded.label,
       disabled_at = NULL`
  ).bind(deviceId, secretHash, label, now).run();

  return new Response(JSON.stringify({
    device_id: deviceId,
    secret,
    note: "this secret is shown once - store it on the router now, e.g. via " +
      "$SECRET \"set\" \"R2_BACKUP_SECRET\" password=\"...\"",
  }), { headers: { "content-type": "application/json" } });
}

async function setDisabled(env, deviceId, disabled) {
  const value = disabled ? new Date().toISOString() : null;
  const result = await env.DB.prepare(
    "UPDATE routers SET disabled_at = ? WHERE device_id = ?"
  ).bind(value, deviceId).run();

  if (!result.meta || result.meta.changes === 0) {
    return new Response("Not found", { status: 404 });
  }
  return new Response(JSON.stringify({ device_id: deviceId, disabled }), {
    headers: { "content-type": "application/json" },
  });
}

// ----------------------------------------------------------------- crypto --

async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomHex(byteLength) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

