// Cloudflare Worker: R2 pre-signed backup-upload gateway for RouterOS scripts.
// Per-router identity + revocation via D1, presigned R2 PUT URLs via aws4fetch.
//
// RouterOS's /tool fetch can only ever hand a file to an HTTP PUT by first
// reading it into a script variable - and both that read (/file/get contents)
// and the PUT body (http-data) are hard-capped at tens of KB (see the
// companion .rsc script's header). So files are uploaded in small chunks,
// each its own temporary R2 object, and reassembled here server-side where
// none of those router-side limits apply.
//
// ROUTER-FACING
//   GET or POST /presign?ext=<backup|rsc>&base=<name>&part=<n>
//   Header:  X-Router-Auth: <device_id>:<secret>
//   -> 200 { "url": "...", "key": "...", "expiresIn": 120 }
//   -> 401 if the device is unknown, disabled, or the secret doesn't match
//   Presigns a PUT for ONE chunk of the file, stored as a temporary part
//   object under parts/<device_id>/<date>/<base>.<ext>/<part, zero-padded>.
//   Call this once per chunk, right before uploading that chunk - not once
//   up front for the whole file - so a slow multi-chunk upload can never
//   outlive PRESIGN_TTL_SECONDS.
//
//   POST /finalize
//   Header:  X-Router-Auth: <device_id>:<secret>
//   Body:    {"ext": "backup", "base": "<name>", "parts": <count>}
//   -> 200 { "key": "...", "size": <bytes>, "parts": <count> }
//   -> 409 if any expected part object is missing (never assembles a
//      truncated file)
//   Call once after every chunk from a /presign+PUT round has succeeded.
//   Streams the part objects back together in order into the final object
//   at <device_id>/<date>/<base>.<ext>, then best-effort deletes the parts
//   (an R2 lifecycle rule on the parts/ prefix is the backstop for any left
//   behind by a run that dies before calling this).
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
//   3. Add an [[r2_buckets]] binding (env.BUCKET below) to wrangler.toml,
//      pointing at the SAME bucket as the R2_BUCKET_NAME secret - /finalize
//      reads/writes/deletes objects directly, which the presigning
//      credentials alone can't do from inside the Worker.
//   4. wrangler secret put ADMIN_SECRET   (new - keep this OFF every router;
//      it's not the same as any router's own secret)
//   5. Register each router:
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

    if (url.pathname === "/finalize") {
      return handleFinalize(request, env);
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

  const url = new URL(request.url);

  const creds = await authenticateRouter(request, env);
  if (!creds) {
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

  // ext picks the file extension (backup or rsc); unset defaults to "backup"
  // for old callers. base names the file (matches the router's own local
  // basename, e.g. "<identity>-<date>"); part is this chunk's zero-based
  // index within that file - each chunk gets its own temporary part object.
  const requestedExt = url.searchParams.get("ext") || "backup";
  const allowedExts = ["backup", "rsc"];
  if (!allowedExts.includes(requestedExt)) {
    return new Response("Bad request: ext must be one of " + allowedExts.join(", "), { status: 400 });
  }

  const base = url.searchParams.get("base") || "";
  if (!base) {
    return new Response("Bad request: base is required", { status: 400 });
  }

  const part = Number(url.searchParams.get("part"));
  if (!Number.isInteger(part) || part < 0 || part > 999999) {
    return new Response("Bad request: part must be a non-negative integer", { status: 400 });
  }

  // The key is built from the AUTHENTICATED device_id, never from anything
  // client-supplied verbatim - a router can only ever get a presigned URL
  // under its own prefix, and base is sanitized the same way device_id is.
  const key = partKey(creds.deviceId, base, requestedExt, part);
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

// -------------------------------------------------------------- finalize --

async function handleFinalize(request, env) {
  if (request.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  const creds = await authenticateRouter(request, env);
  if (!creds) {
    return new Response("Unauthorized", { status: 401 });
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return new Response("Bad request: expected a JSON body", { status: 400 });
  }

  const ext = body && body.ext;
  const allowedExts = ["backup", "rsc"];
  if (!allowedExts.includes(ext)) {
    return new Response("Bad request: ext must be one of " + allowedExts.join(", "), { status: 400 });
  }

  const base = body && body.base;
  if (!base || typeof base !== "string") {
    return new Response("Bad request: base is required", { status: 400 });
  }

  const parts = body && Number(body.parts);
  if (!Number.isInteger(parts) || parts < 1 || parts > 999999) {
    return new Response("Bad request: parts must be a positive integer", { status: 400 });
  }

  const finalKey = finalObjectKey(creds.deviceId, base, ext);
  const partKeys = [];
  for (let i = 0; i < parts; i++) {
    partKeys.push(partKey(creds.deviceId, base, ext, i));
  }

  // Confirm every part actually made it before assembling anything - never
  // hand back a "success" for a file that's silently missing a chunk.
  let totalSize = 0;
  for (const key of partKeys) {
    const head = await env.BUCKET.head(key);
    if (!head) {
      return new Response(`Conflict: missing part ${key}`, { status: 409 });
    }
    totalSize += head.size;
  }

  // bucket.put() requires a stream of known length - a plain ReadableStream
  // built from N part reads doesn't declare one, so pipe through a
  // FixedLengthStream (we already know totalSize from the head() checks
  // above) while a separate pump concurrently feeds it from each part.
  const { readable, writable } = new FixedLengthStream(totalSize);
  const pumpDone = pumpPartsInto(env.BUCKET, partKeys, writable);
  await Promise.all([env.BUCKET.put(finalKey, readable), pumpDone]);

  // Best-effort cleanup; an R2 lifecycle rule on the parts/ prefix is the
  // backstop for anything a crashed/interrupted run leaves behind.
  await Promise.allSettled(partKeys.map((key) => env.BUCKET.delete(key)));

  return new Response(JSON.stringify({ key: finalKey, size: totalSize, parts }), {
    headers: { "content-type": "application/json" },
  });
}

// Writes R2 part objects into `writable`, in order, without buffering the
// whole file in memory at once.
async function pumpPartsInto(bucket, partKeys, writable) {
  const writer = writable.getWriter();
  try {
    for (const key of partKeys) {
      const obj = await bucket.get(key);
      if (!obj) {
        throw new Error(`part disappeared during assembly: ${key}`);
      }
      await writer.write(new Uint8Array(await obj.arrayBuffer()));
    }
    await writer.close();
  } catch (e) {
    await writer.abort(e);
    throw e;
  }
}

function finalObjectKey(deviceId, base, ext) {
  const safeDeviceId = deviceId.replace(/[^a-zA-Z0-9._-]/g, "_");
  const safeBase = base.replace(/[^a-zA-Z0-9._-]/g, "_");
  const today = new Date().toISOString().slice(0, 10);
  return `${safeDeviceId}/${today}/${safeBase}.${ext}`;
}

// Lives under a top-level "parts/" prefix (rather than nested under the
// final key) specifically so a single R2 lifecycle rule on that prefix can
// clean up orphaned temp parts without ever matching a final backup object -
// R2 lifecycle rules match a literal prefix from the start of the key, and
// device/date vary per router/day, so nesting parts/ under the final key
// would leave no prefix that matches every part but no final object.
function partKey(deviceId, base, ext, part) {
  return `parts/${finalObjectKey(deviceId, base, ext)}/${String(part).padStart(6, "0")}`;
}

// -------------------------------------------------------------------------

// Checks X-Router-Auth against D1 (unknown device, disabled device, or
// wrong secret all fail alike). Returns the parsed {deviceId, secret} creds
// on success, or null.
async function authenticateRouter(request, env) {
  const creds = parseRouterAuth(request);
  if (!creds) return null;

  const row = await env.DB.prepare(
    "SELECT secret_hash, disabled_at FROM routers WHERE device_id = ?"
  ).bind(creds.deviceId).first();

  if (!row || row.disabled_at) return null;

  const suppliedHash = await sha256Hex(creds.secret);
  if (!timingSafeEqualHex(suppliedHash, row.secret_hash)) return null;

  return creds;
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

