'use strict';

/**
 * ProfitPilot AI — Salla Easy Mode webhook endpoint
 * ------------------------------------------------------------------
 * Vercel serverless function:  GET|POST  /api/salla/authorize
 *
 * Salla "Easy Mode" does NOT redirect the merchant's browser to you.
 * Instead, when a merchant installs/authorizes your app on their store,
 * Salla POSTs an `app.store.authorize` event to your registered Webhook URL.
 * That event carries the access_token / refresh_token for that store.
 *
 * Official payload shape (docs.salla.dev → Partners Apps APIs → App Events):
 *   {
 *     "event": "app.store.authorize",
 *     "merchant": 1234509876,
 *     "created_at": "2022-12-31 12:31:25",
 *     "data": {
 *       "access_token": "...",
 *       "expires": 1634819484,
 *       "refresh_token": "...",
 *       "scope": "settings.read orders.read offline_access",
 *       "token_type": "bearer"
 *     }
 *   }
 *
 * Verification: Salla sends your App "Webhook Secret" in the
 * `Authorization` header. (Confirmed against Salla's own
 * @salla.sa/webhooks-actions package, which compares that header
 * directly to the configured secret — it is NOT an HMAC signature.)
 *
 * SCOPE OF THIS FILE (intentionally minimal, phase 1):
 *   - accept + validate, verify sender, log SAFE info only, return 200 fast.
 *   - NO database / token storage yet  <-- added in the next step.
 *   - ZERO npm dependencies (Node built-ins only).
 *   - Never logs or returns access_token, refresh_token, client_secret,
 *     webhook secret, or the raw request body.
 */

const crypto = require('crypto');

// ---------------------------------------------------------------- config ----
const APP_ID = String(process.env.SALLA_APP_ID || '1810469992');
const OAUTH_MODE = String(process.env.SALLA_AUTHORIZATION_MODE || 'easy');
const WEBHOOK_SECRET = String(process.env.SALLA_WEBHOOK_SECRET || '');
const CLIENT_ID = String(process.env.SALLA_OAUTH_CLIENT_ID || '');
const CLIENT_SECRET = String(process.env.SALLA_OAUTH_CLIENT_SECRET || '');
const MAX_BODY_BYTES = 1024 * 1024; // 1 MB is far above any Salla event
const HANDLED_EVENT = 'app.store.authorize';

// ------------------------------------------------------------- utilities ----

/** Send a JSON response without ever echoing request contents back. */
function sendJson(res, status, payload, extraHeaders) {
  const body = JSON.stringify(payload);
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Length', Buffer.byteLength(body));
  // A webhook URL must never be cached or framed.
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (extraHeaders) {
    for (const k of Object.keys(extraHeaders)) res.setHeader(k, extraHeaders[k]);
  }
  res.end(body);
}

/**
 * One-way, non-reversible fingerprint of a secret.
 * Lets us confirm "same token arrived twice" in the logs WITHOUT
 * ever writing any part of the token itself.
 */
function fingerprint(value) {
  if (!value || typeof value !== 'string') return null;
  return crypto.createHash('sha256').update(value).digest('hex').slice(0, 12);
}

/** True when a value looks like a token/secret we must never print. */
function isSecretLike(key) {
  return /(token|secret|password|authorization|credential|api[_-]?key|signature)/i.test(
    String(key)
  );
}

/**
 * Recursively strip secret-like values so an accidental future
 * `log(obj)` can never leak credentials. Values are replaced by
 * a marker; only key NAMES survive.
 */
function redact(value, depth) {
  if (depth === undefined) depth = 0;
  if (depth > 4) return '[max-depth]';
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  if (value && typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value)) {
      out[k] = isSecretLike(k) ? '[REDACTED]' : redact(value[k], depth + 1);
    }
    return out;
  }
  return value;
}

/** Strip control characters from anything we log (log-injection guard). */
function safeText(value, max) {
  const s = String(value === undefined || value === null ? '' : value)
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .trim();
  return s.length > (max || 200) ? s.slice(0, max || 200) + '…' : s;
}

/** Read the raw request body as text, with a hard size cap. */
function readRawBody(req) {
  return new Promise((resolve, reject) => {
    // Some runtimes pre-parse the body. Prefer the raw string if present.
    if (typeof req.body === 'string') return resolve(req.body);
    if (req.body && typeof req.body === 'object') {
      try {
        return resolve(JSON.stringify(req.body));
      } catch (_) {
        /* fall through to stream reading */
      }
    }

    const chunks = [];
    let size = 0;
    let done = false;

    req.on('data', (chunk) => {
      if (done) return;
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        done = true;
        const err = new Error('payload_too_large');
        err.statusCode = 413;
        reject(err);
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (done) return;
      done = true;
      resolve(Buffer.concat(chunks).toString('utf8'));
    });

    req.on('error', (err) => {
      if (done) return;
      done = true;
      reject(err);
    });
  });
}

/**
 * Verify the sender using Salla's scheme: the App Webhook Secret is sent
 * in the `Authorization` header (raw, or as `Bearer <secret>`).
 *
 * Returns: 'ok' | 'invalid' | 'not_configured'
 */
function verifySender(req) {
  if (!WEBHOOK_SECRET) return 'not_configured';

  const header =
    req.headers['authorization'] ||
    req.headers['x-salla-secret'] ||
    req.headers['x-webhook-secret'] ||
    '';

  const provided = String(header).replace(/^Bearer\s+/i, '').trim();

  if (!provided) return 'invalid';

  const a = Buffer.from(provided, 'utf8');
  const b = Buffer.from(WEBHOOK_SECRET, 'utf8');

  // timingSafeEqual throws on length mismatch, so compare lengths first.
  if (a.length !== b.length) return 'invalid';

  return crypto.timingSafeEqual(a, b) ? 'ok' : 'invalid';
}

/** Pull a field from several plausible locations (Salla payload shapes vary). */
function pick(obj, keys) {
  for (const k of keys) {
    if (obj && obj[k] !== undefined && obj[k] !== null) return obj[k];
  }
  return undefined;
}

// ---------------------------------------------------------------- handler ----

module.exports = async function handler(req, res) {
  const method = String(req.method || 'GET').toUpperCase();
  const startedAt = Date.now();

  // Never let an unexpected error surface internals to the caller.
  try {
    // --- CORS preflight -----------------------------------------------------
    if (method === 'OPTIONS') {
      return sendJson(res, 204, {}, { Allow: 'GET, POST, OPTIONS' });
    }

    // --- GET: deployment confirmation (no secrets) -------------------------
    if (method === 'GET') {
      // Only booleans about configuration — never the values themselves.
      return sendJson(res, 200, {
        ok: true,
        endpoint: '/api/salla/authorize',
        method: 'GET',
        purpose: 'Salla Easy Mode webhook receiver',
        app: { id: APP_ID, oauth_mode: OAUTH_MODE },
        configured: {
          webhook_secret: Boolean(WEBHOOK_SECRET),
          client_id: Boolean(CLIENT_ID),
          client_secret: Boolean(CLIENT_SECRET),
        },
        handles_event: HANDLED_EVENT,
        storage_enabled: false, // <-- becomes true in the next phase
        received_at: new Date().toISOString(),
        message:
          'Endpoint is live. POST Salla app.store.authorize events here. ' +
          'Tokens are NOT stored yet (phase 1: receive, verify, log safely).',
      });
    }

    // --- Anything else -------------------------------------------------------
    if (method !== 'POST') {
      return sendJson(
        res,
        405,
        { ok: false, error: 'method_not_allowed', allowed: ['GET', 'POST'] },
        { Allow: 'GET, POST, OPTIONS' }
      );
    }

    // --- Verify the sender BEFORE parsing/trusting anything ------------------
    const auth = verifySender(req);

    if (auth === 'invalid') {
      console.warn(
        `[salla] rejected webhook: invalid Authorization header (app_id=${APP_ID})`
      );

      return sendJson(res, 401, {
        ok: false,
        error: 'unauthorized',
      });
    }

    if (auth === 'not_configured') {
      // Deliberately permissive so you can test before setting the secret.
      // Set SALLA_WEBHOOK_SECRET in Vercel to enforce verification.
      console.warn(
        '[salla] SALLA_WEBHOOK_SECRET is not set — accepting WITHOUT sender verification. ' +
          'Set it in Vercel env vars for production.'
      );
    }

    // --- Read + validate JSON ------------------------------------------------
    const raw = await readRawBody(req);

    if (!raw || !raw.trim()) {
      return sendJson(res, 400, {
        ok: false,
        error: 'empty_body',
      });
    }

    let event;

    try {
      event = JSON.parse(raw);
    } catch (_) {
      // Log the failure WITHOUT the body (the body may contain tokens).
      console.warn('[salla] rejected webhook: malformed JSON body');

      return sendJson(res, 400, {
        ok: false,
        error: 'invalid_json',
      });
    }

    if (!event || typeof event !== 'object' || Array.isArray(event)) {
      return sendJson(res, 400, {
        ok: false,
        error: 'invalid_payload',
      });
    }

    // --- Identify the event ---------------------------------------------------
    const eventName = String(
      pick(event, ['event', 'event_name', 'type', 'name']) ||
        req.headers['x-salla-event'] ||
        ''
    ).trim();

    const merchantId = pick(event, ['merchant', 'merchant_id', 'user_id']);

    const createdAt = pick(event, ['created_at', 'created']);

    const data =
      event.data && typeof event.data === 'object' ? event.data : {};

    const accessToken = pick(data, ['access_token', 'accessToken']);

    const refreshToken = pick(data, ['refresh_token', 'refreshToken']);

    const expires = pick(data, ['expires', 'expires_at', 'expires_in']);

    const scope = pick(data, ['scope', 'scopes', 'app_scopes']);

    const tokenType = pick(data, ['token_type', 'tokenType']);

    const storeId = pick(data, ['id', 'store_id', 'store']);

    // --- SAFE logging only ----------------------------------------------------
    // Key names are logged so you can confirm the real payload shape,
    // but no secret-like VALUE is ever printed.
    console.log(
      '[salla] webhook received',
      JSON.stringify({
        event: safeText(eventName || '(missing)'),

        merchant_id:
          merchantId !== undefined ? String(merchantId) : null,

        store_id:
          storeId !== undefined ? String(storeId) : null,

        scope: scope
          ? safeText(
              Array.isArray(scope) ? scope.join(' ') : scope,
              300
            )
          : null,

        token_type: tokenType
          ? safeText(tokenType, 40)
          : null,

        expires:
          expires !== undefined ? String(expires) : null,

        expires_readable:
          typeof expires === 'number' && expires > 1e9
            ? new Date(
                expires * (expires < 1e11 ? 1000 : 1)
              ).toISOString()
            : null,

        has_access_token: Boolean(accessToken),

        has_refresh_token: Boolean(refreshToken),

        // non-reversible fingerprints — safe to log, useful for dedupe
        access_token_fp: fingerprint(accessToken),

        refresh_token_fp: fingerprint(refreshToken),

        top_level_keys: Object.keys(event).map((k) =>
          safeText(k, 60)
        ),

        data_keys: Object.keys(data).map((k) =>
          safeText(k, 60)
        ),

        created_at: createdAt
          ? safeText(createdAt, 40)
          : null,

        auth: auth,

        app_id: APP_ID,

        bytes: Buffer.byteLength(raw),
      })
    );

    // --- Handle the event we care about ---------------------------------------
    if (eventName !== HANDLED_EVENT) {
      // Acknowledge other events with 200 so Salla does not retry them,
      // but mark them as not handled.
      console.log(
        `[salla] event "${safeText(
          eventName || '(missing)'
        )}" acknowledged but not handled in phase 1`
      );

      return sendJson(res, 200, {
        ok: true,
        received: eventName || null,
        handled: false,
        reason:
          'only app.store.authorize is processed in phase 1',
      });
    }

    if (!accessToken) {
      console.warn(
        '[salla] app.store.authorize arrived WITHOUT an access_token — nothing to do'
      );

      return sendJson(res, 200, {
        ok: true,
        received: HANDLED_EVENT,
        handled: false,
        reason: 'no_access_token_in_payload',
      });
    }

    // =====================================================================
    // TODO (NEXT STEP — secure token storage):
    //   Persist, per merchant/store: access_token (encrypted at rest),
    //   refresh_token (encrypted at rest), expires, scope, store_id,
    //   merchant_id. Then use them to call https://api.salla.dev/admin/v2
    //   with `Authorization: Bearer <access_token>`.
    //
    //   IMPORTANT for Vercel: do the storage work BEFORE sending the
    //   response. The function instance can be frozen/killed right after
    //   `res.end()`, so fire-and-forget async work is not reliable here.
    // =====================================================================

    console.log(
      `[salla] app.store.authorize verified for merchant=${
        merchantId !== undefined
          ? String(merchantId)
          : 'unknown'
      } — token received but NOT stored yet (phase 1)`
    );

    return sendJson(res, 200, {
      ok: true,
      received: HANDLED_EVENT,
      handled: true,
      stored: false, // storage is the next step, by design
      duration_ms: Date.now() - startedAt,
    });

  } catch (err) {
    // Message only — never a stack trace or request contents to the caller.
    const status =
      err && err.statusCode
        ? err.statusCode
        : 500;

    console.error(
      `[salla] webhook handler error: ${safeText(
        err && err.message,
        200
      )}`
    );

    return sendJson(res, status, {
      ok: false,
      error:
        status === 413
          ? 'payload_too_large'
          : 'internal_error',
    });
  }
};

// Exported for the local test harness only (never imported by the browser).
module.exports.__test = {
  redact,
  fingerprint,
  verifySender,
  safeText,
  isSecretLike,
};
