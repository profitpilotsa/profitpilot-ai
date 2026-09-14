'use strict';

/**
 * ProfitPilot AI — Supabase SERVER-ONLY configuration + zero-dependency client
 * =============================================================================
 * Lives OUTSIDE /api on purpose: Vercel turns every file in /api into a public
 * function, but happily traces `require('../server/...')` from inside one.
 *
 * Design rules enforced here:
 *   - NO hard-coded keys or URLs. Everything comes from process.env.
 *   - SUPABASE_SECRET_KEY (sb_secret_…, RLS-bypassing) is server-only.
 *   - SUPABASE_PUBLISHABLE_KEY (sb_publishable_…, RLS-enforced) is the only key
 *     that may ever reach the browser — and only via /api/config.
 *   - PLATFORM-INDEPENDENT: nothing here is Salla-specific. Commerce platforms
 *     are just a `provider` string ('salla' today; 'zid', 'shopify', … later).
 *   - ZERO dependencies: uses Node's built-in crypto and global fetch (Node 18+).
 */

const crypto = require('crypto');

// ------------------------------------------------------------------- env ----

const ENV_URL = 'SUPABASE_URL';
const ENV_PUBLISHABLE = 'SUPABASE_PUBLISHABLE_KEY';
const ENV_SECRET = 'SUPABASE_SECRET_KEY';

function clean(value) {
  return String(value === undefined || value === null ? '' : value).trim();
}

/** Read the three env vars. Never throws; callers decide what to do. */
function readEnv() {
  const url = clean(process.env[ENV_URL]).replace(/\/+$/, '');
  return {
    url,
    publishableKey: clean(process.env[ENV_PUBLISHABLE]),
    secretKey: clean(process.env[ENV_SECRET]),
  };
}

// ------------------------------------------------------- key safety tools ----

/** Decode ONLY the `role` claim of a legacy JWT key. Never returns the token. */
function legacyJwtRole(key) {
  try {
    const parts = String(key).split('.');
    if (parts.length !== 3) return null;

    const payload = JSON.parse(
      Buffer.from(parts[1], 'base64').toString('utf8')
    );

    return typeof payload.role === 'string' ? payload.role : null;
  } catch (_) {
    return null;
  }
}

/**
 * Classify a key so we can catch the classic misconfiguration
 * (a secret key pasted into the publishable variable).
 *
 * -> 'secret'
 * -> 'publishable'
 * -> 'legacy-service-role'
 * -> 'legacy-anon'
 * -> 'unknown'
 * -> 'missing'
 */
function classifyKey(key) {
  const k = clean(key);

  if (!k) return 'missing';
  if (k.startsWith('sb_secret_')) return 'secret';
  if (k.startsWith('sb_publishable_')) return 'publishable';

  const role = legacyJwtRole(k);

  if (role === 'service_role') return 'legacy-service-role';
  if (role === 'anon') return 'legacy-anon';

  return 'unknown';
}

/** True for keys that bypass Row Level Security. */
function isPrivilegedKey(key) {
  const t = classifyKey(key);

  return t === 'secret' || t === 'legacy-service-role';
}

/**
 * Non-reversible description of a key.
 * Reveals type + length + fingerprint, NEVER the actual key.
 */
function describeKey(key) {
  const k = clean(key);

  if (!k) {
    return {
      present: false,
      type: 'missing',
      length: 0,
      fingerprint: null,
    };
  }

  return {
    present: true,
    type: classifyKey(k),
    length: k.length,
    fingerprint: crypto
      .createHash('sha256')
      .update(k)
      .digest('hex')
      .slice(0, 8),
  };
}

/** Replace any key-looking value inside a string. */
function scrubSecrets(text) {
  return String(text)
    .replace(
      /sb_secret_[A-Za-z0-9_-]+/g,
      'sb_secret_[REDACTED]'
    )
    .replace(
      /sb_publishable_[A-Za-z0-9_-]+/g,
      'sb_publishable_[REDACTED]'
    )
    .replace(
      /eyJ[A-Za-z0-9_+/=-]{4,}\.[A-Za-z0-9_+/=-]{2,}\.[A-Za-z0-9_+/=-]{2,}/g,
      '[JWT_REDACTED]'
    );
}

// ------------------------------------------------------------ browser guard ----

/** Hard-fail if this module is somehow evaluated in a browser bundle. */
function assertServerContext(context) {
  if (
    typeof window !== 'undefined' ||
    typeof document !== 'undefined'
  ) {
    throw new Error(
      'supabase_server_only: this module must never be imported by browser code. ' +
        'Use /api/config + lib/supabase-browser.js (publishable key only) instead.'
    );
  }

  return context;
}

// ------------------------------------------------------------ validation ----

/** Validate SUPABASE_URL and derive the project ref. */
function inspectUrl(url) {
  const u = clean(url);

  if (!u) {
    return {
      present: false,
      valid: false,
      project_ref: null,
      host: null,
      error: 'SUPABASE_URL is not set',
    };
  }

  let parsed;

  try {
    parsed = new URL(u);
  } catch (_) {
    return {
      present: true,
      valid: false,
      project_ref: null,
      host: null,
      error: 'SUPABASE_URL is not a valid URL',
    };
  }

  if (parsed.protocol !== 'https:') {
    return {
      present: true,
      valid: false,
      project_ref: null,
      host: parsed.hostname,
      error: 'SUPABASE_URL must use https://',
    };
  }

  const host = parsed.hostname;

  const projectRef = host.endsWith('.supabase.co')
    ? host.split('.')[0]
    : null;

  return {
    present: true,
    valid: true,
    project_ref: projectRef,
    host,
    error: null,
  };
}

/**
 * Full configuration report.
 * Contains NO key values, only presence/type/fingerprint.
 */
function getConfigReport() {
  const env = readEnv();

  const urlInfo = inspectUrl(env.url);
  const secret = describeKey(env.secretKey);
  const publishable = describeKey(env.publishableKey);

  const warnings = [];

  if (urlInfo.error) {
    warnings.push(urlInfo.error);
  }

  if (!secret.present) {
    warnings.push(
      ENV_SECRET +
        ' is not set (privileged server access unavailable)'
    );
  }

  if (!publishable.present) {
    warnings.push(
      ENV_PUBLISHABLE +
        ' is not set (browser access unavailable)'
    );
  }

  if (
    publishable.present &&
    isPrivilegedKey(env.publishableKey)
  ) {
    warnings.push(
      'DANGER: ' +
        ENV_PUBLISHABLE +
        ' holds a PRIVILEGED (RLS-bypassing) key. ' +
        'It would be served to browsers by /api/config — replace it with an sb_publishable_ key.'
    );
  }

  if (
    secret.present &&
    classifyKey(env.secretKey) === 'publishable'
  ) {
    warnings.push(
      ENV_SECRET +
        ' holds a publishable key; privileged operations will be blocked by RLS.'
    );
  }

  if (
    secret.type === 'legacy-service-role' ||
    publishable.type === 'legacy-anon'
  ) {
    warnings.push(
      'Legacy JWT key detected. Supabase deprecates anon/service_role by end of 2026 — migrate to sb_publishable_/sb_secret_.'
    );
  }

  return {
    url: urlInfo,
    keys: {
      secret,
      publishable,
    },

    server_ready: Boolean(
      urlInfo.valid &&
        secret.present &&
        isPrivilegedKey(env.secretKey)
    ),

    browser_ready: Boolean(
      urlInfo.valid &&
        publishable.present &&
        !isPrivilegedKey(env.publishableKey)
    ),

    warnings,
  };
}

// ------------------------------------------------------ zero-dep REST core ----

function assertFetch() {
  if (typeof fetch !== 'function') {
    throw new Error(
      'global fetch is unavailable — Supabase client needs Node 18+ (Vercel Node runtime provides it).'
    );
  }
}

/** Build a PostgREST query string. */
function buildQuery(opts) {
  const params = new URLSearchParams();

  if (opts.select) {
    params.set('select', opts.select);
  }

  if (Array.isArray(opts.filters)) {
    for (const f of opts.filters) {
      if (!f || !f.column) continue;

      const op = f.op || 'eq';

      const value = Array.isArray(f.value)
        ? '(' + f.value.join(',') + ')'
        : String(f.value);

      params.append(
        f.column,
        op + '.' + value
      );
    }
  }

  if (opts.order) {
    params.set('order', opts.order);
  }

  if (
    opts.limit !== undefined &&
    opts.limit !== null
  ) {
    params.set('limit', String(opts.limit));
  }

  if (
    opts.offset !== undefined &&
    opts.offset !== null
  ) {
    params.set('offset', String(opts.offset));
  }

  const qs = params.toString();

  return qs ? '?' + qs : '';
}

function preferHeader(opts, method) {
  const parts = [];

  if (opts.upsert) {
    parts.push('resolution=merge-duplicates');
  }

  if (
    method !== 'GET' &&
    method !== 'HEAD'
  ) {
    parts.push('return=representation');
  }

  return parts.length
    ? parts.join(',')
    : undefined;
}

/**
 * One authenticated request against the Supabase REST gateway.
 */
async function restRequest(path, opts) {
  assertServerContext();
  assertFetch();

  const o = opts || {};

  const env = readEnv();
  const urlInfo = inspectUrl(env.url);

  if (!urlInfo.valid) {
    const err = new Error(
      urlInfo.error || 'SUPABASE_URL invalid'
    );

    err.code = 'supabase_config';

    throw err;
  }

  const slot =
    o.keySlot === 'publishable'
      ? 'publishable'
      : 'secret';

  const key =
    slot === 'publishable'
      ? env.publishableKey
      : env.secretKey;

  if (!key) {
    const err = new Error(
      'missing_key: ' +
        (
          slot === 'publishable'
            ? ENV_PUBLISHABLE
            : ENV_SECRET
        ) +
        ' is not set'
    );

    err.code = 'missing_key';

    throw err;
  }

  if (
    slot === 'publishable' &&
    isPrivilegedKey(key)
  ) {
    const err = new Error(
      'refused: a privileged key was supplied for a publishable-slot request'
    );

    err.code = 'key_misuse';

    throw err;
  }

  const method =
    (o.method || 'GET').toUpperCase();

  const endpoint =
    env.url +
    path +
    (o.query
      ? buildQuery(o.query)
      : '');

  const headers = {
    apikey: key,

    Authorization:
      'Bearer ' + key,

    Accept:
      o.single
        ? 'application/vnd.pgrst.object+json'
        : 'application/json',
  };

  const prefer =
    preferHeader(o, method);

  if (prefer) {
    headers.Prefer = prefer;
  }

  if (o.body !== undefined) {
    headers['Content-Type'] =
      'application/json';
  }

  const startedAt = Date.now();

  let res;

  try {
    res = await fetch(endpoint, {
      method,
      headers,
      body:
        o.body === undefined
          ? undefined
          : JSON.stringify(o.body),
    });
  } catch (networkErr) {
    const err = new Error(
      'network: ' +
        scrubSecrets(
          networkErr &&
            networkErr.message
        )
    );

    err.code = 'network';
    err.ms =
      Date.now() - startedAt;

    throw err;
  }

  const text = await res.text();

  let data = null;

  if (text) {
    try {
      data = JSON.parse(text);
    } catch (_) {
      data = {
        raw_length: text.length,
      };
    }
  }

  if (!res.ok) {
    const err = new Error(
      'supabase_http_' +
        res.status +
        ': ' +
        scrubSecrets(
          (data &&
            (
              data.message ||
              data.error
            )) ||
            res.statusText
        )
    );

    err.code =
      (data && data.code) ||
      'http_' + res.status;

    err.status = res.status;

    err.ms =
      Date.now() - startedAt;

    throw err;
  }

  return {
    status: res.status,
    data,
    ms:
      Date.now() - startedAt,
  };
}

// --------------------------------------------------------- admin client ----

/**
 * Privileged server-side data access.
 */
function createAdminClient() {
  assertServerContext();

  return {
    /** Connectivity probe that works with zero tables. */
    async probe(keySlot) {
      const slot =
        keySlot || 'secret';

      const out = {};

      const t0 = Date.now();

      try {
        await restRequest(
          '/auth/v1/health',
          {
            keySlot: slot,
          }
        );

        out.auth = {
          ok: true,
        };
      } catch (e) {
        out.auth = {
          ok: false,
          code:
            e.code || 'error',
          status:
            e.status || null,
          message:
            e.message,
        };
      }

      try {
        const r =
          await restRequest(
            '/rest/v1/',
            {
              keySlot: slot,
            }
          );

        out.postgrest = {
          ok: true,
          status: r.status,
          ms: r.ms,
        };
      } catch (e) {
        out.postgrest = {
          ok: false,
          code:
            e.code || 'error',
          status:
            e.status || null,
          message:
            e.message,
        };
      }

      out.ms =
        Date.now() - t0;

      out.key_slot = slot;

      out.key =
        describeKey(
          slot === 'publishable'
            ? readEnv().publishableKey
            : readEnv().secretKey
        );

      out.connected =
        Boolean(
          out.auth.ok &&
            out.postgrest.ok
        );

      return out;
    },

    async select(table, opts) {
      const o = opts || {};

      const r =
        await restRequest(
          '/rest/v1/' +
            encodeURIComponent(table),
          {
            method: 'GET',
            keySlot:
              o.keySlot ||
              'secret',
            single:
              Boolean(o.single),

            query: {
              select:
                o.select || '*',

              filters:
                o.filters,

              order:
                o.order,

              limit:
                o.limit,

              offset:
                o.offset,
            },
          }
        );

      return r.data;
    },

    async insert(
      table,
      rows,
      opts
    ) {
      const o = opts || {};

      const r =
        await restRequest(
          '/rest/v1/' +
            encodeURIComponent(table),
          {
            method: 'POST',
            keySlot:
              o.keySlot ||
              'secret',
            body: rows,
          }
        );

      return r.data;
    },

    async upsert(
      table,
      rows,
      opts
    ) {
      const o = opts || {};

      const r =
        await restRequest(
          '/rest/v1/' +
            encodeURIComponent(table),
          {
            method: 'POST',
            keySlot:
              o.keySlot ||
              'secret',
            upsert: true,
            body: rows,
          }
        );

      return r.data;
    },

    async update(
      table,
      patch,
      opts
    ) {
      const o = opts || {};

      if (
        !o.filters ||
        !o.filters.length
      ) {
        throw new Error(
          'refusing to UPDATE without filters (would touch every row)'
        );
      }

      const r =
        await restRequest(
          '/rest/v1/' +
            encodeURIComponent(table),
          {
            method: 'PATCH',
            keySlot:
              o.keySlot ||
              'secret',

            body: patch,

            query: {
              filters:
                o.filters,
            },
          }
        );

      return r.data;
    },

    async remove(
      table,
      opts
    ) {
      const o = opts || {};

      if (
        !o.filters ||
        !o.filters.length
      ) {
        throw new Error(
          'refusing to DELETE without filters (would empty the table)'
        );
      }

      const r =
        await restRequest(
          '/rest/v1/' +
            encodeURIComponent(table),
          {
            method: 'DELETE',
            keySlot:
              o.keySlot ||
              'secret',

            query: {
              filters:
                o.filters,
            },
          }
        );

      return r.data;
    },

    async rpc(
      fn,
      args,
      opts
    ) {
      const o = opts || {};

      const r =
        await restRequest(
          '/rest/v1/rpc/' +
            encodeURIComponent(fn),
          {
            method: 'POST',
            keySlot:
              o.keySlot ||
              'secret',

            body:
              args || {},
          }
        );

      return r.data;
    },
  };
}

/**
 * RLS-respecting client for server-side work.
 */
function createPublishableServerClient() {
  assertServerContext();

  const admin =
    createAdminClient();

  const wrap =
    (fn) =>
    (table, opts) =>
      fn(
        table,
        Object.assign(
          {},
          opts,
          {
            keySlot:
              'publishable',
          }
        )
      );

  return {
    select:
      wrap(admin.select),

    insert:
      wrap(admin.insert),

    upsert:
      wrap(admin.upsert),

    update:
      wrap(admin.update),

    remove:
      wrap(admin.remove),

    rpc:
      (fn, args) =>
        admin.rpc(
          fn,
          args,
          {
            keySlot:
              'publishable',
          }
        ),

    probe:
      () =>
        admin.probe(
          'publishable'
        ),
  };
}

// --------------------------------------------------------------- exports ----

module.exports = {
  // config
  readEnv,
  getConfigReport,
  inspectUrl,

  // key safety
  classifyKey,
  isPrivilegedKey,
  describeKey,
  scrubSecrets,
  assertServerContext,

  // clients
  restRequest,
  createAdminClient,
  createPublishableServerClient,

  // constants
  ENV_URL,
  ENV_PUBLISHABLE,
  ENV_SECRET,
};
