'use strict';

/**
 * Public entry point for server-side Supabase access.
 *
 *   const { getAdminClient, getConfigReport } = require('../server/supabase');
 *
 * Server code should import THIS file, not the internals, so the
 * implementation can be swapped (e.g. for @supabase/supabase-js) later
 * without touching call sites.
 */

const config = require('./config.js');

let adminSingleton = null;
let publishableSingleton = null;

/** Privileged (RLS-bypassing) client. Server-only. */
function getAdminClient() {
  if (!adminSingleton) adminSingleton = config.createAdminClient();
  return adminSingleton;
}

/** RLS-respecting client using the publishable key from server code. */
function getPublishableClient() {
  if (!publishableSingleton) publishableSingleton = config.createPublishableServerClient();
  return publishableSingleton;
}

module.exports = {
  getAdminClient,
  getPublishableClient,
  getConfigReport: config.getConfigReport,
  describeKey: config.describeKey,
  classifyKey: config.classifyKey,
  isPrivilegedKey: config.isPrivilegedKey,
  scrubSecrets: config.scrubSecrets,
  inspectUrl: config.inspectUrl,
  readEnv: config.readEnv,
  ENV_URL: config.ENV_URL,
  ENV_PUBLISHABLE: config.ENV_PUBLISHABLE,
  ENV_SECRET: config.ENV_SECRET,
};
