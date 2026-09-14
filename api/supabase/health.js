'use strict';

const {
  getAdminClient,
  getConfigReport,
} = require('../../server/supabase');

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({
      ok: false,
      error: 'method_not_allowed',
    });
  }

  const config = getConfigReport();
  const client = getAdminClient();
  const probe = await client.probe('secret');

  return res.status(probe.connected ? 200 : 503).json({
    ok: probe.connected,
    service: 'profitpilot-ai',
    supabase: {
      connected: probe.connected,
      auth: probe.auth,
      postgrest: probe.postgrest,
    },
    config: {
      url: config.url,
      server_ready: config.server_ready,
      browser_ready: config.browser_ready,
      keys: {
        secret: config.keys.secret,
        publishable: config.keys.publishable,
      },
      warnings: config.warnings,
    },
    timing_ms: probe.ms,
  });
};
