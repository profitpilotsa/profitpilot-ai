'use strict';

const {
  readEnv,
  inspectUrl,
  describeKey,
  isPrivilegedKey,
} = require('../server/supabase/config');

module.exports = function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({
      ok: false,
      error: 'method_not_allowed',
    });
  }

  const env = readEnv();
  const url = inspectUrl(env.url);
  const publishable = describeKey(env.publishableKey);

  if (!url.valid) {
    return res.status(503).json({
      ok: false,
      error: 'supabase_url_not_configured',
    });
  }

  if (!publishable.present || isPrivilegedKey(env.publishableKey)) {
    return res.status(503).json({
      ok: false,
      error: 'publishable_key_not_safe',
    });
  }

  return res.status(200).json({
    ok: true,
    supabase_url: env.url,
    supabase_publishable_key: env.publishableKey,
  });
};
