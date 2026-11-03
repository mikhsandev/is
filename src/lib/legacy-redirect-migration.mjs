import { validateDevHttpUri } from './dev-redirect-policy.mjs';

/** Pure migration planner; never mutates the existing registration. */
export function planLegacyRedirectMigration(input, additionalHttpsUri = '') {
  if (!Array.isArray(input) || !input.length || input.length > 20 || input.some(x => typeof x !== 'string')) {
    return { error: 'invalid_registered_redirects' };
  }
  if (new Set(input).size !== input.length) return { error: 'duplicate_registered_redirects' };
  const https = [];
  const http = [];
  for (const uri of input) {
    if (validateDevHttpUri(uri)) { http.push(uri); continue; }
    try {
      const u = new URL(uri);
      if (u.protocol === 'https:' && u.href === uri && !u.username && !u.password && !u.hash && !uri.includes('*')) {
        https.push(uri); continue;
      }
    } catch { /* invalid */ }
    return { error: 'unsupported_legacy_redirect' };
  }
  if (!http.length) return { error: 'no_legacy_http_redirects' };
  if (http.length > 10) return { error: 'too_many_legacy_http_redirects' };
  const supplied = additionalHttpsUri.trim();
  if (supplied) {
    if (https.length) return { error: 'https_base_already_exists' };
    try {
      const u = new URL(supplied);
      if (u.protocol !== 'https:' || u.href !== supplied || u.hash || u.username || u.password || supplied.includes('*')) {
        return { error: 'invalid_https_base_uri' };
      }
      https.push(supplied);
    } catch { return { error: 'invalid_https_base_uri' }; }
  }
  if (!https.length) return { error: 'https_base_uri_required' };
  return { httpsUris: https, httpUris: http };
}
