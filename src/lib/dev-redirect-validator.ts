import { pool } from '@/lib/database';
import { validateDevHttpUri, matchingRegistrationSet } from '@/lib/dev-redirect-policy.mjs';

/** Called by Better Auth at authorization time. No broad trusted origins. */
export async function validateOAuthRedirect(uri: string, registeredUris: readonly string[], defaultResult: boolean): Promise<boolean> {
  console.info("IS OAuth redirect comparison", {
    requested: uri,
    registered: registeredUris,
    exactMatch: registeredUris.includes(uri),
    defaultResult,
  });
  if (uri.startsWith('https://')) return defaultResult;
  if (!validateDevHttpUri(uri)) return false;
  // A unique HTTPS marker makes each admin-registered client distinguishable
  // using Better Auth's validator signature (which omits the client ID).
  const result = await pool.query(`
    SELECT c.marker_uri, c.enabled, o.redirect_uris, a.status
      FROM nexus_oauth_dev_capabilities c
      JOIN nexus_application_oauth_clients o ON o.oauth_client_id = c.oauth_client_id
      JOIN nexus_applications a ON a.id = o.application_id
      JOIN nexus_oauth_dev_redirects r ON r.oauth_client_id = c.oauth_client_id
     WHERE c.marker_uri = ANY($1::text[])
       AND o.environment = 'development' AND c.enabled = true
       AND a.status = 'active' AND r.redirect_uri = $2
  `, [registeredUris, uri]);
  if (result.rowCount !== 1) return false;
  const record = result.rows[0];
  return matchingRegistrationSet(registeredUris, record.redirect_uris, record.marker_uri);
}
