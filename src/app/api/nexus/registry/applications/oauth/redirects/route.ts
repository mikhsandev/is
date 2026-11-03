import type { NextRequest } from "next/server";
import { auth } from "@/lib/auth";
import { pool } from "@/lib/database";
import { currentNexusOperatorId } from "@/lib/nexus-operator-access";
import { hasTrustedOrigin } from "@/lib/admin-access";
import { reply } from "@/lib/nexus-response";
import { parseBody } from "@/lib/nexus-registry";
import { validateRedirectUris, sameUris } from "@/lib/oauth-redirect-uris.mjs";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Update Better Auth's canonical redirects and the Nexus snapshot.
 * Never update Better Auth-managed database tables directly.
 */
export async function PATCH(req: NextRequest) {
  if (!hasTrustedOrigin(req.headers)) return reply({ error: "invalid_origin" }, 403);
  try {
    const actor = await currentNexusOperatorId(req.headers);
    if (!actor) return reply({ error: "forbidden" }, 403);
    const body = parseBody(await req.json().catch(() => null));
    if (!body || typeof body.clientId !== "string" || body.clientId.length > 255 ||
      !validateRedirectUris(body.redirectUris) || !Array.isArray(body.expectedRedirectUris) ||
      body.expectedRedirectUris.length > 10 ||
      !body.expectedRedirectUris.every(x => typeof x === "string" && x.length <= 2048)) {
      return reply({ error: "invalid_redirect_uris" }, 400);
    }
    const clientId = body.clientId;
    const nextUris = body.redirectUris as string[];
    const expectedUris = body.expectedRedirectUris as string[];
    const db = await pool.connect();
    try {
      await db.query("BEGIN");
      const result = await db.query(`SELECT o.application_id, o.environment, o.redirect_uris
        FROM nexus_application_oauth_clients o
        WHERE o.oauth_client_id = $1 FOR UPDATE`, [clientId]);
      if (result.rowCount !== 1) {
        await db.query("ROLLBACK");
        return reply({ error: "client_not_found" }, 404);
      }
      const record = result.rows[0];
      const previous = record.redirect_uris as string[];
      if (!sameUris(previous, expectedUris)) {
        await db.query("ROLLBACK");
        return reply({ error: "redirects_changed_reload" }, 409);
      }
      if (sameUris(previous, nextUris)) {
        await db.query("ROLLBACK");
        return reply({ client_id: clientId, redirect_uris: nextUris, unchanged: true });
      }
      // Better Auth is authoritative. This retains client_id and client_secret.
      await auth.api.adminUpdateOAuthClient({
        headers: req.headers,
        body: { client_id: clientId, update: { redirect_uris: nextUris } },
      });
      try {
        await db.query(`UPDATE nexus_application_oauth_clients SET redirect_uris=$2::jsonb
          WHERE oauth_client_id=$1`, [clientId, JSON.stringify(nextUris)]);
        await db.query(`INSERT INTO nexus_registry_audit
          (actor_user_id, entity_type, entity_id, action, detail)
          VALUES ($1, 'application', $2, 'update', $3::jsonb)`, [
          actor, record.application_id,
          JSON.stringify({ event: "oauth_redirect_update", environment: record.environment,
            client_id: clientId, old_uris: previous, new_uris: nextUris }),
        ]);
        await db.query("COMMIT");
        return reply({ client_id: clientId, redirect_uris: nextUris });
      } catch (dbError) {
        await db.query("ROLLBACK");
        try {
          await auth.api.adminUpdateOAuthClient({
            headers: req.headers,
            body: { client_id: clientId, update: { redirect_uris: previous } },
          });
        } catch (rollbackError) {
          console.error("CRITICAL: OAuth redirects need reconciliation for client", clientId, rollbackError);
        }
        throw dbError;
      }
    } catch (error) {
      await db.query("ROLLBACK").catch(() => {});
      throw error;
    } finally { db.release(); }
  } catch (error) {
    console.error("Nexus OAuth redirect update failure", error);
    return reply({ error: "oauth_redirect_update_failed" }, 500);
  }
}
