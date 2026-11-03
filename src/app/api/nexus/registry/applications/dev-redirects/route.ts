import type { NextRequest } from 'next/server';
import { randomUUID } from 'node:crypto';
import { auth } from '@/lib/auth';
import { pool } from '@/lib/database';
import { currentNexusOperatorId } from '@/lib/nexus-operator-access';
import { hasTrustedOrigin } from '@/lib/admin-access';
import { reply } from '@/lib/nexus-response';
import { parseBody } from '@/lib/nexus-registry';
import { validateDevHttpUri } from '@/lib/dev-redirect-policy.mjs';
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const isId = (x: unknown): x is string => typeof x === 'string' && x.length > 0 && x.length < 256;
const audit = (db: import('pg').PoolClient, actor:string, appId:string, detail:object) =>
  db.query(`INSERT INTO nexus_registry_audit(actor_user_id,entity_type,entity_id,action,detail)
    VALUES($1,'application',$2,'update',$3::jsonb)`,[actor,appId,JSON.stringify(detail)]);

export async function GET(req:NextRequest) {
  try {
    if (!await currentNexusOperatorId(req.headers)) return reply({error:'forbidden'},403);
    const rows=await pool.query(`SELECT o.oauth_client_id,o.application_id,o.environment,a.name AS application_name,
      COALESCE(c.enabled,false) AS enabled,
      COALESCE((SELECT json_agg(r.redirect_uri ORDER BY r.redirect_uri) FROM nexus_oauth_dev_redirects r
        WHERE r.oauth_client_id=o.oauth_client_id),'[]'::json) AS http_redirects
      FROM nexus_application_oauth_clients o
      JOIN nexus_applications a ON a.id=o.application_id
      LEFT JOIN nexus_oauth_dev_capabilities c ON c.oauth_client_id=o.oauth_client_id
      WHERE o.environment='development' ORDER BY a.name,o.created_at`);
    return reply({clients:rows.rows});
  }catch(e){console.error('Nexus dev redirect list failed',e);return reply({error:'internal_error'},500);}
}

export async function POST(req:NextRequest) {
  if(!hasTrustedOrigin(req.headers)) return reply({error:'invalid_origin'},403);
  const actor=await currentNexusOperatorId(req.headers);
  if(!actor) return reply({error:'forbidden'},403);
  const b=parseBody(await req.json().catch(()=>null));
  if(!b || !isId(b.clientId) || !['enable','disable','add','remove'].includes(String(b.action))) return reply({error:'invalid_body'},400);
  const clientId=b.clientId, action=b.action as 'enable'|'disable'|'add'|'remove';
  const uri = action==='add'||action==='remove' ? validateDevHttpUri(b.uri) : null;
  if((action==='add'||action==='remove')&&!uri) return reply({error:'invalid_private_http_uri'},400);
  if(action==='enable' && b.confirmInsecureDev !== true) return reply({error:'explicit_confirmation_required'},400);
  const db=await pool.connect();
  try {
    await db.query('BEGIN');
    const registry=await db.query(`SELECT o.application_id,o.environment,o.redirect_uris,a.status
      FROM nexus_application_oauth_clients o JOIN nexus_applications a ON a.id=o.application_id
      WHERE o.oauth_client_id=$1 FOR UPDATE OF o`,[clientId]);
    if(registry.rowCount!==1 || registry.rows[0].environment!=='development'){
      await db.query('ROLLBACK');return reply({error:'development_client_not_found'},404);
    }
    if(registry.rows[0].status!=='active'){
      await db.query('ROLLBACK');return reply({error:'application_not_active'},409);
    }
    const appId=registry.rows[0].application_id;
    const existing=await db.query('SELECT marker_uri,enabled FROM nexus_oauth_dev_capabilities WHERE oauth_client_id=$1 FOR UPDATE',[clientId]);
    if(action==='enable'){
      // Per-client unique HTTPS marker is registered with Better Auth, because its validator
      // receives registered URIs rather than a client ID. No LAN HTTP URI is registered there.
      const marker=existing.rowCount===1 ? existing.rows[0].marker_uri :
        `${new URL(process.env.BETTER_AUTH_URL!).origin}/.well-known/is-dev-client/${randomUUID()}`;
      const base=registry.rows[0].redirect_uris;
      if(!Array.isArray(base)||base.some((x:unknown)=>typeof x!=='string'||!x.startsWith('https://'))){
        await db.query('ROLLBACK');return reply({error:'client_base_redirects_must_be_https'},409);
      }
      // Better Auth remains authoritative for redirect registration. Its client update may
      // fail; the transaction then rolls back and no unsafe callback is enabled.
      await auth.api.adminUpdateOAuthClient({headers:req.headers,
        body:{client_id:clientId,update:{redirect_uris:[...base,marker]}}});
      await db.query(`INSERT INTO nexus_oauth_dev_capabilities(oauth_client_id,marker_uri,enabled,changed_by)
        VALUES($1,$2,true,$3) ON CONFLICT(oauth_client_id)
        DO UPDATE SET enabled=true,changed_by=$3,changed_at=now()`,[clientId,marker,actor]);
      await audit(db,actor,appId,{event:'dev_http_capability_enabled',client_id:clientId});
    }else if(action==='disable'){
      await db.query(`UPDATE nexus_oauth_dev_capabilities SET enabled=false,changed_at=now(),changed_by=$2 WHERE oauth_client_id=$1`,[clientId,actor]);
      await audit(db,actor,appId,{event:'dev_http_capability_disabled',client_id:clientId});
    }else{
      if(existing.rowCount!==1){await db.query('ROLLBACK');return reply({error:'enable_capability_first'},409);}
      if(action==='add'){
        const count=await db.query('SELECT count(*)::int AS count FROM nexus_oauth_dev_redirects WHERE oauth_client_id=$1',[clientId]);
        if(count.rows[0].count>=10){await db.query('ROLLBACK');return reply({error:'limit_reached'},409);}
        const added=await db.query(`INSERT INTO nexus_oauth_dev_redirects(oauth_client_id,redirect_uri,created_by)
          VALUES($1,$2,$3) ON CONFLICT DO NOTHING RETURNING redirect_uri`,[clientId,uri,actor]);
        if(!added.rowCount){await db.query('ROLLBACK');return reply({error:'already_exists'},409);}
      }else{
        const removed=await db.query('DELETE FROM nexus_oauth_dev_redirects WHERE oauth_client_id=$1 AND redirect_uri=$2 RETURNING redirect_uri',[clientId,uri]);
        if(!removed.rowCount){await db.query('ROLLBACK');return reply({error:'not_found'},404);}
      }
      await audit(db,actor,appId,{event:action==='add'?'dev_http_redirect_added':'dev_http_redirect_removed',client_id:clientId,redirect_uri:uri});
    }
    await db.query('COMMIT');
    return reply({success:true});
  }catch(e){await db.query('ROLLBACK').catch(()=>{});console.error('Nexus dev HTTP redirect change failed',e);return reply({error:'operation_failed'},500);}
  finally{db.release();}
}
