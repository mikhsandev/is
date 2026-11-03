import test from 'node:test';
import assert from 'node:assert/strict';
import { planLegacyRedirectMigration } from '../src/lib/legacy-redirect-migration.mjs';

const lan = 'http://192.168.0.99:5173/api/auth/callback';
const https = 'https://sandcastle-api.vercel.app/api/auth/callback';
test('migrates mixed HTTPS and LAN HTTP without dropping HTTPS base',()=>{
 const p=planLegacyRedirectMigration([https,lan]);
 assert.deepEqual(p,{httpsUris:[https],httpUris:[lan]});
});
test('requires an HTTPS base when only HTTP callback exists',()=>{
 assert.equal(planLegacyRedirectMigration([lan]).error,'https_base_uri_required');
 assert.deepEqual(planLegacyRedirectMigration([lan],https),{httpsUris:[https],httpUris:[lan]});
});
test('rejects unapproved public HTTP and wildcard',()=>{
 for(const uri of ['http://8.8.8.8:5173/auth/callback','http://*.example.com/auth/callback']){
  assert.equal(planLegacyRedirectMigration([https,uri]).error,'unsupported_legacy_redirect');
 }
});
test('rejects duplicate and malformed callbacks',()=>{
 assert.equal(planLegacyRedirectMigration([https,lan,lan]).error,'duplicate_registered_redirects');
 assert.equal(planLegacyRedirectMigration([https]).error,'no_legacy_http_redirects');
 assert.equal(planLegacyRedirectMigration([lan],'http://example.com/callback').error,'invalid_https_base_uri');
});
