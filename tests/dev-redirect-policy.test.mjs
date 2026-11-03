import test from 'node:test';
import assert from 'node:assert/strict';
import { validateDevHttpUri, matchingRegistrationSet } from '../src/lib/dev-redirect-policy.mjs';
const allowed = [
  'http://192.168.1.50:3000/auth/callback',
  'http://10.0.0.15:8000/oidc/callback',
  'http://172.16.2.4:8080/auth/callback',
  'http://172.31.255.254/auth/callback',
  'http://localhost:3000/auth/callback',
  'http://127.0.0.1:8000/callback',
];
const denied = [
  'http://8.8.8.8:3000/callback', 'http://172.32.1.1/callback',
  'http://192.169.1.5/callback', 'http://169.254.1.1/callback',
  'http://example.local/callback', 'http://app.example.com/callback',
  'http://192.168.1.1:3000/call*', 'http://192.168.1.1:3000/',
  'http://user:pass@10.0.0.1/callback', 'http://10.0.0.1/callback#fragment',
  'http://10.0.0.1/callback?key=x', 'http://010.000.000.001/callback',
  'http://[::1]:3000/callback', 'https://192.168.1.5/callback',
  'ftp://192.168.1.5/callback'
];
test('allows exact canonical private and loopback HTTP callbacks', () => {
  for (const uri of allowed) assert.equal(validateDevHttpUri(uri), uri, uri);
});
test('rejects public, DNS, ambiguous and unsafe redirects', () => {
  for (const uri of denied) assert.equal(validateDevHttpUri(uri), null, uri);
});
test('registered URI set must contain a unique marker and match exactly', () => {
  const base=['https://sandcastle-api.vercel.app/api/auth/callback'];
  const mark='https://sandcastle-auth.vercel.app/.well-known/is-dev-client/fafebabe';
  assert.ok(matchingRegistrationSet([...base,mark],base,mark));
  assert.equal(matchingRegistrationSet(base,base,mark),false);
  assert.equal(matchingRegistrationSet([...base,mark,'https://extra.test/cb'],base,mark),false);
});
