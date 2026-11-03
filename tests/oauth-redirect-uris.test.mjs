import test from 'node:test';
import assert from 'node:assert/strict';
import { validateRedirectUris, sameUris } from '../src/lib/oauth-redirect-uris.mjs';

test('accepts HTTPS LAN IP and HTTPS hosted callbacks', () => {
  assert.equal(validateRedirectUris([
    'https://192.168.0.99:5173/api/auth/callback',
    'https://sandcastle-api.vercel.app/api/auth/callback',
  ]), true);
});
test('rejects HTTP LAN and public IP callbacks', () => {
  assert.equal(validateRedirectUris(['http://192.168.0.99:5173/api/auth/callback']), false);
  assert.equal(validateRedirectUris(['http://8.8.8.8/auth/callback']), false);
});
test('supports HTTP loopback only', () => {
  assert.equal(validateRedirectUris(['http://127.0.0.1:5173/auth/callback']), true);
  assert.equal(validateRedirectUris(['http://localhost:5173/auth/callback']), true);
});
test('rejects duplicate, wildcard, embedded credentials and fragments', () => {
  assert.equal(validateRedirectUris(['https://example.test/a','https://example.test/a']), false);
  assert.equal(validateRedirectUris(['https://*.example.test/a']), false);
  assert.equal(validateRedirectUris(['https://name:pass@example.test/a']), false);
  assert.equal(validateRedirectUris(['https://example.test/a#fragment']), false);
});
test('exact snapshot comparison preserves order and contents', () => {
  assert.equal(sameUris(['a','b'], ['a','b']), true);
  assert.equal(sameUris(['a','b'], ['b','a']), false);
});
