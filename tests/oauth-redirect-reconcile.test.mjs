import test from 'node:test';
import assert from 'node:assert/strict';
import { equalRedirectSets, decodeProviderRedirects } from '../src/lib/oauth-redirect-reconcile.mjs';

test('native callback is missing from a marker-only registration', () => {
  const registered = ['https://sandcastle-api.vercel.app/api/auth/callback',
    'https://sandcastle-auth.vercel.app/.well-known/is-dev-client/legacy'];
  const expected = ['https://sandcastle-api.vercel.app/api/auth/callback',
    'https://192.168.0.99:5173/api/auth/callback'];
  assert.equal(equalRedirectSets(registered, expected), false);
});
test('order is immaterial, URI spelling is exact', () => {
  const x = ['https://example.com/a', 'https://example.com/b'];
  assert.equal(equalRedirectSets(x, [...x].reverse()), true);
  assert.equal(equalRedirectSets(x, ['https://example.com/a/', 'https://example.com/b']), false);
  assert.equal(equalRedirectSets(x, [x[0], x[0]]), false);
});
test('provider JSON decoding', () => {
  assert.deepEqual(decodeProviderRedirects('["https://example.com/callback"]'), ['https://example.com/callback']);
  assert.deepEqual(decodeProviderRedirects(['https://example.com/callback']), ['https://example.com/callback']);
  assert.equal(decodeProviderRedirects('{}'), null);
});
