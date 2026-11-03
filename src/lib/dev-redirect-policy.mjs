/** LAN development OAuth callback policy. Keep protocol checks independent of HTTP handlers. */
export function validateDevHttpUri(input) {
  if (typeof input !== 'string' || input.length > 2048 || input.includes('*')) return null;
  let url;
  try { url = new URL(input); } catch { return null; }
  if (url.protocol !== 'http:' || url.href !== input || url.username || url.password || url.hash || url.search) return null;
  if (!url.pathname || url.pathname === '/' || !/^\/[a-zA-Z0-9_./~-]+$/.test(url.pathname)) return null;
  const host = url.hostname;
  if (host === 'localhost') return input;
  // IPv4 literals only: no DNS rebinding, wildcard DNS, decimal/octal forms, IPv6 scope IDs.
  if (!/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(host)) return null;
  const octets = host.split('.').map(Number);
  if (octets.some(n => n > 255)) return null;
  const [a,b] = octets;
  if (a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return input;
  return null;
}
export function matchingRegistrationSet(registeredUris, baseUris, marker) {
  if (!Array.isArray(registeredUris) || !Array.isArray(baseUris) || !marker) return false;
  const expected = [...baseUris, marker];
  if (expected.length !== new Set(expected).size || expected.length !== registeredUris.length) return false;
  return expected.every(uri => registeredUris.includes(uri));
}
