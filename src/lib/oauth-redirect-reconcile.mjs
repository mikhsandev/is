/** Pure helpers: exact URI membership, no normalization or wildcard matching. */
export function equalRedirectSets(left, right) {
  return Array.isArray(left) && Array.isArray(right) &&
    left.length === right.length &&
    new Set(left).size === left.length && new Set(right).size === right.length &&
    left.every(uri => typeof uri === 'string' && right.includes(uri));
}

/** pg drivers may expose an OAuth client's JSON redirect list as an array or JSON text. */
export function decodeProviderRedirects(raw) {
  let decoded = raw;
  if (typeof decoded === 'string') {
    try { decoded = JSON.parse(decoded); } catch { return null; }
  }
  return Array.isArray(decoded) && decoded.every(uri => typeof uri === 'string')
    ? decoded : null;
}
