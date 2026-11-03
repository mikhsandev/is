/** Conservative redirect policy for the operator-managed OAuth editor.
 * Private/LAN endpoints are accepted only when they use HTTPS.
 */
export function validateRedirectUris(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 10) return false;
  if (new Set(value).size !== value.length) return false;
  return value.every((item) => {
    if (typeof item !== 'string' || item.length > 2048 || !item || item.trim() !== item) return false;
    if (/[*\\\s]/.test(item)) return false;
    let url;
    try { url = new URL(item); } catch { return false; }
    if (url.username || url.password || url.hash) return false;
    if (url.protocol === 'https:') return true;
    return url.protocol === 'http:' && (url.hostname === 'localhost' || url.hostname === '127.0.0.1');
  });
}

export function sameUris(a, b) {
  return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((v, i) => v === b[i]);
}
