/**
 * Shared filtering logic used by every candidate-domain source (bundled
 * list, live top-sites fetch, ASN-neighbor reverse-DNS, CT-log lookups) so
 * they all apply the same bar consistently.
 */

// Known-blocked-in-Iran, adult/gambling-adjacent, or otherwise likely to draw
// more DPI attention than they deflect.
// ponytail: substrings only for words that are never part of a real brand;
// short ones (x.com, bet) are matched on label boundaries so netflix.com,
// dropbox.com and alphabet.com survive.
const DENY_SUBSTRINGS = ["porn", "xxx", "casino", "gambl", "torrent"];
const DENY_BET = /(^|[.-])(\d*x)?bet(\d|[.-]|$)/;
const DENY_HOSTS = [
  "facebook.com",
  "twitter.com",
  "x.com",
  "instagram.com",
  "youtube.com", // frequently rate-limited/throttled by DPI itself, bad DEST choice
];

const HOSTNAME_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;

/** True if `domain` is a syntactically valid, non-denylisted hostname. */
export function isAcceptableDomain(domain: string): boolean {
  const lower = domain.trim().toLowerCase().replace(/\.$/, "");
  if (lower.length > 253) return false;
  if (!HOSTNAME_RE.test(lower)) return false;
  if (DENY_SUBSTRINGS.some((bad) => lower.includes(bad))) return false;
  if (DENY_BET.test(lower)) return false;
  return !DENY_HOSTS.some((h) => lower === h || lower.endsWith(`.${h}`));
}

/** Normalizes a hostname and rejects it unless it passes the shared policy. */
export function normalizeAcceptableDomain(domain: string): string | null {
  const normalized = domain.trim().toLowerCase().replace(/\.$/, "");
  return isAcceptableDomain(normalized) ? normalized : null;
}
