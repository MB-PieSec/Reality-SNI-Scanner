/**
 * Shared filtering logic used by every candidate-domain source (bundled
 * list, live top-sites fetch, ASN-neighbor reverse-DNS, CT-log lookups) so
 * they all apply the same bar consistently.
 */

// Domains that show up in various discovery sources but are poor Reality
// camouflage picks: known-blocked-in-Iran, adult/gambling-adjacent, or
// otherwise likely to draw more DPI attention than they deflect.
const DENYLIST_SUBSTRINGS = [
  "porn",
  "xxx",
  "bet",
  "casino",
  "gambl",
  "torrent",
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
  return !DENYLIST_SUBSTRINGS.some((bad) => lower.includes(bad));
}

/** Normalizes a hostname and rejects it unless it passes the shared policy. */
export function normalizeAcceptableDomain(domain: string): string | null {
  const normalized = domain.trim().toLowerCase().replace(/\.$/, "");
  return isAcceptableDomain(normalized) ? normalized : null;
}
