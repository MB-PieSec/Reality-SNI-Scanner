import { normalizeAcceptableDomain } from "./filters.ts";

/**
 * Every publicly-trusted TLS certificate ever issued is permanently logged
 * in Certificate Transparency logs — that's a CA/Browser Forum requirement,
 * not a leak. This means every real subdomain a big provider has ever put
 * a cert on (things like delivery.mp.microsoft.com, which will never show
 * up in a "top sites by backlink" dataset because nobody links to it) is
 * publicly queryable.
 *
 * We query crt.sh (the standard free CT-log search engine, no signup/key
 * needed) for each seed domain and pull out every concrete hostname that's
 * ever appeared on one of its certs. This is the piece that finds the
 * `play.google.com` / `delivery.mp.microsoft.com`-style subdomains the
 * bundled top-sites list mostly misses.
 */

// Large, well-known providers that (a) run huge numbers of legitimate,
// well-maintained subdomains and (b) are essentially never blocked
// wholesale, since doing so would break too much unrelated traffic.
export const DEFAULT_CT_SEEDS = [
  "microsoft.com",
  "google.com",
  "apple.com",
  "cloudflare.com",
  "amazon.com",
  "akamai.com",
  "fastly.net",
  "wikipedia.org",
  "github.com",
  "mozilla.org",
];

interface CrtShEntry {
  name_value: string;
}

const MAX_CT_RESPONSE_BYTES = 5 * 1024 * 1024;

async function readJsonWithinLimit(res: Response): Promise<unknown> {
  if (!res.body) throw new Error("empty response body");
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  for await (const chunk of res.body as AsyncIterable<Uint8Array>) {
    totalBytes += chunk.byteLength;
    if (totalBytes > MAX_CT_RESPONSE_BYTES) {
      throw new Error(`response exceeded ${MAX_CT_RESPONSE_BYTES / (1024 * 1024)} MiB limit`);
    }
    chunks.push(chunk);
  }
  const body = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder().decode(body));
}

async function queryCrtSh(seed: string, timeoutMs: number, limit: number): Promise<string[]> {
  const res = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(seed)}&output=json`, {
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const entries = (await readJsonWithinLimit(res)) as CrtShEntry[];

  const names = new Set<string>();
  for (const entry of entries) {
    if (!entry.name_value) continue;
    // A single cert can cover multiple names (SANs), one per line.
    for (const raw of entry.name_value.split("\n")) {
      const name = normalizeAcceptableDomain(raw);
      // Wildcard entries ("*.foo.com") aren't a dialable hostname on their
      // own — skip them, we only want concrete names we can actually SNI to.
      if (!name || raw.trim().startsWith("*.")) continue;
      if (!name.endsWith(`.${seed}`) && name !== seed) continue; // stay on-topic
      names.add(name);
      if (names.size >= limit) return [...names];
    }
  }
  return [...names];
}

/**
 * Queries CT logs for each seed domain and returns a deduped, capped list
 * of real subdomains discovered. Seeds are queried one at a time with a
 * short gap between requests to stay well within crt.sh's fair-use limits;
 * a failure on one seed is logged and skipped rather than aborting the rest.
 */
export async function discoverCTSubdomains(
  seeds: string[],
  totalLimit: number,
  timeoutMs = 15_000,
): Promise<string[]> {
  const found = new Set<string>();

  for (const seed of seeds) {
    if (found.size >= totalLimit) break;
    try {
      const names = await queryCrtSh(seed, timeoutMs, totalLimit - found.size);
      const symbol = names.length > 0 ? "[+]" : "[!]";
      console.error(`${symbol} ctlogs: ${seed}: found ${names.length} candidate subdomain(s)`);
      for (const n of names) {
        found.add(n);
        if (found.size >= totalLimit) break;
      }
    } catch (err) {
      const cause = (err as { cause?: { message?: string; code?: string } })?.cause;
      const detail = cause?.code ?? cause?.message ?? (err as Error).message;
      console.error(`[!] ctlogs: ${seed}: lookup failed (${detail}), skipping`);
    }
    // Small politeness delay between requests to a free, shared service.
    await new Promise((r) => setTimeout(r, 300));
  }

  return [...found].slice(0, totalLimit);
}
