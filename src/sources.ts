/**
 * Where candidate SNI/DEST domains come from.
 *
 * You never hand this script a list. By default it reads a snapshot of
 * ~485 major, globally-reputable domains bundled directly in the package
 * (src/data/top-domains.json) — no network call required just to build the
 * candidate pool. This matters specifically because fetching a live list
 * from GitHub (or anywhere) can itself require a VPN/proxy in a filtered
 * network, which would poison every latency measurement downstream: you'd
 * be testing the VPN's path, not the real, unfiltered path your Reality
 * clients will actually use.
 *
 * Pass --remote if you want a fresher live-fetched list instead (falls
 * back to the bundled snapshot automatically if the fetch fails).
 */

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { normalizeAcceptableDomain } from "./filters.ts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BUNDLED_LIST_PATH = path.join(__dirname, "data", "top-domains.json");
const REMOTE_LIST_URL =
  "https://raw.githubusercontent.com/Kikobeats/top-sites/master/top-sites.json";

interface TopSiteEntry {
  rank: number;
  rootDomain: string;
}

async function loadBundled(limit: number): Promise<string[]> {
  const raw = await readFile(BUNDLED_LIST_PATH, "utf-8");
  const domains = JSON.parse(raw) as string[];
  return selectAcceptableDomains(domains, limit);
}

function selectAcceptableDomains(domains: string[], limit: number): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of domains) {
    const domain = normalizeAcceptableDomain(raw);
    if (!domain || seen.has(domain)) continue;
    seen.add(domain);
    out.push(domain);
    if (out.length >= limit) break;
  }
  return out;
}

async function fetchRemote(limit: number, timeoutMs: number): Promise<string[]> {
  const res = await fetch(REMOTE_LIST_URL, { signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const entries = (await res.json()) as TopSiteEntry[];

  const seen = new Set<string>();
  const out: string[] = [];
  for (const entry of entries.sort((a, b) => a.rank - b.rank)) {
    const domain = normalizeAcceptableDomain(entry.rootDomain ?? "");
    if (!domain || seen.has(domain)) continue;
    seen.add(domain);
    out.push(domain);
    if (out.length >= limit) break;
  }
  if (out.length === 0) throw new Error("parsed list was empty");
  return out;
}

/**
 * Returns the candidate domain list. Bundled (offline, no network needed)
 * by default; pass useRemote=true to try a live fetch first, falling back
 * to the bundled snapshot if that fails or times out.
 */
export async function fetchTopDomains(
  limit: number,
  useRemote = false,
  remoteTimeoutMs = 10_000,
): Promise<string[]> {
  if (useRemote) {
    try {
      return await fetchRemote(limit, remoteTimeoutMs);
    } catch (err) {
      console.error(
        `[!] sources: live fetch failed (${(err as Error).message}), falling back to bundled snapshot`,
      );
    }
  }
  return loadBundled(limit);
}
