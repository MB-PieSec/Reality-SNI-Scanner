import dns from "node:dns/promises";
import { normalizeAcceptableDomain } from "./filters.ts";

export function isValidIPv4(ip: string): boolean {
  const octets = ip.split(".");
  return octets.length === 4 && octets.every((octet) => {
    if (!/^\d+$/.test(octet)) return false;
    const value = Number(octet);
    return Number.isInteger(value) && value >= 0 && value <= 255;
  });
}

export function isSampleableIPv4Cidr(cidr: string): boolean {
  const [base, prefixLenStr] = cidr.split("/");
  const prefixLen = Number(prefixLenStr);
  return Boolean(base) && isValidIPv4(base) && /^\d{1,2}$/.test(prefixLenStr ?? "") && Number.isInteger(prefixLen) && prefixLen >= 16 && prefixLen <= 32;
}

/**
 * Optional discovery path: given your VPS's IP, find other domains hosted
 * in the same network neighborhood (same ASN/CIDR block). Co-located DEST
 * targets are a stronger Reality pick than an arbitrary big-name domain,
 * since the routing/latency/geo fingerprint matches your real server more
 * closely.
 *
 * Two independent lookup providers are tried in sequence, and timeouts are
 * generous by default — on a heavily-filtered/throttled connection a single
 * round trip can already take 2-3s, so a naive 10s budget can fail requests
 * that would otherwise succeed.
 */

interface BgpViewIpResponse {
  data?: { prefixes?: { prefix: string }[] };
}

interface RipeStatResponse {
  data?: { resource?: string };
}

async function tryBgpView(ip: string, timeoutMs: number): Promise<string | null> {
  const res = await fetch(`https://api.bgpview.io/ip/${ip}`, {
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const json = (await res.json()) as BgpViewIpResponse;
  return json.data?.prefixes?.[0]?.prefix ?? null;
}

async function tryRipeStat(ip: string, timeoutMs: number): Promise<string | null> {
  const res = await fetch(
    `https://stat.ripe.net/data/network-info/data.json?resource=${ip}`,
    { signal: AbortSignal.timeout(timeoutMs) },
  );
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const json = (await res.json()) as RipeStatResponse;
  return json.data?.resource ?? null;
}

/**
 * Looks up the CIDR block your IP's ASN announces. Tries BGPView first,
 * then falls back to RIPEstat (a different provider/network path — useful
 * if one happens to be slow or unreachable from your vantage point).
 */
async function getAnnouncedPrefix(ip: string, timeoutMs: number): Promise<string | null> {
  const providers: [string, (ip: string, t: number) => Promise<string | null>][] = [
    ["bgpview.io", tryBgpView],
    ["stat.ripe.net", tryRipeStat],
  ];
  for (const [name, fn] of providers) {
    try {
      const prefix = await fn(ip, timeoutMs);
      if (prefix) return prefix;
    } catch (err) {
      const cause = (err as { cause?: { message?: string; code?: string } })?.cause;
      const detail = cause?.code ?? cause?.message ?? (err as Error).message;
      console.error(`[!] asn: ${name} lookup failed: ${detail}`);
    }
  }
  return null;
}

/** Turns "203.0.113.0/24" into a bounded, randomly-sampled list of host IPs within it. */
function sampleIPsInCIDR(cidr: string, sampleSize: number): string[] {
  if (!isSampleableIPv4Cidr(cidr)) return [];
  const [base, prefixLenStr] = cidr.split("/");
  const prefixLen = parseInt(prefixLenStr, 10);
  if (!base || Number.isNaN(prefixLen) || prefixLen < 16) {
    // Refuse to sample absurdly large blocks (e.g. a /8) — cap scope.
    return [];
  }

  const hostBits = 32 - prefixLen;
  const totalHosts = Math.pow(2, hostBits);
  const networkMask = (0xffffffff << hostBits) >>> 0;
  const baseInt = (ipToInt(base) & networkMask) >>> 0;
  const count = Math.min(sampleSize, Math.max(totalHosts - 2, 0));

  const offsets = new Set<number>();
  while (offsets.size < count) {
    // Skip network (.0) and broadcast (last) addresses.
    const offset = 1 + Math.floor(Math.random() * (totalHosts - 2));
    offsets.add(offset);
  }

  return [...offsets].map((offset) => intToIp(baseInt + offset));
}

function ipToInt(ip: string): number {
  return ip.split(".").reduce((acc, octet) => acc * 256 + Number(octet), 0);
}

function intToIp(int: number): string {
  return [24, 16, 8, 0].map((shift) => (int >>> shift) & 255).join(".");
}

/**
 * Full pipeline: your IP -> its announced CIDR -> sampled reverse-DNS sweep
 * -> unique hostnames. If you already know your prefix (e.g. from your
 * hosting provider's docs), pass it directly via explicitPrefix to skip the
 * ASN lookup step entirely — useful if both lookup providers are
 * unreachable from your network.
 */
export async function discoverNeighborDomains(
  targetIp: string,
  sampleSize: number,
  lookupTimeoutMs = 20_000,
  explicitPrefix?: string,
): Promise<string[]> {
  const prefix = explicitPrefix ?? (await getAnnouncedPrefix(targetIp, lookupTimeoutMs));
  if (!prefix) {
    console.error(
      "[!] asn: no announced prefix found (both lookup providers failed or timed out) — " +
        "skipping neighbor discovery. You can bypass this with --prefix <cidr> if you " +
        "know your provider's block (check their docs / WHOIS from another machine).",
    );
    return [];
  }
  console.error(`[*] asn: ${targetIp} sits in ${prefix}, sampling ${sampleSize} IPs for PTR records...`);

  const ips = sampleIPsInCIDR(prefix, sampleSize);
  const hostnames = new Set<string>();

  const concurrency = 25;
  let idx = 0;
  async function worker() {
    while (idx < ips.length) {
      const ip = ips[idx++];
      try {
        const names = await dns.reverse(ip);
        for (const rawName of names) {
          const hostname = normalizeAcceptableDomain(rawName);
          if (hostname) hostnames.add(hostname);
        }
      } catch {
        // No PTR record — normal, most sampled IPs won't have one.
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, ips.length) }, worker));

  const symbol = hostnames.size > 0 ? "[+]" : "[!]";
  console.error(`${symbol} asn: found ${hostnames.size} candidate hostname(s) via reverse DNS`);
  return [...hostnames];
}
