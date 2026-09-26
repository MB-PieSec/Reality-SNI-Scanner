import { writeFile } from "node:fs/promises";
import path from "node:path";
import { fetchTopDomains } from "./sources.ts";
import { discoverNeighborDomains, isSampleableIPv4Cidr, isValidIPv4 } from "./asn.ts";
import {
  discoverCTSubdomains,
  CTDiscoveryMode,
  CTSource,
  DEFAULT_CT_SEEDS,
  DEFAULT_CT_BUDGET_MS,
  describeCTCoverage,
  setCTLogger,
} from "./ctlogs.ts";
import { probeAll, passesFilters } from "./probe.ts";
import { ensureXrayBinary } from "./xray.ts";
import { rankRealityResults, runRealityTests } from "./reality-test.ts";
import type { ProbeResult, RealityTestResult, ScanOptions } from "./types.ts";

function parseArgs(argv: string[]) {
  const flags = new Map<string, string>();
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith("--")) {
        flags.set(key, next);
        i++;
      } else {
        flags.set(key, "true");
      }
    }
  }
  return flags;
}

function printHelp() {
  console.log(`
reality-sni-scanner — auto-discovers and ranks candidate SNI/DEST domains for Xray Reality

No target list required: candidates are sourced automatically from a public
top-domains dataset. Optionally add --target <ip> --neighbors to also
auto-discover domains co-located with your own server.

Usage:
  node run.js [options]

Options:
  --target <ip>        Your Xray server's public IP (required for --neighbors)
  --neighbors           Also discover ASN-neighbor domains around --target
  --prefix <cidr>       Skip the ASN lookup and sample this CIDR block directly
  --ct                  Also discover real subdomains via Certificate Transparency
                         logs (finds things like delivery.mp.microsoft.com that
                         never show up in top-sites lists)
  --ct-seeds <list>      Comma-separated seed domains to query CT logs for
                         (default: microsoft.com,google.com,apple.com,cloudflare.com,
                         amazon.com,akamai.com,fastly.net,wikipedia.org,github.com,mozilla.org)
  --ct-limit <n>         Max total subdomains to pull from CT logs (default 300)
  --ct-timeout <ms>      Total wall-clock budget for one CT discovery phase, shared
                         by every source, retry and fallback (default 10000)
  --ct-source <name>     Which CT source discovery may use: auto (default — crt.sh,
                         then Cert Spotter, then DNS brute-force), crtsh, certspotter, dns
  --ct-refresh           Ignore the ct-cache.json disk cache and refetch everything
  --no-ct                Skip Phase 1.5 subdomain discovery entirely
  --remote              Fetch a live top-domains list instead of the bundled snapshot
                         (falls back to the snapshot automatically if this fails)
  --candidates <n>      How many candidate domains to try (default 400)
  --sample <n>          IPs to sample for reverse-DNS neighbor discovery (default 200)
  --concurrency <n>     Concurrent TLS probes (default 40)
  --port <n>            Port to probe (default 443)
  --timeout <ms>        Per-connection TLS probe timeout in ms (default 4000)
  --asn-timeout <ms>    Per-provider ASN lookup timeout in ms (default 20000 —
                         raise this further on very high-latency connections)
  --top <n>             How many ranked results to print (default 15)
  --out <file>          Write full JSON results here (default results.json)
  --no-require-h2       Don't require ALPN h2 (default: required)
  --no-require-tls13    Don't require TLS 1.3 (default: required)
  --require-authorized  Require a fully valid/trusted cert chain (default: off — Reality doesn't need CA trust, just a plausible cert)
  --reality-test <n>    Stage 2: re-test the top N Stage-1 candidates by pushing a
                         real upload through a temporary Xray Reality tunnel, then
                         rank those N by measured upload speed (default 10, 0 = off)
  --reality-upload-kb <n>  Stage 2 upload payload size in KB (default 512)
  --reality-concurrency <n>  Stage 2 tests to run in parallel, 1-4 (default 2 —
                         each one launches two Xray processes, so keep this low)
  --xray <path>         Use this Xray binary for Stage 2 instead of the cached one
  --help                Show this help

Stage 1 vs Stage 2:
  - Stage 1 is the fast, offline-first TLS 1.3 + HTTP/2 handshake probe. It
    never touches Xray and needs no download.
  - Stage 2 validates the leaders of Stage 1 end to end: it downloads the
    official Xray-core build for your OS into ./bin/ on first use, starts a
    short-lived Xray Reality pair per candidate, pushes an upload through it
    and measures the speed. Expect roughly 5-15 s per candidate plus a one-off
    ~20 MB download on first run, so Stage 2 takes minutes rather than
    seconds. Use --reality-test 0 for a plain TLS-only scan.

Notes:
  - Candidates come from a bundled offline snapshot by default, specifically
    so this tool works over your real, unfiltered network path without
    needing a VPN just to build the candidate list.
  - Phase 1.5 starts its CT discovery in the background while Stage 1 probes,
    walks crt.sh -> Cert Spotter -> DNS brute-force under one --ct-timeout
    budget, and caches what it learns in ct-cache.json for 7 days.
  - Run this WITHOUT a VPN/proxy active if your goal is to find SNI/DEST
    targets that work well for clients on your real (filtered) network —
    tunneling the scan itself defeats the purpose.
`);
}

function readIntegerFlag(
  flags: Map<string, string>,
  name: string,
  defaultValue: number,
  min: number,
  max: number,
): number {
  const raw = flags.get(name);
  if (raw === undefined) return defaultValue;
  if (!/^\d+$/.test(raw)) {
    throw new Error(`--${name} must be an integer between ${min} and ${max}`);
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`--${name} must be an integer between ${min} and ${max}`);
  }
  return value;
}

function dedupeCandidates(
  candidates: { hostname: string; source: ProbeResult["source"] }[],
): { hostname: string; source: ProbeResult["source"] }[] {
  const seen = new Set<string>();
  const out: { hostname: string; source: ProbeResult["source"] }[] = [];
  for (const c of candidates) {
    if (seen.has(c.hostname)) continue;
    seen.add(c.hostname);
    out.push(c);
  }
  return out;
}

/**
 * Ranks probe results with tie-breaking rules:
 * 1. Lower handshake latency is better
 * 2. Better TLS version (TLSv1.3 > TLSv1.2)
 * 3. Authorized certificates are preferred over unauthorized
 * 4. Original hostname source priority (top-sites > ct-log)
 */
function rankProbeResults(results: ProbeResult[]): ProbeResult[] {
  return [...results].sort((a, b) => {
    // Sort by latency (lower is better)
    const latencyA = a.handshakeMs ?? Infinity;
    const latencyB = b.handshakeMs ?? Infinity;
    if (latencyA !== latencyB) return latencyA - latencyB;

    // Tie-breaker 1: TLS version (TLSv1.3 > TLSv1.2)
    const tlsA = (a.tlsVersion?.indexOf("1.3") ?? 0) >= 0 ? 1 : (a.tlsVersion?.indexOf("1.2") ?? 0) >= 0 ? 2 : 3;
    const tlsB = (b.tlsVersion?.indexOf("1.3") ?? 0) >= 0 ? 1 : (b.tlsVersion?.indexOf("1.2") ?? 0) >= 0 ? 2 : 3;
    if (tlsA !== tlsB) return tlsA - tlsB;

    // Tie-breaker 2: Certificate authorization
    const authA = a.authorized ? 1 : 2;
    const authB = b.authorized ? 1 : 2;
    if (authA !== authB) return authA - authB;

    // Tie-breaker 3: Source order for reproducibility
    const sourceOrder: Record<ProbeResult["source"], number> = {
      "top-sites": 1,
      "asn-neighbor": 2,
      "ct-subdomain": 3,
      "ct-log": 4,
      "fallback": 5,
    };
    return sourceOrder[a.source] - sourceOrder[b.source];
  });
}

/** Extract eTLD+1 base domain from a hostname (e.g., "www.google.com" -> "google.com"). */
function extractBaseDomain(hostname: string): string {
  const parts = hostname.split(".");
  if (parts.length <= 2) return hostname;
  // Simple heuristic: return last two parts (handles most common TLDs)
  // For more accuracy, use a proper public suffix list
  return parts.slice(-2).join(".");
}

/**
 * How many base domains the background CT prefetch may warm up. The candidate
 * list is rank-ordered, so its earliest bases are the most plausible Stage 1
 * winners — the prefetch is a best-effort head start, not a guarantee: any
 * base it misses is fetched (inside the normal budget) once Phase 1's real
 * ranking exists.
 */
const CT_PREFETCH_BASE_LIMIT = 40;

/** Unique base domains of the first `limit` candidates, in list order. */
function collectBaseDomains(candidates: { hostname: string }[], limit: number): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const c of candidates) {
    const base = extractBaseDomain(c.hostname);
    if (seen.has(base)) continue;
    seen.add(base);
    out.push(base);
    if (out.length >= limit) break;
  }
  return out;
}

interface Stage2Report {
  options: {
    tested: number;
    uploadKb: number;
    concurrency: number;
    destPort: number;
    xrayPath: string;
  };
  results: RealityTestResult[];
}

function printStage2Table(results: RealityTestResult[]): void {
  const ranked = rankRealityResults(results);
  const okCount = results.filter((r) => r.ok).length;
  console.log(`\nStage 2 — measured upload through a real Reality tunnel (${okCount}/${results.length} passed):\n`);
  const widths = {
    idx: 3,
    hostname: Math.max(8, ...ranked.map((r) => r.hostname.length)) + 2,
    handshakeMs: 13,
    realityUploadKbps: 20,
    status: 8,
  };
  const row = (cells: string[]) =>
    cells
      .map((v, i) => v.padEnd(Object.values(widths)[i]))
      .join("");
  console.log(row(["#", "hostname", "handshakeMs", "realityUploadKbps", "status"]));
  ranked.forEach((r, i) => {
    console.log(
      row([
        String(i + 1),
        r.hostname,
        String(r.handshakeMs ?? "-"),
        r.ok ? String(r.realityUploadKbps ?? "-") : "-",
        r.ok ? "ok" : "failed",
      ]),
    );
  });
  const failed = ranked.filter((r) => !r.ok);
  if (failed.length > 0) {
    console.log("");
    for (const r of failed) console.log(`  [!] ${r.hostname}: ${r.error ?? "failed"}`);
  }
}

/** CLI-derived settings shared by every Certificate Transparency lookup. */
interface CtRuntimeConfig {
  /** False when --no-ct was given: Phase 1.5 (and --ct seed discovery) stay off. */
  enabled: boolean;
  /** Total wall-clock budget for one discovery run (--ct-timeout). */
  budgetMs: number;
  /** Which source(s) discovery may use (--ct-source). */
  source: CTSource;
  /** Cache file path, kept next to the --out report. */
  cacheFile: string;
  /** --ct-refresh: ignore existing cache entries, then rewrite them. */
  refresh: boolean;
}

/**
 * Phase 1.5: Discover subdomains for top domains from Stage 1 and probe them.
 * Returns the best-performing subdomains (full ProbeResult), capped at the original top limit.
 */
async function phase1point5(
  topCandidates: { hostname: string; result: ProbeResult }[],
  opts: ScanOptions,
  topN: number,
  ct: CtRuntimeConfig,
  onProgress?: (done: number, total: number) => void,
): Promise<ProbeResult[]> {
  console.error(`\n[*] phase 1.5: discovering subdomains for top ${Math.min(topN, topCandidates.length)} domains...`);

  const mainDomains = topCandidates
    .slice(0, topN)
    .map((c) => c.hostname);

  // Extract base domains (eTLD+1) from main domains for CT queries
  // e.g., "www.google.com" -> "google.com", "apple.com" -> "apple.com"
  const baseDomains = [...new Set(mainDomains.map(extractBaseDomain))];

  console.error(`[*] phase 1.5: querying CT sources for ${baseDomains.length} base domain(s): ${baseDomains.join(", ")}`);
  console.error(`[*] phase 1.5: budget ${ct.budgetMs}ms, source ${ct.source}, cache ${path.basename(ct.cacheFile)}`);

  try {
    const discovery = await discoverCTSubdomains(baseDomains, {
      totalLimit: topN * 10, // We'll probe many more candidates than we need
      budgetMs: ct.budgetMs,
      mode: CTDiscoveryMode.MAIN_DOMAINS,
      source: ct.source,
      cacheFile: ct.cacheFile,
      refresh: ct.refresh,
    });
    const discoveredSubdomains = discovery.names;
    const coverage = describeCTCoverage(discovery.bySource);

    if (discoveredSubdomains.length === 0) {
      console.error(`[!] phase 1.5: no subdomains discovered (crt.sh, Cert Spotter and DNS brute-force all failed)`);
      return [];
    }

    // Say where the names came from: cache/fallback answers mean the CT
    // enumeration may cover only part of each base domain.
    console.error(`[*] phase 1.5: source coverage: ${coverage}`);
    const usedFallback = Object.keys(discovery.bySource).some((s) => s !== "crtsh");

    // Probe all discovered subdomains
    console.error(`[*] phase 1.5: probing ${discoveredSubdomains.length} discovered subdomains...`);
    const probingResults = await probeAll(
      discoveredSubdomains.map((hostname) => ({ hostname, source: "ct-subdomain" })),
      opts,
      onProgress,
    );

    // Filter passing results and rank them
    const passing = probingResults
      .filter((r) => passesFilters(r, opts));

    // Report *why* the rest were dropped — "0 passed" with no reason is
    // unactionable (timeout storm? TLS version? ALPN?).
    if (passing.length < probingResults.length) {
      const reasons = new Map<string, number>();
      for (const r of probingResults) {
        if (passesFilters(r, opts)) continue;
        const reason = !r.ok
          ? (r.error ?? "connection failed")
          : opts.requireTls13 && r.tlsVersion !== "TLSv1.3"
            ? `tls ${r.tlsVersion ?? "?"}`
            : opts.requireH2 && r.alpn !== "h2"
              ? `alpn ${String(r.alpn)}`
              : opts.requireAuthorized && !r.authorized
                ? "unauthorized"
                : "filtered";
        reasons.set(reason, (reasons.get(reason) ?? 0) + 1);
      }
      const summary = [...reasons.entries()]
        .map(([reason, count]) => `${reason.replace(/\s+/g, " ").trim()} x${count}`)
        .join(", ");
      console.error(`[!] phase 1.5: filters dropped ${probingResults.length - passing.length} subdomain(s): ${summary}`);
    }

    if (passing.length === 0) {
      console.error(`[!] phase 1.5: no subdomains passed filtering`);
      return [];
    }

    console.error(`[+] phase 1.5: ${passing.length} subdomains passed filters`);

    // Rank by latency, TLS version, authorization
    const ranked = rankProbeResults(passing);

    // Take top N
    const selectedSubdomains = ranked.slice(0, topN);

    const widths = {
      idx: 3,
      hostname: Math.max(8, ...selectedSubdomains.map((r) => r.hostname.length)) + 2,
      tls: 10,
      alpn: 8,
      ms: 8,
      authorized: 10,
    };
    const row = (cells: string[]) =>
      cells
        .map((v, i) => v.padEnd(Object.values(widths)[i]))
        .join("");
    // Surface a fallback/cache-backed result in the header itself, so nobody
    // mistakes DNS-wordlist coverage for a full CT enumeration.
    const headerNote = usedFallback && coverage ? ` [coverage: ${coverage}]` : "";
    console.log(`\nPhase 1.5 — best subdomains (${selectedSubdomains.length}/${passing.length})${headerNote}:\n`);
    console.log(row(["#", "hostname", "tls", "alpn", "ms", "authorized"]));
    selectedSubdomains.forEach((r, i) => {
      console.log(
        row([
          String(i + 1),
          r.hostname,
          r.tlsVersion ?? "-",
          String(r.alpn ?? "-"),
          String(r.handshakeMs ?? "-"),
          String(r.authorized ?? "-"),
        ]),
      );
    });

    return selectedSubdomains;
  } catch (err) {
    console.error(`[!] phase 1.5 skipped: ${err instanceof Error ? err.message : String(err)}`);
    return [];
  }
}

async function main() {
  const flags = parseArgs(process.argv.slice(2));
  if (flags.has("help")) {
    printHelp();
    return;
  }

  const opts: ScanOptions = {
    candidateCount: readIntegerFlag(flags, "candidates", 400, 1, 10_000),
    concurrency: readIntegerFlag(flags, "concurrency", 40, 1, 200),
    port: readIntegerFlag(flags, "port", 443, 1, 65_535),
    timeoutMs: readIntegerFlag(flags, "timeout", 4000, 100, 120_000),
    requireH2: !flags.has("no-require-h2"),
    requireTls13: !flags.has("no-require-tls13"),
    requireAuthorized: flags.has("require-authorized"),
  };
  const topN = readIntegerFlag(flags, "top", 15, 1, 10_000);
  const outFile = flags.get("out") ?? "results.json";
  const useNeighbors = flags.has("neighbors");
  const targetIp = flags.get("target");
  const useRemote = flags.has("remote");
  const explicitPrefix = flags.get("prefix");
  const asnTimeoutMs = readIntegerFlag(flags, "asn-timeout", 20_000, 100, 300_000);
  const realityTestCount = readIntegerFlag(flags, "reality-test", 10, 0, 100);
  const realityUploadKb = readIntegerFlag(flags, "reality-upload-kb", 512, 1, 16_384);
  const realityConcurrency = readIntegerFlag(flags, "reality-concurrency", 2, 1, 4);
  const xrayOverride = flags.get("xray");
  if (xrayOverride === "true") {
    throw new Error("--xray requires a path to an Xray binary");
  }

  // ---------------------------------------------------- Certificate Transparency
  // --ct-timeout is ONE wall-clock budget per discovery run, shared by every
  // source, retry and fallback in the chain, so a dead provider can never
  // stack up (N base domains x attempts x per-request timeout) on a big scan.
  const rawCtSource = flags.get("ct-source");
  if (rawCtSource === "true") {
    throw new Error("--ct-source requires one of: auto, crtsh, certspotter, dns");
  }
  const ctSource = (rawCtSource ?? CTSource.AUTO) as CTSource;
  if (!Object.values(CTSource).includes(ctSource)) {
    throw new Error("--ct-source must be one of: auto, crtsh, certspotter, dns");
  }
  const ct: CtRuntimeConfig = {
    enabled: !flags.has("no-ct"),
    budgetMs: readIntegerFlag(flags, "ct-timeout", DEFAULT_CT_BUDGET_MS, 1_000, 600_000),
    source: ctSource,
    // Kept next to the report: whatever --out points at, the cache sits beside it.
    cacheFile: path.join(path.dirname(outFile), "ct-cache.json"),
    refresh: flags.has("ct-refresh"),
  };

  if (useNeighbors && !targetIp && !explicitPrefix) {
    console.error("[x] Error: --neighbors requires --target <ip> (or --prefix <cidr> to skip the lookup)");
    process.exit(1);
  }
  if (targetIp && !isValidIPv4(targetIp)) {
    throw new Error("--target must be a valid IPv4 address");
  }
  if (explicitPrefix && !isSampleableIPv4Cidr(explicitPrefix)) {
    throw new Error("--prefix must be an IPv4 CIDR from /16 through /32");
  }

  console.error(
    `[*] main: loading ${opts.candidateCount} candidate domains (${useRemote ? "live fetch" : "bundled offline snapshot"})...`,
  );
  const topSites = await fetchTopDomains(opts.candidateCount, useRemote);

  let neighborDomains: string[] = [];
  if (useNeighbors) {
    const sampleSize = readIntegerFlag(flags, "sample", 200, 0, 10_000);
    neighborDomains = await discoverNeighborDomains(
      targetIp ?? "0.0.0.0",
      sampleSize,
      asnTimeoutMs,
      explicitPrefix,
    );
  }

  let ctDomains: string[] = [];
  if (flags.has("ct")) {
    if (!ct.enabled) {
      console.error("[i] main: --no-ct given, skipping the --ct seed discovery too");
    } else {
      const seeds = flags.has("ct-seeds")
        ? flags.get("ct-seeds")!.split(",").map((s) => s.trim()).filter(Boolean)
        : DEFAULT_CT_SEEDS;
      const ctLimit = readIntegerFlag(flags, "ct-limit", 300, 1, 5_000);
      console.error(`[*] main: querying CT logs for ${seeds.length} seed domain(s) (budget ${ct.budgetMs}ms)...`);
      ctDomains = (
        await discoverCTSubdomains(seeds, {
          totalLimit: ctLimit,
          budgetMs: ct.budgetMs,
          mode: CTDiscoveryMode.SEEDS,
          source: ct.source,
          cacheFile: ct.cacheFile,
          refresh: ct.refresh,
        })
      ).names;
    }
  }

  const candidates = dedupeCandidates([
    ...topSites.map((hostname) => ({ hostname, source: "top-sites" as const })),
    ...neighborDomains.map((hostname) => ({ hostname, source: "asn-neighbor" as const })),
    ...ctDomains.map((hostname) => ({ hostname, source: "ct-log" as const })),
  ]);

  // ----------------------------------------------------------- CT prefetch
  // Phase 1.5 can only ask about the bases of Phase 1's *winners*, which are
  // unknown until Phase 1 finishes — but the expensive half of CT discovery
  // (provider latency, a cold cache) does not depend on which bases win. So
  // start a speculative prefetch over the first candidate bases now, with its
  // log lines buffered so they cannot garble the \r progress line, and stop
  // it the moment Phase 1's ranking is ready. Phase 1.5 then reuses whatever
  // this warmed up and fetches the rest inside its own budget, so the serial
  // cost added after Phase 1 is still at most one budget window.
  let ctPrefetch: Promise<void> | null = null;
  let ctPrefetchStop: AbortController | null = null;
  const ctPrefetchLines: string[] = [];
  if (ct.enabled && candidates.length > 0) {
    const prefetchBases = collectBaseDomains(candidates, CT_PREFETCH_BASE_LIMIT);
    if (prefetchBases.length > 0) {
      console.error(
        `[i] ctlogs: background CT prefetch started for ${prefetchBases.length} base domain(s) — its log lines print after phase 1`,
      );
      ctPrefetchStop = new AbortController();
      const stopSignal = ctPrefetchStop.signal;
      setCTLogger((line) => ctPrefetchLines.push(line));
      ctPrefetch = discoverCTSubdomains(prefetchBases, {
        totalLimit: 400,
        budgetMs: ct.budgetMs,
        mode: CTDiscoveryMode.MAIN_DOMAINS,
        source: ct.source,
        cacheFile: ct.cacheFile,
        refresh: ct.refresh,
        signal: stopSignal,
      })
        .then(() => undefined)
        .catch((err) => {
          // Never let a background failure reject un-awaited: it would take
          // the whole run down as an unhandled rejection.
          ctPrefetchLines.push(`[!] ctlogs: background prefetch failed: ${err instanceof Error ? err.message : String(err)}`);
        })
        .finally(() => setCTLogger(null));
    }
  }

  console.error(`[*] main: probing ${candidates.length} candidates on port ${opts.port} (concurrency ${opts.concurrency})...`);
  console.error("[i] measurement scope: this process -> candidate. Run this command on the Xray server too to validate the server -> DEST path.");

  let lastPrinted = 0;
  const results = await probeAll(candidates, opts, (done, total) => {
    const pct = Math.floor((done / total) * 20); // 0-20% for Phase 1
    if (pct > lastPrinted) {
      lastPrinted = pct;
      process.stderr.write(`\r[*] progress: ${done}/${total} (phase 1)`);
    }
  });
  process.stderr.write("\n");

  const passing = results
    .filter((r) => passesFilters(r, opts))
    .sort((a, b) => (a.handshakeMs ?? Infinity) - (b.handshakeMs ?? Infinity));

  await writeFile(outFile, JSON.stringify({ options: opts, results }, null, 2));
  console.error(`[+] main: full results (including failures) written to ${outFile}`);

  // The prefetch has served its purpose once the ranking exists: cancel it
  // (in-flight requests abort immediately, partial results are kept and the
  // cache is written) and replay its buffered log lines. Ordering users see:
  // phase 1 progress -> results.json written -> prefetch output -> phase 1.5.
  if (ctPrefetch && ctPrefetchStop) {
    ctPrefetchStop.abort();
    await ctPrefetch;
    if (ctPrefetchLines.length > 0) {
      console.error("[i] ctlogs: background prefetch output (produced during phase 1):");
      for (const line of ctPrefetchLines) console.error(line);
    }
  }

  // ---------------------------------------------------------------- Phase 1.5
  // Discover subdomains for top-stage-1 domains and probe them
  let subdomainResults: ProbeResult[] = [];
  if (ct.enabled && passing.length > 0) {
    const stage1TopHostnames = passing
      .slice(0, topN)
      .map((r) => ({ hostname: r.hostname, result: r }));

    subdomainResults = await phase1point5(stage1TopHostnames, opts, topN, ct, (done, total) => {
      const pct = Math.floor((done / total) / 2 * 20) + 20; // Append to Stage 1 progress
      if (pct > lastPrinted) {
        lastPrinted = Math.min(pct, 39);
        process.stderr.write(`\r[*] progress: ${done}/${total} (phase 1.5)`);
      }
    });
  } else if (!ct.enabled && passing.length > 0) {
    console.error("[*] phase 1.5: skipped (--no-ct)");
  }
  process.stderr.write("\n");

  // ---------------------------------------------------------------- Merge Phase 1 + Phase 1.5
  // Combine original passing domains with discovered subdomains, re-rank, and take top N
  let finalCandidates: ProbeResult[] = [...passing];
  if (subdomainResults.length > 0) {
    // Add subdomain results to the pool
    finalCandidates = [...finalCandidates, ...subdomainResults];
    // Re-rank first (so fastest comes first)
    finalCandidates = rankProbeResults(finalCandidates);
    // Deduplicate by base domain (eTLD+1) - www.blogger.com and blogger.com are the same
    // Since we already ranked by latency, keep the first (fastest) for each base domain
    const seen = new Set<string>();
    finalCandidates = finalCandidates.filter((r) => {
      const base = extractBaseDomain(r.hostname);
      if (seen.has(base)) return false;
      seen.add(base);
      return true;
    });
    // Take top N from combined pool
    finalCandidates = finalCandidates.slice(0, topN);
    console.error(`[+] merged: ${passing.length} Phase 1 + ${subdomainResults.length} Phase 1.5 = ${finalCandidates.length} final candidates (deduped by base domain)`);
  }

  // Print final combined results
  console.log(`\nTop ${Math.min(topN, finalCandidates.length)} of ${finalCandidates.length} final candidates (Phase 1 + Phase 1.5):\n`);
  const shown = finalCandidates.slice(0, topN);
  const widths = {
    idx: 3,
    hostname: Math.max(8, ...shown.map((r) => r.hostname.length)) + 2,
    source: 14,
    tls: 10,
    alpn: 8,
    ms: 8,
    authorized: 10,
  };
  const row = (cells: string[]) =>
    cells
      .map((v, i) => v.padEnd(Object.values(widths)[i]))
      .join("");
  console.log(row(["#", "hostname", "source", "tls", "alpn", "ms", "authorized"]));
  shown.forEach((r: ProbeResult, i) => {
    console.log(
      row([
        String(i + 1),
        r.hostname,
        r.source,
        r.tlsVersion ?? "-",
        String(r.alpn ?? "-"),
        String(r.handshakeMs ?? "-"),
        String(r.authorized ?? "-"),
      ]),
    );
  });

  // ---------------------------------------------------------------- Stage 2
  // Re-test the best candidates through a real (temporary) Xray
  // Reality tunnel. Uses the merged final candidates.
  // Stage-1 results are already on disk, so a Stage-2 problem can never lose them.
  let stage2: Stage2Report | undefined;
  if (realityTestCount > 0 && finalCandidates.length > 0) {
    const tested = finalCandidates
      .slice(0, realityTestCount)
      .map((r) => ({ hostname: r.hostname, handshakeMs: r.handshakeMs }));
    console.error(`\n[*] stage 2: starting full Reality tunnel test on top ${tested.length} domains.`);
    console.error("[*] stage 2: this will launch multiple Xray processes and may take several minutes...");

    let sawProgress = false;
    let progressLineLength = 0;
    try {
      const xrayPath = await ensureXrayBinary(xrayOverride);
      const results = await runRealityTests(
        tested,
        {
          uploadKb: realityUploadKb,
          concurrency: realityConcurrency,
          xrayPath,
          destPort: opts.port,
        },
        (done, total, result) => {
          sawProgress = true;
          const line = `[*] stage 2 progress: ${done}/${total} (${result.ok ? "ok" : "failed"})`;
          // Redrawing with \r does not erase: "(failed)" is 4 chars longer than
          // "(ok)", so without padding a success after a failure would leave a
          // "led)" tail on screen. Wipe whatever the previous line left over.
          const pad = " ".repeat(Math.max(0, progressLineLength - line.length));
          progressLineLength = line.length;
          process.stderr.write(`\r${line}${pad}`);
        },
      );
      if (sawProgress) process.stderr.write("\n");
      stage2 = {
        options: {
          tested: tested.length,
          uploadKb: realityUploadKb,
          concurrency: realityConcurrency,
          destPort: opts.port,
          xrayPath,
        },
        results,
      };
    } catch (err) {
      if (sawProgress) process.stderr.write("\n");
      console.error(`[!] stage 2 skipped: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  if (stage2) {
    printStage2Table(stage2.results);
    await writeFile(outFile, JSON.stringify({ options: opts, results, stage2 }, null, 2));
    console.error(`[+] main: Stage 1 + Stage 2 results written to ${outFile}`);
  }

  const stage2Winner = stage2 ? rankRealityResults(stage2.results).find((r) => r.ok) : undefined;
  if (stage2Winner) {
    const source = subdomainResults.length > 0 ? "Phase 1.5 subdomain" : "Stage 1 main domain";
    console.log(`\nBest pick (${source}): ${stage2Winner.hostname}`);
    console.log(
      `${stage2Winner.realityUploadKbps ?? "-"} kbps measured upload through a real Reality tunnel ` +
        `(Stage 1/Phase 1.5 handshake ${stage2Winner.handshakeMs ?? "-"} ms)`,
    );
    console.log(`Use in your Reality config as both SNI and DEST, e.g.:`);
    console.log(`  "dest": "${stage2Winner.hostname}:443",`);
    console.log(`  "serverNames": ["${stage2Winner.hostname}"]`);
  } else {
    if (stage2) {
      console.error("[!] stage 2: no candidate completed the tunnel test — falling back to the Stage 1/1.5 pick.");
    }
    if (finalCandidates.length > 0) {
      const best = finalCandidates[0];
      console.log(`\nBest pick: ${best.hostname}`);
      console.log(`Use in your Reality config as both SNI and DEST, e.g.:`);
      console.log(`  "dest": "${best.hostname}:443",`);
      console.log(`  "serverNames": ["${best.hostname}"]`);
    } else {
      console.log("\n[!] No candidates passed the filters — try relaxing them (--no-require-h2) or increasing --candidates.");
    }
  }
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error("[x] Fatal error:", err);
    process.exit(1);
  });
