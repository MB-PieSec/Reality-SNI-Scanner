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
  sourceLabel,
} from "./ctlogs.ts";
import { probeAll, passesFilters } from "./probe.ts";
import { ensureXrayBinary } from "./xray.ts";
import { rankRealityResults, runRealityTests } from "./reality-test.ts";
import type { ProbeResult, RealityTestResult, ScanOptions } from "./types.ts";
import {
  forPhase,
  buffered,
  finishProgress,
  setVerbosity,
  STAGES,
  Level,
} from "./log.ts";

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
  --ct-timeout <ms>      Total wall-clock time limit for one CT discovery phase,
                         shared by every source, retry and fallback (default 10000)
  --ct-source <name>     Which CT source discovery may use: auto (default — crt.sh,
                         then Cert Spotter, then DNS guessing), crtsh, certspotter, dns
  --ct-refresh           Ignore the ct-cache.json disk cache and refetch everything
  --no-ct                Skip Stage 1.5 subdomain discovery entirely
  --remote              Fetch a live top-domains list instead of the bundled snapshot
                         (falls back to the snapshot automatically if this fails)
  --candidates <n>      How many candidate domains to try (default 400)
  --sample <n>          IPs to sample for reverse-DNS neighbor discovery (default 200)
  --concurrency <n>     Concurrent TLS probes (default 40)
  --port <n>            Port to probe (default 443)
  --timeout <ms>        Per-connection TLS probe timeout in ms (default 4000)
  --asn-timeout <ms>    Per-provider ASN lookup timeout in ms (default 20000 —
                         raise this further on very high-latency connections)
  --top <n>             How many ranked results to print (default 15); also caps
                         how many candidates Stage 2 may re-test
  --out <file>          Write full JSON results here (default results.json)
  --no-require-h2       Don't require ALPN h2 (default: required)
  --no-require-tls13    Don't require TLS 1.3 (default: required)
  --require-authorized  Require a fully valid/trusted cert chain (default: off — Reality doesn't need CA trust, just a plausible cert)
  --reality-test <n>    Stage 2: re-test the top N candidates by pushing a
                         real upload through a temporary Xray Reality tunnel, then
                         rank those N by measured upload speed
                         (default: min(10, --top); 0 = off)
  --reality-upload-kb <n>  Stage 2 upload payload size in KB (default 512)
  --reality-concurrency <n>  Stage 2 tests to run in parallel, 1-4 (default 2 —
                         each one launches two Xray processes, so keep this low)
  --xray <path>         Use this Xray binary for Stage 2 instead of the cached one
  --verbose, -v         Enable debug logging (also set REALITY_DEBUG_LOG=1)
  --quiet, -q           Suppress all non-error output
  --help                Show this help

Stages (run in this order):
  - Stage 1: fast TLS 1.3 + HTTP/2 handshake probe (no Xray, no download).
  - Stage 1.5: discovers subdomains of Stage 1's best domains using CT logs
    (crt.sh -> Cert Spotter -> DNS guessing) and probes them with the same
    TLS check. Starts in the background while Stage 1 probes; its lines are
    buffered and replayed under a "--- stage 1.5 ---" banner after Stage 1.
    Cached in ct-cache.json for 7 days (--ct-refresh to refetch, --no-ct to
    skip).
  - Stage 2: validates the leaders of Stage 1 + 1.5 end-to-end by launching
    temporary Xray Reality tunnels and measuring upload speed. Roughly
    5-15 s per candidate. Use --reality-test 0 for a TLS-only scan.

Log output (stderr; stdout is reserved for the result tables):
  [i]  info     what is happening right now
  [+]  success  something completed well
  [!]  warn     something failed, but the run continues
  [x]  error    something failed and the run stopped or degraded
  [~]  debug    verbose internals (--verbose only)
  Each line is prefixed with the stage or module that wrote it, e.g.
  "[i] stage 1.5: ..." or "[!] asn: ...". Progress bars redraw in place
  with a carriage return and always end with a newline.

Notes:
  - Candidates come from a bundled offline snapshot by default, specifically
    so this tool works over your real, unfiltered network path without
    needing a VPN just to build the candidate list.
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

/**
 * Common two-label public suffixes that show up among this project's own
 * candidate sources (bundled top-domains.json, --remote, --ct discovery),
 * e.g. bbc.co.uk, ig.com.br, amazon.co.jp. This is NOT a full Public Suffix
 * List (https://publicsuffix.org/) — just the handful that matter for the
 * domains this tool actually deals with — but it's enough to stop the old
 * "always take the last two labels" heuristic from treating e.g.
 * "bbc.co.uk" and "mirror.co.uk" as the same base domain "co.uk", which
 * corrupted both the Stage 1.5 CT query targeting and the final
 * base-domain dedup.
 */
const TWO_LABEL_PUBLIC_SUFFIXES = new Set([
  "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk",
  "com.br", "gov.br", "net.br", "org.br",
  "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
  "com.au", "net.au", "org.au", "gov.au",
  "co.in", "gov.in", "net.in", "org.in",
  "co.nz", "org.nz", "govt.nz",
  "co.za", "org.za", "gov.za",
  "com.mx", "gob.mx",
  "co.kr", "or.kr", "go.kr",
  "co.id", "or.id", "go.id",
  "com.tr", "gov.tr",
  "com.ar", "gob.ar",
]);

/**
 * Extract eTLD+1 base domain from a hostname (e.g., "www.google.com" ->
 * "google.com", "bbc.co.uk" -> "bbc.co.uk", NOT "co.uk"). Falls back to a
 * simple last-two-labels rule for anything not in the suffix table above —
 * still a heuristic, not a full public-suffix-list lookup, but no longer
 * one that merges every ".co.uk"/".com.br"/".co.jp" site together.
 */
function extractBaseDomain(hostname: string): string {
  const parts = hostname.split(".");
  if (parts.length <= 2) return hostname;
  const lastTwo = parts.slice(-2).join(".");
  if (parts.length >= 3 && TWO_LABEL_PUBLIC_SUFFIXES.has(lastTwo)) {
    return parts.slice(-3).join(".");
  }
  return lastTwo;
}

/**
 * One short, human phrase for why a probe didn't pass, grouped into buckets a
 * reader can act on ("timed out x27") instead of raw OpenSSL blobs — the full
 * per-host error string stays in results.json.
 */
function friendlyProbeFailure(r: ProbeResult, opts: ScanOptions): string {
  if (!r.ok) {
    const lower = (r.error ?? "connection failed").toLowerCase();
    if (lower.includes("timeout")) return "timed out";
    if (/enotfound|enodata|querya |query4 /.test(lower)) return "hostname does not resolve";
    if (lower.includes("econnrefused")) return "connection refused";
    if (lower.includes("econnreset") || lower.includes("socket disconnected")) return "connection dropped";
    if (lower.includes("getaddrinfo")) return "DNS lookup failed";
    if (/alert|handshake|protocol version/.test(lower)) return "rejected the TLS handshake";
    return "connection failed";
  }
  if (opts.requireTls13 && r.tlsVersion !== "TLSv1.3") return `no TLS 1.3 (got ${r.tlsVersion ?? "?"})`;
  if (opts.requireH2 && r.alpn !== "h2") return "no HTTP/2";
  if (opts.requireAuthorized && !r.authorized) return "certificate not trusted";
  return "filtered out";
}

/** "10s" for 10000, "1500ms" for 1500 — how humans say a budget. */
function formatMs(ms: number): string {
  return ms >= 1000 ? `${ms / 1000}s` : `${ms}ms`;
}

/**
 * How many base domains the background CT prefetch may warm up. The candidate
 * list is rank-ordered, so its earliest bases are the most plausible Stage 1
 * winners — the prefetch is a best-effort head start, not a guarantee: any
 * base it misses is fetched (inside the normal budget) once Stage 1's real
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
  /** False when --no-ct was given: Stage 1.5 (and --ct seed discovery) stay off. */
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
 * Stage 1.5: Discover subdomains for top domains from Stage 1 and probe them.
 * Returns the best-performing subdomains (full ProbeResult), capped at the original top limit.
 */
async function stage1point5(
  topCandidates: { hostname: string; result: ProbeResult }[],
  opts: ScanOptions,
  topN: number,
  ct: CtRuntimeConfig,
  onProgress?: (done: number, total: number) => void,
): Promise<ProbeResult[]> {
  const log = forPhase(STAGES[1]);

  const mainDomains = topCandidates
    .slice(0, topN)
    .map((c) => c.hostname);

  // Extract base domains (eTLD+1) from main domains for CT queries
  // e.g., "www.google.com" -> "google.com", "apple.com" -> "apple.com"
  const baseDomains = [...new Set(mainDomains.map(extractBaseDomain))];

  const sourceDesc =
    ct.source === CTSource.AUTO
      ? "crt.sh -> Cert Spotter -> DNS guessing"
      : `${sourceLabel(ct.source)} only (--ct-source ${ct.source})`;
  log.info(`discovering subdomains of ${baseDomains.length} domains: ${baseDomains.join(", ")}`);
  log.info(
    `rules: ${formatMs(ct.budgetMs)} time limit, sources: ${sourceDesc}, results cached in ${path.basename(ct.cacheFile)}`,
  );

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
    // Which sources actually answered — shown in the table header so nobody
    // mistakes DNS-wordlist coverage for a full CT enumeration.
    const headerSources = Object.keys(discovery.bySource)
      .map(sourceLabel)
      .join(", ");

    if (discoveredSubdomains.length === 0) {
      log.warn(`no subdomains found — every source failed or returned nothing (stage 1 results are unaffected)`);
      return [];
    }

    // Probe all discovered subdomains with the same TLS check as stage 1
    log.info(
      `testing ${discoveredSubdomains.length} discovered subdomains with the same TLS check as stage 1...`,
    );
    const probingResults = await probeAll(
      discoveredSubdomains.map((hostname) => ({ hostname, source: "ct-subdomain" })),
      opts,
      onProgress,
    );

    // Filter passing results and rank them
    const passing = probingResults
      .filter((r) => passesFilters(r, opts));

    // Report *why* the rest were dropped — "0 passed" with no reason is
    // unactionable (timeout storm? TLS version? ALPN?). Reasons are grouped
    // into short human phrases; raw errors stay in results.json.
    if (passing.length < probingResults.length) {
      const reasons = new Map<string, number>();
      for (const r of probingResults) {
        if (passesFilters(r, opts)) continue;
        const reason = friendlyProbeFailure(r, opts);
        reasons.set(reason, (reasons.get(reason) ?? 0) + 1);
      }
      const summary = [...reasons.entries()]
        .map(([reason, count]) => `${reason} x${count}`)
        .join(", ");
      log.warn(
        `${probingResults.length - passing.length} of ${probingResults.length} subdomains did not pass: ${summary}`,
      );
    }

    if (passing.length === 0) {
      log.warn(
        `none of the ${probingResults.length} discovered subdomains passed — stage 1 results are unaffected (reasons above)`,
      );
      return [];
    }

    log.success(`${passing.length} of ${probingResults.length} subdomains passed the TLS check`);

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
    // Surface where the names came from in the header itself, so nobody
    // mistakes DNS-wordlist coverage for a full CT enumeration.
    const headerNote = headerSources ? ` [sources: ${headerSources}]` : "";
    console.log(`\nStage 1.5 — best subdomains (${selectedSubdomains.length}/${passing.length})${headerNote}:\n`);
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
    log.error(`skipped: ${err instanceof Error ? err.message : String(err)}`);
    return [];
  }
}

async function main() {
  const flags = parseArgs(process.argv.slice(2));
  if (flags.has("help")) {
    printHelp();
    return;
  }

  // Verbosity from CLI (--verbose/--quiet) or env (REALITY_DEBUG_LOG=1)
  const verbose = flags.has("verbose") || flags.has("v");
  const quiet = flags.has("quiet") || flags.has("q");
  if (verbose) setVerbosity(Level.Debug);
  else if (quiet) setVerbosity(Level.Error); // errors only, per --help
  else if (process.env.REALITY_DEBUG_LOG) setVerbosity(Level.Debug);

  // One logger per stage, plus one for the overall flow: see STAGES in log.ts.
  const mainLog = forPhase("main");
  const stage1Log = forPhase(STAGES[0]);

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
  // Stage 2 re-tests at most 10 candidates and never more than --top, so
  // "--top 5" means five of everything instead of five printed / ten tested.
  const realityTestCount = readIntegerFlag(flags, "reality-test", Math.min(10, topN), 0, 100);
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
    mainLog.error("--neighbors requires --target <ip> (or --prefix <cidr> to skip the lookup)");
    process.exit(1);
  }
  if (targetIp && !isValidIPv4(targetIp)) {
    throw new Error("--target must be a valid IPv4 address");
  }
  if (explicitPrefix && !isSampleableIPv4Cidr(explicitPrefix)) {
    throw new Error("--prefix must be an IPv4 CIDR from /16 through /32");
  }

  mainLog.info(
    `loading ${opts.candidateCount} candidate domains (${useRemote ? "live fetch" : "bundled offline snapshot"})...`,
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
      mainLog.info("--no-ct given, skipping the --ct seed discovery too");
    } else {
      const seeds = flags.has("ct-seeds")
        ? flags.get("ct-seeds")!.split(",").map((s) => s.trim()).filter(Boolean)
        : DEFAULT_CT_SEEDS;
      const ctLimit = readIntegerFlag(flags, "ct-limit", 300, 1, 5_000);
      const ctSeedLog = forPhase("ct seed");
      ctSeedLog.info(
        `querying certificate logs for ${seeds.length} seed domains (time limit ${formatMs(ct.budgetMs)})...`,
      );
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
  // Stage 1.5 can only ask about the bases of Stage 1's *winners*, which are
  // unknown until Stage 1 finishes — but the expensive half of CT discovery
  // (provider latency, a cold cache) does not depend on which bases win. So
  // start a speculative prefetch over the first candidate bases now, with its
  // log lines buffered so they cannot garble the \r progress line, and stop
  // it the moment Stage 1's ranking is ready. Stage 1.5 then reuses whatever
  // this warmed up and fetches the rest inside its own budget, so the serial
  // cost added after Stage 1 is still at most one budget window.
  let ctPrefetch: Promise<void> | null = null;
  let ctPrefetchStop: AbortController | null = null;
  const { logger: prefetchLog, replay: replayPrefetch } = buffered(STAGES[1]);
  if (ct.enabled && candidates.length > 0) {
    const prefetchBases = collectBaseDomains(candidates, CT_PREFETCH_BASE_LIMIT);
    if (prefetchBases.length > 0) {
      prefetchLog.info(
        `background discovery started for ${prefetchBases.length} domains while stage 1 probes — these lines are buffered and replayed below`,
      );
      ctPrefetchStop = new AbortController();
      const stopSignal = ctPrefetchStop.signal;
      ctPrefetch = discoverCTSubdomains(prefetchBases, {
        totalLimit: 400,
        budgetMs: ct.budgetMs,
        mode: CTDiscoveryMode.MAIN_DOMAINS,
        source: ct.source,
        cacheFile: ct.cacheFile,
        refresh: ct.refresh,
        signal: stopSignal,
        logger: prefetchLog,
      })
        .then(() => undefined)
        .catch((err) => {
          // Never let a background failure reject un-awaited: it would take
          // the whole run down as an unhandled rejection.
          prefetchLog.warn(`background discovery failed: ${err instanceof Error ? err.message : String(err)}`);
        });
    }
  }

  stage1Log.banner(
    `${STAGES[0]}: probing ${candidates.length} candidates on port ${opts.port} (concurrency ${opts.concurrency})`,
  );
  stage1Log.info(
    "measuring from this machine to each candidate. To validate your server -> destination path too, run this command on the Xray server itself.",
  );

  const results = await probeAll(candidates, opts, (done, total) => {
    stage1Log.progress(done, total);
  });
  finishProgress();

  const passing = results
    .filter((r) => passesFilters(r, opts))
    .sort((a, b) => (a.handshakeMs ?? Infinity) - (b.handshakeMs ?? Infinity));

  await writeFile(outFile, JSON.stringify({ options: opts, results }, null, 2));
  mainLog.success(`full results (including failures) written to ${outFile}`);

  // The prefetch has served its purpose once the ranking exists: cancel it
  // (in-flight requests abort immediately, partial results are kept and the
  // cache is written) and replay its buffered log lines. Ordering users see:
  // stage 1 progress -> results.json written -> stage 1.5 banner -> prefetch
  // output -> the stage 1.5 discovery for the actual top domains.
  const stage15Log = forPhase(STAGES[1]);
  const stage15Running = ct.enabled && passing.length > 0;
  if (stage15Running) {
    stage15Log.banner(
      `${STAGES[1]}: finding subdomains of your best stage 1 domains (they get the same TLS test)`,
    );
  }
  if (ctPrefetch && ctPrefetchStop) {
    ctPrefetchStop.abort();
    await ctPrefetch;
    replayPrefetch();
  }

  // ---------------------------------------------------------------- Stage 1.5
  // Discover subdomains for top-stage-1 domains and probe them
  let subdomainResults: ProbeResult[] = [];
  if (ct.enabled && passing.length > 0) {
    const stage1TopHostnames = passing
      .slice(0, topN)
      .map((r) => ({ hostname: r.hostname, result: r }));

    subdomainResults = await stage1point5(stage1TopHostnames, opts, topN, ct, (done, total) => {
      stage15Log.progress(done, total);
    });
  } else if (!ct.enabled && passing.length > 0) {
    stage15Log.info("skipped (--no-ct)");
  }
  finishProgress();

  // ---------------------------------------------------------------- Merge Stage 1 + Stage 1.5
  // Combine original passing domains with discovered subdomains, re-rank, and take top N
  let finalCandidates: ProbeResult[] = [...passing];
  if (subdomainResults.length > 0) {
    // Add subdomain results to the pool
    const pooled = finalCandidates.length + subdomainResults.length;
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
    const ranked = finalCandidates.length;
    finalCandidates = finalCandidates.slice(0, topN);
    // Report each reduction separately: "61 + 5 = 5" with only "deduped"
    // attributed to dedupe reads like dedupe threw away 61 results.
    const cuts: string[] = [];
    const dupes = pooled - ranked;
    const beyond = ranked - finalCandidates.length;
    if (dupes > 0) cuts.push(`${dupes} same-base duplicate(s)`);
    if (beyond > 0) cuts.push(`${beyond} beyond --top ${topN}`);
    mainLog.success(
      `merged: ${passing.length} Stage 1 + ${subdomainResults.length} Stage 1.5 = ${ranked} ranked` +
        `${cuts.length ? `, kept ${finalCandidates.length} (${cuts.join(", ")})` : `, kept ${ranked}`}`,
    );
  }

  // Name only the stages that actually contributed to this table.
  const poolLabel = subdomainResults.length > 0 ? "Stage 1 + Stage 1.5" : "Stage 1";

  // Print final combined results
  console.log(`\nTop ${Math.min(topN, finalCandidates.length)} of ${finalCandidates.length} final candidates (${poolLabel}):\n`);
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
    const stage2Log = forPhase(STAGES[2]);
    stage2Log.banner(
      `${STAGES[2]}: re-testing the top ${tested.length} candidates through a real Reality tunnel`,
    );
    stage2Log.info(`each test launches temporary Xray processes (~5-15s each; count set by --reality-test)`);

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
          // The per-result status rides in the label: "(failed)" is longer than
          // "(ok)", which is exactly the case progress() pads against.
          stage2Log.progress(done, total, `${STAGES[2]} (${result.ok ? "ok" : "failed"})`);
        },
      );
      finishProgress();
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
      finishProgress();
      stage2Log.error(`skipped: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  if (stage2) {
    printStage2Table(stage2.results);
    await writeFile(outFile, JSON.stringify({ options: opts, results, stage2 }, null, 2));
    mainLog.success(`Stage 1 + Stage 2 results written to ${outFile}`);
  }

  const stage2Winner = stage2 ? rankRealityResults(stage2.results).find((r) => r.ok) : undefined;
  if (stage2Winner) {
    const source = subdomainResults.length > 0 ? "Stage 1.5 subdomain" : "Stage 1 main domain";
    console.log(`\nBest pick (${source}): ${stage2Winner.hostname}`);
    console.log(
      `${stage2Winner.realityUploadKbps ?? "-"} kbps measured upload through a real Reality tunnel ` +
        `(Stage 1/Stage 1.5 handshake ${stage2Winner.handshakeMs ?? "-"} ms)`,
    );
    console.log(`Use in your Reality config as both SNI and DEST, e.g.:`);
    console.log(`  "dest": "${stage2Winner.hostname}:443",`);
    console.log(`  "serverNames": ["${stage2Winner.hostname}"]`);
  } else {
    if (stage2) {
      mainLog.warn("no candidate completed the tunnel test — falling back to the Stage 1/1.5 pick.");
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
    forPhase("main").error(`fatal: ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
    process.exit(1);
  });