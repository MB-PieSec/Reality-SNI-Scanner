import { writeFile } from "node:fs/promises";
import { fetchTopDomains } from "./sources.ts";
import { discoverNeighborDomains, isSampleableIPv4Cidr, isValidIPv4 } from "./asn.ts";
import { discoverCTSubdomains, DEFAULT_CT_SEEDS } from "./ctlogs.ts";
import { probeAll, passesFilters } from "./probe.ts";
import type { ProbeResult, ScanOptions } from "./types.ts";

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
  --ct-timeout <ms>      Per-seed CT-log query timeout in ms (default 15000)
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
  --help                Show this help

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
    const seeds = flags.has("ct-seeds")
      ? flags.get("ct-seeds")!.split(",").map((s) => s.trim()).filter(Boolean)
      : DEFAULT_CT_SEEDS;
    const ctLimit = readIntegerFlag(flags, "ct-limit", 300, 1, 5_000);
    const ctTimeoutMs = readIntegerFlag(flags, "ct-timeout", 15_000, 100, 300_000);
    console.error(`[*] main: querying CT logs for ${seeds.length} seed domain(s)...`);
    ctDomains = await discoverCTSubdomains(seeds, ctLimit, ctTimeoutMs);
  }

  const candidates = dedupeCandidates([
    ...topSites.map((hostname) => ({ hostname, source: "top-sites" as const })),
    ...neighborDomains.map((hostname) => ({ hostname, source: "asn-neighbor" as const })),
    ...ctDomains.map((hostname) => ({ hostname, source: "ct-log" as const })),
  ]);

  console.error(`[*] main: probing ${candidates.length} candidates on port ${opts.port} (concurrency ${opts.concurrency})...`);
  console.error("[i] measurement scope: this process -> candidate. Run this command on the Xray server too to validate the server -> DEST path.");

  let lastPrinted = 0;
  const results = await probeAll(candidates, opts, (done, total) => {
    const pct = Math.floor((done / total) * 20);
    if (pct > lastPrinted) {
      lastPrinted = pct;
      process.stderr.write(`\r[*] progress: ${done}/${total}`);
    }
  });
  process.stderr.write("\n");

  const passing = results
    .filter((r) => passesFilters(r, opts))
    .sort((a, b) => (a.handshakeMs ?? Infinity) - (b.handshakeMs ?? Infinity));

  await writeFile(outFile, JSON.stringify({ options: opts, results }, null, 2));
  console.error(`[+] main: full results (including failures) written to ${outFile}`);

  console.log(`\nTop ${Math.min(topN, passing.length)} of ${passing.length} qualifying domain(s):\n`);
  const shown = passing.slice(0, topN);
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

  if (passing.length > 0) {
    const best = passing[0];
    console.log(`\nBest pick: ${best.hostname}`);
    console.log(`Use in your Reality config as both SNI and DEST, e.g.:`);
    console.log(`  "dest": "${best.hostname}:443",`);
    console.log(`  "serverNames": ["${best.hostname}"]`);
  } else {
    console.log("\n[!] No candidates passed the filters — try relaxing them (--no-require-h2) or increasing --candidates.");
  }
}

main().catch((err) => {
  console.error("[x] Fatal error:", err);
  process.exit(1);
});
