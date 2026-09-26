import tls from "node:tls";
import net from "node:net";
import { promises as dns } from "node:dns";
import type { ProbeResult, ScanOptions } from "./types.ts";

type DnsOutcome =
  | { kind: "ok"; ips: string[] }
  | { kind: "error"; message: string }
  | { kind: "timeout" };

/**
 * Resolve a hostname through c-ares (`dns.resolve4/resolve6`) instead of
 * letting `tls.connect` call getaddrinfo internally.
 *
 * Why: on some systems (observed on Windows) the getaddrinfo path stalls
 * for 10–20s after bursts of DNS/TLS activity — e.g. right after CT
 * discovery runs — while c-ares answers in ~1ms during the very same
 * window. Probes with a 3s budget would otherwise ALL fail with
 * "timeout". We then connect to the resolved IP with `servername` set,
 * so SNI, ALPN and certificate identity checks stay identical.
 *
 * Both lookups are given rejection handlers up front, so losing the race
 * against the budget clock can never surface as an unhandled rejection.
 */
async function resolveAddresses(
  hostname: string,
  budgetMs: number,
): Promise<DnsOutcome> {
  if (net.isIP(hostname)) return { kind: "ok", ips: [hostname] };
  if (budgetMs <= 0) return { kind: "timeout" };

  let timer: NodeJS.Timeout | undefined;
  const clock = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error("dns budget exceeded")), budgetMs);
  });
  const both = Promise.all([
    dns.resolve4(hostname).then(
      (ips) => ({ ips, err: undefined as Error | undefined }),
      (err: Error) => ({ ips: [] as string[], err }),
    ),
    dns.resolve6(hostname).then(
      (ips) => ({ ips, err: undefined as Error | undefined }),
      (err: Error) => ({ ips: [] as string[], err }),
    ),
  ]);

  try {
    // Prefer A over AAAA: connecting to the first v4 address matches what
    // the OS resolver would have offered on a typical dual-stack network.
    const [v4, v6] = await Promise.race([both, clock]);
    const ips = v4.ips.length > 0 ? v4.ips : v6.ips;
    if (ips.length > 0) return { kind: "ok", ips };
    return { kind: "error", message: v4.err?.message ?? v6.err?.message ?? "ENOTFOUND" };
  } catch {
    return { kind: "timeout" };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Opens a real TLS connection to hostname:port with SNI = hostname,
 * requests ALPN h2, and measures how it behaves. This is the check that
 * matters for Reality: your DEST/SNI target must terminate TLS 1.3, ideally
 * speak h2, and present a normal, currently-valid certificate — otherwise
 * the disguise falls apart under inspection.
 */
async function probeOne(
  hostname: string,
  port: number,
  timeoutMs: number,
): Promise<Omit<ProbeResult, "source" | "hostname">> {
  const start = performance.now();
  const remaining = () => timeoutMs - (performance.now() - start);

  // Phase 1: name resolution (stall-proof path, see resolveAddresses).
  const resolved = await resolveAddresses(hostname, remaining());
  if (resolved.kind === "timeout") return { ok: false, error: "timeout" };
  if (resolved.kind === "error") return { ok: false, error: resolved.message };

  // Phase 2: TLS handshake, with whatever is left of the probe budget.
  const budget = Math.max(1, Math.round(remaining()));
  return new Promise((resolve) => {
    let settled = false;

    const socket = tls.connect(
      {
        host: resolved.ips[0],
        port,
        servername: hostname,
        ALPNProtocols: ["h2", "http/1.1"],
        minVersion: "TLSv1.3",
        timeout: budget,
        // We want to see the real cert outcome ourselves, not have the
        // connection throw on a self-signed/mismatched cert.
        rejectUnauthorized: false,
      },
      () => {
        if (settled) return;
        settled = true;
        const handshakeMs = Math.round(performance.now() - start);
        const cert = socket.getPeerCertificate();
        const issuerField = cert?.issuer?.O ?? cert?.issuer?.CN;
        resolve({
          ok: true,
          tlsVersion: socket.getProtocol() ?? undefined,
          alpn: socket.alpnProtocol ?? false,
          handshakeMs,
          authorized: socket.authorized,
          issuer: Array.isArray(issuerField) ? issuerField[0] : issuerField,
        });
        socket.destroy();
      },
    );

    socket.on("timeout", () => {
      if (settled) return;
      settled = true;
      resolve({ ok: false, error: "timeout" });
      socket.destroy();
    });

    socket.on("error", (err) => {
      if (settled) return;
      settled = true;
      resolve({ ok: false, error: err.message });
    });
  });
}

/** Simple fixed-size worker pool so we don't open thousands of sockets at once. */
async function runPool<T, R>(
  items: T[],
  concurrency: number,
  worker: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let nextIndex = 0;

  async function runWorker() {
    while (nextIndex < items.length) {
      const i = nextIndex++;
      results[i] = await worker(items[i]);
    }
  }

  const workers = Array.from(
    { length: Math.min(concurrency, items.length) },
    runWorker,
  );
  await Promise.all(workers);
  return results;
}

export async function probeAll(
  candidates: { hostname: string; source: ProbeResult["source"] }[],
  opts: ScanOptions,
  onProgress?: (done: number, total: number) => void,
): Promise<ProbeResult[]> {
  let done = 0;
  const results = await runPool(candidates, opts.concurrency, async (c) => {
    const r = await probeOne(c.hostname, opts.port, opts.timeoutMs);
    done++;
    onProgress?.(done, candidates.length);
    return { hostname: c.hostname, source: c.source, ...r };
  });
  return results;
}

/** Applies the pass/fail bar (TLS 1.3, h2, valid cert) an operator asked for. */
export function passesFilters(r: ProbeResult, opts: ScanOptions): boolean {
  if (!r.ok) return false;
  if (opts.requireTls13 && r.tlsVersion !== "TLSv1.3") return false;
  if (opts.requireH2 && r.alpn !== "h2") return false;
  if (opts.requireAuthorized && !r.authorized) return false;
  return true;
}
