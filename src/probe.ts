import tls from "node:tls";
import type { ProbeResult, ScanOptions } from "./types.ts";

/**
 * Opens a real TLS connection to hostname:port with SNI = hostname,
 * requests ALPN h2, and measures how it behaves. This is the check that
 * matters for Reality: your DEST/SNI target must terminate TLS 1.3, ideally
 * speak h2, and present a normal, currently-valid certificate — otherwise
 * the disguise falls apart under inspection.
 */
function probeOne(
  hostname: string,
  port: number,
  timeoutMs: number,
): Promise<Omit<ProbeResult, "source" | "hostname">> {
  return new Promise((resolve) => {
    const start = performance.now();
    let settled = false;

    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname,
        ALPNProtocols: ["h2", "http/1.1"],
        minVersion: "TLSv1.3",
        timeout: timeoutMs,
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
