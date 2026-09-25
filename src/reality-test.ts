/**
 * Stage 2: verify the best Stage-1 candidates by pushing real traffic through
 * an actual Xray REALITY tunnel.
 *
 * For every candidate this starts a short-lived pair of Xray processes:
 *
 *     this process --TCP--> [Xray client] ==REALITY==> [Xray server] --TCP--> sink (this process)
 *
 * The server's REALITY dest is the candidate domain, so the whole path only
 * works if that domain really is reachable on the expected port and really
 * answers with a usable TLS 1.3 ServerHello — which is exactly what Xray
 * needs from a dest in production. The upload is timed end to end, from
 * opening the local connection to the last byte landing in the sink, so the
 * number includes the REALITY handshake and the server's round trip to the
 * candidate.
 *
 * Everything is torn down per candidate: both processes are killed and the
 * temporary config files removed in a finally block, and Ctrl+C kills whatever
 * is still running.
 *
 * When a candidate fails, the tail of both Xray logs is folded into the error
 * message, because REALITY's own diagnostics say exactly which step of the
 * handshake went wrong. Set REALITY_DEBUG_LOG=1 to additionally dump the full
 * logs of every candidate and turn on REALITY's verbose per-record handshake
 * trace (which record the dest sent and where the handshake aborted).
 */

import { spawn, type ChildProcess } from "node:child_process";
import { randomFillSync } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { buildClientConfig, buildServerConfig } from "./reality-config.ts";
import type { RealityTestCandidate, RealityTestOptions, RealityTestResult } from "./types.ts";

/** Budget for spawning Xray and seeing it accept connections. */
const STARTUP_TIMEOUT_MS = 8_000;
/**
 * First connection through the tunnel, not measured. On startup Xray probes
 * the dest to learn how many post-handshake records the real site sends, and
 * an authenticated connection that arrives while that probe is still running
 * waits for it (re-checked every 5s). Spending that wait here instead of
 * inside the timed run keeps candidates comparable, and needs enough headroom
 * for a slow probe: dial + TLS handshake + a 5s read deadline, then the next
 * 5s re-check.
 */
const WARMUP_TIMEOUT_MS = 20_000;
const UPLOAD_TIMEOUT_MS = 15_000;
const WARMUP_BYTES = 16 * 1024;
/** Kept in memory only, and only read when a candidate fails. */
const LOG_TAIL_BYTES = 16 * 1024;
const LOG_SNIPPET_CHARS = 160;
/** Startup failures are usually a port race, so they are worth one retry. */
const MAX_ATTEMPTS = 2;

/** Xray refusing to start/listen — retryable, as opposed to a candidate failing. */
class StartupError extends Error {}

interface XrayInstance {
  child: ChildProcess;
  logs(): string;
}

const liveChildren = new Set<ChildProcess>();
let signalsInstalled = false;

/** Makes sure a Ctrl+C (or an ordinary exit) never leaves Xray processes behind. */
function installSignalHandlers(): void {
  if (signalsInstalled) return;
  signalsInstalled = true;

  const killAll = () => {
    for (const child of liveChildren) {
      try {
        child.kill("SIGTERM");
      } catch {
        // already gone
      }
    }
  };

  process.on("SIGINT", () => {
    console.error("\n[!] stage 2 interrupted — stopping Xray processes");
    killAll();
    process.exit(130);
  });
  process.on("SIGTERM", () => {
    killAll();
    process.exit(143);
  });
  process.on("exit", killAll);
}

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Drops Xray's `2026/09/25 23:43:00.340724 [Info] ` prefix. */
function stripLogPrefix(line: string): string {
  return line.replace(/^\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}\.\d+ \[[^\]]+\]\s*/, "");
}

/**
 * A short, human-sized reason from a failed Xray instance: enough to tell a
 * rejected handshake from a startup problem without printing a wall of log
 * that reads like a crash. The complete logs for both sides are one
 * REALITY_DEBUG_LOG away.
 */
function logSnippet(instance: XrayInstance | undefined): string {
  if (!instance) return "";
  const lines = instance
    .logs()
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !/Reading config/.test(line));
  if (lines.length === 0) return "";

  // REALITY states its verdict plainly. The timestamp, level, logger and
  // address around it are noise, and a retrying client logs the same verdict
  // several times, so collect the distinct ones.
  const reasons = new Set<string>();
  for (const line of lines) {
    const match = line.match(/REALITY: processed invalid connection from .*?: (.+)$/);
    if (match) reasons.add(match[1]);
  }
  const chosen = reasons.size > 0 ? [...reasons] : [stripLogPrefix(lines[lines.length - 1])];
  return chosen.join("; ").slice(0, LOG_SNIPPET_CHARS);
}

function spawnXray(binPath: string, configPath: string): XrayInstance {
  const child = spawn(binPath, ["run", "-c", configPath], {
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });

  let buffer = "";
  const collect = (chunk: Buffer | string) => {
    buffer += String(chunk);
    if (buffer.length > LOG_TAIL_BYTES) buffer = buffer.slice(-LOG_TAIL_BYTES);
  };
  child.stdout?.on("data", collect);
  child.stderr?.on("data", collect);
  child.on("error", (err) => collect(`\nspawn error: ${err.message}`));

  liveChildren.add(child);
  child.on("exit", () => liveChildren.delete(child));

  return { child, logs: () => buffer };
}

function stopChild(child: ChildProcess | undefined): void {
  if (!child || child.exitCode !== null || child.killed) return;
  try {
    child.kill("SIGTERM");
  } catch {
    return;
  }
  const timer = setTimeout(() => {
    if (child.exitCode === null) {
      try {
        child.kill("SIGKILL");
      } catch {
        // already gone
      }
    }
  }, 1_000);
  timer.unref();
}

function connectTo(port: number, timeoutMs: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: "127.0.0.1", port });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`no connection to 127.0.0.1:${port} within ${timeoutMs}ms`));
    }, timeoutMs);
    socket.once("connect", () => {
      clearTimeout(timer);
      resolve(socket);
    });
    socket.once("error", (err) => {
      clearTimeout(timer);
      socket.destroy();
      reject(err);
    });
  });
}

/** Resolves once something is listening on the port, or throws StartupError. */
async function waitForPort(
  port: number,
  timeoutMs: number,
  instance: XrayInstance,
  label: string,
): Promise<void> {
  const deadline = performance.now() + timeoutMs;
  while (performance.now() < deadline) {
    if (instance.child.exitCode !== null) {
      throw new StartupError(
        `${label} Xray exited with code ${instance.child.exitCode}: ${logSnippet(instance)}`,
      );
    }
    try {
      const socket = await connectTo(port, 500);
      socket.destroy();
      // A port can be taken by something else between reserving it and Xray
      // binding it. If that happened our connect succeeded against a stranger
      // and this Xray is on its way out, so let it die and treat it as a
      // startup failure worth one retry.
      await delay(150);
      if (instance.child.exitCode !== null) {
        throw new StartupError(
          `${label} Xray lost 127.0.0.1:${port} to another process (exit code ${instance.child.exitCode})`,
        );
      }
      return;
    } catch (err) {
      if (err instanceof StartupError) throw err;
      await delay(100);
    }
  }
  throw new StartupError(`${label} Xray did not listen on 127.0.0.1:${port} in ${timeoutMs}ms: ${logSnippet(instance)}`);
}

/**
 * Loopback sink that swallows uploaded bytes and counts them. It exists so the
 * upload has somewhere to land without depending on any third-party endpoint.
 */
interface Sink {
  port: number;
  received(): number;
  reset(): void;
  waitForBytes(target: number, timeoutMs: number): Promise<void>;
  close(): Promise<void>;
}

interface SinkWaiter {
  target: number;
  timer?: ReturnType<typeof setTimeout>;
  resolve(): void;
  reject(err: Error): void;
}

function createSink(): Promise<Sink> {
  return new Promise((resolve, reject) => {
    let receivedBytes = 0;
    const sockets = new Set<net.Socket>();
    const waiters = new Set<SinkWaiter>();

    const settleAll = (err: Error) => {
      for (const waiter of [...waiters]) {
        clearTimeout(waiter.timer);
        waiters.delete(waiter);
        waiter.reject(err);
      }
    };

    const server = net.createServer((socket) => {
      sockets.add(socket);
      socket.on("error", () => {
        // a failed upload surfaces as a byte-count timeout, not as an exception
      });
      socket.on("close", () => sockets.delete(socket));
      socket.on("data", (chunk: Buffer) => {
        receivedBytes += chunk.length;
        for (const waiter of [...waiters]) {
          if (receivedBytes >= waiter.target) {
            clearTimeout(waiter.timer);
            waiters.delete(waiter);
            waiter.resolve();
          }
        }
      });
    });

    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as net.AddressInfo;
      resolve({
        port: address.port,
        received: () => receivedBytes,
        reset: () => {
          receivedBytes = 0;
        },
        waitForBytes: (target, timeoutMs) =>
          new Promise<void>((res, rej) => {
            if (receivedBytes >= target) return;
            const waiter: SinkWaiter = { target, resolve: res, reject: rej };
            waiter.timer = setTimeout(() => {
              waiters.delete(waiter);
              rej(new Error(`only ${receivedBytes} of ${target} bytes arrived within ${timeoutMs}ms`));
            }, timeoutMs);
            waiters.add(waiter);
          }),
        close: async () => {
          settleAll(new Error("sink closed"));
          for (const socket of sockets) socket.destroy();
          await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
        },
      });
    });
  });
}

/** Asks the OS for free loopback ports while the probes are still open, so two calls cannot hand back the same one. */
async function reserveFreePorts(count: number): Promise<number[]> {
  const servers: net.Server[] = [];
  try {
    for (let i = 0; i < count; i++) {
      servers.push(
        await new Promise<net.Server>((resolvePort, rejectPort) => {
          const probe = net.createServer();
          probe.once("error", rejectPort);
          probe.listen(0, "127.0.0.1", () => resolvePort(probe));
        }),
      );
    }
    return servers.map((probe) => (probe.address() as net.AddressInfo).port);
  } finally {
    await Promise.all(servers.map((probe) => new Promise<void>((done) => probe.close(() => done()))));
  }
}

/**
 * Pushes `data` through the client's local inbound and waits until the sink
 * has received all of it. Returns the wall-clock time from opening the
 * connection to the last byte landing.
 */
async function pushPayload(
  port: number,
  sink: Sink,
  data: Buffer,
  timeoutMs: number,
  phase: string,
): Promise<number> {
  const startedAt = performance.now();
  let socket: net.Socket | undefined;
  if (process.env.REALITY_DEBUG_LOG) console.error(`[debug] ${phase}: connect 127.0.0.1:${port}`);
  try {
    socket = await connectTo(port, timeoutMs);
    // Later errors just leave the byte count short; the waiter reports them.
    socket.on("error", () => {});
    socket.write(data);
    await sink.waitForBytes(data.length, timeoutMs);
  } catch (err) {
    throw new Error(`${phase}: ${errorMessage(err)}`);
  } finally {
    socket?.destroy();
  }
  return performance.now() - startedAt;
}

async function runAttempt(
  candidate: RealityTestCandidate,
  opts: RealityTestOptions,
  payload: Buffer,
): Promise<RealityTestResult> {
  const { hostname, handshakeMs } = candidate;
  // The sink is bound first on purpose: reserveFreePorts hands its ports back
  // as soon as its probes close, and a sink created after that could be given
  // one of the ports Xray is about to use.
  const sink = await createSink();
  const [serverPort, clientPort] = await reserveFreePorts(2);
  if (process.env.REALITY_DEBUG_LOG) {
    console.error(`[debug] ${hostname}: server=${serverPort} client=${clientPort} sink=${sink.port}`);
  }
  let server: XrayInstance | undefined;
  let client: XrayInstance | undefined;
  let workDir: string | undefined;

  try {
    workDir = await mkdtemp(path.join(os.tmpdir(), "reality-sni-"));
    const serverConfigPath = path.join(workDir, "server.json");
    const clientConfigPath = path.join(workDir, "client.json");
    await writeFile(
      serverConfigPath,
      JSON.stringify(
        buildServerConfig({ hostname, listenPort: serverPort, destPort: opts.destPort }),
        null,
        2,
      ),
    );
    await writeFile(
      clientConfigPath,
      JSON.stringify(
        buildClientConfig({ hostname, inboundPort: clientPort, serverPort, sinkPort: sink.port }),
        null,
        2,
      ),
    );

    server = spawnXray(opts.xrayPath, serverConfigPath);
    await waitForPort(serverPort, STARTUP_TIMEOUT_MS, server, "server");
    client = spawnXray(opts.xrayPath, clientConfigPath);
    await waitForPort(clientPort, STARTUP_TIMEOUT_MS, client, "client");

    // Untimed warm-up: absorbs the dest-detection wait described above and
    // proves the tunnel actually carries bytes before we start measuring.
    await pushPayload(clientPort, sink, Buffer.alloc(WARMUP_BYTES), WARMUP_TIMEOUT_MS, "warmup");
    sink.reset();

    const elapsedMs = Math.max(
      1,
      await pushPayload(clientPort, sink, payload, UPLOAD_TIMEOUT_MS, "upload"),
    );
    const realityUploadKbps = Math.round((payload.length * 8) / 1000 / (elapsedMs / 1000));

    return {
      hostname,
      ok: true,
      handshakeMs,
      realityUploadKbps,
      uploadBytes: sink.received(),
      elapsedMs: Math.round(elapsedMs),
    };
  } catch (err) {
    if (err instanceof StartupError) throw err;
    // The server states why it refused the handshake; the client's line is
    // almost always just the consequence of that, so only fall back to it when
    // the server has nothing to say. Printing both made an ordinary,
    // expected rejection look like a crash.
    const parts = [errorMessage(err)];
    const serverReason = logSnippet(server);
    const clientReason = serverReason ? "" : logSnippet(client);
    if (serverReason) parts.push(`server: ${serverReason}`);
    else if (clientReason) parts.push(`client: ${clientReason}`);
    return { hostname, ok: false, handshakeMs, error: parts.join(" | ") };
  } finally {
    if (process.env.REALITY_DEBUG_LOG) {
      console.error(`\n--- server log [${hostname}] ---\n${server?.logs()}\n--- client log [${hostname}] ---\n${client?.logs()}`);
    }
    stopChild(client?.child);
    stopChild(server?.child);
    await sink.close();
    if (workDir) await rm(workDir, { recursive: true, force: true });
  }
}

async function testOne(
  candidate: RealityTestCandidate,
  opts: RealityTestOptions,
  payload: Buffer,
): Promise<RealityTestResult> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    try {
      return await runAttempt(candidate, opts, payload);
    } catch (err) {
      lastError = err;
      // Only a failure to get the local processes up is worth another try.
      if (!(err instanceof StartupError)) break;
    }
  }
  const detail = errorMessage(lastError);
  return { hostname: candidate.hostname, ok: false, handshakeMs: candidate.handshakeMs, error: detail };
}

/**
 * Runs Stage 2 over `candidates`, at most `opts.concurrency` tunnels at a
 * time, and returns one result per candidate in input order.
 */
export async function runRealityTests(
  candidates: RealityTestCandidate[],
  opts: RealityTestOptions,
  onProgress?: (done: number, total: number, result: RealityTestResult) => void,
): Promise<RealityTestResult[]> {
  installSignalHandlers();

  const payload = Buffer.alloc(opts.uploadKb * 1024);
  randomFillSync(payload);

  const results = new Array<RealityTestResult>(candidates.length);
  let nextIndex = 0;
  let done = 0;

  const worker = async () => {
    while (nextIndex < candidates.length) {
      const index = nextIndex++;
      results[index] = await testOne(candidates[index], opts, payload);
      done++;
      onProgress?.(done, candidates.length, results[index]);
    }
  };

  const workerCount = Math.min(Math.max(opts.concurrency, 1), candidates.length);
  await Promise.all(Array.from({ length: workerCount }, worker));
  return results;
}

/** Ranks Stage-2 results: fastest measured upload first, then Stage-1 latency. */
export function rankRealityResults(results: RealityTestResult[]): RealityTestResult[] {
  return [...results].sort((a, b) => {
    if (a.ok !== b.ok) return a.ok ? -1 : 1;
    if (a.ok && b.ok) {
      const delta = (b.realityUploadKbps ?? 0) - (a.realityUploadKbps ?? 0);
      if (delta !== 0) return delta;
    }
    return (a.handshakeMs ?? Infinity) - (b.handshakeMs ?? Infinity);
  });
}
