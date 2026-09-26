import { readFile, writeFile } from "node:fs/promises";
import { resolve4, resolve6 } from "node:dns/promises";
import { normalizeAcceptableDomain } from "./filters.ts";
import { forPhase, STAGES, type Logger } from "./log.ts";

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
 *
 * No single provider is dependable enough to be the only answer, though:
 * crt.sh is a free, shared service that is routinely slow or down, and
 * Cert Spotter is a free tier with rate limits. So every base domain walks
 * a fallback chain — crt.sh -> Cert Spotter -> a bundled DNS wordlist —
 * under one hard wall-clock budget, and whatever has been found is cached
 * on disk for a week. Discovery therefore degrades (it never fails the run)
 * when a provider is down, and a warm cache skips the network entirely.
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

interface CertSpotterIssuance {
  dns_names?: string[];
}

const MAX_CT_RESPONSE_BYTES = 5 * 1024 * 1024;

/** No single HTTP request may outlive this, whatever the total budget is. */
const PER_REQUEST_TIMEOUT_MS = 5_000;
/** Default wall-clock budget for one whole discovery run (--ct-timeout). */
export const DEFAULT_CT_BUDGET_MS = 10_000;
/** Gap between requests aimed at the same free, shared provider. */
const POLITE_DELAY_MS = 300;
/** How long a cached discovery stays fresh before we refetch (--ct-refresh bypasses it). */
export const CT_CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
/** Names no single base domain may claim, even when its share is larger —
 *  one huge zone (google.com) must not consume the whole run's name budget. */
const PER_BASE_LIMIT = 200;
/** Cert Spotter pages followed per base domain (one HTTP request each), so a
 *  single huge base domain can never stall the phase on pagination. */
const CERTSPOTTER_MAX_PAGES = 3;
/** DNS brute-force: short per-lookup timeout, modest fan-out. */
const DNS_PER_LOOKUP_TIMEOUT_MS = 1_200;
const DNS_CONCURRENCY = 25;

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

// ------------------------------------------------------------------- logging
// Use the unified logger from log.ts. Callers pass a phase name via the
// `mode` option (or we default to "ct discovery" for seed mode).

/**
 * Which certificate-transparency source a discovery run may use.
 * - "auto": the full fallback chain (crt.sh -> certspotter -> dns)
 * - anything else: pin exactly that source, no fallback (debugging)
 */
export const CTSource = {
  AUTO: "auto" as const,
  CRTSH: "crtsh" as const,
  CERTSPOTTER: "certspotter" as const,
  DNS: "dns" as const,
} as const;

export type CTSource = (typeof CTSource)[keyof typeof CTSource];

type CTSourceId = Exclude<CTSource, "auto">;

/** The order sources are tried in when nothing is pinned. */
const CT_SOURCE_CHAIN: readonly CTSourceId[] = [CTSource.CRTSH, CTSource.CERTSPOTTER, CTSource.DNS];

const SOURCE_LABELS: Record<string, string> = {
  crtsh: "crt.sh",
  certspotter: "Cert Spotter",
  dns: "DNS guessing",
  cache: "cached",
  "stale-cache": "old cache",
};

/** Friendly name for a source id, e.g. certspotter -> "Cert Spotter". */
export function sourceLabel(id: string): string {
  return SOURCE_LABELS[id] ?? id;
}

/** Human-readable provenance line, e.g. "cached 3, Cert Spotter 1". */
export function describeCTCoverage(bySource: Record<string, number>): string {
  return Object.entries(bySource)
    .map(([id, count]) => `${sourceLabel(id)} ${count}`)
    .join(", ");
}

/**
 * Bundled wordlist for the DNS brute-force floor: resolve `<word>.<base>`
 * and keep the ones that answer. This can only find labels it already knows
 * about — it is deliberately NOT a full enumeration (that's what the CT
 * sources are for) — it exists purely so Stage 1.5 is never empty-handed
 * when both CT providers are unreachable. No download, no API, works offline
 * as long as DNS itself answers.
 */
const DNS_WORDLIST = [
  "www", "www1", "www2", "m", "mobile", "app", "apps", "api",
  "dev", "test", "stage", "staging", "demo", "beta", "alpha",
  "admin", "administrator", "portal", "dashboard", "console", "panel", "control", "manage", "manager",
  "backend", "frontend", "internal", "intranet", "private", "public",
  "mail", "smtp", "pop", "imap", "webmail", "mx", "autodiscover", "autoconfig", "owa", "exchange",
  "ftp", "ns", "ns1", "ns2", "dns", "vpn", "remote", "gateway", "proxy", "tunnel",
  "cdn", "static", "assets", "img", "image", "images", "media", "video", "videos", "live", "stream", "origin", "edge",
  "node", "nodes", "server", "servers", "host", "hosts", "cloud", "storage", "files",
  "download", "downloads", "dl", "update", "updates",
  "auth", "sso", "oauth", "login", "signin", "signup", "register", "account", "accounts", "member", "members",
  "user", "users", "id", "identity", "secure", "security",
  "billing", "pay", "payment", "payments", "checkout", "cart", "shop", "store", "sale", "sales",
  "promo", "marketing", "partner", "partners", "affiliate", "affiliates",
  "blog", "news", "press", "forum", "forums", "community", "careers", "jobs",
  "help", "support", "service", "services", "status", "feedback", "contact", "about", "info",
  "doc", "docs", "documentation", "wiki", "faq",
  "search", "discover",
  "db", "database", "sql", "mysql", "postgres", "redis", "mongo", "cache", "queue",
  "workers", "ci", "build", "git",
  "monitoring", "metrics", "grafana", "logs",
  "calendar", "chat", "meet", "teams", "sip", "voip", "phone", "call", "sms", "push", "notify",
  "webhook", "hooks", "ws", "websocket", "socket", "sockets",
  "drive", "photos", "music", "audio", "podcast", "radio", "tv", "game", "games", "play",
  "old", "new", "v1", "v2", "v3",
  "eu", "us", "uk", "de", "fr", "jp", "au", "in", "br", "ca",
];

// ---------------------------------------------------------------------- cache
/**
 * Discovered subdomains are written to ct-cache.json (next to results.json)
 * so a re-run within CT_CACHE_TTL_MS does not touch any provider again.
 * The file is deliberately treated as untrusted: a corrupt or half-written
 * cache is logged and ignored, never allowed to crash a scan.
 */
interface CTCacheEntry {
  fetchedAt: number;
  source: string;
  names: string[];
}

interface CTCacheState {
  file: string;
  entries: Map<string, CTCacheEntry>;
  dirty: boolean;
}

// One cache per process: the background prefetch and the later Stage 1.5 run
// share it, so anything the prefetch already fetched is a cache hit for
// Stage 1.5 without a second disk read (or a second HTTP request).
let cacheState: CTCacheState | null = null;

async function loadCache(file: string, log: ReturnType<typeof forPhase>): Promise<CTCacheState> {
  if (cacheState && cacheState.file === file) return cacheState;

  const state: CTCacheState = { file, entries: new Map(), dirty: false };
  let raw: string | null = null;
  try {
    raw = await readFile(file, "utf-8");
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    // ENOENT is the normal first run; anything else (permissions, ...) just
    // means "no usable cache" — refetch rather than fail.
    if (code !== "ENOENT") {
      log.warn(`cannot read cache file ${file} (${code ?? (err as Error).message}) — fetching fresh results`);
    }
  }

  if (raw !== null) {
    try {
      const parsed = JSON.parse(raw) as { entries?: Record<string, unknown> };
      if (parsed && typeof parsed === "object" && parsed.entries && typeof parsed.entries === "object") {
        for (const [base, value] of Object.entries(parsed.entries)) {
          const entry = value as Partial<CTCacheEntry> | null;
          if (!entry || typeof entry.fetchedAt !== "number" || !Array.isArray(entry.names)) continue;
          state.entries.set(base, {
            fetchedAt: entry.fetchedAt,
            source: typeof entry.source === "string" ? entry.source : "unknown",
            names: entry.names.filter((n): n is string => typeof n === "string"),
          });
        }
      } else {
        log.info(`cache file ${file} is malformed — ignoring it, fetching fresh results`);
      }
    } catch {
      log.info(`cache file ${file} is corrupt — ignoring it, fetching fresh results`);
    }
  }

  cacheState = state;
  return state;
}

/** Best-effort write: a full disk or read-only checkout must not kill a scan. */
async function saveCache(state: CTCacheState, log: ReturnType<typeof forPhase>): Promise<void> {
  if (!state.dirty || state.entries.size === 0) return;
  try {
    const body = JSON.stringify({ version: 1, entries: Object.fromEntries(state.entries) }, null, 2);
    await writeFile(state.file, body);
    state.dirty = false;
  } catch (err) {
    log.warn(`cannot write cache file ${state.file}: ${(err as Error).message} (this run still works, it just won't be remembered)`);
  }
}

function formatAge(fetchedAt: number): string {
  const age = Date.now() - fetchedAt;
  const days = Math.floor(age / 86_400_000);
  if (days >= 1) return `${days}d old`;
  const hours = Math.floor(age / 3_600_000);
  if (hours >= 1) return `${hours}h old`;
  const minutes = Math.floor(age / 60_000);
  if (minutes >= 1) return `${minutes}m old`;
  return "just now";
}

// -------------------------------------------------------- abort plumbing
/** Everything a source needs to respect the phase-wide wall clock. */
interface SourceContext {
  /** Absolute deadline (epoch ms) for the whole discovery run. */
  deadline: number;
  /** Aborted when the budget expires or the caller cancels the run. */
  signal: AbortSignal;
  /** Phase logger, so retries/warnings report under the caller's brand. */
  log: Logger;
}

/**
 * Signal for one HTTP request: aborts on whichever comes first — the fixed
 * per-request timeout or the phase-wide budget/cancel signal. That keeps a
 * request bounded at PER_REQUEST_TIMEOUT_MS even when the budget is larger,
 * so a budget smaller than perRequest x domains still stops predictably.
 */
function boundedSignal(ctx: SourceContext): { signal: AbortSignal; done: () => void } {
  const ctl = new AbortController();
  const remainingMs = ctx.deadline - Date.now();
  const timeoutMs = Math.max(1, Math.min(PER_REQUEST_TIMEOUT_MS, remainingMs));
  const timer = setTimeout(() => ctl.abort(new DOMException("timeout", "TimeoutError")), timeoutMs);
  const onBudgetAbort = () => ctl.abort(ctx.signal.reason);
  if (ctx.signal.aborted) ctl.abort(ctx.signal.reason);
  else ctx.signal.addEventListener("abort", onBudgetAbort, { once: true });

  return {
    signal: ctl.signal,
    done() {
      clearTimeout(timer);
      ctx.signal.removeEventListener("abort", onBudgetAbort);
    },
  };
}

/** Resolves as soon as `signal` aborts — used to cut retry backoffs short. */
function abortPromise(signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) resolve();
    else signal.addEventListener("abort", () => resolve(), { once: true });
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Compact, log-friendly error detail (keeps cause codes like ENOTFOUND). */
function describeError(err: unknown): string {
  const e = err as { name?: string; message?: string; cause?: { code?: string; message?: string } };
  if (e?.name === "TimeoutError" || e?.name === "AbortError" || /timeout/i.test(e?.message ?? "")) {
    return "timeout";
  }
  return e?.cause?.code ?? e?.cause?.message ?? e?.message ?? String(err);
}

/**
 * One short plain-language phrase for why a source failed, meant to be read
 * as "crt.sh <phrase>": "did not respond (timeout)", "returned HTTP 404",
 * "rate-limited (retry after 30s)", ...
 */
function friendlySourceError(err: unknown): string {
  if (err instanceof RateLimitError) return err.message;
  const detail = describeError(err);
  if (/timeout/i.test(detail)) return "did not respond (timeout)";
  if (/^HTTP \d{3}$/.test(detail)) return `returned ${detail}`;
  return `failed (${detail})`;
}

/**
 * True when an error says the *provider* is unavailable (as opposed to "this
 * particular domain had a problem"): timeouts, transport failures, 5xx and
 * 429. Those fail for every base domain, so once one shows up the source is
 * marked down for the rest of the process instead of costing its time slice
 * again on every remaining base — that stacking is exactly what used to make
 * a dead crt.sh cost N domains x retries on large scans.
 */
function isProviderDown(err: unknown): boolean {
  if (err instanceof RateLimitError) return true;
  const message = err instanceof Error ? err.message : String(err);
  if (/HTTP (5\d\d|429)/.test(message)) return true;
  if (/timeout|fetch|network/i.test(message)) return true;
  const e = err as { name?: string };
  return e?.name === "TimeoutError" || e?.name === "AbortError";
}

/** Sources already known to be down in this process (shared across runs' phases). */
const downSources = new Set<CTSourceId>();

/** Raised when a provider answers 429 — the caller falls through to the next source. */
class RateLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RateLimitError";
  }
}

/**
 * How the time left for one base domain is split across the chain. crt.sh
 * hangs indefinitely when it is down (it never even answers), so without a
 * slice it would eat the whole budget and the fallbacks would never run.
 * Shares are renormalized over the sources still in play, so a source that
 * fails fast hands its time to the ones behind it.
 */
const SOURCE_TIME_WEIGHTS: Record<CTSourceId, number> = {
  crtsh: 0.5,
  certspotter: 0.3,
  dns: 0.2,
};

// ----------------------------------------------------------------- crt.sh
async function queryCrtSh(base: string, ctx: SourceContext, limit: number, maxRetries = 2): Promise<string[]> {
  let lastError: Error | null = null;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    const request = boundedSignal(ctx);
    try {
      const res = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(base)}&output=json`, {
        signal: request.signal,
      });

      if (!res.ok) {
        // Retry on server errors (5xx) and rate limits (429)
        if (res.status >= 500 || res.status === 429) {
          if (attempt >= maxRetries) throw new Error(`HTTP ${res.status}`);
          const retryAfter = res.headers.get("retry-after");
          let delay = retryAfter ? parseInt(retryAfter, 10) * 1000 : Math.min(500 * attempt, 2000);
          if (!Number.isFinite(delay) || delay < 0) delay = Math.min(500 * attempt, 2000);
          // Never schedule a retry the budget cannot afford.
          if (Date.now() + delay >= ctx.deadline) throw new Error(`HTTP ${res.status}`);
          ctx.log.warn(`${base}: HTTP ${res.status} — retrying in ${delay}ms (attempt ${attempt}/${maxRetries})`);
          await Promise.race([sleep(delay), abortPromise(ctx.signal)]);
          continue;
        }
        throw new Error(`HTTP ${res.status}`);
      }

      const entries = (await readJsonWithinLimit(res)) as CrtShEntry[];

      const names = new Set<string>();
      for (const entry of entries) {
        if (!entry.name_value) continue;
        for (const raw of entry.name_value.split("\n")) {
          const name = normalizeAcceptableDomain(raw);
          if (!name || raw.trim().startsWith("*.")) continue;
          // Strictly a subdomain: the base itself is never a discovery result
          // (the caller already has it), and handing back only the base would
          // stop the fallback chain from hunting for real subdomains.
          if (!name.endsWith(`.${base}`)) continue;
          names.add(name);
          if (names.size >= limit) return [...names];
        }
      }
      return [...names];
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      const isTimeout = lastError.name === "TimeoutError" || lastError.message.includes("timeout");
      const isNetwork = lastError.message.includes("fetch") || lastError.message.includes("network");

      if (attempt < maxRetries && (isTimeout || isNetwork)) {
        const delay = Math.min(500 * attempt, 2000);
        if (Date.now() + delay >= ctx.deadline) throw lastError;
        ctx.log.warn(`${base}: ${lastError.message} — retrying in ${delay}ms (attempt ${attempt}/${maxRetries})`);
        await Promise.race([sleep(delay), abortPromise(ctx.signal)]);
        continue;
      }
      throw lastError;
    } finally {
      request.done();
    }
  }

  throw lastError ?? new Error(`Failed after ${maxRetries} attempts`);
}

// ----------------------------------------------------------- Cert Spotter
/** Follows RFC 8288 `Link: <url>; rel="next"` — only within certspotter's own origin. */
function nextLink(header: string | null): string | null {
  if (!header) return null;
  const match = /<([^>]+)>\s*;\s*rel="?next"?/i.exec(header);
  const url = match?.[1];
  if (!url || !url.startsWith("https://api.certspotter.com/")) return null;
  return url;
}

/**
 * Cert Spotter's free, keyless API. Paginated via the `next` Link header
 * (falling back to nothing when absent) and hard-capped at
 * CERTSPOTTER_MAX_PAGES so one base domain cannot stall the whole phase.
 * A 429 becomes a RateLimitError so the caller can fall through to the next
 * source instead of hammering a rate-limited service.
 */
async function queryCertSpotter(base: string, ctx: SourceContext, limit: number): Promise<string[]> {
  let url: string | null =
    `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(base)}` +
    `&include_subdomains=true&expand=dns_names`;
  const names = new Set<string>();

  for (let page = 1; url && page <= CERTSPOTTER_MAX_PAGES; page++) {
    const request = boundedSignal(ctx);
    try {
      const res = await fetch(url, {
        signal: request.signal,
        headers: { "User-Agent": "reality-sni-scanner" },
      });

      if (res.status === 429) {
        const retryAfter = res.headers.get("retry-after");
        throw new RateLimitError(retryAfter ? `rate-limited (retry after ${retryAfter}s)` : "rate-limited");
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const items = (await readJsonWithinLimit(res)) as CertSpotterIssuance[];
      for (const item of items) {
        for (const raw of item.dns_names ?? []) {
          const name = normalizeAcceptableDomain(raw);
          if (!name || raw.trim().startsWith("*.")) continue;
          // Strictly a subdomain — see the note in queryCrtSh().
          if (!name.endsWith(`.${base}`)) continue;
          names.add(name);
          if (names.size >= limit) return [...names];
        }
      }

      url = nextLink(res.headers.get("link"));
    } finally {
      request.done();
    }
  }

  return [...names];
}

// --------------------------------------------------------- DNS brute-force
async function dnsResolves(name: string, ctx: SourceContext): Promise<boolean> {
  const remainingMs = ctx.deadline - Date.now();
  if (remainingMs <= 0 || ctx.signal.aborted) return false;
  const timeoutMs = Math.min(DNS_PER_LOOKUP_TIMEOUT_MS, remainingMs);

  let timer: NodeJS.Timeout | undefined;
  const timedOut = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("dns timeout")), timeoutMs);
  });
  try {
    // Either address family answering is enough; the loser's rejection is
    // handled by Promise.any itself, so nothing is left unhandled.
    await Promise.race([Promise.any([resolve4(name), resolve6(name)]), timedOut]);
    return true;
  } catch {
    return false;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function queryDnsBrute(base: string, ctx: SourceContext, limit: number): Promise<string[]> {
  // A wildcard zone (*.base) — or an ISP that hijacks NXDOMAIN — answers for
  // every label, which would make the wordlist "discover" hosts that do not
  // exist (and every probe of them would fail). Two random canary labels
  // detect that before we spend the rest of the budget on garbage.
  const stamp = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
  for (const label of [`zzk1ctscan${stamp}`, `zzk2ctscan${stamp}`]) {
    if (ctx.signal.aborted) return [];
    if (await dnsResolves(`${label}.${base}`, ctx)) {
      ctx.log.warn(`${base}: skipping DNS guessing — random test names also resolve here (wildcard DNS), so guessed names would be fake`);
      return [];
    }
  }

  const found = new Set<string>();
  const candidates = DNS_WORDLIST.map((word) => `${word}.${base}`);
  let nextIndex = 0;
  let stopped = false;

  const worker = async () => {
    while (!stopped) {
      if (ctx.signal.aborted || found.size >= limit) {
        stopped = true;
        break;
      }
      const i = nextIndex++;
      if (i >= candidates.length) break;
      if (await dnsResolves(candidates[i], ctx)) {
        const name = normalizeAcceptableDomain(candidates[i]);
        if (name) found.add(name);
      }
    }
  };

  await Promise.all(Array.from({ length: Math.min(DNS_CONCURRENCY, candidates.length) }, worker));
  // The chain's fallthrough log skips DNS (this function is its voice), so
  // an empty sweep is explained here — unless it was cut short by cancel.
  if (found.size === 0 && !ctx.signal.aborted) {
    ctx.log.info(`${base}: DNS guessing found no subdomains`);
  }
  return [...found];
}

// -------------------------------------------------------------- orchestration
async function runSource(id: CTSourceId, base: string, ctx: SourceContext, limit: number): Promise<string[]> {
  if (id === CTSource.CRTSH) return queryCrtSh(base, ctx, limit);
  if (id === CTSource.CERTSPOTTER) return queryCertSpotter(base, ctx, limit);
  return queryDnsBrute(base, ctx, limit);
}

/**
 * Mode for subdomain discovery.
 * - "seeds": Query CT sources for new domains from a list of seed domains (original behavior)
 * - "main-domains": Stage 1.5 — discover subdomains of the Stage 1 top domains
 */
export const CTDiscoveryMode = {
  SEEDS: "seeds" as const,
  MAIN_DOMAINS: "main-domains" as const,
} as const;

export type CTDiscoveryMode = (typeof CTDiscoveryMode)[keyof typeof CTDiscoveryMode];

export interface CTDiscoverOptions {
  /** Hard cap on how many hostnames come back from the whole run. */
  totalLimit: number;
  /** Single wall-clock budget for this run; default DEFAULT_CT_BUDGET_MS. */
  budgetMs?: number;
  mode?: CTDiscoveryMode;
  /** "auto" walks the fallback chain; anything else pins one source. */
  source?: CTSource;
  /** Cache file (ct-cache.json); omit to disable caching for this run. */
  cacheFile?: string;
  /** Ignore cache entries and refetch (the fresh result rewrites them). */
  refresh?: boolean;
  /** External cancel — used to stop the background prefetch when Stage 1 ends. */
  signal?: AbortSignal;
  /**
   * Logger for this run's lines. Defaults to forPhase(mode), but callers with
   * a buffering logger (the background prefetch, which must not print into
   * Stage 1's live \r progress line) pass theirs here instead of swapping a
   * global sink around.
   */
  logger?: Logger;
}

export interface CTDiscoveryResult {
  /** Concrete hostnames, deduped and capped. Wildcards are never included. */
  names: string[];
  /** How many base domains each source answered for, e.g. { crtsh: 8, cache: 3 }. */
  bySource: Record<string, number>;
  /** Base domains that produced an answer (cache included). */
  completed: number;
  /** Base domains where every allowed source failed or returned nothing. */
  failed: number;
  /** Base domains never attempted because the budget expired (or we were cancelled). */
  skipped: number;
  total: number;
  budgetExpired: boolean;
  cancelled: boolean;
}

/**
 * Discovers real subdomains for each base domain, walking the source chain
 * crt.sh -> Cert Spotter -> DNS brute-force and using the first source that
 * answers for a given base (results are NOT merged across sources — one
 * provider's answer per base keeps the run inside its budget; the chain only
 * continues when a source fails or comes back empty).
 *
 * A fresh cache entry short-circuits the network entirely. Everything honors
 * one shared deadline: when budgetMs elapses, in-flight requests are aborted,
 * whatever has already been collected is kept, and a summary of how many
 * base domains completed vs. were skipped is logged.
 */
export async function discoverCTSubdomains(
  seeds: string[],
  opts: CTDiscoverOptions,
): Promise<CTDiscoveryResult> {
  const totalLimit = opts.totalLimit;
  const budgetMs = opts.budgetMs ?? DEFAULT_CT_BUDGET_MS;
  const source = opts.source ?? CTSource.AUTO;
  const refresh = opts.refresh ?? false;
  const mode = opts.mode ?? CTDiscoveryMode.SEEDS;

  // Create a logger for this discovery run: the caller's (e.g. the buffering
  // prefetch logger), else one named after this run's mode.
  const log = opts.logger ?? forPhase(mode === CTDiscoveryMode.SEEDS ? "ct seed" : STAGES[1]);

  const chain: CTSourceId[] =
    source === CTSource.AUTO ? [...CT_SOURCE_CHAIN] : [source];
  // Split the total name budget evenly across the base domains: without this,
  // the first huge zone answers for everything and the other base domains are
  // never even queried (topN*10 spread over ~topN/2 bases is plenty each).
  const perBaseLimit = Math.max(
    1,
    Math.min(PER_BASE_LIMIT, Math.ceil(totalLimit / Math.max(1, seeds.length))),
  );

  const deadline = Date.now() + budgetMs;
  let budgetFired = false;
  const stopCtl = new AbortController();
  const stopTimer = setTimeout(() => {
    budgetFired = true;
    stopCtl.abort();
  }, budgetMs);
  const onExternalStop = () => stopCtl.abort();
  if (opts.signal) {
    if (opts.signal.aborted) stopCtl.abort();
    else opts.signal.addEventListener("abort", onExternalStop, { once: true });
  }

  const result: CTDiscoveryResult = {
    names: [],
    bySource: {},
    completed: 0,
    failed: 0,
    skipped: 0,
    total: seeds.length,
    budgetExpired: false,
    cancelled: false,
  };
  const collected = new Set<string>();
  let cacheStateForRun: CTCacheState | null = null;

  const record = (sourceId: string, names: string[]) => {
    result.bySource[sourceId] = (result.bySource[sourceId] ?? 0) + 1;
    // Same per-base cap a fresh fetch gets, so an oversized cache entry (or
    // one written by an older version) cannot swallow the whole name budget
    // before the other base domains are queried.
    let addedForBase = 0;
    for (const raw of names) {
      const name = normalizeAcceptableDomain(raw);
      if (!name || collected.has(name)) continue;
      collected.add(name);
      addedForBase++;
      if (collected.size >= totalLimit || addedForBase >= perBaseLimit) break;
    }
  };

  try {
    // Loaded inside the try so even a pathological cache problem still lands
    // in the finally below (timer cleared, partial results returned).
    cacheStateForRun = opts.cacheFile ? await loadCache(opts.cacheFile, log) : null;

    for (const base of seeds) {
      if (collected.size >= totalLimit) break;
      if (stopCtl.signal.aborted) break;

      let httpUsed = false;
      let producedNames: string[] | null = null;
      let producedSource: string | null = null;

      // 1. A fresh cache entry skips the network for this base entirely.
      const cached = refresh ? undefined : cacheStateForRun?.entries.get(base);
      if (cached && Date.now() - cached.fetchedAt < CT_CACHE_TTL_MS) {
        log.info(`${base}: using cached results (${formatAge(cached.fetchedAt)})`);
        record("cache", cached.names);
        result.completed++;
        continue;
      }
      if (cached) {
        log.info(`${base}: cached results are ${formatAge(cached.fetchedAt)} — fetching fresh ones`);
      }

      // 2. The fallback chain: first source that answers wins for this base.
      for (let s = 0; s < chain.length; s++) {
        const id = chain[s];
        if (stopCtl.signal.aborted) break;
        // Already-proven-down sources are skipped without paying again; the
        // trip itself is logged (once) where it happens, below.
        if (downSources.has(id)) continue;
        const nextId = chain[s + 1];
        const nextLabel = nextId ? sourceLabel(nextId) : null;
        const isHttp = id !== CTSource.DNS;
        if (isHttp) httpUsed = true;

        // Time slice for this source: the time left for this base, weighted
        // by this source's share of the sources still in play. A hung source
        // therefore only ever costs its own slice (the fallbacks keep theirs),
        // and any unused time flows forward to the sources behind it.
        const stillInPlay = chain.slice(s);
        const weightSum = stillInPlay.reduce((sum, sid) => sum + SOURCE_TIME_WEIGHTS[sid], 0);
        const shareMs = Math.floor((deadline - Date.now()) * (SOURCE_TIME_WEIGHTS[id] / weightSum));
        const sourceCtx: SourceContext = {
          deadline: Date.now() + shareMs,
          signal: stopCtl.signal,
          log,
        };

        try {
          const names = await runSource(id, base, sourceCtx, perBaseLimit);
          if (names.length === 0) {
            // An empty answer is treated like a failure so the chain keeps
            // going — an outage can also look like "success, zero rows".
            // (The DNS runner explains its own empty answers — wildcard zone
            // or "guessing found nothing" — so that isn't repeated here.)
            if (id !== CTSource.DNS) {
              log.info(`${base}: ${sourceLabel(id)} found no subdomains${nextLabel ? ` — trying ${nextLabel} instead` : ""}`);
            }
            continue;
          }
          producedNames = names;
          producedSource = id;
          break;
        } catch (err) {
          if (stopCtl.signal.aborted) break;
          // A down provider is down for every base domain: mark it so the
          // remaining bases go straight to the fallbacks (only worth doing
          // while there IS a fallback — a pinned source stays pinned).
          const trips = nextId !== undefined && isProviderDown(err);
          if (trips) downSources.add(id);
          log.warn(
            `${base}: ${sourceLabel(id)} ${friendlySourceError(err)}` +
              `${nextLabel ? ` — trying ${nextLabel} instead` : " — no other source to try"}` +
              (trips ? " (treated as down for the rest of this run)" : ""),
          );
        }
      }

      // 3. Nothing worked: a stale cache entry still beats an empty stage 1.5.
      if (!producedNames && cached && cached.names.length > 0) {
        log.warn(
          `${base}: all sources failed — using cached results (${formatAge(cached.fetchedAt)}, ${cached.names.length} names)`,
        );
        producedNames = cached.names;
        producedSource = "stale-cache";
      }

      if (producedNames && producedSource) {
        record(producedSource, producedNames);
        result.completed++;
        if (producedSource !== "stale-cache" && cacheStateForRun) {
          // Only real, non-empty answers enter the cache: an outage must
          // never be remembered as "this domain has no subdomains".
          cacheStateForRun.entries.set(base, {
            fetchedAt: Date.now(),
            source: producedSource,
            names: producedNames,
          });
          cacheStateForRun.dirty = true;
        }
        // Politeness gap between requests to the same free, shared provider
        // (skipped when this base never touched HTTP or the budget is gone).
        if (httpUsed && !stopCtl.signal.aborted && deadline - Date.now() > POLITE_DELAY_MS) {
          await Promise.race([sleep(POLITE_DELAY_MS), abortPromise(stopCtl.signal)]);
        }
      } else {
        result.failed++;
      }
    }
  } finally {
    clearTimeout(stopTimer);
    opts.signal?.removeEventListener("abort", onExternalStop);
    result.budgetExpired = budgetFired;
    result.cancelled = stopCtl.signal.aborted && !budgetFired;
    result.names = [...collected].slice(0, totalLimit);
    if (cacheStateForRun) await saveCache(cacheStateForRun, log);
  }

  if (result.total > 0) {
    const attempted = result.completed + result.failed;
    result.skipped = result.total - attempted;
    const coverage = describeCTCoverage(result.bySource);
    const from =
      attempted === result.total ? `all ${result.total}` : `${attempted} of ${result.total}`;
    const kept = result.names.length > 0 ? ` (the ${result.names.length} found are kept)` : "";
    if (result.names.length > 0) {
      log.success(
        `found ${result.names.length} subdomains from ${from} domains` +
          (coverage ? ` — ${coverage}` : ""),
      );
    } else {
      log.info(`checked ${from} domains, found no subdomains`);
    }
    // Only worth saying when something was actually cut short: a limit that
    // fires on the last domain has nothing to complain about.
    const budgetLabel = budgetMs >= 1000 ? `${budgetMs / 1000}s` : `${budgetMs}ms`;
    if (result.budgetExpired && result.skipped > 0) {
      log.warn(
        `${result.skipped} of ${result.total} domains not checked — the ${budgetLabel} time limit ran out${kept}`,
      );
    } else if (result.cancelled && result.skipped > 0) {
      log.info(`stopping early — ${result.skipped} of ${result.total} domains not checked${kept}`);
    }
  }

  return result;
}
