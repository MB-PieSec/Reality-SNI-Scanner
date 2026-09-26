/**
 * Unified logging — the only module in this project allowed to call
 * console.log/console.error (progress redraws write to stderr directly).
 *
 * Usage:
 *   const log = forPhase("stage 1.5");   // one logger per phase/module
 *   log.info("what we're doing now");
 *   log.progress(done, total, "stage 1"); // owns the \r redraw + padding
 *   log.banner("stage 1.5: ...");         // "--- ... ---" section header
 *
 * Verbosity comes from --verbose/--quiet (see setVerbosity), with
 * REALITY_DEBUG_LOG=1 still accepted as an alias for --verbose.
 *
 * `buffered()` captures a logger's lines instead of printing them, so work
 * running behind an active \r progress line (the Stage 1.5 prefetch) can be
 * replayed cleanly afterwards rather than garbling the bar.
 */

/**
 * The scan's stages, in the order they run — the single place that names
 * them, so no module has to invent (or disagree about) a label. Modules ask
 * for these via forPhase(STAGES[1]) rather than passing brand strings around.
 *
 * Stage 1.5 starts in the background while Stage 1 is still probing; its
 * lines are buffered (see buffered()) and replayed under its banner once
 * Stage 1's ranking is final.
 */
export const STAGES = ["stage 1", "stage 1.5", "stage 2"] as const;

/**
 * Severity threshold — controls what reaches stderr.
 *
 * A const object rather than an `enum`: this project runs TypeScript directly
 * through Node's type stripping, which only erases types (enums emit runtime
 * code, so they are rejected in strip-only mode).
 */
export const Level = {
  Silent: 0,
  Error: 1,
  Warn: 2,
  Info: 3,
  Debug: 4,
} as const;
export type Level = (typeof Level)[keyof typeof Level];

let currentLevel: Level = Level.Info;

/** Set global verbosity (called once at startup from CLI flags / env). */
export function setVerbosity(level: Level): void {
  currentLevel = level;
}

/** Current verbosity (read-only). */
export function getVerbosity(): Level {
  return currentLevel;
}

/**
 * The prefix legend, fixed here so no call site has to remember it:
 *   [i]  info    — what we're doing now
 *   [+]  success — something completed well
 *   [!]  warn    — something didn't work, but the run continues
 *   [x]  error   — something failed and the run stopped or degraded
 *   [~]  debug   — verbose internals, only with --verbose
 */
type Kind = "info" | "success" | "warn" | "error" | "debug";
const PREFIX: Record<Kind, string> = {
  info: "[i]",
  success: "[+]",
  warn: "[!]",
  error: "[x]",
  debug: "[~]",
};
/** Success is not a severity of its own — it is reported at info level. */
const SEVERITY: Record<Kind, Level> = {
  info: Level.Info,
  success: Level.Info,
  warn: Level.Warn,
  error: Level.Error,
  debug: Level.Debug,
};

/** A logger bound to one phase name (e.g. "stage 1.5", "asn", "xray"). */
export interface Logger {
  /** Informational message — "what we're doing now". */
  info(msg: string): void;
  /** Success/confirmation — "something completed well". */
  success(msg: string): void;
  /** Warning — "something didn't work but we're continuing". */
  warn(msg: string): void;
  /** Error — "something failed and the run stopped or degraded". */
  error(msg: string): void;
  /** Debug — only prints when verbosity is Level.Debug (--verbose). */
  debug(msg: string): void;
  /** Progress redraw — owns the \r + padding so leftovers never show. */
  progress(done: number, total: number, label?: string): void;
  /** Section banner — "--- <title> ---", used for every stage transition. */
  banner(title: string): void;
}

function write(kind: Kind, phase: string, msg: string): void {
  if (SEVERITY[kind] > currentLevel) return;
  console.error(`${PREFIX[kind]} ${phase}: ${msg}`);
}

/** Create a logger bound to a named phase. */
export function forPhase(phase: string): Logger {
  const label = phase.trim();
  return {
    info: (msg) => write("info", label, msg),
    success: (msg) => write("success", label, msg),
    warn: (msg) => write("warn", label, msg),
    error: (msg) => write("error", label, msg),
    debug: (msg) => write("debug", label, msg),
    progress: (done, total, label_) => drawProgress(done, total, label_ ?? label),
    banner: (title) => drawBanner(title),
  };
}

function drawBanner(title: string): void {
  if (Level.Info > currentLevel) return;
  finishProgress(); // never glue a banner onto a half-drawn bar
  console.error(`\n--- ${title} ---`);
}

// --------------------------------------------------------------- progress
interface ProgressState {
  active: boolean;
  lastLen: number;
}
const progressState: ProgressState = { active: false, lastLen: 0 };

/**
 * Draw "[i] <label>: <done>/<total>". Redrawing with \r does not erase, so
 * each frame pads out whatever the previous (longer) frame left behind —
 * without this, "ok" after "failed" leaves a "led)" tail on screen.
 */
function drawProgress(done: number, total: number, label: string): void {
  if (Level.Info > currentLevel) return;
  const line = `[i] ${label}: ${done}/${total}`;
  const pad = " ".repeat(Math.max(0, progressState.lastLen - line.length));
  progressState.active = true;
  progressState.lastLen = line.length;
  process.stderr.write(`\r${line}${pad}`);
  // Terminate the bar the moment it completes, so the phase's summary lines
  // print on their own line instead of onto the end of the progress line.
  if (total > 0 && done >= total) finishProgress();
}

/** End the progress line (no-op when nothing is on screen). */
export function finishProgress(): void {
  if (!progressState.active) return;
  process.stderr.write("\n");
  progressState.active = false;
  progressState.lastLen = 0;
}

// --------------------------------------------------------------- buffered
/**
 * Capture a logger's output instead of printing it, then replay it later.
 * Used by the Stage 1.5 prefetch: its lines would otherwise print into the
 * middle of Stage 1's half-drawn \r progress line. Lines keep the same
 * prefix/phase formatting they would have had live, so a replay is
 * indistinguishable from having printed immediately.
 */
export function buffered(phase?: string): { logger: Logger; replay(): void } {
  const captured: { severity: Level; text: string }[] = [];
  const stamp = (kind: Kind, msg: string) =>
    `${PREFIX[kind]}${phase ? ` ${phase}:` : ""} ${msg}`;
  const capture = (kind: Kind, msg: string) =>
    captured.push({ severity: SEVERITY[kind], text: stamp(kind, msg) });
  const logger: Logger = {
    info: (msg) => capture("info", msg),
    success: (msg) => capture("success", msg),
    warn: (msg) => capture("warn", msg),
    error: (msg) => capture("error", msg),
    debug: (msg) => capture("debug", msg),
    progress: () => {
      // nothing to redraw while buffering
    },
    banner: (title) => captured.push({ severity: Level.Info, text: `--- ${title} ---` }),
  };
  let replayed = false;
  return {
    logger,
    replay(): void {
      if (replayed) return;
      replayed = true;
      // Filtered at replay, not capture: verbosity is set once at startup,
      // but filtering here keeps a buffered run honest if it ever changes.
      const visible = captured.filter((c) => c.severity <= currentLevel);
      if (visible.length > 0) finishProgress();
      for (const { text } of visible) console.error(text);
      captured.length = 0;
    },
  };
}
