/**
 * Stage 2 needs a real Xray-core binary. Users should not have to install one,
 * so this module downloads the official release for the current OS/arch the
 * first time Stage 2 runs and caches it permanently under ./bin/.
 *
 * Everything here only runs when Stage 2 is enabled — Stage 1 stays fully
 * offline, exactly as before.
 */

import { spawn } from "node:child_process";
import { chmod, mkdir, rename, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { extractZipEntry } from "./zip.ts";
import { forPhase } from "./log.ts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const XRAY_BIN_DIR = path.join(__dirname, "..", "bin");

const RELEASES_API_URL = "https://api.github.com/repos/XTLS/Xray-core/releases/latest";
// Used when the release feed itself cannot be reached (GitHub is filtered in
// some of the networks this tool targets). Keep in step with the newest
// release published when this file was written.
const FALLBACK_VERSION = "v26.3.27";
const API_TIMEOUT_MS = 10_000;
const DOWNLOAD_TIMEOUT_MS = 120_000;
const VERIFY_TIMEOUT_MS = 15_000;
const DOWNLOAD_ATTEMPTS = 2;
// Anything this small cannot be a real Xray binary; it catches a truncated or
// empty cache file without having to run it.
const MIN_BINARY_BYTES = 1_000_000;

interface PlatformTarget {
  /** Release asset file name, e.g. "Xray-windows-64.zip". */
  asset: string;
  /** File name of the executable inside that archive. */
  binaryName: string;
  /** Human readable label for log lines. */
  label: string;
}

const ASSETS_BY_PLATFORM: Record<string, Record<string, string>> = {
  linux: {
    x64: "linux-64",
    arm64: "linux-arm64-v8a",
    ia32: "linux-32",
    arm: "linux-arm32-v7a",
  },
  darwin: {
    x64: "macos-64",
    arm64: "macos-arm64-v8a",
  },
  win32: {
    x64: "windows-64",
    arm64: "windows-arm64-v8a",
    ia32: "windows-32",
  },
};

function detectTarget(): PlatformTarget {
  const suffix = ASSETS_BY_PLATFORM[process.platform]?.[process.arch];
  if (!suffix) {
    throw new Error(
      `no bundled Xray-core build for ${process.platform}-${process.arch}; ` +
        `pass --xray <path> to use an Xray binary you already have`,
    );
  }
  return {
    asset: `Xray-${suffix}.zip`,
    binaryName: process.platform === "win32" ? "xray.exe" : "xray",
    label: `${process.platform}-${process.arch}`,
  };
}

function errorMessage(err: unknown): string {
  const cause = (err as { cause?: { message?: string; code?: string } })?.cause;
  return cause?.code ?? cause?.message ?? (err as Error)?.message ?? String(err);
}

async function isFile(filePath: string): Promise<boolean> {
  try {
    return (await stat(filePath)).isFile();
  } catch {
    return false;
  }
}

/** Cached binaries must at least be big enough to plausibly be Xray. */
async function isUsableBinary(filePath: string): Promise<boolean> {
  try {
    const info = await stat(filePath);
    return info.isFile() && info.size >= MIN_BINARY_BYTES;
  } catch {
    return false;
  }
}

/** Asks GitHub for the newest release tag; falls back to a pinned version. */
async function resolveLatestVersion(): Promise<string> {
  try {
    const res = await fetch(RELEASES_API_URL, {
      signal: AbortSignal.timeout(API_TIMEOUT_MS),
      headers: {
        "User-Agent": "reality-sni-scanner",
        Accept: "application/vnd.github+json",
      },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const json = (await res.json()) as { tag_name?: string };
    if (!json.tag_name) throw new Error("release feed had no tag_name");
    return json.tag_name;
  } catch (err) {
    const log = forPhase("xray");
    log.warn(`latest-release lookup failed (${errorMessage(err)}), using pinned ${FALLBACK_VERSION}`);
    return FALLBACK_VERSION;
  }
}

async function downloadAndInstall(target: PlatformTarget, binPath: string): Promise<void> {
  const log = forPhase("xray");
  await mkdir(path.dirname(binPath), { recursive: true });
  let lastError: unknown;

  for (let attempt = 1; attempt <= DOWNLOAD_ATTEMPTS; attempt++) {
    try {
      const version = await resolveLatestVersion();
      const url = `https://github.com/XTLS/Xray-core/releases/download/${version}/${target.asset}`;
      log.info(`downloading ${target.asset} (${version}) for ${target.label}...`);

      const res = await fetch(url, { signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS), redirect: "follow" });
      if (!res.ok) throw new Error(`download failed: HTTP ${res.status} for ${url}`);
      const archive = Buffer.from(await res.arrayBuffer());

      const binary = extractZipEntry(archive, target.binaryName);
      if (binary.length < MIN_BINARY_BYTES) {
        throw new Error(`extracted ${target.binaryName} looks truncated (${binary.length} bytes)`);
      }

      // Write beside the final path first so a failed download can never leave
      // a half-written executable behind as the cache.
      const stagingPath = `${binPath}.download`;
      await writeFile(stagingPath, binary);
      if (process.platform !== "win32") await chmod(stagingPath, 0o755);
      await rename(stagingPath, binPath);

      log.success(`installed ${binPath} (${version}, ${binary.length} bytes)`);
      return;
    } catch (err) {
      lastError = err;
      log.warn(`attempt ${attempt}/${DOWNLOAD_ATTEMPTS} failed: ${errorMessage(err)}`);
    }
  }

  throw new Error(`could not download Xray-core: ${errorMessage(lastError)}`);
}

function runXrayVersion(binPath: string): Promise<{ code: number | null; output: string }> {
  return new Promise((resolve, reject) => {
    let output = "";
    const child = spawn(binPath, ["version"], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`xray version timed out after ${VERIFY_TIMEOUT_MS}ms`));
    }, VERIFY_TIMEOUT_MS);
    timer.unref();

    const collect = (chunk: Buffer | string) => {
      output += String(chunk);
      if (output.length > 2_000) output = output.slice(-2_000);
    };
    child.stdout?.on("data", collect);
    child.stderr?.on("data", collect);
    child.once("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.once("exit", (code) => {
      clearTimeout(timer);
      resolve({ code, output: output.trim() });
    });
  });
}

/** Runs the cached binary once to catch a corrupt or wrong-architecture file. */
async function verifyBinary(binPath: string): Promise<void> {
  try {
    const { code, output } = await runXrayVersion(binPath);
    if (code !== 0) throw new Error(`exited with code ${code}${output ? `: ${output}` : ""}`);
  } catch (err) {
    await rm(binPath, { force: true }); // only ever our own cache
    throw new Error(
      `the downloaded Xray binary at ${binPath} does not run here (${errorMessage(err)}). ` +
        `Pass --xray <path> to use your own binary instead.`,
    );
  }
}

/**
 * Returns the absolute path to an Xray binary, downloading it into ./bin/ on
 * first use. An explicit `overridePath` (--xray) is validated but never
 * downloaded to or deleted.
 */
export async function ensureXrayBinary(overridePath?: string): Promise<string> {
  if (overridePath) {
    const resolved = path.resolve(overridePath);
    if (!(await isFile(resolved))) {
      throw new Error(`--xray: no file at ${resolved}`);
    }
    return resolved;
  }

  const target = detectTarget();
  const binPath = path.join(XRAY_BIN_DIR, target.binaryName);
  if (await isUsableBinary(binPath)) return binPath;

  await downloadAndInstall(target, binPath);
  await verifyBinary(binPath);
  return binPath;
}
