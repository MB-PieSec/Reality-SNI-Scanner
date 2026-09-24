#!/usr/bin/env node
// Entry point. Deliberately plain JavaScript, no TypeScript syntax at all,
// so this file itself can run on any Node version — including ones too old
// to run the rest of the tool — and print a clear error instead of a raw
// crash. The actual tool lives in src/index.ts and is loaded below, once
// we've confirmed the environment can run it.
//
// Node added the ability to run TypeScript directly in v22.6.0, but it
// stayed behind an explicit --experimental-strip-types flag for a while
// before later versions turned it on by default. That means, depending on
// exactly which 22.x version is installed, running the tool may or may not
// need that flag. Rather than making that the user's problem, we try
// without it first, and if that specific failure shows up, we retry once
// automatically with the flag added — so this keeps working with zero
// manual steps either way.

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const indexPath = path.join(__dirname, "src", "index.ts");

const REQUIRED_MAJOR = 22;
const REQUIRED_MINOR = 6; // first Node version with any TypeScript support at all

function parseVersion(v) {
  const parts = v.replace(/^v/, "").split(".").map(Number);
  return { major: parts[0], minor: parts[1], patch: parts[2] };
}

function meetsMinimum(current) {
  if (current.major !== REQUIRED_MAJOR) return current.major > REQUIRED_MAJOR;
  return current.minor >= REQUIRED_MINOR;
}

function printBox(lines) {
  const bar = "=".repeat(60);
  console.error(bar);
  for (const line of lines) console.error(line);
  console.error(bar);
}

function isUnknownTsExtensionError(err) {
  const message = String((err && err.message) || err);
  return (
    (err && err.code === "ERR_UNKNOWN_FILE_EXTENSION") ||
    /unknown file extension "?\.ts"?/i.test(message)
  );
}

/** Re-runs the tool in a fresh Node process with --experimental-strip-types added. */
function runWithStripTypesFlag() {
  return new Promise((resolve) => {
    const child = spawn(
      process.execPath,
      ["--experimental-strip-types", indexPath, ...process.argv.slice(2)],
      { stdio: "inherit" },
    );
    child.on("exit", (code) => resolve(code ?? 1));
    child.on("error", () => resolve(1));
  });
}

const current = parseVersion(process.version);

if (!meetsMinimum(current)) {
  printBox([
    "[x] Node.js version too old",
    "",
    `This tool needs Node.js v${REQUIRED_MAJOR}.${REQUIRED_MINOR} or newer`,
    "(it runs TypeScript directly — no install or build step).",
    `You have: ${process.version}`,
    "",
    "Download the latest version here: https://nodejs.org",
  ]);
  process.exit(1);
}

try {
  await import("./src/index.ts");
} catch (err) {
  if (isUnknownTsExtensionError(err)) {
    // This Node version has TypeScript support but needs the flag spelled
    // out explicitly. Retry once, transparently.
    const exitCode = await runWithStripTypesFlag();
    process.exit(exitCode);
  }

  printBox([
    "[x] Failed to start",
    "",
    String((err && err.message) || err),
    "",
    `Node.js version: ${process.version}`,
    "If this doesn't make sense, try updating Node.js: https://nodejs.org",
  ]);
  process.exit(1);
}
