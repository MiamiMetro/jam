#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function usage() {
  console.log(
    [
      "usage:",
      "  node tools/opus-acceptance.mjs --external-manifest <validation/opus-external-validation.json> [--local-out <dir>]",
      "  node tools/opus-acceptance.mjs --external-manifest <validation/opus-external-validation.json> --skip-local --use-saved-local-report [--local-out <dir>]",
      "",
      "Runs the final Opus acceptance gate.",
      "This command is intentionally stricter than local verification: it requires",
      "a real external Windows/macOS evidence manifest.",
    ].join("\n"),
  );
}

function parseArgs(argv) {
  const options = {
    externalManifest: "",
    localOut: "build/opus-local-verify/current",
    skipLocal: false,
    useSavedLocalReport: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = argv[i + 1];
    if (arg === "--external-manifest" && next) options.externalManifest = argv[++i];
    else if (arg === "--local-out" && next) options.localOut = argv[++i];
    else if (arg === "--skip-local") options.skipLocal = true;
    else if (arg === "--use-saved-local-report") options.useSavedLocalReport = true;
    else if (arg === "--help" || arg === "-h") {
      usage();
      process.exit(0);
    } else {
      throw new Error(`unknown option: ${arg}`);
    }
  }

  return options;
}

function repoPath(value) {
  return path.isAbsolute(value) ? value : path.resolve(repoRoot, value);
}

function repoRelativePath(value) {
  const full = repoPath(value);
  const relative = path.relative(repoRoot, full);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) return "";
  return relative.split(path.sep).join("/");
}

function ignoredRepoPathIssue(value, description = "external manifest path") {
  const relative = repoRelativePath(value);
  if (!relative) return "";
  const result = spawnSync("git", ["check-ignore", relative], {
    cwd: repoRoot,
    encoding: "utf8",
    timeout: 30000,
    windowsHide: true,
  });
  if ((result.status ?? 1) === 0) return "";
  return `${description} inside repo must be ignored generated evidence: ${relative}`;
}

function runStep(name, command, args) {
  console.log(`== ${name}`);
  console.log(`$ ${[command, ...args].join(" ")}`);
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: "inherit",
    windowsHide: true,
  });
  if ((result.status ?? 1) !== 0) {
    throw new Error(`${name} failed with exit ${result.status ?? 1}`);
  }
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  if (!options.externalManifest) {
    usage();
    throw new Error("--external-manifest is required");
  }

  const manifestFile = repoPath(options.externalManifest);
  if (!fs.existsSync(manifestFile)) {
    throw new Error(`external manifest does not exist: ${options.externalManifest}`);
  }
  const manifestPathIssue = ignoredRepoPathIssue(options.externalManifest);
  if (manifestPathIssue) {
    throw new Error(manifestPathIssue);
  }
  const localOutIssue = ignoredRepoPathIssue(
    path.join(options.localOut, "report.md"),
    "local verifier output path",
  );
  if (localOutIssue) {
    throw new Error(localOutIssue);
  }
  if (options.skipLocal && !options.useSavedLocalReport) {
    throw new Error("--skip-local requires --use-saved-local-report so final acceptance does not accidentally rely on cached local evidence");
  }
  if (options.skipLocal && !fs.existsSync(path.join(options.localOut, "report.md"))) {
    throw new Error(`saved local verifier report does not exist: ${path.join(options.localOut, "report.md")}`);
  }

  if (!options.skipLocal) {
    runStep("local verification", process.execPath, [
      path.join("tools", "opus-local-verify.mjs"),
      "--out",
      options.localOut,
    ]);
  }

  runStep("external evidence manifest", process.execPath, [
    path.join("tools", "opus-external-evidence-check.mjs"),
    options.externalManifest,
    "--strict",
  ]);

  runStep("completion audit", process.execPath, [
    path.join("tools", "opus-completion-audit.mjs"),
    "--external-manifest",
    options.externalManifest,
    "--local-report",
    path.join(options.localOut, "report.md"),
  ]);

  console.log("PASS: Opus acceptance gate passed");
}

try {
  main();
} catch (error) {
  console.error(`FAIL: ${error.message}`);
  process.exit(2);
}
