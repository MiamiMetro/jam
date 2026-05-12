#!/usr/bin/env node

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { sourceFingerprint, sourceFingerprintFileList } from "./opus-source-fingerprint.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function usage() {
  console.log(
    [
      "usage:",
      "  node tools/opus-validation.mjs smoke [--skip-audio] [--out <dir>]",
      "  node tools/opus-validation.mjs instructions",
      "",
      "The smoke command writes process logs, native --log-file logs, and report.md under build/opus-validation/.",
      "Run it on Windows and macOS before promoting the Opus branch to main.",
    ].join("\n"),
  );
}

function parseArgs(argv) {
  const options = {
    command: argv[0],
    skipAudio: false,
    outDir: "",
    client: "",
    harness: "",
  };

  for (let i = 1; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = argv[i + 1];
    if (arg === "--skip-audio") options.skipAudio = true;
    else if (arg === "--out" && next) options.outDir = argv[++i];
    else if (arg === "--client" && next) options.client = argv[++i];
    else if (arg === "--harness" && next) options.harness = argv[++i];
    else {
      console.error(`unknown option: ${arg}`);
      process.exit(2);
    }
  }

  return options;
}

function timestamp() {
  const now = new Date();
  const pad = (value) => String(value).padStart(2, "0");
  return [
    now.getFullYear(),
    pad(now.getMonth() + 1),
    pad(now.getDate()),
    "-",
    pad(now.getHours()),
    pad(now.getMinutes()),
    pad(now.getSeconds()),
  ].join("");
}

function resolveExe(explicit, candidates) {
  if (explicit) return path.resolve(repoRoot, explicit);
  for (const candidate of candidates) {
    const full = path.resolve(repoRoot, candidate);
    if (fs.existsSync(full)) return full;
  }
  return path.resolve(repoRoot, candidates[0]);
}

function relativeDisplay(...parts) {
  return path.relative(repoRoot, path.join(...parts)).split(path.sep).join("/");
}

function repoRelativePath(value) {
  const full = path.isAbsolute(value) ? value : path.resolve(repoRoot, value);
  const relative = path.relative(repoRoot, full);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) return "";
  return relative.split(path.sep).join("/");
}

function ignoredRepoPathIssue(value) {
  const relative = repoRelativePath(value);
  if (!relative) return "";
  const result = spawnSync("git", ["check-ignore", relative], {
    cwd: repoRoot,
    encoding: "utf8",
    timeout: 30000,
    windowsHide: true,
  });
  if ((result.status ?? 1) === 0) return "";
  return `validation output path inside repo must be ignored generated evidence: ${relative}`;
}

function runStep(outDir, name, command, args) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    windowsHide: true,
  });

  const output = [
    `$ ${[command, ...args].join(" ")}`,
    "",
    result.stdout ?? "",
    result.stderr ?? "",
  ].join("\n");

  const logPath = path.join(outDir, `${name}.log`);
  fs.writeFileSync(logPath, output);
  return {
    name,
    command,
    args,
    code: result.status ?? 1,
    signal: result.signal ?? "",
    logPath,
  };
}

function writeReport(outDir, steps) {
  const lines = [
    "# Opus Validation Report",
    "",
    `Date: ${new Date().toISOString()}`,
    `Platform: ${os.platform()} ${os.release()} ${os.arch()}`,
    `Host: ${os.hostname()}`,
    `Source SHA256: ${sourceFingerprint(repoRoot)}`,
    `Source files: ${sourceFingerprintFileList(repoRoot).length}`,
    "",
    "## Results",
    "",
    "| Step | Exit | Log |",
    "| --- | ---: | --- |",
  ];

  for (const step of steps) {
    lines.push(
      `| ${step.name} | ${step.code}${step.signal ? ` (${step.signal})` : ""} | ${path.basename(
        step.logPath,
      )} |`,
    );
  }

  lines.push(
    "",
    "## Interpretation",
    "",
    "- All steps exiting `0` means this machine passed the local Opus smoke checks.",
    "- This does not replace real cross-machine listening, long-session drift capture, or PCM research.",
    "- Attach this directory's logs when comparing Windows and macOS behavior.",
    "",
  );

  fs.writeFileSync(path.join(outDir, "report.md"), `${lines.join("\n")}\n`);
}

function smoke(options) {
  const outDir = path.resolve(
    repoRoot,
    options.outDir || path.join("build", "opus-validation", timestamp()),
  );
  const outPathIssue = ignoredRepoPathIssue(path.join(outDir, "report.md"));
  if (outPathIssue) {
    console.error(outPathIssue);
    process.exit(2);
  }
  fs.mkdirSync(outDir, { recursive: true });

  const client = resolveExe(options.client, [
    "build/Debug/client.exe",
    "build/client",
    "build/Debug/client",
  ]);
  const harness = resolveExe(options.harness, [
    "build/Debug/opus_receiver_harness.exe",
    "build/opus_receiver_harness",
    "build/Debug/opus_receiver_harness",
  ]);

  const steps = [
    runStep(outDir, "startup-default", client, [
      "--startup-config-smoke",
      "--codec",
      "opus",
      "--frames",
      "120",
      "--log-file",
      path.join(outDir, "startup-default-client.log"),
    ]),
    runStep(outDir, "startup-no-auto", client, [
      "--startup-config-smoke",
      "--codec",
      "opus",
      "--frames",
      "120",
      "--no-auto-jitter",
      "--log-file",
      path.join(outDir, "startup-no-auto-client.log"),
    ]),
    runStep(outDir, "harness-self-test", harness, ["--self-test"]),
  ];

  if (!options.skipAudio) {
    steps.push(
      runStep(outDir, "audio-open", client, [
        "--audio-open-smoke",
        "--frames",
        "120",
        "--log-file",
        path.join(outDir, "audio-open-client.log"),
      ]),
    );
  }

  writeReport(outDir, steps);
  console.log(`wrote ${relativeDisplay(outDir, "report.md")}`);

  const failed = steps.filter((step) => step.code !== 0);
  if (failed.length > 0) {
    console.error(`failed steps: ${failed.map((step) => step.name).join(", ")}`);
    process.exit(1);
  }
}

function instructions() {
  console.log(
    [
      "External Opus validation:",
      "",
      "1. Build the branch on Windows and macOS.",
      "2. On each machine, run:",
      "   node tools/opus-validation.mjs smoke",
      "3. Save each build/opus-validation/<timestamp>/ directory.",
      "4. Run real Windows-to-macOS and macOS-to-Windows Opus 120 sessions.",
      "5. Add --log-file <path> to each native client/server command.",
      "6. For long-session validation, run 30-60 minutes and capture client logs for:",
      "   drift_ppm, queue age, underruns, PLC, auto jitter inc/dec, and subjective audio.",
      "7. Summarize logs:",
      "   node tools/opus-log-summary.mjs --out validation/validation-summary.md <client-a.log> <client-b.log> <server.log>",
      "8. Initialize the evidence manifest:",
      "   node tools/opus-external-evidence-check.mjs --init validation/opus-external-validation.json --windows-smoke <windows-report.md> --mac-smoke <mac-report.md> --win-to-mac-logs <windows.log,macos.log,server.log> --mac-to-win-logs <windows.log,macos.log,server.log> --long-logs <windows.log,macos.log,server.log>",
      "9. Edit manifest network/subjective notes, then check the evidence packet:",
      "   node tools/opus-external-evidence-check.mjs validation/opus-external-validation.json",
      "10. Treat PCM as research until cross-machine PCM is explained or corrected.",
    ].join("\n"),
  );
}

const options = parseArgs(process.argv.slice(2));

if (options.command === "smoke") {
  smoke(options);
} else if (options.command === "instructions") {
  instructions();
} else {
  usage();
  process.exit(options.command ? 2 : 0);
}
