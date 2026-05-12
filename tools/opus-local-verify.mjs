#!/usr/bin/env node

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { sourceFingerprint, sourceFingerprintFileList } from "./opus-source-fingerprint.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const criticalFingerprintFiles = [
  ".gitignore",
  "CMakeLists.txt",
  "OPUS_COMPETITIVE_ROADMAP.md",
  "OPUS_COMPETITIVE_IMPLEMENTATION_CHECKLIST.md",
  "OPUS_COMPETITIVE_COMPLETION_AUDIT.md",
  "OPUS_EXTERNAL_VALIDATION_RUNBOOK.md",
  "OPUS_EXTERNAL_VALIDATION_MANIFEST.example.json",
  "client.cpp",
  "server.cpp",
  "participant_info.h",
  "participant_manager.h",
  "protocol.h",
  "opus_receiver_harness.cpp",
  "udp_impair_proxy.cpp",
  "multi_participant_jitter_probe.cpp",
  "tools/opus-acceptance.mjs",
  "tools/opus-competitor-evidence-check.mjs",
  "tools/opus-completion-audit.mjs",
  "tools/opus-external-commands.mjs",
  "tools/opus-external-evidence-check.mjs",
  "tools/opus-local-evidence.mjs",
  "tools/opus-local-verify.mjs",
  "tools/opus-log-summary.mjs",
  "tools/opus-source-fingerprint.mjs",
  "tools/opus-validation.mjs",
];

function usage() {
  console.log(
    [
      "usage:",
      "  node tools/opus-local-verify.mjs [--out <dir>]",
      "",
      "Runs the full local Opus verification set for this machine and writes a report.",
      "This does not replace macOS/cross-machine external validation.",
    ].join("\n"),
  );
}

function parseArgs(argv) {
  const options = { outDir: "" };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = argv[i + 1];
    if (arg === "--out" && next) options.outDir = argv[++i];
    else if (arg === "--help" || arg === "-h") {
      usage();
      process.exit(0);
    } else {
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
  return `local verifier output path inside repo must be ignored generated evidence: ${relative}`;
}

function runStep(outDir, name, command, args, timeoutMs = 180000) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    timeout: timeoutMs,
    windowsHide: true,
  });

  const output = [
    `$ ${[command, ...args].join(" ")}`,
    "",
    result.stdout ?? "",
    result.stderr ?? "",
  ].join("\n");
  const logPath = path.join(outDir, `${name}.log`);
  fs.writeFileSync(logPath, output, "utf8");

  return {
    name,
    code: result.status ?? 1,
    signal: result.signal ?? "",
    logPath,
    summary: summarizeOutput(output),
  };
}

function runExpectedFailureStep(outDir, name, command, args, expectedText, timeoutMs = 30000) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    timeout: timeoutMs,
    windowsHide: true,
  });

  const output = [
    `$ ${[command, ...args].join(" ")}`,
    "",
    result.stdout ?? "",
    result.stderr ?? "",
  ].join("\n");
  const logPath = path.join(outDir, `${name}.log`);
  fs.writeFileSync(logPath, output, "utf8");

  const failedAsExpected = (result.status ?? 1) !== 0 && output.includes(expectedText);
  return {
    name,
    code: failedAsExpected ? 0 : 1,
    signal: result.signal ?? "",
    logPath,
    summary: failedAsExpected
      ? `observed expected failure: ${expectedText}`
      : `expected non-zero exit containing: ${expectedText}`,
  };
}

function checkFileContainsStep(outDir, name, file, needles) {
  const fullPath = path.isAbsolute(file) ? file : path.resolve(repoRoot, file);
  const logPath = path.join(outDir, `${name}.log`);
  const text = fs.existsSync(fullPath) ? fs.readFileSync(fullPath, "utf8") : "";
  const missing = needles.filter((needle) => !text.includes(needle));

  fs.writeFileSync(
    logPath,
    [
      `$ check ${path.relative(repoRoot, fullPath).split(path.sep).join("/")}`,
      "",
      missing.length === 0
        ? `PASS: found ${needles.join(", ")}`
        : `FAIL: missing ${missing.join(", ")}`,
      "",
    ].join("\n"),
    "utf8",
  );

  return {
    name,
    code: missing.length === 0 ? 0 : 1,
    signal: "",
    logPath,
    summary: missing.length === 0
      ? `found ${needles.join(", ")}`
      : `missing ${missing.join(", ")}`,
  };
}

function commandArg(line, flag) {
  const pattern = new RegExp(`${flag.replaceAll("-", "\\-")}\\s+(?:"([^"]+)"|([^\\s]+))`);
  const match = line.match(pattern);
  return match ? match[1] ?? match[2] : "";
}

function checkExternalCommandTokensStep(outDir, name, file) {
  const fullPath = path.isAbsolute(file) ? file : path.resolve(repoRoot, file);
  const logPath = path.join(outDir, `${name}.log`);
  const text = fs.existsSync(fullPath) ? fs.readFileSync(fullPath, "utf8") : "";
  const commandLines = text
    .split(/\r?\n/)
    .filter((line) => line.includes("--join-token"));
  const failures = [];
  const now = Date.now();
  const minRemainingMs = 3 * 60 * 60 * 1000;
  const ttlMatch = text.match(/^Validation token TTL:\s*(\d+)\s+ms/m);
  const generatedMatch = text.match(/^Generated at \(UTC\):\s*(.+)$/m);
  const expiresMatch = text.match(/^Validation tokens expire at \(UTC\):\s*(.+)$/m);
  const ttlMs = ttlMatch ? Number(ttlMatch[1]) : NaN;
  const generatedAtMs = generatedMatch ? Date.parse(generatedMatch[1]) : NaN;
  const headerExpiresAtMs = expiresMatch ? Date.parse(expiresMatch[1]) : NaN;
  const tokenExpirations = new Set();

  if (commandLines.length !== 6) {
    failures.push(`expected 6 generated client commands, found ${commandLines.length}`);
  }
  if (!Number.isFinite(ttlMs)) failures.push("missing or malformed validation token TTL header");
  if (!Number.isFinite(generatedAtMs)) failures.push("missing or malformed generated-at header");
  if (!Number.isFinite(headerExpiresAtMs)) failures.push("missing or malformed token-expiry header");
  if (
    Number.isFinite(ttlMs) &&
    Number.isFinite(generatedAtMs) &&
    Number.isFinite(headerExpiresAtMs) &&
    headerExpiresAtMs - generatedAtMs !== ttlMs
  ) {
    failures.push("generated-at, token-expiry, and TTL headers do not agree");
  }

  for (const line of commandLines) {
    const room = commandArg(line, "--room");
    const user = commandArg(line, "--user-id");
    const token = commandArg(line, "--join-token");
    const parts = token.split(".");
    if (!room || !user || !token) {
      failures.push(`missing room/user/token in command: ${line}`);
      continue;
    }
    if (parts.length !== 8) {
      failures.push(`token for ${user}/${room} has ${parts.length} fields, expected 8`);
      continue;
    }
    const [version, expiresAtMs, serverId, tokenRoom, profileId, role, nonce, signature] = parts;
    if (version !== "v1") failures.push(`token for ${user}/${room} has wrong version ${version}`);
    if (serverId !== "local-dev") failures.push(`token for ${user}/${room} has wrong server id ${serverId}`);
    if (tokenRoom !== room) failures.push(`token room ${tokenRoom} does not match command room ${room}`);
    if (profileId !== user) failures.push(`token user ${profileId} does not match command user ${user}`);
    if (role !== "performer") failures.push(`token for ${user}/${room} has wrong role ${role}`);
    if (!/^[a-f0-9]{32}$/i.test(nonce)) failures.push(`token for ${user}/${room} has malformed nonce`);
    const expiresNumber = Number(expiresAtMs);
    if (!Number.isFinite(expiresNumber)) {
      failures.push(`token for ${user}/${room} has malformed expiration ${expiresAtMs}`);
    } else if (expiresNumber - now < minRemainingMs) {
      failures.push(`token for ${user}/${room} expires too soon for external validation`);
    } else {
      tokenExpirations.add(expiresNumber);
    }
    const payload = ["v1", expiresAtMs, serverId, tokenRoom, profileId, role, nonce].join("|");
    const expectedSignature = crypto.createHmac("sha256", "dev-secret").update(payload).digest("hex");
    if (signature !== expectedSignature) failures.push(`token for ${user}/${room} has invalid signature`);
  }
  if (tokenExpirations.size > 1) failures.push("generated join tokens do not share one expiration");
  if (
    tokenExpirations.size === 1 &&
    Number.isFinite(headerExpiresAtMs) &&
    !tokenExpirations.has(headerExpiresAtMs)
  ) {
    failures.push("token-expiry header does not match generated join-token expiration");
  }

  fs.writeFileSync(
    logPath,
    [
      `$ check generated external join tokens in ${path.relative(repoRoot, fullPath).split(path.sep).join("/")}`,
      "",
      failures.length === 0
        ? `PASS: verified ${commandLines.length} generated join tokens`
        : `FAIL:\n${failures.map((failure) => `- ${failure}`).join("\n")}`,
      "",
    ].join("\n"),
    "utf8",
  );

  return {
    name,
    code: failures.length === 0 ? 0 : 1,
    signal: "",
    logPath,
    summary: failures.length === 0
      ? `verified ${commandLines.length} generated join tokens and expiry headers`
      : `${failures.length} token issue(s)`,
  };
}

function summarizeOutput(output) {
  const lines = output
    .split(/\r?\n/)
    .filter((line) => line.startsWith("wrote ") || line.startsWith("PASS:") || line.startsWith("failed "));
  return lines.join("; ");
}

function documentationIssues(files) {
  const issues = [];
  for (const file of files) {
    const full = path.resolve(repoRoot, file);
    const lines = fs.readFileSync(full, "utf8").split(/\r?\n/);
    lines.forEach((line, index) => {
      if (file === "OPUS_COMPETITIVE_ROADMAP.md" && /^\s*-\s+\[[ xX]\]/.test(line)) {
        issues.push(`${file}:${index + 1}:roadmap checkbox:${line}`);
      }
      if (/^\s*-\s+\[\s\]/.test(line)) issues.push(`${file}:${index + 1}:unchecked checkbox:${line}`);
      if (line.trim() === "Tasks:") issues.push(`${file}:${index + 1}:roadmap task marker:${line}`);
    });
  }
  return issues;
}

function checkExternalCommandSourceFingerprintStep(outDir, name, file) {
  const fullPath = path.isAbsolute(file) ? file : path.resolve(repoRoot, file);
  const logPath = path.join(outDir, `${name}.log`);
  const text = fs.existsSync(fullPath) ? fs.readFileSync(fullPath, "utf8") : "";
  const fingerprint = sourceFingerprint(repoRoot);
  const fileCount = sourceFingerprintFileList(repoRoot).length;
  const failures = [];
  if (!text.includes(`Source SHA256: ${fingerprint}`)) {
    failures.push("generated command packet missing current Source SHA256");
  }
  if (!text.includes(`Source files: ${fileCount}`)) {
    failures.push("generated command packet missing current source file count");
  }
  if (!text.includes("node tools/opus-source-fingerprint.mjs")) {
    failures.push("generated command packet missing source-fingerprint preflight command");
  }

  fs.writeFileSync(
    logPath,
    [
      `$ check generated external command source fingerprint in ${path.relative(repoRoot, fullPath).split(path.sep).join("/")}`,
      "",
      failures.length === 0 ? "PASS: command packet includes current source fingerprint preflight" : `FAIL:\n${failures.join("\n")}`,
      "",
    ].join("\n"),
    "utf8",
  );

  return {
    name,
    code: failures.length === 0 ? 0 : 1,
    signal: "",
    logPath,
    summary: failures.length === 0
      ? "command packet includes current source fingerprint preflight"
      : failures.join("; "),
  };
}

function sourceWhitespaceHygieneStep(outDir) {
  const logPath = path.join(outDir, "source-whitespace-hygiene.log");
  const issues = [];

  for (const file of sourceFingerprintFileList(repoRoot)) {
    const full = path.resolve(repoRoot, file);
    if (!fs.existsSync(full)) continue;
    const lines = fs.readFileSync(full, "utf8").split(/\r?\n/);
    lines.forEach((line, index) => {
      if (/[ \t]+$/.test(line)) issues.push(`${file}:${index + 1}: trailing whitespace`);
    });
  }

  fs.writeFileSync(
    logPath,
    [
      "$ check source whitespace hygiene",
      "",
      issues.length === 0
        ? "PASS: no trailing whitespace in source-fingerprint files"
        : `FAIL:\n${issues.map((issue) => `- ${issue}`).join("\n")}`,
      "",
    ].join("\n"),
    "utf8",
  );

  return {
    name: "source-whitespace-hygiene",
    code: issues.length === 0 ? 0 : 1,
    signal: "",
    logPath,
    summary: issues.length === 0
      ? "no trailing whitespace in source-fingerprint files"
      : `${issues.length} whitespace issue(s)`,
  };
}

function sourceFingerprintCoverageStep(outDir) {
  const fingerprintFiles = new Set(sourceFingerprintFileList(repoRoot));
  const missing = criticalFingerprintFiles.filter((file) => !fingerprintFiles.has(file));
  const logPath = path.join(outDir, "source-fingerprint-critical-files.log");

  fs.writeFileSync(
    logPath,
    [
      "$ check critical source fingerprint coverage",
      "",
      `fingerprinted files=${fingerprintFiles.size}`,
      "",
      missing.length === 0
        ? "PASS: all critical roadmap/tool/native files are covered by Source SHA256"
        : `FAIL:\n${missing.map((file) => `- missing from Source SHA256: ${file}`).join("\n")}`,
      "",
    ].join("\n"),
    "utf8",
  );

  return {
    name: "source-fingerprint-critical-files",
    code: missing.length === 0 ? 0 : 1,
    signal: "",
    logPath,
    summary: missing.length === 0
      ? "critical files covered by Source SHA256"
      : `${missing.length} critical file(s) missing from Source SHA256`,
  };
}

function validationDirIgnoredStep(outDir) {
  const expectedIgnoredPaths = [
    "validation/opus-external-commands.md",
    "validation/opus-external-validation.json",
    "validation/validation-summary.md",
    "validation_logs/legacy-evidence.json",
  ];
  const result = spawnSync("git", ["check-ignore", ...expectedIgnoredPaths], {
    cwd: repoRoot,
    encoding: "utf8",
    timeout: 30000,
    windowsHide: true,
  });

  const output = [
    `$ git check-ignore ${expectedIgnoredPaths.join(" ")}`,
    "",
    result.stdout ?? "",
    result.stderr ?? "",
  ].join("\n");
  const logPath = path.join(outDir, "validation-dir-gitignored.log");
  fs.writeFileSync(logPath, output, "utf8");

  const ignored = (result.status ?? 1) === 0;
  const ignoredPaths = new Set(
    String(result.stdout || "")
      .split(/\r?\n/)
      .map((line) => line.trim().replaceAll("\\", "/"))
      .filter(Boolean),
  );
  const missing = expectedIgnoredPaths.filter((entry) => !ignoredPaths.has(entry));
  return {
    name: "validation-dir-gitignored",
    code: ignored && missing.length === 0 ? 0 : 1,
    signal: result.signal ?? "",
    logPath,
    summary: ignored && missing.length === 0
      ? "validation artifact paths are ignored"
      : `validation artifact ignore missing: ${missing.join(", ") || "check-ignore failed"}`,
  };
}

function sourceFingerprintLineEndingStep(outDir) {
  const root = path.join(outDir, "source-fingerprint-line-ending-fixture");
  const lfRepo = path.join(root, "lf");
  const crlfRepo = path.join(root, "crlf");
  fs.mkdirSync(lfRepo, { recursive: true });
  fs.mkdirSync(crlfRepo, { recursive: true });
  fs.writeFileSync(path.join(lfRepo, "sample.md"), "# Title\n\nLine one\nLine two\n", "utf8");
  fs.writeFileSync(path.join(crlfRepo, "sample.md"), "# Title\r\n\r\nLine one\r\nLine two\r\n", "utf8");

  const lfFingerprint = sourceFingerprint(lfRepo);
  const crlfFingerprint = sourceFingerprint(crlfRepo);
  const logPath = path.join(outDir, "source-fingerprint-line-endings.log");
  fs.writeFileSync(
    logPath,
    [
      "$ check source fingerprint line-ending normalization",
      "",
      `lf=${lfFingerprint}`,
      `crlf=${crlfFingerprint}`,
      lfFingerprint === crlfFingerprint ? "PASS: fingerprints match" : "FAIL: fingerprints differ",
      "",
    ].join("\n"),
    "utf8",
  );

  return {
    name: "source-fingerprint-line-endings",
    code: lfFingerprint === crlfFingerprint ? 0 : 1,
    signal: "",
    logPath,
    summary: lfFingerprint === crlfFingerprint
      ? "CRLF/LF fingerprints match"
      : "CRLF/LF fingerprints differ",
  };
}

function sourceFingerprintGeneratedDirsStep(outDir) {
  const root = path.join(outDir, "source-fingerprint-generated-dirs-fixture");
  fs.rmSync(root, { recursive: true, force: true });
  fs.mkdirSync(path.join(root, "validation"), { recursive: true });
  fs.mkdirSync(path.join(root, "validation_logs"), { recursive: true });
  fs.writeFileSync(path.join(root, "CMakeLists.txt"), "cmake_minimum_required(VERSION 3.20)\n", "utf8");
  fs.writeFileSync(path.join(root, "validation", "opus-external-validation.json"), "{}\n", "utf8");
  fs.writeFileSync(path.join(root, "validation_logs", "legacy-evidence.md"), "# generated\n", "utf8");

  const files = sourceFingerprintFileList(root);
  const unexpected = files.filter((file) => file.startsWith("validation/") || file.startsWith("validation_logs/"));
  const logPath = path.join(outDir, "source-fingerprint-generated-dirs.log");
  fs.writeFileSync(
    logPath,
    [
      "$ check source fingerprint generated evidence directory exclusions",
      "",
      `files=${files.join(", ")}`,
      "",
      unexpected.length === 0
        ? "PASS: generated validation directories are excluded from Source SHA256"
        : `FAIL:\n${unexpected.map((file) => `- generated file included in Source SHA256: ${file}`).join("\n")}`,
      "",
    ].join("\n"),
    "utf8",
  );

  return {
    name: "source-fingerprint-generated-dirs",
    code: unexpected.length === 0 ? 0 : 1,
    signal: "",
    logPath,
    summary: unexpected.length === 0
      ? "generated validation directories excluded from Source SHA256"
      : `${unexpected.length} generated file(s) included in Source SHA256`,
  };
}

function writeReport(outDir, steps, docIssues) {
  const lines = [
    "# Opus Local Verification Report",
    "",
    `Date: ${new Date().toISOString()}`,
    `Platform: ${os.platform()} ${os.release()} ${os.arch()}`,
    `Host: ${os.hostname()}`,
    `Source SHA256: ${sourceFingerprint(repoRoot)}`,
    `Source files: ${sourceFingerprintFileList(repoRoot).length}`,
    "",
    "## Command Results",
    "",
    "| Step | Exit | Summary | Log |",
    "| --- | ---: | --- | --- |",
  ];

  for (const step of steps) {
    lines.push(
      `| ${step.name} | ${step.code}${step.signal ? ` (${step.signal})` : ""} | ${
        step.summary || ""
      } | ${path.basename(step.logPath)} |`,
    );
  }

  lines.push(
    "",
    "## Documentation Check",
    "",
    docIssues.length === 0
      ? "- No roadmap task checkboxes, unchecked `- [ ]` boxes, or `Tasks:` markers remain in the roadmap/checklist/audit/runbook docs."
      : "- Documentation issues found:",
  );
  for (const issue of docIssues) lines.push(`  - ${issue}`);

  lines.push(
    "",
    "## Boundary",
    "",
    "- This report verifies local build, local probes, local smoke, competitor-source evidence, parser self-tests, and documentation hygiene.",
    "- It does not replace `OPUS_EXTERNAL_VALIDATION_RUNBOOK.md` or a passing external validation manifest.",
    "",
  );

  fs.writeFileSync(path.join(outDir, "report.md"), `${lines.join("\n")}\n`, "utf8");
}

const options = parseArgs(process.argv.slice(2));
const outDir = path.resolve(repoRoot, options.outDir || path.join("build", "opus-local-verify", timestamp()));
const outPathIssue = ignoredRepoPathIssue(path.join(outDir, "report.md"));
if (outPathIssue) {
  console.error(outPathIssue);
  process.exit(2);
}
fs.mkdirSync(outDir, { recursive: true });
const placeholderSavedLocalReportDir = path.join(outDir, "placeholder-saved-local-report");
fs.mkdirSync(placeholderSavedLocalReportDir, { recursive: true });
fs.writeFileSync(
  path.join(placeholderSavedLocalReportDir, "report.md"),
  "# Placeholder saved local report\n\nUsed only to keep acceptance expected-failure ordering deterministic.\n",
  "utf8",
);
const ignoredPlaceholderManifest = path.join(outDir, "ignored-placeholder-external-manifest.json");
fs.writeFileSync(ignoredPlaceholderManifest, "{}\n", "utf8");
const malformedManifest = path.join(outDir, "malformed-external-manifest.json");
fs.writeFileSync(malformedManifest, "{ not json\n", "utf8");
const nonObjectManifest = path.join(outDir, "non-object-external-manifest.json");
fs.writeFileSync(nonObjectManifest, "[]\n", "utf8");
const minimalExternalSessions = [
  {
    name: "windows-to-macos-5min",
    direction: "windows-to-macos",
    room: "opus-validation-room-win-to-mac",
    codec: "opus",
    frames: 120,
    jitter: 8,
    speakerPlatform: "windows",
    listenerPlatform: "macos",
    minMinutes: 5,
    network: "routable home LAN between separate Windows and macOS machines",
    subjective: "Windows source heard on macOS: clear audio during the run.",
    logs: [
      "validation/win-to-mac-windows-client.log",
      "validation/win-to-mac-macos-client.log",
      "validation/win-to-mac-server.log",
    ],
  },
  {
    name: "macos-to-windows-5min",
    direction: "macos-to-windows",
    room: "opus-validation-room-mac-to-win",
    codec: "opus",
    frames: 120,
    jitter: 8,
    speakerPlatform: "macos",
    listenerPlatform: "windows",
    minMinutes: 5,
    network: "routable home LAN between separate Windows and macOS machines",
    subjective: "macOS source heard on Windows: clear audio during the run.",
    logs: [
      "validation/mac-to-win-windows-client.log",
      "validation/mac-to-win-macos-client.log",
      "validation/mac-to-win-server.log",
    ],
  },
  {
    name: "long-session-30min",
    direction: "bidirectional",
    room: "opus-validation-long-room",
    codec: "opus",
    frames: 120,
    jitter: 8,
    participants: ["windows", "macos"],
    minMinutes: 30,
    network: "routable home LAN between separate Windows and macOS machines",
    subjective: "Long-session Windows and macOS audio remained clear.",
    logs: [
      "validation/windows-client-long.log",
      "validation/macos-client-long.log",
      "validation/server-long.log",
    ],
  },
];
const sourceControlledSmokeManifest = path.join(outDir, "source-controlled-smoke-manifest.json");
fs.writeFileSync(
  sourceControlledSmokeManifest,
  `${JSON.stringify(
    {
      windowsSmokeReport: "OPUS_COMPETITIVE_ROADMAP.md",
      macSmokeReport: ignoredPlaceholderManifest,
      sessions: minimalExternalSessions,
    },
    null,
    2,
  )}\n`,
  "utf8",
);
const sourceControlledLogManifest = path.join(outDir, "source-controlled-log-manifest.json");
fs.writeFileSync(
  sourceControlledLogManifest,
  `${JSON.stringify(
    {
      windowsSmokeReport: ignoredPlaceholderManifest,
      macSmokeReport: ignoredPlaceholderManifest,
      sessions: [
        {
          ...minimalExternalSessions[0],
          logs: [
            "OPUS_COMPETITIVE_ROADMAP.md",
            "validation/win-to-mac-macos-client.log",
            "validation/win-to-mac-server.log",
          ],
        },
        minimalExternalSessions[1],
        minimalExternalSessions[2],
      ],
    },
    null,
    2,
  )}\n`,
  "utf8",
);
const malformedBooleanManifest = path.join(outDir, "malformed-boolean-external-manifest.json");
fs.writeFileSync(
  malformedBooleanManifest,
  `${JSON.stringify(
    {
      windowsSmokeReport: ignoredPlaceholderManifest,
      windowsSmokeAllowAudioOpenFailure: "false",
      macSmokeReport: ignoredPlaceholderManifest,
      macSmokeAllowAudioOpenFailure: false,
      sessions: [
        {
          ...minimalExternalSessions[0],
          allowWarnings: "false",
        },
        minimalExternalSessions[1],
        minimalExternalSessions[2],
      ],
    },
    null,
    2,
  )}\n`,
  "utf8",
);
const malformedTypeManifest = path.join(outDir, "malformed-type-external-manifest.json");
fs.writeFileSync(
  malformedTypeManifest,
  `${JSON.stringify(
    {
      windowsSmokeReport: ignoredPlaceholderManifest,
      macSmokeReport: ignoredPlaceholderManifest,
      sessions: [
        {
          ...minimalExternalSessions[0],
          frames: "120",
        },
        minimalExternalSessions[1],
        minimalExternalSessions[2],
      ],
    },
    null,
    2,
  )}\n`,
  "utf8",
);
const unknownFieldManifest = path.join(outDir, "unknown-field-external-manifest.json");
fs.writeFileSync(
  unknownFieldManifest,
  `${JSON.stringify(
    {
      windowsSmokeReport: ignoredPlaceholderManifest,
      macSmokeReport: ignoredPlaceholderManifest,
      unexpectedRootField: true,
      sessions: [
        {
          ...minimalExternalSessions[0],
          unexpectedSessionField: true,
        },
        minimalExternalSessions[1],
        minimalExternalSessions[2],
      ],
    },
    null,
    2,
  )}\n`,
  "utf8",
);
const logSummaryFixture = path.join(outDir, "log-summary-fixture.log");
fs.writeFileSync(
  logSummaryFixture,
  "[2026-05-11 20:00:00.000] [info] Participant diag 1: ready=true q=5 q_avg=5 q_max=6 q_drift=0.00 jitter_buffer=5 queue_limit=16 frames pkt/cb=120/120 decoded_frames=0 decoded_packets=100 age_avg_ms=12.5 drift_ppm last/avg/max=0.0/0.0/0.0 underruns=0 pcm_hold/drop=0/0 drops q/age=0/0 drop_detail limit/age/overflow=0/0/0 seq gap/late=0/0 target_trim=0\n",
  "utf8",
);

const steps = [
  runStep(outDir, "cmake-build-debug", "cmake", ["--build", "build", "--config", "Debug"], 180000),
  runStep(outDir, "cmake-build-release", "cmake", ["--build", "build", "--config", "Release"], 300000),
  runStep(
    outDir,
    "opus-receiver-harness-self-test",
    "cmake",
    ["--build", "build", "--target", "opus_receiver_harness_self_test", "--config", "Debug"],
    120000,
  ),
  runStep(outDir, "check-opus-validation-js", process.execPath, ["--check", path.join("tools", "opus-validation.mjs")]),
  runStep(
    outDir,
    "check-opus-local-evidence-js",
    process.execPath,
    ["--check", path.join("tools", "opus-local-evidence.mjs")],
  ),
  runStep(
    outDir,
    "check-opus-log-summary-js",
    process.execPath,
    ["--check", path.join("tools", "opus-log-summary.mjs")],
  ),
  runStep(
    outDir,
    "check-opus-external-evidence-js",
    process.execPath,
    ["--check", path.join("tools", "opus-external-evidence-check.mjs")],
  ),
  runStep(
    outDir,
    "check-opus-external-commands-js",
    process.execPath,
    ["--check", path.join("tools", "opus-external-commands.mjs")],
  ),
  runStep(
    outDir,
    "check-opus-acceptance-js",
    process.execPath,
    ["--check", path.join("tools", "opus-acceptance.mjs")],
  ),
  checkFileContainsStep(
    outDir,
    "opus-acceptance-runs-completion-audit",
    path.join("tools", "opus-acceptance.mjs"),
    [
      "completion audit",
      "tools\", \"opus-external-evidence-check.mjs",
      "--strict",
      "tools\", \"opus-completion-audit.mjs",
      "--external-manifest",
      "--local-report",
    ],
  ),
  runStep(
    outDir,
    "check-opus-completion-audit-js",
    process.execPath,
    ["--check", path.join("tools", "opus-completion-audit.mjs")],
  ),
  runStep(
    outDir,
    "check-opus-competitor-evidence-js",
    process.execPath,
    ["--check", path.join("tools", "opus-competitor-evidence-check.mjs")],
  ),
  runStep(
    outDir,
    "opus-competitor-evidence-check",
    process.execPath,
    [path.join("tools", "opus-competitor-evidence-check.mjs")],
  ),
  runStep(
    outDir,
    "opus-log-summary-self-test",
    process.execPath,
    [path.join("tools", "opus-log-summary.mjs"), "--self-test"],
  ),
  runExpectedFailureStep(
    outDir,
    "opus-log-summary-rejects-unignored-output",
    process.execPath,
    [
      path.join("tools", "opus-log-summary.mjs"),
      "--out",
      "OPUS_LOG_SUMMARY_SHOULD_FAIL.md",
      logSummaryFixture,
    ],
    "log summary output path inside repo must be ignored generated evidence",
  ),
  runStep(
    outDir,
    "opus-external-evidence-check-self-test",
    process.execPath,
    [path.join("tools", "opus-external-evidence-check.mjs"), "--self-test"],
  ),
  runStep(
    outDir,
    "opus-external-commands-smoke",
    process.execPath,
    [
      path.join("tools", "opus-external-commands.mjs"),
      "--secret",
      "dev-secret",
      "--server-host",
      "192.168.1.50",
      "--write",
      path.join(outDir, "external-commands.md"),
    ],
  ),
  checkFileContainsStep(
    outDir,
    "opus-external-commands-flags",
    path.join(outDir, "external-commands.md"),
    [
      "--codec opus",
      "--frames 120",
      "--jitter 8",
      "--auto-jitter",
      "Validation token TTL: 14400000 ms",
      "Generated at (UTC):",
      "Validation tokens expire at (UTC):",
      "Regenerate this command sheet before running validation",
      "Source SHA256:",
      "Source files:",
      "## Preflight On Checker Machine",
      "node tools/opus-completion-audit.mjs --local-only",
      "node tools/opus-source-fingerprint.mjs",
      "git check-ignore validation/opus-external-commands.md validation/opus-external-validation.json validation/validation-summary.md validation_logs/legacy-evidence.json",
      "New-Item -ItemType Directory -Force -Path validation",
      "mkdir -p validation",
      "Collect Logs Onto One Machine",
      "node tools/opus-log-summary.mjs --out validation/validation-summary.md",
      "The summary output path must be ignored generated evidence",
      "node tools/opus-external-evidence-check.mjs --init validation/opus-external-validation.json",
      "The manifest output path must be ignored generated evidence",
      "the checker rejects placeholders",
      "--windows-smoke latest",
      "--mac-smoke latest",
      "node tools/opus-external-evidence-check.mjs validation/opus-external-validation.json",
      "node tools/opus-acceptance.mjs --external-manifest validation/opus-external-validation.json",
      "strict mode",
      "Windows the active talker/source",
      "macOS the active talker/source",
      "Exercise both directions",
      "startup-default-client.log",
      "opus-validation-room-win-to-mac",
      "opus-validation-room-mac-to-win",
      "opus-validation-long-room",
    ],
  ),
  checkExternalCommandTokensStep(
    outDir,
    "opus-external-commands-token-integrity",
    path.join(outDir, "external-commands.md"),
  ),
  checkExternalCommandSourceFingerprintStep(
    outDir,
    "opus-external-commands-source-fingerprint",
    path.join(outDir, "external-commands.md"),
  ),
  runStep(
    outDir,
    "opus-external-commands-custom-room-smoke",
    process.execPath,
    [
      path.join("tools", "opus-external-commands.mjs"),
      "--secret",
      "dev-secret",
      "--server-host",
      "192.168.1.50",
      "--room",
      "custom-validation-room",
      "--long-room",
      "custom-long-room",
      "--write",
      path.join(outDir, "external-commands-custom-room.md"),
    ],
  ),
  checkFileContainsStep(
    outDir,
    "opus-external-commands-custom-room-flags",
    path.join(outDir, "external-commands-custom-room.md"),
    [
      "custom-validation-room-win-to-mac",
      "custom-validation-room-mac-to-win",
      "custom-long-room",
      "--win-to-mac-room custom-validation-room-win-to-mac",
      "--mac-to-win-room custom-validation-room-mac-to-win",
      "--long-room custom-long-room",
    ],
  ),
  checkExternalCommandTokensStep(
    outDir,
    "opus-external-commands-custom-room-token-integrity",
    path.join(outDir, "external-commands-custom-room.md"),
  ),
  sourceFingerprintLineEndingStep(outDir),
  sourceFingerprintGeneratedDirsStep(outDir),
  sourceFingerprintCoverageStep(outDir),
  validationDirIgnoredStep(outDir),
  runExpectedFailureStep(
    outDir,
    "opus-validation-rejects-unignored-output",
    process.execPath,
    [
      path.join("tools", "opus-validation.mjs"),
      "smoke",
      "--out",
      "OPUS_VALIDATION_SHOULD_FAIL",
    ],
    "validation output path inside repo must be ignored generated evidence",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-local-evidence-rejects-unignored-output",
    process.execPath,
    [
      path.join("tools", "opus-local-evidence.mjs"),
      "--out",
      "OPUS_LOCAL_EVIDENCE_SHOULD_FAIL",
    ],
    "local evidence output path inside repo must be ignored generated evidence",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-local-verify-rejects-unignored-output",
    process.execPath,
    [
      path.join("tools", "opus-local-verify.mjs"),
      "--out",
      "OPUS_LOCAL_VERIFY_SHOULD_FAIL",
    ],
    "local verifier output path inside repo must be ignored generated evidence",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-completion-audit-rejects-unignored-local-report",
    process.execPath,
    [
      path.join("tools", "opus-completion-audit.mjs"),
      "--local-only",
      "--local-report",
      path.join("OPUS_LOCAL_REPORT_SHOULD_FAIL", "report.md"),
    ],
    "local verifier report path inside repo must be ignored generated evidence",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-acceptance-requires-external-manifest",
    process.execPath,
    [
      path.join("tools", "opus-acceptance.mjs"),
      "--skip-local",
      "--external-manifest",
      path.join(outDir, "missing-external-manifest.json"),
    ],
    "external manifest does not exist",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-acceptance-rejects-unignored-external-manifest",
    process.execPath,
    [
      path.join("tools", "opus-acceptance.mjs"),
      "--skip-local",
      "--external-manifest",
      "OPUS_EXTERNAL_VALIDATION_MANIFEST.example.json",
    ],
    "external manifest path inside repo must be ignored generated evidence",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-acceptance-rejects-ignored-placeholder-manifest",
    process.execPath,
    [
      path.join("tools", "opus-acceptance.mjs"),
      "--skip-local",
      "--use-saved-local-report",
      "--external-manifest",
      ignoredPlaceholderManifest,
      "--local-out",
      placeholderSavedLocalReportDir,
    ],
    "windowsSmokeReport must be a non-empty string",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-acceptance-rejects-unacknowledged-skip-local",
    process.execPath,
    [
      path.join("tools", "opus-acceptance.mjs"),
      "--skip-local",
      "--external-manifest",
      ignoredPlaceholderManifest,
    ],
    "--skip-local requires --use-saved-local-report",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-acceptance-rejects-unignored-local-out",
    process.execPath,
    [
      path.join("tools", "opus-acceptance.mjs"),
      "--external-manifest",
      ignoredPlaceholderManifest,
      "--local-out",
      "OPUS_ACCEPTANCE_LOCAL_OUT_SHOULD_FAIL",
    ],
    "local verifier output path inside repo must be ignored generated evidence",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-acceptance-rejects-skip-local-unignored-local-out",
    process.execPath,
    [
      path.join("tools", "opus-acceptance.mjs"),
      "--skip-local",
      "--use-saved-local-report",
      "--external-manifest",
      ignoredPlaceholderManifest,
      "--local-out",
      "OPUS_ACCEPTANCE_LOCAL_OUT_SHOULD_FAIL",
    ],
    "local verifier output path inside repo must be ignored generated evidence",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-acceptance-rejects-missing-saved-local-report",
    process.execPath,
    [
      path.join("tools", "opus-acceptance.mjs"),
      "--skip-local",
      "--use-saved-local-report",
      "--external-manifest",
      ignoredPlaceholderManifest,
      "--local-out",
      path.join(outDir, "missing-saved-local-report"),
    ],
    "saved local verifier report does not exist",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-external-evidence-rejects-example-manifest",
    process.execPath,
    [
      path.join("tools", "opus-external-evidence-check.mjs"),
      "OPUS_EXTERNAL_VALIDATION_MANIFEST.example.json",
    ],
    "windowsSmokeReport is missing",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-external-evidence-rejects-malformed-manifest",
    process.execPath,
    [
      path.join("tools", "opus-external-evidence-check.mjs"),
      malformedManifest,
    ],
    "manifest is not valid JSON",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-external-evidence-rejects-nonobject-manifest",
    process.execPath,
    [
      path.join("tools", "opus-external-evidence-check.mjs"),
      nonObjectManifest,
    ],
    "manifest root must be a JSON object",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-external-evidence-rejects-malformed-booleans",
    process.execPath,
    [
      path.join("tools", "opus-external-evidence-check.mjs"),
      malformedBooleanManifest,
    ],
    "windowsSmokeAllowAudioOpenFailure must be a boolean",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-external-evidence-rejects-malformed-types",
    process.execPath,
    [
      path.join("tools", "opus-external-evidence-check.mjs"),
      malformedTypeManifest,
    ],
    "session windows-to-macos-5min frames must be a number",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-external-evidence-rejects-unknown-fields",
    process.execPath,
    [
      path.join("tools", "opus-external-evidence-check.mjs"),
      unknownFieldManifest,
    ],
    "manifest has unknown field: unexpectedRootField",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-external-evidence-rejects-missing-manifest",
    process.execPath,
    [
      path.join("tools", "opus-external-evidence-check.mjs"),
      path.join(outDir, "missing-external-evidence-manifest.json"),
    ],
    "manifest does not exist",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-external-evidence-rejects-source-controlled-smoke-path",
    process.execPath,
    [
      path.join("tools", "opus-external-evidence-check.mjs"),
      sourceControlledSmokeManifest,
    ],
    "windowsSmokeReport path inside repo must be ignored generated evidence",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-external-evidence-rejects-source-controlled-log-path",
    process.execPath,
    [
      path.join("tools", "opus-external-evidence-check.mjs"),
      sourceControlledLogManifest,
    ],
    "session windows-to-macos-5min log path inside repo must be ignored generated evidence",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-external-evidence-init-rejects-unignored-manifest",
    process.execPath,
    [
      path.join("tools", "opus-external-evidence-check.mjs"),
      "--init",
      "OPUS_EXTERNAL_VALIDATION_INIT_SHOULD_FAIL.json",
    ],
    "output manifest path inside repo must be ignored generated evidence",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-external-evidence-init-rejects-unignored-smoke-input",
    process.execPath,
    [
      path.join("tools", "opus-external-evidence-check.mjs"),
      "--init",
      path.join(outDir, "init-unignored-smoke-input.json"),
      "--windows-smoke",
      "OPUS_COMPETITIVE_ROADMAP.md",
    ],
    "windows smoke input path inside repo must be ignored generated evidence",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-external-evidence-init-rejects-unignored-log-input",
    process.execPath,
    [
      path.join("tools", "opus-external-evidence-check.mjs"),
      "--init",
      path.join(outDir, "init-unignored-log-input.json"),
      "--win-to-mac-logs",
      "OPUS_COMPETITIVE_ROADMAP.md,validation/win-to-mac-macos-client.log,validation/win-to-mac-server.log",
    ],
    "win-to-mac log input path inside repo must be ignored generated evidence",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-external-commands-requires-server-host",
    process.execPath,
    [path.join("tools", "opus-external-commands.mjs"), "--secret", "dev-secret"],
    "--server-host is required",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-external-commands-rejects-unignored-write",
    process.execPath,
    [
      path.join("tools", "opus-external-commands.mjs"),
      "--secret",
      "dev-secret",
      "--server-host",
      "192.168.1.50",
      "--write",
      "OPUS_EXTERNAL_COMMANDS_SHOULD_FAIL.md",
    ],
    "external command output path inside repo must be ignored generated evidence",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-external-commands-rejects-unignored-out-dir",
    process.execPath,
    [
      path.join("tools", "opus-external-commands.mjs"),
      "--secret",
      "dev-secret",
      "--server-host",
      "192.168.1.50",
      "--out-dir",
      "OPUS_EXTERNAL_OUTPUT_SHOULD_FAIL",
    ],
    "external validation output path inside repo must be ignored generated evidence",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-external-commands-rejects-unignored-manifest",
    process.execPath,
    [
      path.join("tools", "opus-external-commands.mjs"),
      "--secret",
      "dev-secret",
      "--server-host",
      "192.168.1.50",
      "--manifest",
      "OPUS_EXTERNAL_MANIFEST_SHOULD_FAIL.json",
    ],
    "external manifest path inside repo must be ignored generated evidence",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-external-commands-rejects-loopback-host",
    process.execPath,
    [
      path.join("tools", "opus-external-commands.mjs"),
      "--secret",
      "dev-secret",
      "--server-host",
      "127.0.0.1",
    ],
    "loopback/unroutable hosts require --allow-loopback",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-external-commands-rejects-ipv6-loopback-host",
    process.execPath,
    [
      path.join("tools", "opus-external-commands.mjs"),
      "--secret",
      "dev-secret",
      "--server-host",
      "[::1]",
    ],
    "loopback/unroutable hosts require --allow-loopback",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-external-commands-rejects-ipv6-loopback-host-port",
    process.execPath,
    [
      path.join("tools", "opus-external-commands.mjs"),
      "--secret",
      "dev-secret",
      "--server-host",
      "[::1]:9999",
    ],
    "loopback/unroutable hosts require --allow-loopback",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-external-commands-rejects-full-ipv6-loopback-host-port",
    process.execPath,
    [
      path.join("tools", "opus-external-commands.mjs"),
      "--secret",
      "dev-secret",
      "--server-host",
      "0:0:0:0:0:0:0:1:9999",
    ],
    "loopback/unroutable hosts require --allow-loopback",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-external-commands-rejects-localhost-port",
    process.execPath,
    [
      path.join("tools", "opus-external-commands.mjs"),
      "--secret",
      "dev-secret",
      "--server-host",
      "localhost:9999",
    ],
    "loopback/unroutable hosts require --allow-loopback",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-external-commands-rejects-unspecified-host",
    process.execPath,
    [
      path.join("tools", "opus-external-commands.mjs"),
      "--secret",
      "dev-secret",
      "--server-host",
      "[::]",
    ],
    "loopback/unroutable hosts require --allow-loopback",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-external-commands-rejects-full-ipv6-unspecified-host-port",
    process.execPath,
    [
      path.join("tools", "opus-external-commands.mjs"),
      "--secret",
      "dev-secret",
      "--server-host",
      "0:0:0:0:0:0:0:0:9999",
    ],
    "loopback/unroutable hosts require --allow-loopback",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-external-commands-rejects-invalid-ttl",
    process.execPath,
    [
      path.join("tools", "opus-external-commands.mjs"),
      "--secret",
      "dev-secret",
      "--server-host",
      "192.168.1.50",
      "--ttl-ms",
      "not-a-number",
    ],
    "--ttl-ms must be an integer number of milliseconds",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-external-commands-rejects-short-ttl",
    process.execPath,
    [
      path.join("tools", "opus-external-commands.mjs"),
      "--secret",
      "dev-secret",
      "--server-host",
      "192.168.1.50",
      "--ttl-ms",
      "3600000",
    ],
    "--ttl-ms must be at least 10800000 ms for external validation",
  ),
  runStep(outDir, "opus-validation-smoke", process.execPath, [path.join("tools", "opus-validation.mjs"), "smoke"]),
  runStep(outDir, "opus-local-evidence", process.execPath, [path.join("tools", "opus-local-evidence.mjs")]),
  sourceWhitespaceHygieneStep(outDir),
  runStep(outDir, "git-diff-check", "git", ["diff", "--check"], 30000),
];

const docIssues = documentationIssues([
  "OPUS_COMPETITIVE_ROADMAP.md",
  "OPUS_COMPETITIVE_IMPLEMENTATION_CHECKLIST.md",
  "OPUS_COMPETITIVE_COMPLETION_AUDIT.md",
  "OPUS_EXTERNAL_VALIDATION_RUNBOOK.md",
]);

writeReport(outDir, steps, docIssues);
const missingLogReport = path.join(outDir, "missing-companion-log-report.md");
fs.copyFileSync(path.join(outDir, "report.md"), missingLogReport);
fs.writeFileSync(
  missingLogReport,
  fs
    .readFileSync(missingLogReport, "utf8")
    .replace("cmake-build-debug.log", "missing-companion-log.log"),
  "utf8",
);
steps.push(
  runExpectedFailureStep(
    outDir,
    "opus-completion-audit-rejects-missing-companion-log",
    process.execPath,
    [
      path.join("tools", "opus-completion-audit.mjs"),
      "--local-only",
      "--local-report",
      missingLogReport,
    ],
    "local verifier companion log missing for cmake-build-debug",
  ),
);
writeReport(outDir, steps, docIssues);
const staleReport = path.join(outDir, "stale-local-report.md");
fs.copyFileSync(path.join(outDir, "report.md"), staleReport);
fs.writeFileSync(
  staleReport,
  fs
    .readFileSync(staleReport, "utf8")
    .replace(/^Date: .+$/m, "Date: 2000-01-01T00:00:00.000Z"),
  "utf8",
);
steps.push(
  runExpectedFailureStep(
    outDir,
    "opus-completion-audit-rejects-stale-local-report",
    process.execPath,
    [
      path.join("tools", "opus-completion-audit.mjs"),
      "--local-only",
      "--local-report",
      staleReport,
    ],
    "local verifier report is older than 24 hours",
  ),
);
writeReport(outDir, steps, docIssues);

steps.push(
  runExpectedFailureStep(
    outDir,
    "opus-completion-audit-status-external-fail",
    process.execPath,
    [
      path.join("tools", "opus-completion-audit.mjs"),
      "--status",
      "--external-manifest",
      ignoredPlaceholderManifest,
      "--local-report",
      path.join(outDir, "report.md"),
    ],
    "external manifest: fail",
  ),
);
writeReport(outDir, steps, docIssues);

steps.push(
  runStep(
    outDir,
    "opus-completion-audit-local-only",
    process.execPath,
    [
      path.join("tools", "opus-completion-audit.mjs"),
      "--local-only",
      "--local-report",
      path.join(outDir, "report.md"),
    ],
  ),
  runExpectedFailureStep(
    outDir,
    "opus-completion-audit-rejects-missing-local-report",
    process.execPath,
    [
      path.join("tools", "opus-completion-audit.mjs"),
      "--local-only",
      "--local-report",
      path.join(outDir, "missing-report.md"),
    ],
    "missing; run node tools/opus-local-verify.mjs --out",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-completion-audit-status-incomplete",
    process.execPath,
    [
      path.join("tools", "opus-completion-audit.mjs"),
      "--status",
      "--external-manifest",
      path.join(outDir, "missing-status-manifest.json"),
      "--local-report",
      path.join(outDir, "report.md"),
    ],
    "final status: incomplete",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-completion-audit-requires-external-manifest",
    process.execPath,
    [
      path.join("tools", "opus-completion-audit.mjs"),
      "--local-report",
      path.join(outDir, "report.md"),
    ],
    "Provide --external-manifest",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-completion-audit-rejects-unignored-external-manifest",
    process.execPath,
    [
      path.join("tools", "opus-completion-audit.mjs"),
      "--external-manifest",
      "OPUS_EXTERNAL_VALIDATION_MANIFEST.example.json",
      "--local-report",
      path.join(outDir, "report.md"),
    ],
    "external manifest path inside repo must be ignored generated evidence",
  ),
  runExpectedFailureStep(
    outDir,
    "opus-completion-audit-rejects-ignored-placeholder-manifest",
    process.execPath,
    [
      path.join("tools", "opus-completion-audit.mjs"),
      "--external-manifest",
      ignoredPlaceholderManifest,
      "--local-report",
      path.join(outDir, "report.md"),
    ],
    "External evidence manifest did not pass",
  ),
);

writeReport(outDir, steps, docIssues);
console.log(`wrote ${relativeDisplay(outDir, "report.md")}`);

const failed = steps.filter((step) => step.code !== 0);
if (failed.length > 0 || docIssues.length > 0) {
  if (failed.length > 0) console.error(`failed steps: ${failed.map((step) => step.name).join(", ")}`);
  if (docIssues.length > 0) console.error(`documentation issues: ${docIssues.length}`);
  process.exit(1);
}
