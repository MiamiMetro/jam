#!/usr/bin/env node

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { sourceFingerprint } from "./opus-source-fingerprint.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DRIFT_REVIEW_PPM = 250;
const allowedManifestKeys = new Set([
  "windowsSmokeReport",
  "windowsSmokeAllowAudioOpenFailure",
  "windowsSmokeFailureExplanation",
  "macSmokeReport",
  "macSmokeAllowAudioOpenFailure",
  "macSmokeFailureExplanation",
  "sessions",
]);
const allowedSessionKeys = new Set([
  "name",
  "direction",
  "room",
  "codec",
  "frames",
  "jitter",
  "speakerPlatform",
  "listenerPlatform",
  "participants",
  "minMinutes",
  "network",
  "subjective",
  "allowWarnings",
  "warningExplanation",
  "logs",
]);

function usage() {
  console.log(
    [
      "usage:",
      "  node tools/opus-external-evidence-check.mjs <manifest.json> [--strict]",
      "  node tools/opus-external-evidence-check.mjs --init <manifest.json> [path options]",
      "  node tools/opus-external-evidence-check.mjs --self-test",
      "",
      "Validates the external Opus evidence packet before promoting the branch.",
      "Start from OPUS_EXTERNAL_VALIDATION_MANIFEST.example.json after running",
      "Windows/macOS smoke and real cross-machine Opus sessions.",
      "Use --strict when warnings should fail the command.",
      "",
      "Init path options:",
      "  --windows-smoke <report.md>",
      "  --mac-smoke <report.md>",
      "  --win-to-mac-logs <windows.log,macos.log,server.log>",
      "  --mac-to-win-logs <windows.log,macos.log,server.log>",
      "  --long-logs <windows.log,macos.log,server.log>",
      "  --win-to-mac-room <room>",
      "  --mac-to-win-room <room>",
      "  --long-room <room>",
      "",
      "Use --windows-smoke latest or --mac-smoke latest to auto-select the",
      "latest current-source smoke report for that platform from build/opus-validation.",
    ].join("\n"),
  );
}

function resolveRepoPath(value) {
  if (!value || typeof value !== "string") return "";
  return path.isAbsolute(value) ? value : path.resolve(repoRoot, value);
}

function repoRelativePath(value) {
  const full = resolveRepoPath(value);
  const relative = path.relative(repoRoot, full);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) return "";
  return relative.split(path.sep).join("/");
}

function ignoredRepoPathIssue(value, description = "output manifest path") {
  if (!value || typeof value !== "string") return "";
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

function readText(file) {
  return fs.readFileSync(file, "utf8");
}

function parseTimestamp(value) {
  if (!value) return 0;
  const isoLike = value.replace(" ", "T");
  const parsed = Date.parse(isoLike);
  return Number.isFinite(parsed) ? parsed : 0;
}

function logStats(file) {
  const text = readText(file);
  const stats = {
    file,
    lines: 0,
    warnings: 0,
    errors: 0,
    healthWarnings: 0,
    audioDiag: 0,
    latencyDiag: 0,
    participantDiag: 0,
    runtimeRole: "",
    runtimePlatform: "",
    joinRooms: new Set(),
    joinEndpoints: [],
    startupCodec: "",
    startupFrames: 0,
    startupJitter: -1,
    startupAutoJitter: "",
    audioDiagFrames120: 0,
    underrunMentions: 0,
    sequenceGapMentions: 0,
    latePacketMentions: 0,
    largeDriftMentions: 0,
    maxAbsDriftPpm: 0,
    firstTs: 0,
    lastTs: 0,
  };

  const timestampPattern = /^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\]/;
  for (const line of text.split(/\r?\n/)) {
    if (!line) continue;
    stats.lines += 1;
    const timestamp = parseTimestamp(timestampPattern.exec(line)?.[1] ?? "");
    if (timestamp) {
      if (!stats.firstTs) stats.firstTs = timestamp;
      stats.lastTs = timestamp;
    }
    if (line.includes("[warning]")) stats.warnings += 1;
    if (line.includes("[error]")) stats.errors += 1;
    if (line.includes("Audio health warning")) stats.healthWarnings += 1;
    if (line.includes("Audio diag:")) stats.audioDiag += 1;
    if (line.includes("Latency diag:")) stats.latencyDiag += 1;
    if (line.includes("Participant diag")) stats.participantDiag += 1;
    const audioDiagFrames = /Audio diag:\s+frames=(\d+)/.exec(line);
    if (audioDiagFrames && Number(audioDiagFrames[1]) === 120) stats.audioDiagFrames120 += 1;
    const runtime = /Runtime:\s+role=(\S+)\s+platform=(\S+)/.exec(line);
    if (runtime) {
      stats.runtimeRole = runtime[1].toLowerCase();
      stats.runtimePlatform = platformRole(runtime[2]);
    }
    const joinRoom = /Sent JOIN for room '([^']*)'/.exec(line);
    if (joinRoom) stats.joinRooms.add(joinRoom[1]);
    const serverJoin = /JOIN:\s+(\S+)\s+room='([^']*)'/.exec(line);
    if (serverJoin) {
      stats.joinEndpoints.push(serverJoin[1]);
      stats.joinRooms.add(serverJoin[2]);
    }
    const startupFrames = /Startup requested buffer override:\s+(\d+)\s+frames/i.exec(line);
    if (startupFrames) stats.startupFrames = Number(startupFrames[1]);
    const startupCodec = /Startup codec override:\s+(\S+)/i.exec(line);
    if (startupCodec) stats.startupCodec = startupCodec[1].toLowerCase();
    const startupJitter = /Startup Opus jitter override:\s+(\d+)\s+packets/i.exec(line);
    if (startupJitter) stats.startupJitter = Number(startupJitter[1]);
    if (/Startup Opus auto jitter default enabled/i.test(line)) stats.startupAutoJitter = "true";
    if (/Startup Opus auto jitter default disabled/i.test(line)) stats.startupAutoJitter = "false";
    const startupConfig = /Startup config smoke:\s+.*\bjitter=(\d+)/i.exec(line);
    if (startupConfig) stats.startupJitter = Number(startupConfig[1]);
    const startupConfigAuto = /Startup config smoke:\s+.*\bauto_jitter=(true|false)/i.exec(line);
    if (startupConfigAuto) stats.startupAutoJitter = startupConfigAuto[1].toLowerCase();
    if (/underruns=[1-9]/.test(line)) stats.underrunMentions += 1;

    const sequence = /seq gap\/late=(\d+)\/(\d+)/.exec(line);
    if (sequence) {
      if (Number(sequence[1]) > 0) stats.sequenceGapMentions += 1;
      if (Number(sequence[2]) > 0) stats.latePacketMentions += 1;
    }

    const drift = /drift_ppm last\/avg\/max=([-.\d]+)\/([-.\d]+)\/([-.\d]+)/.exec(line);
    if (drift) {
      const maxAbsDrift = Math.max(Math.abs(Number(drift[1])), Math.abs(Number(drift[2])), Math.abs(Number(drift[3])));
      if (Number.isFinite(maxAbsDrift)) {
        stats.maxAbsDriftPpm = Math.max(stats.maxAbsDriftPpm, maxAbsDrift);
        if (maxAbsDrift > DRIFT_REVIEW_PPM) stats.largeDriftMentions += 1;
      }
    }
  }
  return stats;
}

function smokeReportPassed(file) {
  const text = readText(file);
  const requiredSteps = ["startup-default", "startup-no-auto", "harness-self-test", "audio-open"];
  const missing = [];
  const failed = [];

  for (const step of requiredSteps) {
    const row = new RegExp(`\\|\\s*${step}\\s*\\|\\s*([^|]+)\\|`).exec(text);
    if (!row) {
      missing.push(step);
    } else if (!/^0\b/.test(row[1].trim())) {
      failed.push(`${step}=${row[1].trim()}`);
    }
  }

  return { missing, failed };
}

function smokeReportPlatform(file) {
  const text = readText(file);
  const platform = /^Platform:\s+(\S+)/m.exec(text)?.[1] ?? "";
  return platform.trim().toLowerCase();
}

function smokeReportSourceFingerprint(file) {
  const text = readText(file);
  return /^Source SHA256:\s*([a-f0-9]{64})$/im.exec(text)?.[1]?.toLowerCase() ?? "";
}

function findLatestSmokeReport(expectedPlatform) {
  const root = resolveRepoPath("build/opus-validation");
  if (!fs.existsSync(root)) {
    throw new Error(`cannot auto-discover ${expectedPlatform} smoke report: build/opus-validation does not exist`);
  }

  const expected = platformRole(expectedPlatform);
  const currentSource = sourceFingerprint(repoRoot);
  const candidates = [];
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const report = path.join(root, entry.name, "report.md");
    if (!fs.existsSync(report)) continue;
    try {
      const platform = platformRole(smokeReportPlatform(report));
      const fingerprint = smokeReportSourceFingerprint(report);
      if (platform === expected && fingerprint === currentSource) {
        candidates.push({
          report,
          mtimeMs: fs.statSync(report).mtimeMs,
        });
      }
    } catch {
      // Ignore malformed or partial smoke directories; the manifest checker
      // will validate the selected report in detail later.
    }
  }

  candidates.sort((a, b) => b.mtimeMs - a.mtimeMs || b.report.localeCompare(a.report));
  if (candidates.length === 0) {
    throw new Error(`cannot auto-discover latest current-source ${expectedPlatform} smoke report in build/opus-validation`);
  }
  return path.relative(repoRoot, candidates[0].report).split(path.sep).join("/");
}

function resolveSmokeOption(value, expectedPlatform) {
  const normalized = String(value || "").trim().toLowerCase();
  if (normalized === "latest" || normalized === "auto") {
    return findLatestSmokeReport(expectedPlatform);
  }
  return value;
}

function smokeReportLogEvidence(file, expectedPlatform) {
  const errors = [];
  const logFile = path.join(path.dirname(file), "startup-default-client.log");
  if (!fs.existsSync(logFile)) {
    return { errors: [`missing smoke startup client log: ${path.relative(repoRoot, logFile)}`] };
  }

  const stats = logStats(logFile);
  if (stats.runtimeRole !== "client") {
    errors.push(`smoke startup log must prove runtime role=client: ${path.relative(repoRoot, logFile)}`);
  }
  if (stats.runtimePlatform !== platformRole(expectedPlatform)) {
    errors.push(
      `smoke startup log platform mismatch: expected ${platformRole(expectedPlatform)}, got ${stats.runtimePlatform || "<missing>"} in ${path.relative(
        repoRoot,
        logFile,
      )}`,
    );
  }
  if (stats.startupCodec !== "opus") {
    errors.push(`smoke startup log must prove startup codec Opus: ${path.relative(repoRoot, logFile)}`);
  }
  if (stats.startupFrames !== 120) {
    errors.push(`smoke startup log must prove startup frames 120: ${path.relative(repoRoot, logFile)}`);
  }
  if (stats.startupJitter !== 8) {
    errors.push(`smoke startup log must prove startup jitter 8: ${path.relative(repoRoot, logFile)}`);
  }
  if (stats.startupAutoJitter !== "true") {
    errors.push(`smoke startup log must prove auto jitter enabled: ${path.relative(repoRoot, logFile)}`);
  }
  return { errors };
}

function nonEmptyString(value) {
  if (typeof value !== "string") return false;
  const normalized = value.trim().toLowerCase();
  const placeholders = new Set([
    "lan-or-tunnel",
    "clear / flicker / robotic / dropout notes",
    "windows source heard on macos: clear / flicker / robotic / dropout notes",
    "macos source heard on windows: clear / flicker / robotic / dropout notes",
    "long-session notes",
  ]);
  return Boolean(normalized) && !normalized.includes("<") && !/todo/i.test(normalized) && !placeholders.has(normalized);
}

function optionalBooleanIssue(value, label) {
  return value === undefined || typeof value === "boolean" ? "" : `${label} must be a boolean`;
}

function requiredStringIssue(value, label) {
  return typeof value === "string" && value.trim() ? "" : `${label} must be a non-empty string`;
}

function requiredNumberIssue(value, label, expected) {
  if (typeof value !== "number" || !Number.isFinite(value)) return `${label} must be a number`;
  return expected === undefined || value === expected ? "" : `${label} must be ${expected}`;
}

function unknownKeyIssues(value, allowedKeys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  return Object.keys(value)
    .filter((key) => !allowedKeys.has(key))
    .map((key) => `${label} has unknown field: ${key}`);
}

function externalNetworkDescriptionIssue(value) {
  if (!nonEmptyString(value)) return "missing network description";
  const normalized = value.trim().toLowerCase();
  if (
    /\b127\./.test(normalized) ||
    normalized.includes("0.0.0.0") ||
    normalized.includes("localhost") ||
    normalized.includes("loopback") ||
    normalized.includes("::1") ||
    normalized.includes("[::]") ||
    normalized.includes("unspecified address") ||
    normalized.includes("unroutable") ||
    normalized.includes("same machine") ||
    normalized.includes("same-machine") ||
    normalized.includes("same device") ||
    normalized.includes("same-device") ||
    normalized.includes("single machine") ||
    normalized.includes("single-machine")
  ) {
    return "network description must describe a real Windows/macOS path, not loopback, unroutable, or same-machine testing";
  }
  return "";
}

function subjectiveAudioIssue(value) {
  if (!nonEmptyString(value)) return "missing subjective note";
  const normalized = value.trim().toLowerCase();
  const badTerms = [
    "robotic",
    "corrupt",
    "flicker",
    "flickering",
    "dropout",
    "dropouts",
    "stopped audio",
    "audio stopped",
    "unclear",
    "not clear",
    "bad audio",
    "broken",
  ];
  const hasBadTerm = badTerms.some((term) => normalized.includes(term));
  const clearlyNegated =
    /\b(no|without|zero)\s+(robotic|corrupt|flicker|flickering|dropout|dropouts|stopped|unclear|bad|broken)\b/.test(normalized) ||
    /\bnot\s+(robotic|corrupt|flickering|broken|bad)\b/.test(normalized);
  if (hasBadTerm && !clearlyNegated) {
    return "subjective note reports bad audio and requires warning allowance or a failed validation decision";
  }
  return "";
}

function directionalSubjectiveIssue(session) {
  const subjective = String(session.subjective || "").trim().toLowerCase();
  const direction = String(session.direction || "").trim().toLowerCase();
  if (direction === "windows-to-macos") {
    if (!subjective.includes("windows") || !subjective.includes("mac")) {
      return "subjective note must state that Windows source was judged on macOS";
    }
  } else if (direction === "macos-to-windows") {
    if (!subjective.includes("mac") || !subjective.includes("windows")) {
      return "subjective note must state that macOS source was judged on Windows";
    }
  }
  return "";
}

function platformRole(value) {
  if (typeof value !== "string") return "";
  const normalized = value.trim().toLowerCase();
  if (["windows", "win32", "win"].includes(normalized)) return "windows";
  if (["macos", "mac", "darwin"].includes(normalized)) return "macos";
  return normalized;
}

function requireDirectionalRoles(errors, session, expectedSpeaker, expectedListener) {
  const name = session.name || "<unnamed>";
  const speaker = platformRole(session.speakerPlatform);
  const listener = platformRole(session.listenerPlatform);
  if (speaker !== expectedSpeaker) {
    errors.push(`session ${name} speakerPlatform mismatch: expected ${expectedSpeaker}, got ${speaker || "<missing>"}`);
  }
  if (listener !== expectedListener) {
    errors.push(`session ${name} listenerPlatform mismatch: expected ${expectedListener}, got ${listener || "<missing>"}`);
  }
}

function requireClientLogPlatforms(errors, session, stats, expectedPlatforms) {
  const name = session.name || "<unnamed>";
  const clientPlatforms = new Set(
    stats
      .filter((entry) => entry.runtimeRole === "client")
      .map((entry) => entry.runtimePlatform)
      .filter(Boolean),
  );
  for (const expectedPlatform of expectedPlatforms) {
    if (!clientPlatforms.has(expectedPlatform)) {
      errors.push(`session ${name} missing client runtime log for platform ${expectedPlatform}`);
    }
  }
}

function requireClientLogOpus120(errors, session, stats) {
  const name = session.name || "<unnamed>";
  const expectedRoom = typeof session.room === "string" ? session.room.trim() : "";
  const clientStats = stats.filter((entry) => entry.runtimeRole === "client");
  for (const entry of clientStats) {
    const label = `${name} ${path.relative(repoRoot, entry.file)}`;
    if (entry.startupCodec !== "opus") {
      errors.push(`session ${label} must prove startup codec Opus in the client log`);
    }
    if (entry.startupFrames !== 120) {
      errors.push(`session ${label} must prove startup frames 120 in the client log`);
    }
    if (entry.startupJitter !== 8) {
      errors.push(`session ${label} must prove startup jitter 8 in the client log`);
    }
    if (entry.startupAutoJitter !== "true") {
      errors.push(`session ${label} must prove startup auto jitter enabled in the client log`);
    }
    if (entry.audioDiagFrames120 === 0) {
      errors.push(`session ${label} must include Audio diag lines with frames=120`);
    }
    if (!expectedRoom || !entry.joinRooms.has(expectedRoom)) {
      errors.push(`session ${label} must prove JOIN room ${expectedRoom || "<missing>"} in the client log`);
    }
  }
}

function requireServerLogRoom(errors, session, stats) {
  const name = session.name || "<unnamed>";
  const expectedRoom = typeof session.room === "string" ? session.room.trim() : "";
  const serverStats = stats.filter((entry) => entry.runtimeRole === "server");
  if (serverStats.length === 0) {
    errors.push(`session ${name} must include a server runtime log`);
    return;
  }
  for (const entry of serverStats) {
    const label = `${name} ${path.relative(repoRoot, entry.file)}`;
    if (!expectedRoom || !entry.joinRooms.has(expectedRoom)) {
      errors.push(`session ${label} server log must prove JOIN room ${expectedRoom || "<missing>"}`);
    }
  }
}

function isLoopbackEndpoint(value) {
  const endpoint = String(value || "").trim().toLowerCase();
  let host = endpoint;
  if (endpoint.startsWith("[")) {
    host = endpoint.slice(1, endpoint.indexOf("]") > 0 ? endpoint.indexOf("]") : undefined);
  } else if (endpoint === "::1" || endpoint.startsWith("::1:")) {
    host = "::1";
  } else if (endpoint === "::") {
    host = "::";
  } else if (endpoint === "0:0:0:0:0:0:0:1" || endpoint.startsWith("0:0:0:0:0:0:0:1:")) {
    host = "0:0:0:0:0:0:0:1";
  } else if (endpoint === "0:0:0:0:0:0:0:0" || endpoint.startsWith("0:0:0:0:0:0:0:0:")) {
    host = "0:0:0:0:0:0:0:0";
  } else if (endpoint.startsWith("::ffff:127.")) {
    host = "127.0.0.1";
  } else {
    host = endpoint.split(":")[0];
  }
  return (
    host === "localhost" ||
    host === "::1" ||
    host === "0:0:0:0:0:0:0:1" ||
    host === "0.0.0.0" ||
    host === "::" ||
    host === "0:0:0:0:0:0:0:0" ||
    host.startsWith("::ffff:127.") ||
    host.startsWith("127.")
  );
}

function requireNonLoopbackServerJoin(errors, session, stats) {
  const name = session.name || "<unnamed>";
  const serverStats = stats.filter((entry) => entry.runtimeRole === "server");
  const endpoints = serverStats.flatMap((entry) => entry.joinEndpoints);
  if (endpoints.length > 0 && endpoints.every(isLoopbackEndpoint)) {
    errors.push(`session ${name} server JOIN endpoints are all loopback/unroutable; external proof needs at least one routable non-loopback client endpoint`);
  }
}

function validateManifest(manifestPath) {
  const manifestFile = resolveRepoPath(manifestPath);
  const errors = [];
  const warnings = [];
  if (!manifestFile || !fs.existsSync(manifestFile)) {
    return { errors: [`manifest does not exist: ${manifestPath || ""}`], warnings };
  }
  let manifest;
  try {
    manifest = JSON.parse(readText(manifestFile));
  } catch (error) {
    return { errors: [`manifest is not valid JSON: ${error.message}`], warnings };
  }
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    return { errors: ["manifest root must be a JSON object"], warnings };
  }
  errors.push(...unknownKeyIssues(manifest, allowedManifestKeys, "manifest"));
  const currentSourceFingerprint = sourceFingerprint(repoRoot);
  const smokeFingerprints = [];
  for (const issue of [
    optionalBooleanIssue(manifest.windowsSmokeAllowAudioOpenFailure, "windowsSmokeAllowAudioOpenFailure"),
    optionalBooleanIssue(manifest.macSmokeAllowAudioOpenFailure, "macSmokeAllowAudioOpenFailure"),
  ].filter(Boolean)) {
    errors.push(issue);
  }

  for (const [label, reportPath, expectedPlatform, allowAudioOpenFailure, failureExplanation] of [
    [
      "windowsSmokeReport",
      manifest.windowsSmokeReport,
      "win32",
      manifest.windowsSmokeAllowAudioOpenFailure,
      manifest.windowsSmokeFailureExplanation,
    ],
    [
      "macSmokeReport",
      manifest.macSmokeReport,
      "darwin",
      manifest.macSmokeAllowAudioOpenFailure,
      manifest.macSmokeFailureExplanation,
    ],
  ]) {
    const reportStringIssue = requiredStringIssue(reportPath, label);
    if (reportStringIssue) {
      errors.push(reportStringIssue);
      continue;
    }
    const reportPathIssue = ignoredRepoPathIssue(reportPath, `${label} path`);
    if (reportPathIssue) errors.push(reportPathIssue);
    const file = resolveRepoPath(reportPath);
    if (!file || !fs.existsSync(file)) {
      errors.push(`${label} is missing or does not exist: ${reportPath || ""}`);
      continue;
    }
    const platform = smokeReportPlatform(file);
    if (platform !== expectedPlatform) {
      errors.push(`${label} platform mismatch: expected ${expectedPlatform}, got ${platform || "<missing>"}`);
    }
    const reportSourceFingerprint = smokeReportSourceFingerprint(file);
    if (!reportSourceFingerprint) {
      errors.push(`${label} missing Source SHA256`);
    } else {
      smokeFingerprints.push({ label, value: reportSourceFingerprint });
      if (reportSourceFingerprint !== currentSourceFingerprint) {
        errors.push(`${label} Source SHA256 does not match current source fingerprint`);
      }
    }
    const result = smokeReportPassed(file);
    if (result.missing.length > 0) errors.push(`${label} missing steps: ${result.missing.join(", ")}`);
    if (result.failed.length > 0) {
      const onlyAudioOpenFailed = result.failed.every((failure) => failure.startsWith("audio-open="));
      if (onlyAudioOpenFailed && allowAudioOpenFailure === true && nonEmptyString(failureExplanation)) {
        warnings.push(`${label} allows audio-open failure: ${failureExplanation}`);
      } else {
        errors.push(`${label} failed steps: ${result.failed.join(", ")}`);
      }
    }
    const smokeLog = smokeReportLogEvidence(file, expectedPlatform);
    for (const smokeLogError of smokeLog.errors) errors.push(`${label} ${smokeLogError}`);
  }
  if (smokeFingerprints.length === 2 && smokeFingerprints[0].value !== smokeFingerprints[1].value) {
    errors.push(
      `smoke reports use different Source SHA256 values: ${smokeFingerprints[0].label}=${smokeFingerprints[0].value}, ${smokeFingerprints[1].label}=${smokeFingerprints[1].value}`,
    );
  }

  if (!Array.isArray(manifest.sessions) || manifest.sessions.length < 3) {
    errors.push("sessions must include windows-to-macos, macos-to-windows, and long-session entries");
    return { errors, warnings };
  }

  const directions = new Set();
  const logOwners = new Map();
  for (const session of manifest.sessions) {
    if (!session || typeof session !== "object" || Array.isArray(session)) {
      errors.push("session entry must be a JSON object");
      continue;
    }
    const name = session.name || "<unnamed>";
    errors.push(...unknownKeyIssues(session, allowedSessionKeys, `session ${name}`));
    const allowWarningsIssue = optionalBooleanIssue(session.allowWarnings, `session ${name} allowWarnings`);
    if (allowWarningsIssue) errors.push(allowWarningsIssue);
    if (!nonEmptyString(session.name)) errors.push(`session has invalid name: ${name}`);
    const direction = typeof session.direction === "string" ? session.direction.trim().toLowerCase() : "";
    if (!nonEmptyString(direction)) errors.push(`session ${name} missing direction`);
    else directions.add(direction);
    if (typeof session.codec !== "string" || session.codec.trim().toLowerCase() !== "opus") {
      errors.push(`session ${name} codec must be the string opus`);
    }
    if (!nonEmptyString(session.room)) {
      errors.push(`session ${name} must declare a validation room`);
    }
    const framesIssue = requiredNumberIssue(session.frames, `session ${name} frames`, 120);
    if (framesIssue) errors.push(framesIssue);
    const jitterIssue = requiredNumberIssue(session.jitter, `session ${name} jitter`, 8);
    if (jitterIssue) errors.push(jitterIssue);
    if (direction === "windows-to-macos") {
      requireDirectionalRoles(errors, session, "windows", "macos");
    } else if (direction === "macos-to-windows") {
      requireDirectionalRoles(errors, session, "macos", "windows");
    } else if (direction === "bidirectional" || direction.includes("long")) {
      if (!Array.isArray(session.participants) || !session.participants.every((participant) => typeof participant === "string" && participant.trim())) {
        errors.push(`session ${name} participants must be an array of platform strings`);
      }
      const participants = Array.isArray(session.participants) ? session.participants.map(platformRole) : [];
      if (!participants.includes("windows") || !participants.includes("macos")) {
        errors.push(`session ${name} participants must include windows and macos`);
      }
    }
    const minMinutesIssue = requiredNumberIssue(session.minMinutes, `session ${name} minMinutes`);
    if (minMinutesIssue || session.minMinutes <= 0) errors.push(minMinutesIssue || `session ${name} minMinutes must be positive`);
    const networkIssue = externalNetworkDescriptionIssue(session.network);
    if (networkIssue) errors.push(`session ${name} ${networkIssue}`);
    const subjectiveIssue = subjectiveAudioIssue(session.subjective);
    if (subjectiveIssue) {
      if (session.allowWarnings === true && nonEmptyString(session.warningExplanation)) {
        warnings.push(`${session.name}: subjective issue allowed for review: ${subjectiveIssue}`);
      } else {
        errors.push(`session ${name} ${subjectiveIssue}`);
      }
    }
    const directionalSubjective = directionalSubjectiveIssue(session);
    if (directionalSubjective) errors.push(`session ${name} ${directionalSubjective}`);
    if (!Array.isArray(session.logs) || session.logs.length < 2) {
      errors.push(`session ${name} must include at least two logs`);
      continue;
    }
    if (!session.logs.every((logPath) => typeof logPath === "string" && logPath.trim())) {
      errors.push(`session ${name} logs must be non-empty string paths`);
      continue;
    }
    const sessionLogKeys = new Set();
    for (const logPath of session.logs) {
      const logPathIssue = ignoredRepoPathIssue(logPath, `session ${name} log path`);
      if (logPathIssue) errors.push(logPathIssue);
      const key = path.normalize(resolveRepoPath(logPath)).toLowerCase();
      if (sessionLogKeys.has(key)) {
        errors.push(`session ${name} reuses the same log path more than once: ${logPath}`);
      }
      sessionLogKeys.add(key);
      const previousOwner = logOwners.get(key);
      if (previousOwner && previousOwner !== name) {
        errors.push(`session ${name} reuses log path from session ${previousOwner}: ${logPath}`);
      } else {
        logOwners.set(key, name);
      }
    }

    const sessionStats = [];
    for (const logPath of session.logs) {
      const file = resolveRepoPath(logPath);
      if (!file || !fs.existsSync(file)) {
        errors.push(`session ${name} log missing: ${logPath || ""}`);
        continue;
      }
      const stats = logStats(file);
      sessionStats.push(stats);
      if (
        stats.warnings ||
        stats.errors ||
        stats.healthWarnings ||
        stats.underrunMentions ||
        stats.sequenceGapMentions ||
        stats.latePacketMentions ||
        stats.largeDriftMentions
      ) {
        const detail = `${logPath}: warnings=${stats.warnings}, errors=${stats.errors}, health=${stats.healthWarnings}, underrunLines=${stats.underrunMentions}, seqGapLines=${stats.sequenceGapMentions}, lateLines=${stats.latePacketMentions}, largeDriftLines=${stats.largeDriftMentions}, maxAbsDriftPpm=${stats.maxAbsDriftPpm}`;
        if (session.allowWarnings === true && nonEmptyString(session.warningExplanation)) warnings.push(`${session.name}: allowed warning indicators: ${detail}`);
        else errors.push(`${session.name}: warning indicators require explanation or fix: ${detail}`);
      }
    }

    const firstValues = sessionStats.map((stats) => stats.firstTs).filter(Boolean);
    const lastValues = sessionStats.map((stats) => stats.lastTs).filter(Boolean);
    const first = firstValues.length ? Math.min(...firstValues) : 0;
    const last = lastValues.length ? Math.max(...lastValues) : 0;
    const durationMinutes = first && last ? (last - first) / 60000 : 0;
    const diagnosticStats = sessionStats.filter((stats) => stats.audioDiag > 0 || stats.participantDiag > 0);
    const longEnoughDiagnosticStats = diagnosticStats.filter((stats) => {
      const perLogDurationMinutes = stats.firstTs && stats.lastTs ? (stats.lastTs - stats.firstTs) / 60000 : 0;
      return perLogDurationMinutes >= Number(session.minMinutes);
    });
    if (durationMinutes < Number(session.minMinutes)) {
      errors.push(
        `session ${name} duration ${first && last ? `${durationMinutes.toFixed(1)} min` : "unknown"} is below required ${Number(session.minMinutes)} min`,
      );
    }
    if (diagnosticStats.length < 2) {
      errors.push(`session ${name} must include at least two logs with audio/participant diagnostics`);
    }
    if (longEnoughDiagnosticStats.length < 2) {
      errors.push(`session ${name} must include at least two diagnostic logs covering ${Number(session.minMinutes)} min`);
    }
    if (direction === "windows-to-macos" || direction === "macos-to-windows") {
      requireClientLogPlatforms(errors, session, sessionStats, ["windows", "macos"]);
      requireClientLogOpus120(errors, session, sessionStats);
      requireServerLogRoom(errors, session, sessionStats);
      requireNonLoopbackServerJoin(errors, session, sessionStats);
    } else if (direction === "bidirectional" || direction.includes("long")) {
      requireClientLogPlatforms(errors, session, sessionStats, ["windows", "macos"]);
      requireClientLogOpus120(errors, session, sessionStats);
      requireServerLogRoom(errors, session, sessionStats);
      requireNonLoopbackServerJoin(errors, session, sessionStats);
    }
  }

  for (const required of ["windows-to-macos", "macos-to-windows"]) {
    if (!directions.has(required)) errors.push(`missing required direction: ${required}`);
  }
  if (![...directions].some((direction) => direction.includes("long") || direction === "bidirectional")) {
    errors.push("missing long/bidirectional session direction");
  }

  return { errors, warnings };
}

function strictFailure(result) {
  return result.errors.length > 0 || result.warnings.length > 0;
}

function splitLogList(value, fallback) {
  if (!value) return fallback;
  const parts = value
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
  return parts.length > 0 ? parts : fallback;
}

function parseInitArgs(argv) {
  const options = {
    out: argv[1],
    windowsSmoke: "latest",
    macSmoke: "latest",
    winToMacLogs: ["validation/win-to-mac-windows-client.log", "validation/win-to-mac-macos-client.log", "validation/win-to-mac-server.log"],
    macToWinLogs: ["validation/mac-to-win-windows-client.log", "validation/mac-to-win-macos-client.log", "validation/mac-to-win-server.log"],
    longLogs: ["validation/windows-client-long.log", "validation/macos-client-long.log", "validation/server-long.log"],
    winToMacRoom: "opus-validation-room-win-to-mac",
    macToWinRoom: "opus-validation-room-mac-to-win",
    longRoom: "opus-validation-long-room",
  };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = argv[i + 1];
    if (arg === "--windows-smoke" && next) options.windowsSmoke = argv[++i];
    else if (arg === "--mac-smoke" && next) options.macSmoke = argv[++i];
    else if (arg === "--win-to-mac-logs" && next) options.winToMacLogs = splitLogList(argv[++i], options.winToMacLogs);
    else if (arg === "--mac-to-win-logs" && next) options.macToWinLogs = splitLogList(argv[++i], options.macToWinLogs);
    else if (arg === "--long-logs" && next) options.longLogs = splitLogList(argv[++i], options.longLogs);
    else if (arg === "--win-to-mac-room" && next) options.winToMacRoom = argv[++i];
    else if (arg === "--mac-to-win-room" && next) options.macToWinRoom = argv[++i];
    else if (arg === "--long-room" && next) options.longRoom = argv[++i];
    else throw new Error(`unknown init option: ${arg}`);
  }
  return options;
}

function initializedManifest(options) {
  return {
    windowsSmokeReport: options.windowsSmoke,
    windowsSmokeAllowAudioOpenFailure: false,
    windowsSmokeFailureExplanation: "",
    macSmokeReport: options.macSmoke,
    macSmokeAllowAudioOpenFailure: false,
    macSmokeFailureExplanation: "",
    sessions: [
      {
        name: "windows-to-macos-5min",
        direction: "windows-to-macos",
        room: options.winToMacRoom,
        codec: "opus",
        frames: 120,
        jitter: 8,
        speakerPlatform: "windows",
        listenerPlatform: "macos",
        minMinutes: 5,
        network: "lan-or-tunnel",
        subjective: "clear / flicker / robotic / dropout notes",
        allowWarnings: false,
        warningExplanation: "",
        logs: options.winToMacLogs,
      },
      {
        name: "macos-to-windows-5min",
        direction: "macos-to-windows",
        room: options.macToWinRoom,
        codec: "opus",
        frames: 120,
        jitter: 8,
        speakerPlatform: "macos",
        listenerPlatform: "windows",
        minMinutes: 5,
        network: "lan-or-tunnel",
        subjective: "clear / flicker / robotic / dropout notes",
        allowWarnings: false,
        warningExplanation: "",
        logs: options.macToWinLogs,
      },
      {
        name: "long-session-30min",
        direction: "bidirectional",
        room: options.longRoom,
        codec: "opus",
        frames: 120,
        jitter: 8,
        participants: ["windows", "macos"],
        minMinutes: 30,
        network: "lan-or-tunnel",
        subjective: "long-session notes",
        allowWarnings: false,
        warningExplanation: "",
        logs: options.longLogs,
      },
    ],
  };
}

function runInit(argv) {
  const options = parseInitArgs(argv);
  if (!options.out) {
    throw new Error("--init requires an output manifest path");
  }
  const outputPathIssue = ignoredRepoPathIssue(options.out);
  if (outputPathIssue) {
    throw new Error(outputPathIssue);
  }
  for (const [label, value] of [
    ["windows smoke input path", options.windowsSmoke],
    ["macOS smoke input path", options.macSmoke],
  ]) {
    if (String(value).trim().toLowerCase() === "latest") continue;
    const inputPathIssue = ignoredRepoPathIssue(value, label);
    if (inputPathIssue) {
      throw new Error(inputPathIssue);
    }
  }
  for (const [label, logs] of [
    ["win-to-mac log input path", options.winToMacLogs],
    ["mac-to-win log input path", options.macToWinLogs],
    ["long-session log input path", options.longLogs],
  ]) {
    for (const logPath of logs) {
      const inputPathIssue = ignoredRepoPathIssue(logPath, label);
      if (inputPathIssue) {
        throw new Error(inputPathIssue);
      }
    }
  }
  options.windowsSmoke = resolveSmokeOption(options.windowsSmoke, "windows");
  options.macSmoke = resolveSmokeOption(options.macSmoke, "macos");
  const outFile = resolveRepoPath(options.out);
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(outFile, `${JSON.stringify(initializedManifest(options), null, 2)}\n`, "utf8");
  console.log(`wrote ${options.out}`);
  console.log("Edit network/subjective notes before running the checker; placeholders are rejected.");
}

function writeFixture(file, text) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text, "utf8");
}

function runSelfTest() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "opus-evidence-check-"));
  const cleanSmoke = [
    "# Opus Validation Report",
    "",
    "Platform: win32 10.0.26200 x64",
    `Source SHA256: ${sourceFingerprint(repoRoot)}`,
    "",
    "| Step | Exit | Log |",
    "| --- | ---: | --- |",
    "| startup-default | 0 | startup-default.log |",
    "| startup-no-auto | 0 | startup-no-auto.log |",
    "| harness-self-test | 0 | harness-self-test.log |",
    "| audio-open | 0 | audio-open.log |",
    "",
  ].join("\n");
  const cleanMacSmoke = cleanSmoke.replace("Platform: win32 10.0.26200 x64", "Platform: darwin 24.0.0 arm64");
  const explainedAudioOpenSmoke = cleanMacSmoke.replace("| audio-open | 0 |", "| audio-open | 1 |");
  const fiveMinuteLog = [
    "[2026-05-11 20:00:00.000] [info] Audio diag: frames=120 tx_packets=1 tx_drops pcm/opus=0/0 sendq_age_ms last/avg/max=0.00/0.00/0.00 rx_bytes=100 tx_bytes=100",
    "[2026-05-11 20:06:00.000] [info] Participant diag 1: ready=true q=5 q_avg=5 q_max=6 q_drift=0.00 jitter_buffer=5 queue_limit=16 frames pkt/cb=120/120 decoded_frames=0 decoded_packets=100 age_avg_ms=12.5 drift_ppm last/avg/max=0.0/0.0/0.0 underruns=0 pcm_hold/drop=0/0 drops q/age=0/0 drop_detail limit/age/overflow=0/0/0 seq gap/late=0/0 target_trim=0",
    "",
  ].join("\n");
  const windowsClientLog = [
    "[2026-05-11 20:00:00.000] [info] Runtime: role=client platform=windows arch=x64",
    "[2026-05-11 20:00:00.000] [info] Sent JOIN for room 'opus-validation-room-win-to-mac' user 'windows-user' token present",
    "[2026-05-11 20:00:00.000] [info] Startup requested buffer override: 120 frames",
    "[2026-05-11 20:00:00.000] [info] Startup codec override: Opus",
    "[2026-05-11 20:00:00.000] [info] Startup Opus jitter override: 8 packets",
    "[2026-05-11 20:00:00.000] [info] Startup Opus auto jitter default enabled",
    fiveMinuteLog,
  ].join("\n");
  const macClientLog = [
    "[2026-05-11 20:00:00.000] [info] Runtime: role=client platform=macos arch=arm64",
    "[2026-05-11 20:00:00.000] [info] Sent JOIN for room 'opus-validation-room-win-to-mac' user 'macos-user' token present",
    "[2026-05-11 20:00:00.000] [info] Startup requested buffer override: 120 frames",
    "[2026-05-11 20:00:00.000] [info] Startup codec override: Opus",
    "[2026-05-11 20:00:00.000] [info] Startup Opus jitter override: 8 packets",
    "[2026-05-11 20:00:00.000] [info] Startup Opus auto jitter default enabled",
    fiveMinuteLog,
  ].join("\n");
  const windowsClientLogMacToWin = windowsClientLog
    .replaceAll("opus-validation-room-win-to-mac", "opus-validation-room-mac-to-win");
  const macClientLogMacToWin = macClientLog
    .replaceAll("opus-validation-room-win-to-mac", "opus-validation-room-mac-to-win");
  const serverLogWinToMac = [
    "[2026-05-11 20:00:00.000] [info] Runtime: role=server platform=windows arch=x64",
    "[2026-05-11 20:00:00.000] [info] JOIN: 192.168.1.20:50001 room='opus-validation-room-win-to-mac' user='windows-user' display='Windows User' (ID: 1, token-present)",
    "[2026-05-11 20:00:00.000] [info] JOIN: 192.168.1.21:50002 room='opus-validation-room-win-to-mac' user='macos-user' display='macOS User' (ID: 2, token-present)",
    fiveMinuteLog,
  ].join("\n");
  const serverLogMacToWin = serverLogWinToMac
    .replaceAll("opus-validation-room-win-to-mac", "opus-validation-room-mac-to-win");
  const longLog = fiveMinuteLog.replace("20:06:00.000", "20:31:00.000");
  const windowsLongClientLog = [
    "[2026-05-11 20:00:00.000] [info] Runtime: role=client platform=windows arch=x64",
    "[2026-05-11 20:00:00.000] [info] Sent JOIN for room 'opus-validation-long-room' user 'windows-user-long' token present",
    "[2026-05-11 20:00:00.000] [info] Startup requested buffer override: 120 frames",
    "[2026-05-11 20:00:00.000] [info] Startup codec override: Opus",
    "[2026-05-11 20:00:00.000] [info] Startup Opus jitter override: 8 packets",
    "[2026-05-11 20:00:00.000] [info] Startup Opus auto jitter default enabled",
    longLog,
  ].join("\n");
  const macLongClientLog = [
    "[2026-05-11 20:00:00.000] [info] Runtime: role=client platform=macos arch=arm64",
    "[2026-05-11 20:00:00.000] [info] Sent JOIN for room 'opus-validation-long-room' user 'macos-user-long' token present",
    "[2026-05-11 20:00:00.000] [info] Startup requested buffer override: 120 frames",
    "[2026-05-11 20:00:00.000] [info] Startup codec override: Opus",
    "[2026-05-11 20:00:00.000] [info] Startup Opus jitter override: 8 packets",
    "[2026-05-11 20:00:00.000] [info] Startup Opus auto jitter default enabled",
    longLog,
  ].join("\n");
  const serverLongLog = [
    "[2026-05-11 20:00:00.000] [info] Runtime: role=server platform=windows arch=x64",
    "[2026-05-11 20:00:00.000] [info] JOIN: 192.168.1.20:50001 room='opus-validation-long-room' user='windows-user-long' display='Windows User' (ID: 1, token-present)",
    "[2026-05-11 20:00:00.000] [info] JOIN: 192.168.1.21:50002 room='opus-validation-long-room' user='macos-user-long' display='macOS User' (ID: 2, token-present)",
    longLog,
  ].join("\n");
  const sequenceGapLog = fiveMinuteLog.replace("seq gap/late=0/0", "seq gap/late=1/0");
  const largeDriftLog = fiveMinuteLog.replace("drift_ppm last/avg/max=0.0/0.0/0.0", "drift_ppm last/avg/max=0.0/0.0/300.0");
  const shortDiagnosticLog = fiveMinuteLog.replace("20:06:00.000", "20:01:00.000");
  const noDiagnosticLog = [
    "[2026-05-11 20:00:00.000] [info] Connected",
    "[2026-05-11 20:06:00.000] [info] Disconnected",
    "",
  ].join("\n");

  const windowsReport = path.join(dir, "windows", "report.md");
  const macReport = path.join(dir, "macos", "report.md");
  writeFixture(windowsReport, cleanSmoke);
  writeFixture(macReport, cleanMacSmoke);
  writeFixture(
    path.join(path.dirname(windowsReport), "startup-default-client.log"),
    [
      "[2026-05-11 20:00:00.000] [info] Runtime: role=client platform=windows arch=x64",
      "[2026-05-11 20:00:00.000] [info] Startup requested buffer override: 120 frames",
      "[2026-05-11 20:00:00.000] [info] Startup codec override: Opus",
      "[2026-05-11 20:00:00.000] [info] Startup config smoke: codec=opus frames=120 jitter=8 queue_limit=16 age_limit_ms=40 auto_jitter=true",
      "",
    ].join("\n"),
  );
  writeFixture(
    path.join(path.dirname(macReport), "startup-default-client.log"),
    [
      "[2026-05-11 20:00:00.000] [info] Runtime: role=client platform=macos arch=arm64",
      "[2026-05-11 20:00:00.000] [info] Startup requested buffer override: 120 frames",
      "[2026-05-11 20:00:00.000] [info] Startup codec override: Opus",
      "[2026-05-11 20:00:00.000] [info] Startup config smoke: codec=opus frames=120 jitter=8 queue_limit=16 age_limit_ms=40 auto_jitter=true",
      "",
    ].join("\n"),
  );
  writeFixture(path.join(dir, "win-a.log"), windowsClientLog);
  writeFixture(path.join(dir, "mac-a.log"), macClientLog);
  writeFixture(path.join(dir, "server-a.log"), serverLogWinToMac);
  writeFixture(path.join(dir, "win-b.log"), windowsClientLogMacToWin);
  writeFixture(path.join(dir, "mac-b.log"), macClientLogMacToWin);
  writeFixture(path.join(dir, "server-b.log"), serverLogMacToWin);
  writeFixture(path.join(dir, "win-long.log"), windowsLongClientLog);
  writeFixture(path.join(dir, "mac-long.log"), macLongClientLog);
  writeFixture(path.join(dir, "server-long.log"), serverLongLog);

  const manifest = {
    windowsSmokeReport: windowsReport,
    windowsSmokeAllowAudioOpenFailure: false,
    windowsSmokeFailureExplanation: "",
    macSmokeReport: macReport,
    macSmokeAllowAudioOpenFailure: false,
    macSmokeFailureExplanation: "",
    sessions: [
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
        network: "wired-lan",
        subjective: "Windows source heard clearly on macOS for full five minute pass",
        allowWarnings: false,
        warningExplanation: "",
        logs: [path.join(dir, "win-a.log"), path.join(dir, "mac-a.log"), path.join(dir, "server-a.log")],
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
        network: "wired-lan",
        subjective: "macOS source heard clearly on Windows for full five minute pass",
        allowWarnings: false,
        warningExplanation: "",
        logs: [path.join(dir, "win-b.log"), path.join(dir, "mac-b.log"), path.join(dir, "server-b.log")],
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
        network: "wired-lan",
        subjective: "clear for thirty minute long session",
        allowWarnings: false,
        warningExplanation: "",
        logs: [
          path.join(dir, "win-long.log"),
          path.join(dir, "mac-long.log"),
          path.join(dir, "server-long.log"),
        ],
      },
    ],
  };

  const passManifest = path.join(dir, "pass-manifest.json");
  writeFixture(passManifest, JSON.stringify(manifest, null, 2));
  let result = validateManifest(passManifest);
  if (result.errors.length > 0) {
    throw new Error(`expected clean manifest to pass: ${result.errors.join("; ")}`);
  }
  if (strictFailure(result)) {
    throw new Error("expected clean manifest to pass strict review");
  }

  writeFixture(macReport, explainedAudioOpenSmoke);
  const allowedManifest = path.join(dir, "allowed-audio-open-manifest.json");
  writeFixture(
    allowedManifest,
    JSON.stringify(
      {
        ...manifest,
        macSmokeAllowAudioOpenFailure: true,
        macSmokeFailureExplanation: "Mac test machine had no available input device during smoke; session logs used normal device setup.",
      },
      null,
      2,
    ),
  );
  result = validateManifest(allowedManifest);
  if (result.errors.length > 0) {
    throw new Error(`expected explained audio-open failure to pass: ${result.errors.join("; ")}`);
  }
  if (result.warnings.length === 0) {
    throw new Error("expected explained audio-open failure to produce a review warning");
  }
  if (!strictFailure(result)) {
    throw new Error("expected explained audio-open failure to fail strict review");
  }
  const strictCliResult = spawnSync(
    process.execPath,
    [fileURLToPath(import.meta.url), allowedManifest, "--strict"],
    {
      cwd: repoRoot,
      encoding: "utf8",
      timeout: 30000,
      windowsHide: true,
    },
  );
  if ((strictCliResult.status ?? 0) === 0) {
    throw new Error("expected strict CLI review to reject warning-allowed manifest");
  }
  if (!String(strictCliResult.stderr || "").includes("strict mode requires clean evidence")) {
    throw new Error("expected strict CLI review to explain clean-evidence requirement");
  }
  writeFixture(macReport, cleanMacSmoke);

  const placeholderManifest = path.join(dir, "placeholder-manifest.json");
  writeFixture(
    placeholderManifest,
    JSON.stringify(
      {
        ...manifest,
        sessions: [{ ...manifest.sessions[0], network: "lan-or-tunnel", subjective: "clear / flicker / robotic / dropout notes" }],
      },
      null,
      2,
    ),
  );
  result = validateManifest(placeholderManifest);
  if (result.errors.length === 0) {
    throw new Error("expected placeholder manifest to fail");
  }

  writeFixture(path.join(dir, "win-sequence-gap.log"), sequenceGapLog);
  const sequenceManifest = path.join(dir, "sequence-gap-manifest.json");
  writeFixture(
    sequenceManifest,
    JSON.stringify(
      {
        ...manifest,
        sessions: [
          {
            ...manifest.sessions[0],
            logs: [path.join(dir, "win-sequence-gap.log"), path.join(dir, "mac-a.log"), path.join(dir, "server-a.log")],
          },
          manifest.sessions[1],
          manifest.sessions[2],
        ],
      },
      null,
      2,
    ),
  );
  result = validateManifest(sequenceManifest);
  if (result.errors.length === 0) {
    throw new Error("expected sequence gap manifest to fail");
  }

  writeFixture(path.join(dir, "win-large-drift.log"), largeDriftLog);
  const driftManifest = path.join(dir, "large-drift-manifest.json");
  writeFixture(
    driftManifest,
    JSON.stringify(
      {
        ...manifest,
        sessions: [
          {
            ...manifest.sessions[0],
            logs: [path.join(dir, "win-large-drift.log"), path.join(dir, "mac-a.log"), path.join(dir, "server-a.log")],
          },
          manifest.sessions[1],
          manifest.sessions[2],
        ],
      },
      null,
      2,
    ),
  );
  result = validateManifest(driftManifest);
  if (result.errors.length === 0) {
    throw new Error("expected large drift manifest to fail");
  }

  const wrongPlatformManifest = path.join(dir, "wrong-platform-manifest.json");
  writeFixture(
    wrongPlatformManifest,
    JSON.stringify(
      {
        ...manifest,
        macSmokeReport: windowsReport,
      },
      null,
      2,
    ),
  );
  result = validateManifest(wrongPlatformManifest);
  if (!result.errors.some((error) => error.includes("macSmokeReport platform mismatch"))) {
    throw new Error("expected wrong-platform manifest to fail");
  }

  const wrongSourceReport = path.join(dir, "wrong-source", "report.md");
  writeFixture(wrongSourceReport, cleanSmoke.replace(/^Source SHA256: .+$/m, "Source SHA256: 0000000000000000000000000000000000000000000000000000000000000000"));
  writeFixture(path.join(path.dirname(wrongSourceReport), "startup-default-client.log"), readText(path.join(path.dirname(windowsReport), "startup-default-client.log")));
  const wrongSourceManifest = path.join(dir, "wrong-source-manifest.json");
  writeFixture(
    wrongSourceManifest,
    JSON.stringify(
      {
        ...manifest,
        windowsSmokeReport: wrongSourceReport,
      },
      null,
      2,
    ),
  );
  result = validateManifest(wrongSourceManifest);
  if (!result.errors.some((error) => error.includes("Source SHA256 does not match current source fingerprint"))) {
    throw new Error("expected wrong-source manifest to fail");
  }

  const noSmokeLogReport = path.join(dir, "no-smoke-log", "report.md");
  writeFixture(noSmokeLogReport, cleanSmoke);
  const noSmokeLogManifest = path.join(dir, "no-smoke-log-manifest.json");
  writeFixture(
    noSmokeLogManifest,
    JSON.stringify(
      {
        ...manifest,
        windowsSmokeReport: noSmokeLogReport,
      },
      null,
      2,
    ),
  );
  result = validateManifest(noSmokeLogManifest);
  if (!result.errors.some((error) => error.includes("missing smoke startup client log"))) {
    throw new Error("expected missing smoke startup client log manifest to fail");
  }

  const wrongSessionRoleManifest = path.join(dir, "wrong-session-role-manifest.json");
  writeFixture(
    wrongSessionRoleManifest,
    JSON.stringify(
      {
        ...manifest,
        sessions: [
          {
            ...manifest.sessions[0],
            speakerPlatform: "macos",
            listenerPlatform: "windows",
          },
          manifest.sessions[1],
          manifest.sessions[2],
        ],
      },
      null,
      2,
    ),
  );
  result = validateManifest(wrongSessionRoleManifest);
  if (!result.errors.some((error) => error.includes("speakerPlatform mismatch"))) {
    throw new Error("expected wrong session role manifest to fail");
  }

  const wrongCodecManifest = path.join(dir, "wrong-codec-manifest.json");
  writeFixture(
    wrongCodecManifest,
    JSON.stringify(
      {
        ...manifest,
        sessions: [
          {
            ...manifest.sessions[0],
            codec: "pcm",
          },
          manifest.sessions[1],
          manifest.sessions[2],
        ],
      },
      null,
      2,
    ),
  );
  result = validateManifest(wrongCodecManifest);
  if (!result.errors.some((error) => error.includes("codec must be the string opus"))) {
    throw new Error("expected wrong codec manifest to fail");
  }

  const wrongManifestJitter = path.join(dir, "wrong-manifest-jitter.json");
  writeFixture(
    wrongManifestJitter,
    JSON.stringify(
      {
        ...manifest,
        sessions: [
          {
            ...manifest.sessions[0],
            jitter: 5,
          },
          manifest.sessions[1],
          manifest.sessions[2],
        ],
      },
      null,
      2,
    ),
  );
  result = validateManifest(wrongManifestJitter);
  if (!result.errors.some((error) => error.includes("jitter must be 8"))) {
    throw new Error("expected wrong manifest jitter to fail");
  }

  const loopbackNetworkManifest = path.join(dir, "loopback-network-manifest.json");
  writeFixture(
    loopbackNetworkManifest,
    JSON.stringify(
      {
        ...manifest,
        sessions: [
          {
            ...manifest.sessions[0],
            network: "same machine loopback 127.0.0.1",
          },
          manifest.sessions[1],
          manifest.sessions[2],
        ],
      },
      null,
      2,
    ),
  );
  result = validateManifest(loopbackNetworkManifest);
  if (!result.errors.some((error) => error.includes("not loopback, unroutable, or same-machine testing"))) {
    throw new Error("expected loopback network manifest to fail");
  }

  const unroutableNetworkManifest = path.join(dir, "unroutable-network-manifest.json");
  writeFixture(
    unroutableNetworkManifest,
    JSON.stringify(
      {
        ...manifest,
        sessions: [
          {
            ...manifest.sessions[0],
            network: "0.0.0.0 unspecified address",
          },
          manifest.sessions[1],
          manifest.sessions[2],
        ],
      },
      null,
      2,
    ),
  );
  result = validateManifest(unroutableNetworkManifest);
  if (!result.errors.some((error) => error.includes("not loopback, unroutable, or same-machine testing"))) {
    throw new Error("expected unroutable network manifest to fail");
  }

  const badSubjectiveManifest = path.join(dir, "bad-subjective-manifest.json");
  writeFixture(
    badSubjectiveManifest,
    JSON.stringify(
      {
        ...manifest,
        sessions: [
          {
            ...manifest.sessions[0],
            subjective: "robotic with dropouts",
          },
          manifest.sessions[1],
          manifest.sessions[2],
        ],
      },
      null,
      2,
    ),
  );
  result = validateManifest(badSubjectiveManifest);
  if (!result.errors.some((error) => error.includes("subjective note reports bad audio"))) {
    throw new Error("expected bad subjective manifest to fail");
  }

  const missingDirectionalSubjectiveManifest = path.join(dir, "missing-directional-subjective-manifest.json");
  writeFixture(
    missingDirectionalSubjectiveManifest,
    JSON.stringify(
      {
        ...manifest,
        sessions: [
          {
            ...manifest.sessions[0],
            subjective: "clear for full five minute pass",
          },
          manifest.sessions[1],
          manifest.sessions[2],
        ],
      },
      null,
      2,
    ),
  );
  result = validateManifest(missingDirectionalSubjectiveManifest);
  if (!result.errors.some((error) => error.includes("Windows source was judged on macOS"))) {
    throw new Error("expected missing directional subjective manifest to fail");
  }

  const missingRoomManifest = path.join(dir, "missing-room-manifest.json");
  writeFixture(
    missingRoomManifest,
    JSON.stringify(
      {
        ...manifest,
        sessions: [
          {
            ...manifest.sessions[0],
            room: "",
          },
          manifest.sessions[1],
          manifest.sessions[2],
        ],
      },
      null,
      2,
    ),
  );
  result = validateManifest(missingRoomManifest);
  if (!result.errors.some((error) => error.includes("must declare a validation room"))) {
    throw new Error("expected missing room manifest to fail");
  }

  writeFixture(path.join(dir, "win-wrong-startup.log"), windowsClientLog.replace("Startup requested buffer override: 120 frames", "Startup requested buffer override: 128 frames"));
  const wrongStartupFramesManifest = path.join(dir, "wrong-startup-frames-manifest.json");
  writeFixture(
    wrongStartupFramesManifest,
    JSON.stringify(
      {
        ...manifest,
        sessions: [
          {
            ...manifest.sessions[0],
            logs: [path.join(dir, "win-wrong-startup.log"), path.join(dir, "mac-a.log"), path.join(dir, "server-a.log")],
          },
          manifest.sessions[1],
          manifest.sessions[2],
        ],
      },
      null,
      2,
    ),
  );
  result = validateManifest(wrongStartupFramesManifest);
  if (!result.errors.some((error) => error.includes("must prove startup frames 120"))) {
    throw new Error("expected wrong startup frames manifest to fail");
  }

  writeFixture(path.join(dir, "win-wrong-jitter.log"), windowsClientLog.replace("Startup Opus jitter override: 8 packets", "Startup Opus jitter override: 5 packets"));
  const wrongStartupJitterManifest = path.join(dir, "wrong-startup-jitter-manifest.json");
  writeFixture(
    wrongStartupJitterManifest,
    JSON.stringify(
      {
        ...manifest,
        sessions: [
          {
            ...manifest.sessions[0],
            logs: [path.join(dir, "win-wrong-jitter.log"), path.join(dir, "mac-a.log"), path.join(dir, "server-a.log")],
          },
          manifest.sessions[1],
          manifest.sessions[2],
        ],
      },
      null,
      2,
    ),
  );
  result = validateManifest(wrongStartupJitterManifest);
  if (!result.errors.some((error) => error.includes("must prove startup jitter 8"))) {
    throw new Error("expected wrong startup jitter manifest to fail");
  }

  writeFixture(path.join(dir, "win-wrong-room.log"), windowsClientLog.replace("opus-validation-room-win-to-mac", "wrong-validation-room"));
  const wrongRoomManifest = path.join(dir, "wrong-room-manifest.json");
  writeFixture(
    wrongRoomManifest,
    JSON.stringify(
      {
        ...manifest,
        sessions: [
          {
            ...manifest.sessions[0],
            logs: [path.join(dir, "win-wrong-room.log"), path.join(dir, "mac-a.log"), path.join(dir, "server-a.log")],
          },
          manifest.sessions[1],
          manifest.sessions[2],
        ],
      },
      null,
      2,
    ),
  );
  result = validateManifest(wrongRoomManifest);
  if (!result.errors.some((error) => error.includes("must prove JOIN room"))) {
    throw new Error("expected wrong room manifest to fail");
  }

  writeFixture(path.join(dir, "server-wrong-room.log"), serverLogWinToMac.replaceAll("opus-validation-room-win-to-mac", "wrong-validation-room"));
  const wrongServerRoomManifest = path.join(dir, "wrong-server-room-manifest.json");
  writeFixture(
    wrongServerRoomManifest,
    JSON.stringify(
      {
        ...manifest,
        sessions: [
          {
            ...manifest.sessions[0],
            logs: [path.join(dir, "win-a.log"), path.join(dir, "mac-a.log"), path.join(dir, "server-wrong-room.log")],
          },
          manifest.sessions[1],
          manifest.sessions[2],
        ],
      },
      null,
      2,
    ),
  );
  result = validateManifest(wrongServerRoomManifest);
  if (!result.errors.some((error) => error.includes("server log must prove JOIN room"))) {
    throw new Error("expected wrong server room manifest to fail");
  }

  writeFixture(
    path.join(dir, "server-loopback-only.log"),
    serverLogWinToMac
      .replaceAll("192.168.1.20", "127.0.0.1")
      .replaceAll("192.168.1.21", "127.0.0.1"),
  );
  const loopbackServerEndpointManifest = path.join(dir, "loopback-server-endpoint-manifest.json");
  writeFixture(
    loopbackServerEndpointManifest,
    JSON.stringify(
      {
        ...manifest,
        sessions: [
          {
            ...manifest.sessions[0],
            logs: [path.join(dir, "win-a.log"), path.join(dir, "mac-a.log"), path.join(dir, "server-loopback-only.log")],
          },
          manifest.sessions[1],
          manifest.sessions[2],
        ],
      },
      null,
      2,
    ),
  );
  result = validateManifest(loopbackServerEndpointManifest);
  if (!result.errors.some((error) => error.includes("server JOIN endpoints are all loopback/unroutable"))) {
    throw new Error("expected loopback-only server endpoint manifest to fail");
  }

  writeFixture(
    path.join(dir, "server-ipv6-loopback-only.log"),
    serverLogWinToMac
      .replaceAll("192.168.1.20:50001", "[::1]:50001")
      .replaceAll("192.168.1.21:50002", "[::1]:50002"),
  );
  const ipv6LoopbackServerEndpointManifest = path.join(dir, "ipv6-loopback-server-endpoint-manifest.json");
  writeFixture(
    ipv6LoopbackServerEndpointManifest,
    JSON.stringify(
      {
        ...manifest,
        sessions: [
          {
            ...manifest.sessions[0],
            logs: [path.join(dir, "win-a.log"), path.join(dir, "mac-a.log"), path.join(dir, "server-ipv6-loopback-only.log")],
          },
          manifest.sessions[1],
          manifest.sessions[2],
        ],
      },
      null,
      2,
    ),
  );
  result = validateManifest(ipv6LoopbackServerEndpointManifest);
  if (!result.errors.some((error) => error.includes("server JOIN endpoints are all loopback/unroutable"))) {
    throw new Error("expected IPv6 loopback-only server endpoint manifest to fail");
  }

  writeFixture(
    path.join(dir, "server-full-ipv6-loopback-only.log"),
    serverLogWinToMac
      .replaceAll("192.168.1.20:50001", "0:0:0:0:0:0:0:1:50001")
      .replaceAll("192.168.1.21:50002", "0:0:0:0:0:0:0:1:50002"),
  );
  const fullIpv6LoopbackServerEndpointManifest = path.join(dir, "full-ipv6-loopback-server-endpoint-manifest.json");
  writeFixture(
    fullIpv6LoopbackServerEndpointManifest,
    JSON.stringify(
      {
        ...manifest,
        sessions: [
          {
            ...manifest.sessions[0],
            logs: [path.join(dir, "win-a.log"), path.join(dir, "mac-a.log"), path.join(dir, "server-full-ipv6-loopback-only.log")],
          },
          manifest.sessions[1],
          manifest.sessions[2],
        ],
      },
      null,
      2,
    ),
  );
  result = validateManifest(fullIpv6LoopbackServerEndpointManifest);
  if (!result.errors.some((error) => error.includes("server JOIN endpoints are all loopback/unroutable"))) {
    throw new Error("expected full-form IPv6 loopback-only server endpoint manifest to fail");
  }

  writeFixture(
    path.join(dir, "server-ipv4-mapped-ipv6-loopback-only.log"),
    serverLogWinToMac
      .replaceAll("192.168.1.20:50001", "[::ffff:127.0.0.1]:50001")
      .replaceAll("192.168.1.21:50002", "[::ffff:127.0.0.1]:50002"),
  );
  const ipv4MappedIpv6LoopbackServerEndpointManifest = path.join(dir, "ipv4-mapped-ipv6-loopback-server-endpoint-manifest.json");
  writeFixture(
    ipv4MappedIpv6LoopbackServerEndpointManifest,
    JSON.stringify(
      {
        ...manifest,
        sessions: [
          {
            ...manifest.sessions[0],
            logs: [
              path.join(dir, "win-a.log"),
              path.join(dir, "mac-a.log"),
              path.join(dir, "server-ipv4-mapped-ipv6-loopback-only.log"),
            ],
          },
          manifest.sessions[1],
          manifest.sessions[2],
        ],
      },
      null,
      2,
    ),
  );
  result = validateManifest(ipv4MappedIpv6LoopbackServerEndpointManifest);
  if (!result.errors.some((error) => error.includes("server JOIN endpoints are all loopback/unroutable"))) {
    throw new Error("expected IPv4-mapped IPv6 loopback-only server endpoint manifest to fail");
  }

  writeFixture(
    path.join(dir, "server-without-runtime.log"),
    serverLogWinToMac.replace("[2026-05-11 20:00:00.000] [info] Runtime: role=server platform=windows arch=x64\n", ""),
  );
  const missingServerRuntimeManifest = path.join(dir, "missing-server-runtime-manifest.json");
  writeFixture(
    missingServerRuntimeManifest,
    JSON.stringify(
      {
        ...manifest,
        sessions: [
          {
            ...manifest.sessions[0],
            logs: [path.join(dir, "win-a.log"), path.join(dir, "mac-a.log"), path.join(dir, "server-without-runtime.log")],
          },
          manifest.sessions[1],
          manifest.sessions[2],
        ],
      },
      null,
      2,
    ),
  );
  result = validateManifest(missingServerRuntimeManifest);
  if (!result.errors.some((error) => error.includes("must include a server runtime log"))) {
    throw new Error("expected missing server runtime manifest to fail");
  }

  writeFixture(path.join(dir, "win-missing-auto-jitter.log"), windowsClientLog.replace("[2026-05-11 20:00:00.000] [info] Startup Opus auto jitter default enabled\n", ""));
  const missingAutoJitterManifest = path.join(dir, "missing-auto-jitter-manifest.json");
  writeFixture(
    missingAutoJitterManifest,
    JSON.stringify(
      {
        ...manifest,
        sessions: [
          {
            ...manifest.sessions[0],
            logs: [path.join(dir, "win-missing-auto-jitter.log"), path.join(dir, "mac-a.log"), path.join(dir, "server-a.log")],
          },
          manifest.sessions[1],
          manifest.sessions[2],
        ],
      },
      null,
      2,
    ),
  );
  result = validateManifest(missingAutoJitterManifest);
  if (!result.errors.some((error) => error.includes("must prove startup auto jitter enabled"))) {
    throw new Error("expected missing startup auto jitter manifest to fail");
  }

  writeFixture(path.join(dir, "win-missing-startup-codec.log"), windowsClientLog.replace("[2026-05-11 20:00:00.000] [info] Startup codec override: Opus\n", ""));
  const missingStartupCodecManifest = path.join(dir, "missing-startup-codec-manifest.json");
  writeFixture(
    missingStartupCodecManifest,
    JSON.stringify(
      {
        ...manifest,
        sessions: [
          {
            ...manifest.sessions[0],
            logs: [path.join(dir, "win-missing-startup-codec.log"), path.join(dir, "mac-a.log"), path.join(dir, "server-a.log")],
          },
          manifest.sessions[1],
          manifest.sessions[2],
        ],
      },
      null,
      2,
    ),
  );
  result = validateManifest(missingStartupCodecManifest);
  if (!result.errors.some((error) => error.includes("must prove startup codec Opus"))) {
    throw new Error("expected missing startup codec manifest to fail");
  }

  writeFixture(path.join(dir, "short-diagnostic.log"), shortDiagnosticLog);
  writeFixture(path.join(dir, "no-diagnostic.log"), noDiagnosticLog);
  const weakDiagnosticManifest = path.join(dir, "weak-diagnostic-manifest.json");
  writeFixture(
    weakDiagnosticManifest,
    JSON.stringify(
      {
        ...manifest,
        sessions: [
          {
            ...manifest.sessions[0],
            logs: [path.join(dir, "win-a.log"), path.join(dir, "short-diagnostic.log"), path.join(dir, "no-diagnostic.log")],
          },
          manifest.sessions[1],
          manifest.sessions[2],
        ],
      },
      null,
      2,
    ),
  );
  result = validateManifest(weakDiagnosticManifest);
  if (!result.errors.some((error) => error.includes("at least two diagnostic logs"))) {
    throw new Error("expected weak diagnostic manifest to fail");
  }

  writeFixture(path.join(dir, "mac-without-runtime.log"), fiveMinuteLog);
  const missingRuntimeManifest = path.join(dir, "missing-runtime-manifest.json");
  writeFixture(
    missingRuntimeManifest,
    JSON.stringify(
      {
        ...manifest,
        sessions: [
          {
            ...manifest.sessions[0],
            logs: [path.join(dir, "win-a.log"), path.join(dir, "mac-without-runtime.log"), path.join(dir, "server-a.log")],
          },
          manifest.sessions[1],
          manifest.sessions[2],
        ],
      },
      null,
      2,
    ),
  );
  result = validateManifest(missingRuntimeManifest);
  if (!result.errors.some((error) => error.includes("missing client runtime log for platform macos"))) {
    throw new Error("expected missing runtime manifest to fail");
  }

  const reusedLogManifest = path.join(dir, "reused-log-manifest.json");
  writeFixture(
    reusedLogManifest,
    JSON.stringify(
      {
        ...manifest,
        sessions: [
          manifest.sessions[0],
          {
            ...manifest.sessions[1],
            logs: [path.join(dir, "win-a.log"), path.join(dir, "mac-b.log"), path.join(dir, "server-b.log")],
          },
          manifest.sessions[2],
        ],
      },
      null,
      2,
    ),
  );
  result = validateManifest(reusedLogManifest);
  if (!result.errors.some((error) => error.includes("reuses log path from session"))) {
    throw new Error("expected reused log manifest to fail");
  }

  const initialized = initializedManifest({
    windowsSmoke: windowsReport,
    macSmoke: macReport,
    winToMacLogs: [path.join(dir, "win-a.log"), path.join(dir, "mac-a.log"), path.join(dir, "server-a.log")],
    macToWinLogs: [path.join(dir, "win-b.log"), path.join(dir, "mac-b.log"), path.join(dir, "server-b.log")],
    longLogs: [path.join(dir, "win-long.log"), path.join(dir, "mac-long.log"), path.join(dir, "server-long.log")],
  });
  if (!initialized.sessions[0].logs[0].endsWith("win-a.log")) {
    throw new Error("expected init manifest to preserve supplied log paths");
  }
  if (initialized.sessions.some((session) => session.jitter !== 8)) {
    throw new Error("expected init manifest to include jitter=8 for every session");
  }
  const customRooms = initializedManifest({
    windowsSmoke: windowsReport,
    macSmoke: macReport,
    winToMacRoom: "custom-room-a",
    macToWinRoom: "custom-room-b",
    longRoom: "custom-long-room",
  });
  if (
    customRooms.sessions[0].room !== "custom-room-a" ||
    customRooms.sessions[1].room !== "custom-room-b" ||
    customRooms.sessions[2].room !== "custom-long-room"
  ) {
    throw new Error("expected init manifest to preserve supplied room names");
  }

  const initializedFile = path.join(dir, "initialized-from-cli.json");
  runInit([
    "--init",
    initializedFile,
    "--windows-smoke",
    windowsReport,
    "--mac-smoke",
    macReport,
    "--win-to-mac-logs",
    [path.join(dir, "win-a.log"), path.join(dir, "mac-a.log"), path.join(dir, "server-a.log")].join(","),
    "--win-to-mac-room",
    "custom-room-a",
    "--mac-to-win-logs",
    [path.join(dir, "win-b.log"), path.join(dir, "mac-b.log"), path.join(dir, "server-b.log")].join(","),
    "--mac-to-win-room",
    "custom-room-b",
    "--long-logs",
    [path.join(dir, "win-long.log"), path.join(dir, "mac-long.log"), path.join(dir, "server-long.log")].join(","),
    "--long-room",
    "custom-long-room",
  ]);
  const initializedFromFile = JSON.parse(readText(initializedFile));
  if (initializedFromFile.windowsSmokeReport !== windowsReport) {
    throw new Error("expected --init output to include supplied Windows smoke report");
  }
  if (!initializedFromFile.sessions[2].logs[0].endsWith("win-long.log")) {
    throw new Error("expected --init output to include supplied long-session logs");
  }
  if (initializedFromFile.sessions[1].room !== "custom-room-b") {
    throw new Error("expected --init output to include supplied room names");
  }
  result = validateManifest(initializedFile);
  if (
    !result.errors.some((error) => error.includes("missing network description")) ||
    !result.errors.some((error) => error.includes("missing subjective note"))
  ) {
    throw new Error("expected --init output to require edited network and subjective notes");
  }

  const latestId = `latest-self-test-${process.pid}-${Date.now()}`;
  const latestWinDir = path.join(repoRoot, "build", "opus-validation", `${latestId}-windows`);
  const latestMacDir = path.join(repoRoot, "build", "opus-validation", `${latestId}-macos`);
  try {
    writeFixture(path.join(latestWinDir, "report.md"), cleanSmoke);
    writeFixture(path.join(latestWinDir, "startup-default-client.log"), windowsClientLog);
    writeFixture(path.join(latestMacDir, "report.md"), cleanMacSmoke);
    writeFixture(path.join(latestMacDir, "startup-default-client.log"), macClientLog);

    const latestInitializedFile = path.join(dir, "initialized-from-latest.json");
    runInit([
      "--init",
      latestInitializedFile,
      "--win-to-mac-logs",
      [path.join(dir, "win-a.log"), path.join(dir, "mac-a.log"), path.join(dir, "server-a.log")].join(","),
      "--mac-to-win-logs",
      [path.join(dir, "win-b.log"), path.join(dir, "mac-b.log"), path.join(dir, "server-b.log")].join(","),
      "--long-logs",
      [path.join(dir, "win-long.log"), path.join(dir, "mac-long.log"), path.join(dir, "server-long.log")].join(","),
    ]);
    const latestInitialized = JSON.parse(readText(latestInitializedFile));
    if (!latestInitialized.windowsSmokeReport.endsWith(`${latestId}-windows/report.md`)) {
      throw new Error("expected --init to auto-discover latest Windows smoke report");
    }
    if (!latestInitialized.macSmokeReport.endsWith(`${latestId}-macos/report.md`)) {
      throw new Error("expected --init to auto-discover latest macOS smoke report");
    }
  } finally {
    fs.rmSync(latestWinDir, { recursive: true, force: true });
    fs.rmSync(latestMacDir, { recursive: true, force: true });
  }

  console.log("PASS: opus external evidence checker self-test");
}

function main() {
  const argv = process.argv.slice(2);
  const manifestPath = argv[0];
  if (manifestPath === "--init") {
    runInit(argv);
    return 0;
  }
  if (manifestPath === "--self-test") {
    runSelfTest();
    return 0;
  }
  if (!manifestPath || manifestPath === "--help" || manifestPath === "-h") {
    usage();
    return manifestPath ? 0 : 2;
  }

  const extraArgs = argv.slice(1);
  const strict = extraArgs.includes("--strict");
  const unknownArgs = extraArgs.filter((arg) => arg !== "--strict");
  if (unknownArgs.length > 0) {
    usage();
    console.error(`unknown option: ${unknownArgs[0]}`);
    return 2;
  }

  const result = validateManifest(manifestPath);
  for (const warning of result.warnings) console.warn(`WARN: ${warning}`);
  if (result.errors.length > 0) {
    for (const error of result.errors) console.error(`FAIL: ${error}`);
    return 1;
  }
  if (strict && strictFailure(result)) {
    console.error("FAIL: external Opus evidence packet has warnings; strict mode requires clean evidence");
    return 1;
  }
  console.log("PASS: external Opus evidence packet is complete enough for review");
  return 0;
}

try {
  process.exit(main());
} catch (error) {
  console.error(`FAIL: ${error.message}`);
  process.exit(2);
}
