#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { sourceFingerprint } from "./opus-source-fingerprint.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const maxLocalReportAgeMs = 24 * 60 * 60 * 1000;
const maxLocalReportFutureSkewMs = 5 * 60 * 1000;

const requiredDocs = [
  "OPUS_COMPETITIVE_ROADMAP.md",
  "OPUS_COMPETITIVE_IMPLEMENTATION_CHECKLIST.md",
  "OPUS_COMPETITIVE_COMPLETION_AUDIT.md",
  "OPUS_EXTERNAL_VALIDATION_RUNBOOK.md",
  "OPUS_EXTERNAL_VALIDATION_MANIFEST.example.json",
];

const blockingRequirements = [
  "macOS/CoreAudio Opus smoke report",
  "Windows-to-macOS Opus session logs",
  "macOS-to-Windows Opus session logs",
  "30-60 minute long-session logs",
  "passing external evidence manifest",
];

const objectiveDeliverables = [
  "Keep OPUS_COMPETITIVE_ROADMAP.md as the roadmap, not the executable task list.",
  "Create and maintain a concrete implementation checklist for all roadmap gates.",
  "Implement every local roadmap gate that can be verified from this workspace.",
  "Back implementation with deterministic tests, local probes, competitor evidence, and repeatable command output.",
  "Require real Windows/macOS external validation before claiming competitive/product-ready completion.",
];

const promptArtifactChecklist = [
  {
    requirement: "Roadmap stays non-executable",
    artifact: "OPUS_COMPETITIVE_ROADMAP.md",
    evidence: "Points to the checklist and has no roadmap task checkboxes.",
    status: "covered locally",
  },
  {
    requirement: "Implementation checklist exists",
    artifact: "OPUS_COMPETITIVE_IMPLEMENTATION_CHECKLIST.md",
    evidence: "Contains Gates 1-8 with deliverables, acceptance, and evidence.",
    status: "covered locally",
  },
  {
    requirement: "Roadmap gates implemented locally",
    artifact: "client/server/probe sources",
    evidence: "Saved local verifier report requires build, harness, smoke, local evidence, critical source-fingerprint coverage, source whitespace, and git diff checks.",
    status: "covered locally",
  },
  {
    requirement: "Evidence-backed competitor direction",
    artifact: ".cache/upstream-audio + tools/opus-competitor-evidence-check.mjs",
    evidence: "Local verifier requires the competitor evidence checker to pass.",
    status: "covered locally",
  },
  {
    requirement: "Generated validation artifacts protected",
    artifact: ".gitignore + validation-dir-gitignored + source-fingerprint-generated-dirs verifier steps",
    evidence: "Local verifier requires generated validation command, manifest, summary, and legacy validation-log paths to be ignored and excluded from Source SHA256.",
    status: "covered locally",
  },
  {
    requirement: "External Windows/macOS proof",
    artifact: "validation/opus-external-validation.json",
    evidence: "External evidence checker must pass against real smoke/session/long-run logs.",
    status: "required before full completion",
  },
];

const requiredLocalVerifierSteps = [
  "cmake-build-debug",
  "cmake-build-release",
  "opus-receiver-harness-self-test",
  "check-opus-validation-js",
  "check-opus-local-evidence-js",
  "check-opus-log-summary-js",
  "check-opus-external-evidence-js",
  "check-opus-external-commands-js",
  "check-opus-acceptance-js",
  "opus-acceptance-runs-completion-audit",
  "check-opus-completion-audit-js",
  "check-opus-competitor-evidence-js",
  "opus-competitor-evidence-check",
  "opus-log-summary-self-test",
  "opus-log-summary-rejects-unignored-output",
  "opus-external-evidence-check-self-test",
  "opus-external-commands-smoke",
  "opus-external-commands-flags",
  "opus-external-commands-token-integrity",
  "opus-external-commands-source-fingerprint",
  "opus-external-commands-custom-room-smoke",
  "opus-external-commands-custom-room-flags",
  "opus-external-commands-custom-room-token-integrity",
  "source-fingerprint-line-endings",
  "source-fingerprint-generated-dirs",
  "source-fingerprint-critical-files",
  "validation-dir-gitignored",
  "opus-validation-rejects-unignored-output",
  "opus-local-evidence-rejects-unignored-output",
  "opus-local-verify-rejects-unignored-output",
  "opus-completion-audit-rejects-unignored-local-report",
  "opus-acceptance-requires-external-manifest",
  "opus-acceptance-rejects-unignored-external-manifest",
  "opus-acceptance-rejects-ignored-placeholder-manifest",
  "opus-acceptance-rejects-unacknowledged-skip-local",
  "opus-acceptance-rejects-unignored-local-out",
  "opus-acceptance-rejects-skip-local-unignored-local-out",
  "opus-acceptance-rejects-missing-saved-local-report",
  "opus-external-evidence-rejects-example-manifest",
  "opus-external-evidence-rejects-malformed-manifest",
  "opus-external-evidence-rejects-nonobject-manifest",
  "opus-external-evidence-rejects-malformed-booleans",
  "opus-external-evidence-rejects-malformed-types",
  "opus-external-evidence-rejects-unknown-fields",
  "opus-external-evidence-rejects-missing-manifest",
  "opus-external-evidence-rejects-source-controlled-smoke-path",
  "opus-external-evidence-rejects-source-controlled-log-path",
  "opus-external-evidence-init-rejects-unignored-manifest",
  "opus-external-evidence-init-rejects-unignored-smoke-input",
  "opus-external-evidence-init-rejects-unignored-log-input",
  "opus-external-commands-requires-server-host",
  "opus-external-commands-rejects-unignored-write",
  "opus-external-commands-rejects-unignored-out-dir",
  "opus-external-commands-rejects-unignored-manifest",
  "opus-external-commands-rejects-loopback-host",
  "opus-external-commands-rejects-ipv6-loopback-host",
  "opus-external-commands-rejects-ipv6-loopback-host-port",
  "opus-external-commands-rejects-full-ipv6-loopback-host-port",
  "opus-external-commands-rejects-localhost-port",
  "opus-external-commands-rejects-unspecified-host",
  "opus-external-commands-rejects-full-ipv6-unspecified-host-port",
  "opus-external-commands-rejects-invalid-ttl",
  "opus-external-commands-rejects-short-ttl",
  "opus-validation-smoke",
  "opus-local-evidence",
  "source-whitespace-hygiene",
  "git-diff-check",
  "opus-completion-audit-rejects-missing-companion-log",
  "opus-completion-audit-rejects-stale-local-report",
  "opus-completion-audit-status-external-fail",
];

function usage() {
  console.log(
    [
      "usage:",
      "  node tools/opus-completion-audit.mjs --external-manifest <validation/opus-external-validation.json> [--local-report <report.md>]",
      "  node tools/opus-completion-audit.mjs --local-only [--local-report <report.md>]",
      "  node tools/opus-completion-audit.mjs --status [--external-manifest <validation/opus-external-validation.json>] [--local-report <report.md>]",
      "",
      "Audits whether the Opus competitive roadmap objective can be honestly marked complete.",
      "--local-only verifies local documentation/tooling boundaries but intentionally does not claim completion.",
      "--status prints a concise local/external completion summary, including a supplied external manifest when provided.",
    ].join("\n"),
  );
}

function parseArgs(argv) {
  const options = {
    externalManifest: "",
    localReport: path.join("build", "opus-local-verify", "current", "report.md"),
    localOnly: false,
    status: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = argv[i + 1];
    if (arg === "--external-manifest" && next) options.externalManifest = argv[++i];
    else if (arg === "--local-report" && next) options.localReport = argv[++i];
    else if (arg === "--local-only") options.localOnly = true;
    else if (arg === "--status") options.status = true;
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

function docIssues() {
  const issues = [];
  for (const file of requiredDocs) {
    const full = repoPath(file);
    if (!fs.existsSync(full)) {
      issues.push(`${file}: missing`);
      continue;
    }
    const text = fs.readFileSync(full, "utf8");
    const lines = text.split(/\r?\n/);
    lines.forEach((line, index) => {
      if (file === "OPUS_COMPETITIVE_ROADMAP.md" && /^\s*-\s+\[[ xX]\]/.test(line)) {
        issues.push(`${file}:${index + 1}: roadmap checkbox`);
      }
      if (/^\s*-\s+\[\s\]/.test(line)) issues.push(`${file}:${index + 1}: unchecked checkbox`);
      if (line.trim() === "Tasks:") issues.push(`${file}:${index + 1}: ambiguous Tasks marker`);
    });
  }
  return issues;
}

function runExternalManifest(manifest) {
  return spawnSync(process.execPath, [path.join("tools", "opus-external-evidence-check.mjs"), manifest, "--strict"], {
    cwd: repoRoot,
    encoding: "utf8",
    windowsHide: true,
  });
}

function localVerifierIssues(localReport) {
  const reportFile = repoPath(localReport);
  const reportDir = path.dirname(localReport).split(path.sep).join("/");
  const reportPathIssue = ignoredRepoPathIssue(localReport, "local verifier report path");
  if (reportPathIssue) {
    return [reportPathIssue];
  }
  if (!fs.existsSync(reportFile)) {
    return [`${path.relative(repoRoot, reportFile)}: missing; run node tools/opus-local-verify.mjs --out ${reportDir}`];
  }

  const text = fs.readFileSync(reportFile, "utf8");
  const issues = [];
  const reportDateText = text.match(/^Date:\s*(.+)$/m)?.[1] ?? "";
  const reportDateMs = Date.parse(reportDateText);
  if (!reportDateText || !Number.isFinite(reportDateMs)) {
    issues.push("local verifier report does not include a valid Date");
  } else {
    const ageMs = Date.now() - reportDateMs;
    if (ageMs > maxLocalReportAgeMs) {
      issues.push("local verifier report is older than 24 hours; rerun node tools/opus-local-verify.mjs");
    } else if (ageMs < -maxLocalReportFutureSkewMs) {
      issues.push("local verifier report Date is in the future");
    }
  }
  const currentFingerprint = sourceFingerprint(repoRoot);
  const reportFingerprint = text.match(/^Source SHA256:\s*([a-f0-9]{64})$/m)?.[1] ?? "";
  if (!reportFingerprint) {
    issues.push("local verifier report does not include a source fingerprint");
  } else if (reportFingerprint !== currentFingerprint) {
    issues.push(`local verifier report source fingerprint is stale; rerun node tools/opus-local-verify.mjs --out ${reportDir}`);
  }
  for (const step of requiredLocalVerifierSteps) {
    const rowPattern = new RegExp(`\\|\\s*${step}\\s*\\|\\s*0\\s*\\|`);
    if (!rowPattern.test(text)) issues.push(`local verifier report missing passing step: ${step}`);
  }
  const reportFileDir = path.dirname(reportFile);
  for (const step of requiredLocalVerifierSteps) {
    const rowPattern = new RegExp(`^\\|\\s*${step}\\s*\\|\\s*0\\s*\\|.*\\|\\s*([^|\\s]+\\.log)\\s*\\|\\s*$`, "m");
    const match = rowPattern.exec(text);
    if (!match) continue;
    const logName = match[1];
    const logFile = path.resolve(reportFileDir, logName);
    const relativeLog = path.relative(repoRoot, logFile).split(path.sep).join("/");
    const relativeToReport = path.relative(reportFileDir, logFile);
    if (relativeToReport.startsWith("..") || path.isAbsolute(relativeToReport)) {
      issues.push(`local verifier companion log escapes report directory: ${logName}`);
    } else if (!fs.existsSync(logFile)) {
      issues.push(`local verifier companion log missing for ${step}: ${relativeLog}`);
    } else if (fs.statSync(logFile).size === 0) {
      issues.push(`local verifier companion log is empty for ${step}: ${relativeLog}`);
    }
  }
  if (!/No roadmap task checkboxes, unchecked `- \[ \]` boxes, or `Tasks:` markers/.test(text)) {
    issues.push("local verifier report does not prove documentation hygiene");
  }
  if (!/competitor-source evidence/.test(text)) {
    issues.push("local verifier report does not prove competitor-source evidence");
  }
  return issues;
}

function printObjectiveChecklist() {
  console.log("Objective restated as deliverables:");
  for (const deliverable of objectiveDeliverables) console.log(`- ${deliverable}`);
  console.log("");
  console.log("Prompt-to-artifact checklist:");
  for (const item of promptArtifactChecklist) {
    console.log(`- ${item.requirement}: ${item.artifact} -> ${item.evidence} [${item.status}]`);
  }
  console.log("");
}

function printLocalStatus(issues, verifierIssues) {
  console.log("Opus completion audit");
  console.log("");
  printObjectiveChecklist();
  console.log("Local documentation/tooling boundary:");
  if (issues.length === 0) {
    console.log("- PASS: required roadmap/checklist/audit/runbook files exist and the roadmap has no task checkboxes.");
  } else {
    for (const issue of issues) console.log(`- FAIL: ${issue}`);
  }
  if (verifierIssues.length === 0) {
    console.log("- PASS: saved local verifier report covers build, tests, local evidence, competitor evidence, source-fingerprint coverage/exclusions, source whitespace, and diff-check.");
  } else {
    for (const issue of verifierIssues) console.log(`- FAIL: ${issue}`);
  }
  console.log("");
  console.log("Blocking external proof before full completion:");
  for (const requirement of blockingRequirements) console.log(`- ${requirement}`);
}

function externalManifestStatus(externalManifest) {
  const manifest = externalManifest || path.join("validation", "opus-external-validation.json");
  const manifestFile = repoPath(manifest);
  const hasManifest = fs.existsSync(manifestFile);
  if (!hasManifest) {
    return {
      blocker: "real Windows/macOS validation manifest must pass strict external evidence checking",
      manifest,
      status: "missing",
    };
  }
  const manifestPathIssue = ignoredRepoPathIssue(manifest);
  if (manifestPathIssue) {
    return { blocker: manifestPathIssue, manifest, status: "fail" };
  }
  const reviewResult = spawnSync(process.execPath, [path.join("tools", "opus-external-evidence-check.mjs"), manifest], {
    cwd: repoRoot,
    encoding: "utf8",
    windowsHide: true,
  });
  if ((reviewResult.status ?? 1) !== 0) {
    return { blocker: "external evidence checker failed", manifest, status: "fail" };
  }
  const strictResult = runExternalManifest(manifest);
  if ((strictResult.status ?? 1) === 0) {
    return { blocker: "", manifest, status: "pass" };
  }
  return {
    blocker: "external evidence manifest has review warnings; strict mode requires clean evidence",
    manifest,
    status: "warnings",
  };
}

function printConciseStatus(issues, verifierIssues, externalManifest) {
  const manifestStatus = externalManifestStatus(externalManifest);
  console.log("Opus competitive status");
  console.log(`- local docs/checklist: ${issues.length === 0 ? "pass" : "fail"}`);
  console.log(`- local verifier: ${verifierIssues.length === 0 ? "pass" : "fail"}`);
  console.log(`- external manifest: ${manifestStatus.status}`);
  console.log(`- final status: ${issues.length === 0 && verifierIssues.length === 0 && manifestStatus.status === "pass" ? "complete" : "incomplete"}`);
  if (manifestStatus.blocker) {
    console.log(`- blocker: ${manifestStatus.blocker}`);
  }
  return issues.length === 0 && verifierIssues.length === 0 && manifestStatus.status === "pass";
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const issues = docIssues();
  const verifierIssues = localVerifierIssues(options.localReport);

  if (options.status) {
    const complete = printConciseStatus(issues, verifierIssues, options.externalManifest);
    process.exit(complete ? 0 : 1);
  }

  if (options.localOnly) {
    printLocalStatus(issues, verifierIssues);
    console.log("");
    if (issues.length === 0 && verifierIssues.length === 0) {
      console.log("RESULT: local-only audit passed, but the full objective remains incomplete without external evidence.");
      process.exit(0);
    }
    console.log("RESULT: local-only audit failed. Rerun local verification and fix reported issues.");
    process.exit(1);
  }

  if (!options.externalManifest) {
    usage();
    printLocalStatus(issues, verifierIssues);
    console.log("");
    console.log("RESULT: incomplete. Provide --external-manifest with real Windows/macOS validation evidence.");
    process.exit(1);
  }

  if (issues.length > 0 || verifierIssues.length > 0) {
    printLocalStatus(issues, verifierIssues);
    console.log("");
    console.log("RESULT: incomplete. Local documentation/tooling or verifier evidence has issues.");
    process.exit(1);
  }

  const manifestFile = repoPath(options.externalManifest);
  if (!fs.existsSync(manifestFile)) {
    printLocalStatus(issues, verifierIssues);
    console.log("");
    console.log(`RESULT: incomplete. External manifest does not exist: ${options.externalManifest}`);
    process.exit(1);
  }
  const manifestPathIssue = ignoredRepoPathIssue(options.externalManifest);
  if (manifestPathIssue) {
    printLocalStatus(issues, verifierIssues);
    console.log("");
    console.log(`RESULT: incomplete. ${manifestPathIssue}`);
    process.exit(1);
  }

  const result = runExternalManifest(options.externalManifest);
  if ((result.status ?? 1) !== 0) {
    process.stdout.write(result.stdout || "");
    process.stderr.write(result.stderr || "");
    console.log("");
    console.log("RESULT: incomplete. External evidence manifest did not pass.");
    process.exit(1);
  }

  process.stdout.write(result.stdout || "");
  console.log("");
  console.log("RESULT: complete. Saved local verification report and external Windows/macOS evidence manifest passed.");
}

try {
  main();
} catch (error) {
  console.error(`FAIL: ${error.message}`);
  process.exit(2);
}
