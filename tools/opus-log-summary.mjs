#!/usr/bin/env node

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DRIFT_REVIEW_PPM = 250;

function usage() {
  console.log(
    [
      "usage:",
      "  node tools/opus-log-summary.mjs [--out <report.md>] <log...>",
      "  node tools/opus-log-summary.mjs --self-test",
      "",
      "Summarizes native client/server logs from Opus validation sessions.",
      "Use it on --log-file output from both machines after cross-machine tests.",
    ].join("\n"),
  );
}

function parseArgs(argv) {
  const options = { out: "", logs: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = argv[i + 1];
    if ((arg === "--out" || arg === "-o") && next) options.out = argv[++i];
    else if (arg === "--help" || arg === "-h") {
      usage();
      process.exit(0);
    } else {
      options.logs.push(arg);
    }
  }
  if (options.logs.length === 0) {
    usage();
    process.exit(2);
  }
  return options;
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
  return `log summary output path inside repo must be ignored generated evidence: ${relative}`;
}

function toNumber(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function emptySummary(file) {
  return {
    file,
    lines: 0,
    firstTimestamp: "",
    lastTimestamp: "",
    warnings: 0,
    errors: 0,
    healthWarnings: 0,
    startup: {
      codec: "",
      frames: "",
      jitter: "",
      queueLimit: "",
      ageLimitMs: "",
      autoJitter: "",
    },
    audioDiagCount: 0,
    lastAudio: null,
    latencyDiagCount: 0,
    maxCallbackMs: 0,
    maxCallbackOverruns: 0,
    participants: new Map(),
  };
}

function participantState(id) {
  return {
    id,
    diagCount: 0,
    last: null,
    maxQueue: 0,
    maxAgeMs: 0,
    maxDriftPpm: 0,
    maxUnderruns: 0,
    maxQueueDrops: 0,
    maxAgeDrops: 0,
    maxLimitDrops: 0,
    maxOverflowDrops: 0,
    maxTargetTrim: 0,
    maxSequenceGaps: 0,
    maxLateOrReordered: 0,
  };
}

function parseLog(file) {
  const text = fs.readFileSync(file, "utf8");
  const summary = emptySummary(file);
  const timestampPattern = /^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\]/;

  for (const line of text.split(/\r?\n/)) {
    if (!line) continue;
    summary.lines += 1;

    const timestamp = timestampPattern.exec(line)?.[1] ?? "";
    if (timestamp) {
      if (!summary.firstTimestamp) summary.firstTimestamp = timestamp;
      summary.lastTimestamp = timestamp;
    }
    if (line.includes("[warning]")) summary.warnings += 1;
    if (line.includes("[error]")) summary.errors += 1;
    if (line.includes("Audio health warning")) summary.healthWarnings += 1;

    const startup = /Startup config smoke: codec=(\S+) frames=(\d+) jitter=(\d+) queue_limit=(\d+) age_limit_ms=(\d+) auto_jitter=(\S+)/.exec(
      line,
    );
    if (startup) {
      summary.startup = {
        codec: startup[1],
        frames: startup[2],
        jitter: startup[3],
        queueLimit: startup[4],
        ageLimitMs: startup[5],
        autoJitter: startup[6],
      };
    }

    const audio = /Audio diag: frames=(\d+) tx_packets=(\d+) tx_drops pcm\/opus=(\d+)\/(\d+) sendq_age_ms last\/avg\/max=([\d.]+)\/([\d.]+)\/([\d.]+) rx_bytes=(\d+) tx_bytes=(\d+)/.exec(
      line,
    );
    if (audio) {
      summary.audioDiagCount += 1;
      summary.lastAudio = {
        frames: toNumber(audio[1]),
        txPackets: toNumber(audio[2]),
        pcmDrops: toNumber(audio[3]),
        opusDrops: toNumber(audio[4]),
        sendQueueLastMs: toNumber(audio[5]),
        sendQueueAvgMs: toNumber(audio[6]),
        sendQueueMaxMs: toNumber(audio[7]),
        rxBytes: toNumber(audio[8]),
        txBytes: toNumber(audio[9]),
      };
    }

    const latency = /Latency diag: callback_ms last\/avg\/max\/deadline=([\d.]+)\/([\d.]+)\/([\d.]+)\/([\d.]+) over=(\d+)/.exec(
      line,
    );
    if (latency) {
      summary.latencyDiagCount += 1;
      summary.maxCallbackMs = Math.max(summary.maxCallbackMs, toNumber(latency[3]));
      summary.maxCallbackOverruns = Math.max(summary.maxCallbackOverruns, toNumber(latency[5]));
    }

    const participant = /Participant diag (\d+): ready=(\S+) q=(\d+) q_avg=(\d+) q_max=(\d+) q_drift=([-.\d]+) jitter_buffer=(\d+) queue_limit=(\d+) frames pkt\/cb=(\d+)\/(\d+) decoded_frames=(\d+) decoded_packets=(\d+) age_avg_ms=([-.\d]+) drift_ppm last\/avg\/max=([-.\d]+)\/([-.\d]+)\/([-.\d]+) underruns=(\d+) pcm_hold\/drop=(\d+)\/(\d+) drops q\/age=(\d+)\/(\d+) drop_detail limit\/age\/overflow=(\d+)\/(\d+)\/(\d+) seq gap\/late=(\d+)\/(\d+) target_trim=(\d+)/.exec(
      line,
    );
    if (participant) {
      const id = participant[1];
      const state = summary.participants.get(id) ?? participantState(id);
      const current = {
        ready: participant[2],
        queue: toNumber(participant[3]),
        queueAvg: toNumber(participant[4]),
        queueMax: toNumber(participant[5]),
        queueDrift: toNumber(participant[6]),
        jitterBuffer: toNumber(participant[7]),
        queueLimit: toNumber(participant[8]),
        packetFrames: toNumber(participant[9]),
        callbackFrames: toNumber(participant[10]),
        decodedFrames: toNumber(participant[11]),
        decodedPackets: toNumber(participant[12]),
        ageAvgMs: toNumber(participant[13]),
        driftLastPpm: toNumber(participant[14]),
        driftAvgPpm: toNumber(participant[15]),
        driftMaxPpm: toNumber(participant[16]),
        underruns: toNumber(participant[17]),
        pcmHold: toNumber(participant[18]),
        pcmDriftDrops: toNumber(participant[19]),
        queueDrops: toNumber(participant[20]),
        ageDrops: toNumber(participant[21]),
        limitDrops: toNumber(participant[22]),
        detailAgeDrops: toNumber(participant[23]),
        overflowDrops: toNumber(participant[24]),
        sequenceGaps: toNumber(participant[25]),
        lateOrReordered: toNumber(participant[26]),
        targetTrim: toNumber(participant[27]),
      };
      state.diagCount += 1;
      state.last = current;
      state.maxQueue = Math.max(state.maxQueue, current.queueMax);
      state.maxAgeMs = Math.max(state.maxAgeMs, current.ageAvgMs);
      state.maxDriftPpm = Math.max(state.maxDriftPpm, Math.abs(current.driftMaxPpm));
      state.maxUnderruns = Math.max(state.maxUnderruns, current.underruns);
      state.maxQueueDrops = Math.max(state.maxQueueDrops, current.queueDrops);
      state.maxAgeDrops = Math.max(state.maxAgeDrops, current.ageDrops);
      state.maxLimitDrops = Math.max(state.maxLimitDrops, current.limitDrops);
      state.maxOverflowDrops = Math.max(state.maxOverflowDrops, current.overflowDrops);
      state.maxTargetTrim = Math.max(state.maxTargetTrim, current.targetTrim);
      state.maxSequenceGaps = Math.max(state.maxSequenceGaps, current.sequenceGaps);
      state.maxLateOrReordered = Math.max(state.maxLateOrReordered, current.lateOrReordered);
      summary.participants.set(id, state);
    }
  }

  return summary;
}

function statusFor(summary) {
  let status = "pass";
  const reasons = [];
  if (summary.warnings > 0) {
    status = "warn";
    reasons.push(`${summary.warnings} warning log lines`);
  }
  if (summary.errors > 0) {
    status = "warn";
    reasons.push(`${summary.errors} error log lines`);
  }
  if (summary.healthWarnings > 0) {
    status = "warn";
    reasons.push(`${summary.healthWarnings} audio health warnings`);
  }
  for (const participant of summary.participants.values()) {
    if (participant.maxUnderruns > 0) {
      status = "warn";
      reasons.push(`participant ${participant.id} underruns=${participant.maxUnderruns}`);
    }
    if (participant.maxDriftPpm > DRIFT_REVIEW_PPM) {
      status = "warn";
      reasons.push(`participant ${participant.id} drift_ppm=${participant.maxDriftPpm}`);
    }
    if (participant.maxSequenceGaps > 0 || participant.maxLateOrReordered > 0) {
      status = "warn";
      reasons.push(
        `participant ${participant.id} seq gap/late=${participant.maxSequenceGaps}/${participant.maxLateOrReordered}`,
      );
    }
  }
  if (summary.audioDiagCount === 0 && summary.latencyDiagCount === 0 && summary.participants.size === 0) {
    reasons.push("no long-session audio diagnostics found");
  }
  return { status, reasons: reasons.join("; ") || "no warning indicators parsed" };
}

function markdownReport(summaries) {
  const lines = [
    "# Opus Log Summary",
    "",
    `Generated: ${new Date().toISOString()}`,
    "",
    "## Files",
    "",
    "| File | Status | Lines | Window | Warnings | Errors | Health Warnings | Audio Diag | Latency Diag | Reason |",
    "| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | --- |",
  ];

  for (const summary of summaries) {
    const status = statusFor(summary);
    const window =
      summary.firstTimestamp && summary.lastTimestamp
        ? `${summary.firstTimestamp} -> ${summary.lastTimestamp}`
        : "";
    lines.push(
      `| ${summary.file} | ${status.status} | ${summary.lines} | ${window} | ${summary.warnings} | ${summary.errors} | ${summary.healthWarnings} | ${summary.audioDiagCount} | ${summary.latencyDiagCount} | ${status.reasons} |`,
    );
  }

  lines.push("", "## Startup Config", "", "| File | Codec | Frames | Jitter | Queue Limit | Age Limit ms | Auto Jitter |", "| --- | --- | ---: | ---: | ---: | ---: | --- |");
  for (const summary of summaries) {
    const startup = summary.startup;
    if (!startup.codec) continue;
    lines.push(
      `| ${summary.file} | ${startup.codec} | ${startup.frames} | ${startup.jitter} | ${startup.queueLimit} | ${startup.ageLimitMs} | ${startup.autoJitter} |`,
    );
  }

  lines.push(
    "",
    "## Latest Audio Diagnostics",
    "",
    "| File | Frames | TX packets | TX drops pcm/opus | SendQ avg/max ms | RX bytes | TX bytes |",
    "| --- | ---: | ---: | --- | --- | ---: | ---: |",
  );
  for (const summary of summaries) {
    if (!summary.lastAudio) continue;
    const audio = summary.lastAudio;
    lines.push(
      `| ${summary.file} | ${audio.frames} | ${audio.txPackets} | ${audio.pcmDrops}/${audio.opusDrops} | ${audio.sendQueueAvgMs}/${audio.sendQueueMaxMs} | ${audio.rxBytes} | ${audio.txBytes} |`,
    );
  }

  lines.push(
    "",
    "## Participant Diagnostics",
    "",
    "| File | Participant | Diags | Last q | Max q | Jitter | Queue limit | Last age ms | Max drift ppm | Underruns | Drops q/age | Detail limit/overflow | Seq gap/late | Target trim |",
    "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- | --- | ---: |",
  );
  for (const summary of summaries) {
    for (const participant of summary.participants.values()) {
      const last = participant.last ?? {};
      lines.push(
        `| ${summary.file} | ${participant.id} | ${participant.diagCount} | ${last.queue ?? ""} | ${participant.maxQueue} | ${last.jitterBuffer ?? ""} | ${last.queueLimit ?? ""} | ${last.ageAvgMs ?? ""} | ${participant.maxDriftPpm} | ${participant.maxUnderruns} | ${participant.maxQueueDrops}/${participant.maxAgeDrops} | ${participant.maxLimitDrops}/${participant.maxOverflowDrops} | ${participant.maxSequenceGaps}/${participant.maxLateOrReordered} | ${participant.maxTargetTrim} |`,
      );
    }
  }

  lines.push(
    "",
    "## Notes",
    "",
    "- `pass` means this parser found no warning indicators in the parsed log, not that audio was subjectively perfect.",
    "- `warn` means the log contains warning/error lines, audio health warnings, underruns, sequence issues, drift above `250 ppm`, or other diagnostics that need review.",
    "- This parser is intended for external validation logs produced with `--log-file`.",
    "",
  );

  return `${lines.join("\n")}\n`;
}

function writeFixture(file, text) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text, "utf8");
}

function runSelfTest() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "opus-log-summary-"));
  const baseDiag =
    "[2026-05-11 20:00:00.000] [info] Participant diag 1: ready=true q=5 q_avg=5 q_max=6 q_drift=0.00 jitter_buffer=5 queue_limit=16 frames pkt/cb=120/120 decoded_frames=0 decoded_packets=100 age_avg_ms=12.5 drift_ppm last/avg/max=0.0/0.0/0.0 underruns=0 pcm_hold/drop=0/0 drops q/age=0/0 drop_detail limit/age/overflow=0/0/0 seq gap/late=0/0 target_trim=0";
  const cleanLog = path.join(dir, "clean.log");
  const driftLog = path.join(dir, "drift.log");
  const sequenceLog = path.join(dir, "sequence.log");
  writeFixture(cleanLog, `${baseDiag}\n`);
  writeFixture(driftLog, `${baseDiag.replace("drift_ppm last/avg/max=0.0/0.0/0.0", "drift_ppm last/avg/max=0.0/0.0/300.0")}\n`);
  writeFixture(sequenceLog, `${baseDiag.replace("seq gap/late=0/0", "seq gap/late=1/0")}\n`);

  const clean = statusFor(parseLog(cleanLog));
  if (clean.status !== "pass") {
    throw new Error(`expected clean log to pass, got ${clean.status}: ${clean.reasons}`);
  }
  const drift = statusFor(parseLog(driftLog));
  if (drift.status !== "warn" || !drift.reasons.includes("drift_ppm=300")) {
    throw new Error(`expected drift log to warn on drift, got ${drift.status}: ${drift.reasons}`);
  }
  const sequence = statusFor(parseLog(sequenceLog));
  if (sequence.status !== "warn" || !sequence.reasons.includes("seq gap/late=1/0")) {
    throw new Error(`expected sequence log to warn on seq gap, got ${sequence.status}: ${sequence.reasons}`);
  }
  console.log("PASS: opus log summary self-test");
}

const argv = process.argv.slice(2);
if (argv[0] === "--self-test") {
  runSelfTest();
  process.exit(0);
}

const options = parseArgs(argv);
if (options.out) {
  const outPathIssue = ignoredRepoPathIssue(options.out);
  if (outPathIssue) {
    console.error(outPathIssue);
    process.exit(2);
  }
}
const summaries = options.logs.map((logPath) => parseLog(logPath));
const report = markdownReport(summaries);
if (options.out) {
  fs.mkdirSync(path.dirname(path.resolve(options.out)), { recursive: true });
  fs.writeFileSync(options.out, report);
  console.log(`wrote ${options.out}`);
} else {
  process.stdout.write(report);
}
