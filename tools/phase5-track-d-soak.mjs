#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  delay,
  ensureDir,
  parseArgs,
  requireArgs,
  reserveUdpPort,
  spawnLogged,
  stopChild,
  waitForExit,
  waitForOutput,
  writeJson,
} from "./phase5-track-d-common.mjs";

const SERVER_ID = "local-dev";
const JOIN_SECRET = "dev-secret";
const ROOM = "phase5-soak";
const TOKEN_TTL_MS = 10 * 60 * 60 * 1000;

function usage() {
  console.error(
    [
      "Usage: node tools/phase5-track-d-soak.mjs",
      "  --server-exe <path> --client-exe <path> [--seconds N]",
      "  [--churn-interval-seconds N] [--stable-clients N] [--churn-clients N]",
      "  [--max-queue-drift-packets N] [--out-dir path]",
      "  node tools/phase5-track-d-soak.mjs --parser-smoke",
    ].join("\n"),
  );
}

function timestampForPath(date = new Date()) {
  return date.toISOString().replaceAll(":", "").replaceAll(".", "-");
}

function tokenFor(user) {
  const expiresAtMs = Date.now() + TOKEN_TTL_MS;
  const nonce = crypto.randomBytes(16).toString("hex");
  const role = "performer";
  const payload = ["v1", expiresAtMs, SERVER_ID, ROOM, user, role, nonce].join("|");
  const signature = crypto.createHmac("sha256", JOIN_SECRET).update(payload).digest("hex");
  return ["v1", expiresAtMs, SERVER_ID, ROOM, user, role, nonce, signature].join(".");
}

function positiveInt(value, fallback) {
  const parsed = Number(value ?? fallback);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return Math.floor(parsed);
}

function positiveNumber(value, fallback) {
  const parsed = Number(value ?? fallback);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function clientArgs({ port, user, displayName, label, seconds }) {
  const interval = Math.max(1, Math.min(10, Math.floor(seconds / 2) || 1));
  return [
    "--server",
    "127.0.0.1",
    "--port",
    String(port),
    "--room",
    ROOM,
    "--room-handle",
    ROOM,
    "--user-id",
    user,
    "--display-name",
    displayName,
    "--join-token",
    tokenFor(user),
    "--codec",
    "opus",
    "--frames",
    "120",
    "--latency-profile",
    "low",
    "--jitter",
    "4",
    "--baseline-snapshot-seconds",
    String(seconds),
    "--baseline-snapshot-interval-seconds",
    String(interval),
    "--baseline-snapshot-label",
    label,
  ];
}

function parseSoakLogText(text, source, maxQueueDriftPackets) {
  const result = {
    source,
    snapshots: 0,
    participants: 0,
    maxOverDeadline: 0,
    maxAbsQueueDrift: 0,
    failures: [],
  };
  for (const line of text.split(/\r?\n/)) {
    const snapshot = line.match(/Baseline snapshot .*callback_count=(\d+) over_deadline=(\d+)/);
    if (snapshot) {
      result.snapshots += 1;
      const overDeadline = Number(snapshot[2]);
      result.maxOverDeadline = Math.max(result.maxOverDeadline, overDeadline);
      if (overDeadline > 0) {
        result.failures.push(`${source}: over_deadline=${overDeadline}`);
      }
      continue;
    }

    const participant = line.match(/Baseline participant .*queue_drift=([-+0-9.]+)/);
    if (participant) {
      result.participants += 1;
      const drift = Math.abs(Number(participant[1]));
      result.maxAbsQueueDrift = Math.max(result.maxAbsQueueDrift, drift);
      if (drift > maxQueueDriftPackets) {
        result.failures.push(
          `${source}: queue_drift=${participant[1]} exceeds ${maxQueueDriftPackets}`,
        );
      }
    }
  }
  return result;
}

function listClientLogs(outDir) {
  if (!fs.existsSync(outDir)) {
    return [];
  }
  return fs
    .readdirSync(outDir)
    .filter((name) => /^client-.*\.log$/.test(name))
    .map((name) => path.join(outDir, name));
}

export function parseSoakLogs(outDir, maxQueueDriftPackets) {
  const logs = listClientLogs(outDir);
  const files = logs.map((file) =>
    parseSoakLogText(fs.readFileSync(file, "utf8"), path.basename(file), maxQueueDriftPackets),
  );
  const summary = {
    status: "ok",
    snapshots: files.reduce((sum, file) => sum + file.snapshots, 0),
    participants: files.reduce((sum, file) => sum + file.participants, 0),
    maxOverDeadline: Math.max(0, ...files.map((file) => file.maxOverDeadline)),
    maxAbsQueueDrift: Math.max(0, ...files.map((file) => file.maxAbsQueueDrift)),
    files,
    failures: files.flatMap((file) => file.failures),
  };
  if (logs.length === 0) {
    summary.failures.push("no client logs found");
  }
  if (summary.snapshots === 0) {
    summary.failures.push("no baseline snapshots found");
  }
  if (summary.participants === 0) {
    summary.failures.push("no baseline participant lines found");
  }
  summary.status = summary.failures.length === 0 ? "ok" : "fail";
  return summary;
}

function runParserSmoke() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "phase5-soak-parser-"));
  const log = [
    "[info] Baseline snapshot [stable-0]: platform=windows callback_count=120 over_deadline=0 jitter_floor=4",
    "[info] Baseline participant [stable-0] id=1 profile='a' name='A' ready=true queue=4 queue_avg=4 queue_max=6 queue_drift=0.75 jitter_buffer=4",
    "[info] Baseline snapshot [churn-0]: platform=windows callback_count=90 over_deadline=0 jitter_floor=4",
    "[info] Baseline participant [churn-0] id=2 profile='b' name='B' ready=true queue=5 queue_avg=5 queue_max=7 queue_drift=-1.25 jitter_buffer=4",
    "",
  ].join("\n");
  fs.writeFileSync(path.join(tmpDir, "client-parser.log"), log);
  const summary = parseSoakLogs(tmpDir, 4.0);
  if (summary.status !== "ok" || summary.snapshots !== 2 || summary.participants !== 2) {
    console.error(JSON.stringify(summary, null, 2));
    process.exit(1);
  }
  console.log("phase5 soak parser smoke passed");
}

async function runStableClient(args, outDir, port, index, seconds) {
  const label = `stable-${index}`;
  const child = spawnLogged(
    `client-${label}`,
    args["client-exe"],
    clientArgs({
      port,
      user: `phase5-soak-${label}`,
      displayName: `Phase5 Soak ${label}`,
      label,
      seconds,
    }),
    path.join(outDir, `client-${label}.log`),
  );
  const result = await waitForExit(child);
  return { label, ...result };
}

async function runChurnClientLoop(args, outDir, port, index, totalSeconds, intervalSeconds) {
  const results = [];
  const endAt = Date.now() + totalSeconds * 1000;
  let iteration = 0;
  while (Date.now() < endAt) {
    const remainingSeconds = Math.max(1, Math.ceil((endAt - Date.now()) / 1000));
    const runSeconds = Math.min(intervalSeconds, remainingSeconds);
    const label = `churn-${index}-${String(iteration).padStart(3, "0")}`;
    const child = spawnLogged(
      `client-${label}`,
      args["client-exe"],
      clientArgs({
        port,
        user: `phase5-soak-${label}`,
        displayName: `Phase5 Soak ${label}`,
        label,
        seconds: runSeconds,
      }),
      path.join(outDir, `client-${label}.log`),
    );
    const result = await waitForExit(child);
    results.push({ label, ...result });
    iteration += 1;
    if (Date.now() < endAt) {
      await delay(1000);
    }
  }
  return results;
}

async function runSoak(args) {
  requireArgs(args, ["server-exe", "client-exe"]);
  const seconds = positiveInt(args.seconds, 7200);
  const churnIntervalSeconds = positiveInt(args["churn-interval-seconds"], 120);
  const stableClients = positiveInt(args["stable-clients"], 1);
  const churnClients = positiveInt(args["churn-clients"], 1);
  const maxQueueDriftPackets = positiveNumber(args["max-queue-drift-packets"], 4.0);
  const outDir = path.resolve(
    args["out-dir"] ?? `validation_logs/phase5-track-d/soak-${timestampForPath()}`,
  );
  ensureDir(outDir);

  const port = await reserveUdpPort();
  let server;
  const clientResults = [];
  try {
    server = spawnLogged(
      "server",
      args["server-exe"],
      [
        "--port",
        String(port),
        "--server-id",
        SERVER_ID,
        "--join-secret",
        JOIN_SECRET,
      ],
      path.join(outDir, "server.log"),
    );
    await waitForOutput(server, /SFU server ready/, 5000, "server");

    const stableRuns = Array.from({ length: stableClients }, (_, index) =>
      runStableClient(args, outDir, port, index, seconds),
    );
    const churnRuns = Array.from({ length: churnClients }, (_, index) =>
      runChurnClientLoop(args, outDir, port, index, seconds, churnIntervalSeconds),
    );
    const settled = await Promise.all([...stableRuns, ...churnRuns]);
    for (const item of settled) {
      if (Array.isArray(item)) {
        clientResults.push(...item);
      } else {
        clientResults.push(item);
      }
    }
  } finally {
    await stopChild(server);
  }

  const summary = parseSoakLogs(outDir, maxQueueDriftPackets);
  for (const result of clientResults) {
    if (result.code !== 0) {
      summary.failures.push(`client ${result.label} exited ${result.code}`);
    }
  }
  summary.clientResults = clientResults;
  summary.seconds = seconds;
  summary.churnIntervalSeconds = churnIntervalSeconds;
  summary.maxQueueDriftPackets = maxQueueDriftPackets;
  summary.status = summary.failures.length === 0 ? "ok" : "fail";
  writeJson(path.join(outDir, "summary.json"), summary);
  if (summary.status !== "ok") {
    console.error(JSON.stringify(summary, null, 2));
    process.exit(1);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2), { booleanFlags: ["parser-smoke"] });
  if (args.help) {
    usage();
    return;
  }
  if (args["parser-smoke"]) {
    runParserSmoke();
    return;
  }
  await runSoak(args);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(2);
});
