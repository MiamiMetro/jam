#!/usr/bin/env node

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function usage() {
  console.log(
    [
      "usage:",
      "  node tools/opus-local-evidence.mjs [--out <dir>]",
      "",
      "Starts a local insecure-dev SFU, runs direct/proxy Opus probes,",
      "runs the per-participant jitter probe, and writes process/native logs",
      "plus a Markdown report.",
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

function resolveExe(candidates) {
  for (const candidate of candidates) {
    const full = path.resolve(repoRoot, candidate);
    if (fs.existsSync(full)) return full;
  }
  throw new Error(`missing executable; build first: ${candidates.join(" or ")}`);
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
  return `local evidence output path inside repo must be ignored generated evidence: ${relative}`;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForReady(child, pattern, timeoutMs) {
  return new Promise((resolve, reject) => {
    let done = false;
    const timer = setTimeout(() => {
      if (!done) {
        done = true;
        resolve(false);
      }
    }, timeoutMs);
    const onData = (data) => {
      if (!done && pattern.test(String(data))) {
        done = true;
        clearTimeout(timer);
        resolve(true);
      }
    };
    child.stdout.on("data", onData);
    child.stderr.on("data", onData);
    child.on("exit", (code) => {
      if (!done) {
        done = true;
        clearTimeout(timer);
        reject(new Error(`background process exited before ready, code=${code}`));
      }
    });
  });
}

function startBackground(outDir, name, command, args, readyPattern) {
  const logPath = path.join(outDir, `${name}.log`);
  const log = fs.createWriteStream(logPath);
  const child = spawn(command, args, {
    cwd: repoRoot,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });

  log.write(`$ ${[command, ...args].join(" ")}\n\n`);
  child.stdout.pipe(log, { end: false });
  child.stderr.pipe(log, { end: false });

  return {
    child,
    log,
    logPath,
    ready: readyPattern ? waitForReady(child, readyPattern, 2500) : sleep(500),
  };
}

function stopBackground(background) {
  if (!background) return;
  if (!background.child.killed) background.child.kill();
  background.log.end();
}

function runStep(outDir, name, command, args) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    timeout: 45000,
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
    code: result.status ?? 1,
    signal: result.signal ?? "",
    logPath,
    metrics: parseLatencyMetrics(output),
    rows: parseMultiParticipantRows(output),
    summary: summarizeOutput(output),
  };
}

function parseLatencyMetrics(output) {
  const metrics = {};
  for (const line of output.split(/\r?\n/)) {
    const match = /^([a-z_]+):\s*(-?\d+(?:\.\d+)?)/i.exec(line.trim());
    if (match) metrics[match[1]] = Number(match[2]);
  }
  return metrics;
}

function parseMultiParticipantRows(output) {
  const rows = {};
  for (const line of output.split(/\r?\n/)) {
    if (!line.startsWith("stable,") && !line.startsWith("unstable,")) continue;
    const [source, target, enqueued, played, underruns, avgQueue, maxQueue, avgAgeMs, maxAgeMs] =
      line.split(",");
    rows[source] = {
      source,
      target: Number(target),
      enqueued: Number(enqueued),
      played: Number(played),
      underruns: Number(underruns),
      avgQueue: Number(avgQueue),
      maxQueue: Number(maxQueue),
      avgAgeMs: Number(avgAgeMs),
      maxAgeMs: Number(maxAgeMs),
    };
  }
  return rows;
}

function summarizeOutput(output) {
  const interesting = [
    "latency_ms",
    "avg_queue_depth",
    "queue_drift_from_jitter",
    "underruns",
    "plc_frames",
    "decode_failures",
    "decoded_size_mismatches",
    "warning",
  ];
  const lines = output
    .split(/\r?\n/)
    .filter((line) => interesting.some((key) => line.startsWith(`${key}:`) || line.startsWith(`${key}`)));
  if (output.includes("source,target,enqueued,played,underruns")) {
    const csv = output
      .split(/\r?\n/)
      .filter((line) => line.startsWith("stable,") || line.startsWith("unstable,"));
    lines.push(...csv);
  }
  return lines.join("; ");
}

function writeReport(outDir, steps, checks, details) {
  const lines = [
    "# Opus Local Evidence Report",
    "",
    `Date: ${new Date().toISOString()}`,
    `Platform: ${os.platform()} ${os.release()} ${os.arch()}`,
    `Host: ${os.hostname()}`,
    `Server port: ${details.serverPort}`,
    `Proxy port: ${details.proxyPort}`,
    "",
    "## Results",
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

  lines.push("", "## Checks", "", "| Check | Status | Detail |", "| --- | --- | --- |");
  for (const check of checks) {
    lines.push(`| ${check.name} | ${check.status} | ${check.detail} |`);
  }

  lines.push(
    "",
    "## Interpretation",
    "",
    "- Direct probes cover the local SFU path without artificial impairment.",
    "- Proxy probes cover deterministic UDP jitter/reorder behavior.",
    "- The multi-participant probe verifies one receiver can assign different jitter targets per sender.",
    "- This report does not replace macOS, real cross-machine, or long-session validation.",
    "",
  );

  fs.writeFileSync(path.join(outDir, "report.md"), `${lines.join("\n")}\n`);
}

function metric(step, key) {
  return Number.isFinite(step?.metrics?.[key]) ? step.metrics[key] : 0;
}

function buildChecks(steps) {
  const byName = Object.fromEntries(steps.map((step) => [step.name, step]));
  const direct5 = byName["direct-opus-jitter-5"];
  const direct8 = byName["direct-opus-jitter-8"];
  const proxy0 = byName["proxy-opus-jitter-0"];
  const proxy5 = byName["proxy-opus-jitter-5"];
  const pcm = byName["proxy-pcm-jitter-5"];
  const multi = byName["multi-participant-jitter"];
  const stable = multi?.rows?.stable;
  const unstable = multi?.rows?.unstable;

  const checks = [];
  const add = (name, status, detail) => checks.push({ name, status, detail });

  for (const step of steps) {
    add(
      `${step.name} exited`,
      step.code === 0 ? "pass" : "fail",
      step.signal ? `signal=${step.signal}` : `exit=${step.code}`,
    );
  }

  const direct5Underruns = metric(direct5, "underruns");
  const direct5Plc = metric(direct5, "plc_frames");
  const direct5DecodeFailures = metric(direct5, "decode_failures");
  const direct5SizeMismatch = metric(direct5, "decoded_size_mismatches");
  add(
    "direct jitter 5 baseline has valid decode",
    direct5DecodeFailures === 0 && direct5SizeMismatch === 0
      ? direct5Underruns === 0 && direct5Plc === 0
        ? "pass"
        : "warn"
      : "fail",
    `underruns=${direct5Underruns}, plc=${direct5Plc}, decode_failures=${direct5DecodeFailures}, size_mismatch=${direct5SizeMismatch}`,
  );

  const direct8Underruns = metric(direct8, "underruns");
  const direct8Plc = metric(direct8, "plc_frames");
  const direct8DecodeFailures = metric(direct8, "decode_failures");
  const direct8SizeMismatch = metric(direct8, "decoded_size_mismatches");
  add(
    "direct jitter 8 local SFU decode validity",
    direct8DecodeFailures === 0 && direct8SizeMismatch === 0
      ? direct8Underruns === 0 && direct8Plc === 0
        ? "pass"
        : "warn"
      : "fail",
    `underruns=${direct8Underruns}, plc=${direct8Plc}, decode_failures=${direct8DecodeFailures}, size_mismatch=${direct8SizeMismatch}`,
  );

  add(
    "proxy jitter 0 reproduces low-target PLC risk",
    metric(proxy0, "underruns") > 0 && metric(proxy0, "plc_frames") > 0 ? "pass" : "fail",
    `underruns=${metric(proxy0, "underruns")}, plc=${metric(proxy0, "plc_frames")}`,
  );

  const proxy0Plc = metric(proxy0, "plc_frames");
  const proxy5Plc = metric(proxy5, "plc_frames");
  const proxy0Underruns = metric(proxy0, "underruns");
  const proxy5Underruns = metric(proxy5, "underruns");
  add(
    "proxy jitter 5 improves but is not assumed clean",
    proxy5Plc < proxy0Plc && proxy5Underruns < proxy0Underruns ? "pass" : "fail",
    `jitter0 underruns/plc=${proxy0Underruns}/${proxy0Plc}, jitter5 underruns/plc=${proxy5Underruns}/${proxy5Plc}`,
  );

  add(
    "multi-participant target isolation",
    stable &&
      unstable &&
      stable.target < unstable.target &&
      stable.played === stable.enqueued &&
      unstable.played === unstable.enqueued &&
      unstable.underruns <= stable.underruns
      ? "pass"
      : "fail",
    stable && unstable
      ? `stable target=${stable.target} underruns=${stable.underruns}; unstable target=${unstable.target} underruns=${unstable.underruns}`
      : "missing multi-participant rows",
  );

  add(
    "PCM remains research-only in this run",
    metric(pcm, "decode_failures") === 0 && metric(pcm, "decoded_size_mismatches") === 0
      ? "warn"
      : "fail",
    `underruns=${metric(pcm, "underruns")}, decode_failures=${metric(pcm, "decode_failures")}, size_mismatch=${metric(pcm, "decoded_size_mismatches")}`,
  );

  return checks;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const outDir = path.resolve(
    repoRoot,
    options.outDir || path.join("build", "opus-local-evidence", timestamp()),
  );
  const outPathIssue = ignoredRepoPathIssue(path.join(outDir, "report.md"));
  if (outPathIssue) {
    console.error(outPathIssue);
    process.exit(2);
  }
  fs.mkdirSync(outDir, { recursive: true });

  const server = resolveExe(["build/Debug/server.exe", "build/server", "build/Debug/server"]);
  const latencyProbe = resolveExe([
    "build/Debug/latency_probe.exe",
    "build/latency_probe",
    "build/Debug/latency_probe",
  ]);
  const proxy = resolveExe([
    "build/Debug/udp_impair_proxy.exe",
    "build/udp_impair_proxy",
    "build/Debug/udp_impair_proxy",
  ]);
  const multiProbe = resolveExe([
    "build/Debug/multi_participant_jitter_probe.exe",
    "build/multi_participant_jitter_probe",
    "build/Debug/multi_participant_jitter_probe",
  ]);

  const serverPort = 21000 + Math.floor(Math.random() * 10000);
  const proxyPort = serverPort + 1;
  let serverProc;
  let proxyProc;
  const steps = [];

  try {
    steps.push(
      runStep(outDir, "log-summary-self-test", process.execPath, [
        path.join("tools", "opus-log-summary.mjs"),
        "--self-test",
      ]),
    );
    steps.push(
      runStep(outDir, "external-evidence-checker-self-test", process.execPath, [
        path.join("tools", "opus-external-evidence-check.mjs"),
        "--self-test",
      ]),
    );

    serverProc = startBackground(
      outDir,
      "server",
      server,
      [
        "--port",
        String(serverPort),
        "--allow-insecure-dev-joins",
        "--log-file",
        path.join(outDir, "server-file.log"),
      ],
      /server ready|SFU server ready/i,
    );
    await serverProc.ready;

    steps.push(
      runStep(outDir, "direct-opus-jitter-5", latencyProbe, [
        "--server",
        "127.0.0.1",
        "--port",
        String(serverPort),
        "--codec",
        "opus",
        "--frames",
        "120",
        "--jitter",
        "5",
        "--packets",
        "1200",
      ]),
    );
    steps.push(
      runStep(outDir, "direct-opus-jitter-8", latencyProbe, [
        "--server",
        "127.0.0.1",
        "--port",
        String(serverPort),
        "--codec",
        "opus",
        "--frames",
        "120",
        "--jitter",
        "8",
        "--packets",
        "1200",
      ]),
    );
    steps.push(
      runStep(outDir, "multi-participant-jitter", multiProbe, [
        "--server",
        "127.0.0.1",
        "--port",
        String(serverPort),
        "--stable-target",
        "3",
        "--unstable-target",
        "13",
        "--packets",
        "1200",
      ]),
    );

    proxyProc = startBackground(outDir, "udp-impair-proxy", proxy, [
      "--listen-host",
      "127.0.0.1",
      "--listen-port",
      String(proxyPort),
      "--server",
      "127.0.0.1",
      "--server-port",
      String(serverPort),
      "--jitter-ms",
      "8",
      "--reorder-every",
      "31",
      "--reorder-delay-ms",
      "8",
    ]);
    await proxyProc.ready;

    steps.push(
      runStep(outDir, "proxy-opus-jitter-0", latencyProbe, [
        "--server",
        "127.0.0.1",
        "--port",
        String(proxyPort),
        "--codec",
        "opus",
        "--frames",
        "120",
        "--jitter",
        "0",
        "--packets",
        "1200",
      ]),
    );
    steps.push(
      runStep(outDir, "proxy-opus-jitter-5", latencyProbe, [
        "--server",
        "127.0.0.1",
        "--port",
        String(proxyPort),
        "--codec",
        "opus",
        "--frames",
        "120",
        "--jitter",
        "5",
        "--packets",
        "1200",
      ]),
    );
    steps.push(
      runStep(outDir, "proxy-pcm-jitter-5", latencyProbe, [
        "--server",
        "127.0.0.1",
        "--port",
        String(proxyPort),
        "--codec",
        "pcm",
        "--frames",
        "120",
        "--jitter",
        "5",
        "--packets",
        "1200",
      ]),
    );
  } finally {
    stopBackground(proxyProc);
    stopBackground(serverProc);
  }

  const checks = buildChecks(steps);
  writeReport(outDir, steps, checks, { serverPort, proxyPort });
  console.log(`wrote ${relativeDisplay(outDir, "report.md")}`);

  const failed = steps.filter((step) => step.code !== 0);
  const failedChecks = checks.filter((check) => check.status === "fail");
  if (failed.length > 0 || failedChecks.length > 0) {
    if (failed.length > 0) {
      console.error(`failed steps: ${failed.map((step) => step.name).join(", ")}`);
    }
    if (failedChecks.length > 0) {
      console.error(`failed checks: ${failedChecks.map((check) => check.name).join(", ")}`);
    }
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
