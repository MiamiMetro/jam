#!/usr/bin/env node

import path from "node:path";
import {
  assertBudget,
  delay,
  ensureDir,
  parseArgs,
  parseLatencyProbeOutput,
  requireArgs,
  reserveUdpPort,
  runLogged,
  spawnLogged,
  stopChild,
  waitForOutput,
  writeJson,
} from "./phase5-track-d-common.mjs";

const PROFILES = {
  low: {
    frames: 120,
    jitter: 4,
    maxQueueDriftPackets: 3.0,
    maxQueueDepthPackets: 16,
    e2eMarginMs: 14,
  },
  balanced: {
    frames: 480,
    jitter: 2,
    maxQueueDriftPackets: 3.0,
    maxQueueDepthPackets: 12,
    e2eMarginMs: 25,
  },
  stable: {
    frames: 960,
    jitter: 4,
    maxQueueDriftPackets: 4.0,
    maxQueueDepthPackets: 14,
    e2eMarginMs: 45,
  },
};

const CASES = {
  clean: { proxy: {}, requireClean: true, maxGapPlcRun: 0 },
  loss1: {
    proxy: { "loss-percent": "1", "drop-direction": "server-to-client" },
    maxGapPlcRun: 2,
  },
  reorder: {
    proxy: {
      "reorder-every": "17",
      "reorder-delay-ms": "12",
      "drop-direction": "server-to-client",
    },
    requireClean: true,
    maxGapPlcRun: 2,
  },
  burst: {
    proxy: {
      "burst-every": "120",
      "burst-count": "4",
      "burst-offset": "35",
      "drop-direction": "server-to-client",
    },
    maxGapPlcRun: 2,
  },
};

function usage() {
  console.error(
    [
      "Usage: node tools/phase5-track-d-impairment-matrix.mjs",
      "  --server-exe <path> --proxy-exe <path> --probe-exe <path>",
      "  [--out-dir <path>] [--quick] [--profile low|balanced|stable] [--case clean|loss1|reorder|burst]",
    ].join("\n"),
  );
}

function proxyArgs(config) {
  const result = [];
  for (const [key, value] of Object.entries(config)) {
    result.push(`--${key}`, String(value));
  }
  return result;
}

function rowList(args) {
  if (args.quick) {
    return [
      { profileName: "low", caseName: "clean" },
      { profileName: "low", caseName: "reorder" },
      { profileName: "balanced", caseName: "burst" },
    ];
  }
  const profileNames = args.profile ? [args.profile] : Object.keys(PROFILES);
  const caseNames = args.case ? [args.case] : Object.keys(CASES);
  for (const profileName of profileNames) {
    if (!PROFILES[profileName]) {
      throw new Error(`unknown --profile ${profileName}`);
    }
  }
  for (const caseName of caseNames) {
    if (!CASES[caseName]) {
      throw new Error(`unknown --case ${caseName}`);
    }
  }
  return profileNames.flatMap((profileName) =>
    caseNames.map((caseName) => ({ profileName, caseName })),
  );
}

async function runRow(args, outDir, row, index) {
  const profile = PROFILES[row.profileName];
  const testCase = CASES[row.caseName];
  const packetMs = (profile.frames * 1000) / 48000;
  const e2eBudgetMs =
    profile.jitter * packetMs + packetMs + packetMs + profile.e2eMarginMs;
  const rowDir = path.join(
    outDir,
    `${String(index + 1).padStart(2, "0")}-${row.profileName}-${row.caseName}`,
  );
  ensureDir(rowDir);

  const serverPort = await reserveUdpPort();
  let proxyPort = await reserveUdpPort();
  while (proxyPort === serverPort) {
    proxyPort = await reserveUdpPort();
  }

  let server;
  let proxy;
  const failures = [];
  let metrics = {};
  let exitCode = 1;

  try {
    server = spawnLogged(
      "server",
      args["server-exe"],
      ["--port", String(serverPort), "--allow-insecure-dev-joins"],
      path.join(rowDir, "server.log"),
    );
    await waitForOutput(server, /SFU server ready/, 5000, "server");

    proxy = spawnLogged(
      "proxy",
      args["proxy-exe"],
      [
        "--listen-host",
        "127.0.0.1",
        "--listen-port",
        String(proxyPort),
        "--server",
        "127.0.0.1",
        "--server-port",
        String(serverPort),
        ...proxyArgs(testCase.proxy),
      ],
      path.join(rowDir, "proxy.log"),
    );
    await delay(500);
    if (proxy.exitCode !== null || proxy.signalCode !== null) {
      throw new Error(
        `proxy exited before probe: code=${proxy.exitCode} signal=${proxy.signalCode}`,
      );
    }

    const probeArgs = [
      "--server",
      "127.0.0.1",
      "--port",
      String(proxyPort),
      "--codec",
      "opus",
      "--frames",
      String(profile.frames),
      "--jitter",
      String(profile.jitter),
      "--packets",
      args.quick ? "320" : "900",
      "--max-e2e-latency-ms",
      String(e2eBudgetMs),
      "--e2e-margin-ms",
      String(profile.e2eMarginMs),
      "--max-gap-plc-run",
      String(testCase.maxGapPlcRun),
    ];
    if (testCase.requireClean) {
      probeArgs.push("--require-clean");
    }

    const probe = await runLogged(
      "latency_probe",
      args["probe-exe"],
      probeArgs,
      path.join(rowDir, "latency-probe.log"),
    );
    exitCode = probe.code;
    metrics = parseLatencyProbeOutput(probe.output);
  } catch (error) {
    failures.push(error.message);
  } finally {
    await stopChild(proxy);
    await stopChild(server);
  }

  assertBudget(exitCode === 0, `latency_probe exited ${exitCode}`, failures);
  assertBudget(
    Number.isFinite(metrics.e2e_latency_steady_max_ms),
    "missing steady E2E latency metric",
    failures,
  );
  assertBudget(
    metrics.e2e_latency_steady_max_ms <= e2eBudgetMs,
    `steady E2E ${metrics.e2e_latency_steady_max_ms} ms exceeds ${e2eBudgetMs} ms`,
    failures,
  );
  assertBudget(
    Math.abs(metrics.queue_drift_from_jitter ?? 0) <= profile.maxQueueDriftPackets,
    `queue drift ${metrics.queue_drift_from_jitter} exceeds ${profile.maxQueueDriftPackets} packets`,
    failures,
  );
  assertBudget(
    (metrics.max_queue_depth ?? 0) <= profile.maxQueueDepthPackets,
    `max queue depth ${metrics.max_queue_depth} exceeds ${profile.maxQueueDepthPackets}`,
    failures,
  );
  assertBudget(
    (metrics.max_gap_plc_run ?? 0) <= testCase.maxGapPlcRun,
    `max gap PLC run ${metrics.max_gap_plc_run} exceeds ${testCase.maxGapPlcRun}`,
    failures,
  );

  return {
    ...row,
    e2eBudgetMs,
    metrics,
    exitCode,
    status: failures.length === 0 ? "ok" : "fail",
    failures,
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2), { booleanFlags: ["quick"] });
  if (args.help) {
    usage();
    return;
  }
  requireArgs(args, ["server-exe", "proxy-exe", "probe-exe"]);

  const outDir = path.resolve(args["out-dir"] ?? "validation_logs/phase5-track-d/impairment");
  ensureDir(outDir);
  const rows = rowList(args);
  const results = [];
  for (let i = 0; i < rows.length; i += 1) {
    const row = rows[i];
    console.log(`matrix row ${i + 1}/${rows.length}: ${row.profileName}/${row.caseName}`);
    results.push(await runRow(args, outDir, row, i));
  }

  const summary = {
    createdAt: new Date().toISOString(),
    quick: Boolean(args.quick),
    rows: results,
    status: results.every((row) => row.status === "ok") ? "ok" : "fail",
  };
  writeJson(path.join(outDir, "summary.json"), summary);
  if (summary.status !== "ok") {
    for (const row of results.filter((item) => item.status !== "ok")) {
      console.error(`${row.profileName}/${row.caseName}: ${row.failures.join("; ")}`);
    }
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exit(2);
});
