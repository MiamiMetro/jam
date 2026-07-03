#!/usr/bin/env node

import path from "node:path";
import {
  ensureDir,
  parseArgs,
  requireArgs,
  reserveUdpPort,
  runLogged,
  spawnLogged,
  stopChild,
  waitForOutput,
  writeJson,
} from "./phase5-track-d-common.mjs";

function usage() {
  console.error(
    [
      "Usage: node tools/phase5-track-d-load-benchmark.mjs",
      "  --server-exe <path> --probe-exe <path> [--out-dir <path>]",
      "  [--clients N] [--senders N] [--seconds N] [--frames N]",
      "  [--min-delivery-ratio R] [--max-recv-gap-ms MS]",
    ].join("\n"),
  );
}

function parseProbeOutput(text) {
  const metrics = {};
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^([a-zA-Z0-9_]+):\s+(.+)$/);
    if (!match) {
      continue;
    }
    const value = Number(match[2]);
    metrics[match[1]] = Number.isFinite(value) ? value : match[2];
  }
  return metrics;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    usage();
    return;
  }
  requireArgs(args, ["server-exe", "probe-exe"]);

  const outDir = path.resolve(args["out-dir"] ?? "validation_logs/phase5-track-d/load");
  ensureDir(outDir);
  const serverPort = await reserveUdpPort();
  let server;
  let probeResult = { code: 1, output: "" };

  try {
    server = spawnLogged(
      "server",
      args["server-exe"],
      ["--port", String(serverPort), "--allow-insecure-dev-joins"],
      path.join(outDir, "server.log"),
    );
    await waitForOutput(server, /SFU server ready/, 5000, "server");

    const probeArgs = [
      "--server",
      "127.0.0.1",
      "--port",
      String(serverPort),
      "--clients",
      args.clients ?? "16",
      "--senders",
      args.senders ?? "8",
      "--seconds",
      args.seconds ?? "30",
      "--frames",
      args.frames ?? "120",
      "--min-delivery-ratio",
      args["min-delivery-ratio"] ?? "0.98",
      "--max-recv-gap-ms",
      args["max-recv-gap-ms"] ?? "250",
    ];
    probeResult = await runLogged(
      "relay_load_probe",
      args["probe-exe"],
      probeArgs,
      path.join(outDir, "probe.log"),
    );
  } finally {
    await stopChild(server);
  }

  const metrics = parseProbeOutput(probeResult.output);
  const summary = {
    createdAt: new Date().toISOString(),
    exitCode: probeResult.code,
    metrics,
    status: probeResult.code === 0 ? "ok" : "fail",
  };
  writeJson(path.join(outDir, "summary.json"), summary);
  if (probeResult.code !== 0) {
    process.exit(probeResult.code);
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exit(2);
});
