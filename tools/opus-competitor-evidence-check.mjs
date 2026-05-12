#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const checks = [
  {
    name: "SonoBus per-user manual/automatic jitter",
    file: ".cache/upstream-audio/sonobus/doc/SonoBus User Guide.md",
    patterns: [
      /per-user basis[\s\S]{0,120}manual or automatic "jitter buffer"/i,
      /optimum buffer size for each one/i,
      /adds each participant with their jitter buffer in .Auto. mode/i,
    ],
  },
  {
    name: "SonoBus Wi-Fi and Opus/PCM latency tradeoffs",
    file: ".cache/upstream-audio/sonobus/doc/SonoBus User Guide.md",
    patterns: [
      /WiFi works[\s\S]{0,160}adds a lot of jitter/i,
      /compressed formats[\s\S]{0,120}additional latency/i,
      /minimum sample frame size of 120 samples/i,
      /PCM formats do not have a lower limit/i,
    ],
  },
  {
    name: "AOO automatic buffer and timing model",
    file: ".cache/upstream-audio/sonobus/deps/aoo/doku/aoo_protocol.rst",
    patterns: [
      /automatic buffer control mode/i,
      /shortest possible size for buffering/i,
      /dynamically extended[\s\S]{0,80}slowly reduced/i,
      /resampling/i,
    ],
  },
  {
    name: "Jamulus configurable client/server jitter",
    file: ".cache/upstream-audio/jamulus/src/clientsettingsdlg.cpp",
    patterns: [
      /set the jitter buffer size manually[\s\S]{0,160}local client/i,
      /remote server/i,
      /Auto setting[\s\S]{0,220}network and sound card timing jitter/i,
      /trade-off between audio quality and overall delay/i,
    ],
  },
  {
    name: "Jamulus protocol jitter messages",
    file: ".cache/upstream-audio/jamulus/docs/JAMULUS_PROTOCOL.md",
    patterns: [/REQ_JITT_BUF_SIZE/, /JITT_BUF_SIZE/, /jitter buffer[\s\S]{0,80}configurable/i],
  },
  {
    name: "Jamulus simulation buffers and auto setting",
    file: ".cache/upstream-audio/jamulus/src/buffer.cpp",
    patterns: [/simulation buffers/i, /UpdateAutoSetting/, /Use a specified error bound/i],
  },
  {
    name: "Jamulus net buffer statistics type",
    file: ".cache/upstream-audio/jamulus/src/buffer.h",
    patterns: [/CNetBufWithStats/, /SimulationBuffer/, /jitter buffer error bound/i],
  },
  {
    name: "JackTrip receive queue and auto queue",
    file: ".cache/upstream-audio/jacktrip/src/JitterBuffer.cpp",
    patterns: [/JitterBuffer::JitterBuffer/, /auto queue correction/i, /queueLengthChanged/, /processPacketLoss/],
  },
  {
    name: "JackTrip regulator auto headroom",
    file: ".cache/upstream-audio/jacktrip/src/Regulator.cpp",
    patterns: [/PLC is in auto mode/i, /updateTolerance/, /increase headroom/i, /auto tolerance/i],
  },
  {
    name: "JackTrip UDP redundancy",
    file: ".cache/upstream-audio/jacktrip/docs/Documentation/NetworkProtocol.md",
    patterns: [/UDP redundancy/i, /reduce audible artifacts from packet loss/i, /redundancy factor/i],
  },
  {
    name: "JackTrip strategy selection",
    file: ".cache/upstream-audio/jacktrip/src/JackTrip.cpp",
    patterns: [/Auto queue is not supported by RingBuffer/i, /Using Regulator buffer strategy/i, /Using JitterBuffer strategy/i],
  },
];

function rel(file) {
  return path.relative(repoRoot, file).split(path.sep).join("/");
}

const failures = [];

for (const check of checks) {
  const fullPath = path.resolve(repoRoot, check.file);
  if (!fs.existsSync(fullPath)) {
    failures.push(`${check.name}: missing ${check.file}`);
    continue;
  }

  const text = fs.readFileSync(fullPath, "utf8");
  const missing = check.patterns
    .map((pattern) => pattern.toString())
    .filter((_, index) => !check.patterns[index].test(text));
  if (missing.length > 0) {
    failures.push(`${check.name}: ${rel(fullPath)} missing ${missing.join(", ")}`);
    continue;
  }

  console.log(`PASS: ${check.name} (${check.file})`);
}

if (failures.length > 0) {
  console.error("failed competitor evidence checks:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`PASS: verified ${checks.length} competitor evidence checks`);
