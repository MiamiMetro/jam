#!/usr/bin/env node

import crypto from "node:crypto";
import dgram from "node:dgram";

const CTRL_MAGIC = 0x4354524c;
const AUDIO_V2_MAGIC = 0x41553249;
const CTRL_JOIN = 1;
const CTRL_ALIVE = 3;
const CTRL_LEAVE = 2;
const CTRL_JOIN_ACK = 8;
const CTRL_AUDIO_PATH_STATS = 10;
const AUDIO_CODEC_OPUS = 1;
const AUDIO_CAP_REDUNDANCY = 1;
const CTRL_HDR_SIZE = 9;
const JOIN_HDR_SIZE = CTRL_HDR_SIZE + 64 + 64 + 64 + 64 + 512 + 1 + 4;
const AUDIO_V2_HDR_SIZE = 22;
const AUDIO_PATH_STATS_HDR_SIZE = 29;
const SAMPLE_RATE = 48000;
const NS_PER_SECOND = 1000000000n;
const NS_PER_MS = 1000000n;
const MIN_FEEDBACK_PACKETS = 20;
const UNSTABLE_GAP_RATE = 0.05;
const SEVERE_GAP_RATE = 0.25;

function usage(message) {
  if (message) {
    console.error(message);
  }
  console.error(
    "Usage: audio-path-adapt-probe.mjs --server <host> --port <port> --server-id <id> --join-secret <secret> [--seconds 90] [--frames 480] [--force-gap-after-seconds 5] [--force-gap-size 300] [--expect-adaptation 0|1]",
  );
  process.exit(message ? 2 : 0);
}

function parseArgs(argv) {
  const args = {
    seconds: "90",
    frames: "480",
    "force-gap-size": "300",
    "expect-adaptation": "0",
    room: "audio-path-adapt-probe",
    user: "audio-path-adapt-probe",
  };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      usage();
    }
    if (!arg.startsWith("--") || i + 1 >= argv.length) {
      usage(`unknown or incomplete argument: ${arg}`);
    }
    args[arg.slice(2)] = argv[++i];
  }
  for (const required of ["server", "port", "server-id", "join-secret"]) {
    if (!args[required]) {
      usage(`missing --${required}`);
    }
  }
  return args;
}

function nowMs() {
  return Date.now();
}

function parsePositiveInteger(name, value) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    usage(`--${name} must be a positive integer`);
  }
  return parsed;
}

function parseNonNegativeNumber(name, value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) {
    usage(`--${name} must be a non-negative number`);
  }
  return parsed;
}

function secondsToNs(seconds) {
  return BigInt(Math.round(seconds * Number(NS_PER_SECOND)));
}

function frameDurationNs(frameCount) {
  return BigInt(Math.round((frameCount * Number(NS_PER_SECOND)) / SAMPLE_RATE));
}

function sleepMs(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function yieldEventLoop() {
  return new Promise((resolve) => setImmediate(resolve));
}

async function sleepUntil(deadlineNs) {
  for (;;) {
    const nowNs = process.hrtime.bigint();
    if (nowNs >= deadlineNs) {
      return;
    }
    const remainingNs = deadlineNs - nowNs;
    const remainingMs = Number(remainingNs / NS_PER_MS);
    if (remainingMs > 1) {
      await sleepMs(remainingMs - 1);
    } else {
      await yieldEventLoop();
    }
  }
}

function randomNonce() {
  return crypto.randomBytes(16).toString("hex");
}

function createJoinToken(args) {
  const expiresAtMs = nowMs() + 120000;
  const nonce = randomNonce();
  const message = [
    "v1",
    String(expiresAtMs),
    args["server-id"],
    args.room,
    args.user,
    "performer",
    nonce,
  ].join("|");
  const signature = crypto
    .createHmac("sha256", args["join-secret"])
    .update(message)
    .digest("hex");
  return [
    "v1",
    String(expiresAtMs),
    args["server-id"],
    args.room,
    args.user,
    "performer",
    nonce,
    signature,
  ].join(".");
}

function writeFixed(buffer, offset, size, value) {
  const text = Buffer.from(value, "utf8");
  text.copy(buffer, offset, 0, Math.min(text.length, size - 1));
}

function createJoinPacket(args) {
  const packet = Buffer.alloc(JOIN_HDR_SIZE);
  packet.writeUInt32LE(CTRL_MAGIC, 0);
  packet.writeUInt8(CTRL_JOIN, 4);
  packet.writeUInt32LE(0, 5);
  let offset = CTRL_HDR_SIZE;
  writeFixed(packet, offset, 64, args.room);
  offset += 64;
  writeFixed(packet, offset, 64, args.room);
  offset += 64;
  writeFixed(packet, offset, 64, args.user);
  offset += 64;
  writeFixed(packet, offset, 64, args.user);
  offset += 64;
  writeFixed(packet, offset, 512, createJoinToken(args));
  offset += 512;
  packet.writeUInt8(1, offset);
  offset += 1;
  packet.writeUInt32LE(AUDIO_CAP_REDUNDANCY, offset);
  return packet;
}

function createCtrlPacket(type) {
  const packet = Buffer.alloc(CTRL_HDR_SIZE);
  packet.writeUInt32LE(CTRL_MAGIC, 0);
  packet.writeUInt8(type, 4);
  packet.writeUInt32LE(0, 5);
  return packet;
}

function createAudioPacket(sequence, frameCount) {
  const packet = Buffer.alloc(AUDIO_V2_HDR_SIZE + 1);
  packet.writeUInt32LE(AUDIO_V2_MAGIC, 0);
  packet.writeUInt32LE(0, 4);
  packet.writeUInt32LE(sequence >>> 0, 8);
  packet.writeUInt32LE(SAMPLE_RATE, 12);
  packet.writeUInt16LE(frameCount, 16);
  packet.writeUInt16LE(1, 18);
  packet.writeUInt8(1, 20);
  packet.writeUInt8(AUDIO_CODEC_OPUS, 21);
  packet.writeUInt8(0x7f, AUDIO_V2_HDR_SIZE);
  return packet;
}

function gapRate(received, gaps) {
  const denominator = received + gaps;
  return denominator > 0 ? gaps / denominator : 0;
}

function adaptedFrames(currentFrames, received, gaps) {
  const observed = received + gaps;
  if (observed < MIN_FEEDBACK_PACKETS || gaps === 0) {
    return currentFrames;
  }
  const rate = gapRate(received, gaps);
  if (rate >= SEVERE_GAP_RATE && currentFrames < 960) {
    return 960;
  }
  if (rate >= UNSTABLE_GAP_RATE && currentFrames < 480) {
    return 480;
  }
  return currentFrames;
}

function send(socket, packet, args) {
  return new Promise((resolve, reject) => {
    socket.send(packet, Number(args.port), args.server, (error) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
}

function waitForJoinAck(socket, args) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error("JOIN_ACK not received"));
    }, 5000);
    const retry = setInterval(() => {
      send(socket, createJoinPacket(args), args).catch(reject);
    }, 250);
    const onMessage = (message) => {
      if (message.length >= CTRL_HDR_SIZE &&
          message.readUInt32LE(0) === CTRL_MAGIC &&
          message.readUInt8(4) === CTRL_JOIN_ACK) {
        cleanup();
        resolve(message.readUInt32LE(5));
      }
    };
    const cleanup = () => {
      clearTimeout(timer);
      clearInterval(retry);
      socket.off("message", onMessage);
    };
    socket.on("message", onMessage);
    send(socket, createJoinPacket(args), args).catch(reject);
  });
}

const args = parseArgs(process.argv);
const socket = dgram.createSocket("udp4");
let currentFrames = parsePositiveInteger("frames", args.frames);
const durationSeconds = parseNonNegativeNumber("seconds", args.seconds);
const forceGapAfterSeconds = args["force-gap-after-seconds"] === undefined
  ? 0
  : parseNonNegativeNumber(
      "force-gap-after-seconds",
      args["force-gap-after-seconds"],
    );
const forceGapSize = parsePositiveInteger("force-gap-size", args["force-gap-size"]);
const expectAdaptation = args["expect-adaptation"] === "1";
let sequence = 0;
let sent = 0;
let feedbackCount = 0;
let adaptationCount = 0;
let lastFeedback = null;
let forcedGapApplied = false;
let sendDeadlineMissCount = 0;
let maxSendLateNs = 0n;

socket.on("message", (message) => {
  if (message.length < AUDIO_PATH_STATS_HDR_SIZE ||
      message.readUInt32LE(0) !== CTRL_MAGIC ||
      message.readUInt8(4) !== CTRL_AUDIO_PATH_STATS) {
    return;
  }
  const stats = {
    participantId: message.readUInt32LE(5),
    intervalReceived: message.readUInt32LE(9),
    intervalSequenceGaps: message.readUInt32LE(13),
    totalReceived: message.readUInt32LE(17),
    totalSequenceGaps: message.readUInt32LE(21),
    observedFrameCount: message.readUInt16LE(25),
  };
  feedbackCount += 1;
  lastFeedback = stats;
  const nextFrames = adaptedFrames(
    currentFrames,
    stats.intervalReceived,
    stats.intervalSequenceGaps,
  );
  const ratePercent =
    gapRate(stats.intervalReceived, stats.intervalSequenceGaps) * 100;
  console.log(
    `[feedback] recv=${stats.intervalReceived} gaps=${stats.intervalSequenceGaps} gap_rate=${ratePercent.toFixed(1)}% observed=${stats.observedFrameCount} total_recv=${stats.totalReceived} total_gaps=${stats.totalSequenceGaps} frames=${currentFrames}`,
  );
  if (nextFrames > currentFrames) {
    console.log(`[adapt] frames ${currentFrames} -> ${nextFrames}`);
    currentFrames = nextFrames;
    adaptationCount += 1;
  }
});

await new Promise((resolve) => socket.bind(0, "0.0.0.0", resolve));
try {
  const participantId = await waitForJoinAck(socket, args);
  console.log(`[join] participant=${participantId} local_port=${socket.address().port}`);

  const startedNs = process.hrtime.bigint();
  const stopNs = startedNs + secondsToNs(durationSeconds);
  const forceGapAtNs =
    forceGapAfterSeconds > 0 ? startedNs + secondsToNs(forceGapAfterSeconds) : 0n;
  let nextAliveNs = startedNs;
  let nextSendNs = startedNs;
  while (process.hrtime.bigint() < stopNs) {
    const nowNs = process.hrtime.bigint();
    if (nowNs >= nextAliveNs) {
      await send(socket, createCtrlPacket(CTRL_ALIVE), args);
      nextAliveNs += NS_PER_SECOND;
    }
    if (forceGapAtNs > 0n && !forcedGapApplied && nowNs >= forceGapAtNs) {
      sequence = (sequence + forceGapSize) >>> 0;
      forcedGapApplied = true;
      console.log(`[force-gap] skipped ${forceGapSize} sequence numbers`);
    }
    const lateNs = nowNs - nextSendNs;
    if (lateNs > NS_PER_MS) {
      sendDeadlineMissCount += 1;
      if (lateNs > maxSendLateNs) {
        maxSendLateNs = lateNs;
      }
    }
    await send(socket, createAudioPacket(sequence, currentFrames), args);
    sequence = (sequence + 1) >>> 0;
    sent += 1;
    nextSendNs += frameDurationNs(currentFrames);
    await sleepUntil(nextSendNs);
  }
  await send(socket, createCtrlPacket(CTRL_LEAVE), args);
  const elapsedSeconds =
    Number(process.hrtime.bigint() - startedNs) / Number(NS_PER_SECOND);

  console.log(`audio_path_adapt_probe v1`);
  console.log(`server: ${args.server}:${args.port}`);
  console.log(`seconds: ${elapsedSeconds.toFixed(3)}`);
  console.log(`sent_packets: ${sent}`);
  console.log(`effective_packets_per_second: ${(sent / elapsedSeconds).toFixed(1)}`);
  console.log(`feedback_count: ${feedbackCount}`);
  console.log(`adaptation_count: ${adaptationCount}`);
  console.log(`final_frames: ${currentFrames}`);
  console.log(`forced_gap_applied: ${forcedGapApplied ? 1 : 0}`);
  console.log(`send_deadline_miss_count: ${sendDeadlineMissCount}`);
  console.log(
    `max_send_late_ms: ${(Number(maxSendLateNs) / Number(NS_PER_MS)).toFixed(3)}`,
  );
  if (lastFeedback) {
    console.log(`last_interval_received: ${lastFeedback.intervalReceived}`);
    console.log(`last_interval_sequence_gaps: ${lastFeedback.intervalSequenceGaps}`);
    console.log(`last_total_received: ${lastFeedback.totalReceived}`);
    console.log(`last_total_sequence_gaps: ${lastFeedback.totalSequenceGaps}`);
  }
  if (feedbackCount === 0) {
    console.error("no AUDIO_PATH_STATS feedback received");
    process.exitCode = 1;
  }
  if (expectAdaptation && adaptationCount === 0) {
    console.error("expected adaptation, but packet frame count did not change");
    process.exitCode = 1;
  }
} finally {
  socket.close();
}
