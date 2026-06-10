#!/usr/bin/env node

import dgram from "node:dgram";
import { spawn } from "node:child_process";

const CTRL_MAGIC = 0x4354524c;
const AUDIO_V2_MAGIC = 0x41553249;
const CTRL_JOIN = 1;
const CTRL_JOIN_ACK = 8;
const CTRL_AUDIO_PATH_STATS = 10;
const AUDIO_CODEC_OPUS = 1;
const AUDIO_CAP_REDUNDANCY = 1;
const CTRL_HDR_SIZE = 9;
const JOIN_HDR_SIZE = CTRL_HDR_SIZE + 64 + 64 + 64 + 64 + 512 + 1 + 4;
const AUDIO_V2_HDR_SIZE = 22;
const AUDIO_PATH_STATS_HDR_SIZE = 29;

function usage(message) {
  if (message) {
    console.error(message);
  }
  console.error("Usage: audio-path-feedback-smoke.mjs --server-exe <path>");
  process.exit(message ? 2 : 0);
}

function parseArgs(argv) {
  const args = {};
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
  if (!args["server-exe"]) {
    usage("missing --server-exe");
  }
  return args;
}

function reserveUdpPort() {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket("udp4");
    socket.once("error", reject);
    socket.bind(0, "127.0.0.1", () => {
      const port = socket.address().port;
      socket.close(() => resolve(port));
    });
  });
}

function spawnLogged(name, command, args) {
  const child = spawn(command, args, {
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => process.stdout.write(`[${name}] ${chunk}`));
  child.stderr.on("data", (chunk) => process.stderr.write(`[${name}] ${chunk}`));
  return child;
}

function waitForOutput(child, pattern, timeoutMs, name) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`${name} did not report readiness within ${timeoutMs} ms`));
    }, timeoutMs);

    const onData = (chunk) => {
      if (pattern.test(chunk)) {
        cleanup();
        resolve();
      }
    };
    const onExit = (code, signal) => {
      cleanup();
      reject(new Error(`${name} exited before ready: code=${code} signal=${signal}`));
    };
    const cleanup = () => {
      clearTimeout(timer);
      child.stdout.off("data", onData);
      child.stderr.off("data", onData);
      child.off("exit", onExit);
    };

    child.stdout.on("data", onData);
    child.stderr.on("data", onData);
    child.once("exit", onExit);
  });
}

function stopChild(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) {
    return;
  }
  child.kill();
}

function writeFixed(buffer, offset, size, value) {
  const text = Buffer.from(value, "utf8");
  text.copy(buffer, offset, 0, Math.min(text.length, size - 1));
}

function createJoinPacket() {
  const packet = Buffer.alloc(JOIN_HDR_SIZE);
  packet.writeUInt32LE(CTRL_MAGIC, 0);
  packet.writeUInt8(CTRL_JOIN, 4);
  packet.writeUInt32LE(0, 5);
  let offset = CTRL_HDR_SIZE;
  writeFixed(packet, offset, 64, "audio-path-feedback-smoke");
  offset += 64;
  writeFixed(packet, offset, 64, "audio-path-feedback-smoke");
  offset += 64;
  writeFixed(packet, offset, 64, "smoke-sender");
  offset += 64;
  writeFixed(packet, offset, 64, "smoke-sender");
  offset += 64;
  offset += 512;
  packet.writeUInt8(1, offset);
  offset += 1;
  packet.writeUInt32LE(AUDIO_CAP_REDUNDANCY, offset);
  return packet;
}

function createAudioPacket(sequence) {
  const packet = Buffer.alloc(AUDIO_V2_HDR_SIZE + 1);
  packet.writeUInt32LE(AUDIO_V2_MAGIC, 0);
  packet.writeUInt32LE(0, 4);
  packet.writeUInt32LE(sequence, 8);
  packet.writeUInt32LE(48000, 12);
  packet.writeUInt16LE(480, 16);
  packet.writeUInt16LE(1, 18);
  packet.writeUInt8(1, 20);
  packet.writeUInt8(AUDIO_CODEC_OPUS, 21);
  packet.writeUInt8(0x7f, AUDIO_V2_HDR_SIZE);
  return packet;
}

function send(socket, packet, port) {
  return new Promise((resolve, reject) => {
    socket.send(packet, port, "127.0.0.1", (error) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
}

function waitForJoinAck(socket, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error("JOIN_ACK not received"));
    }, timeoutMs);
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
      socket.off("message", onMessage);
    };
    socket.on("message", onMessage);
  });
}

function waitForAudioPathStats(socket, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error("AUDIO_PATH_STATS not received"));
    }, timeoutMs);
    const onMessage = (message) => {
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
      if (stats.intervalReceived >= 2 &&
          stats.intervalSequenceGaps >= 50 &&
          stats.observedFrameCount === 480) {
        cleanup();
        resolve(stats);
      }
    };
    const cleanup = () => {
      clearTimeout(timer);
      socket.off("message", onMessage);
    };
    socket.on("message", onMessage);
  });
}

const args = parseArgs(process.argv);
const serverPort = await reserveUdpPort();
let server;
const socket = dgram.createSocket("udp4");

try {
  server = spawnLogged("server", args["server-exe"], [
    "--port",
    String(serverPort),
    "--allow-insecure-dev-joins",
  ]);
  await waitForOutput(server, /SFU server ready/, 5000, "server");

  await new Promise((resolve) => socket.bind(0, "127.0.0.1", resolve));
  await send(socket, createJoinPacket(), serverPort);
  const participantId = await waitForJoinAck(socket, 5000);
  console.log(`[smoke] joined participant ${participantId}`);

  await send(socket, createAudioPacket(1), serverPort);
  await send(socket, createAudioPacket(100), serverPort);
  const stats = await waitForAudioPathStats(socket, 8000);
  console.log(
    `[smoke] feedback received=${stats.intervalReceived} gaps=${stats.intervalSequenceGaps} frame=${stats.observedFrameCount}`,
  );
} finally {
  socket.close();
  stopChild(server);
}
