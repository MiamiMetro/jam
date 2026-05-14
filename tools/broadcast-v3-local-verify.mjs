#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import dgram from "node:dgram";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const isWindows = process.platform === "win32";
const exe = (name) =>
  isWindows
    ? path.join(repoRoot, "build", "Release", `${name}.exe`)
    : path.join(repoRoot, "build", name);

const broadcasterExe = exe("jam_broadcaster");
const publishPassphrase = "jam-v3-publish-passphrase";
const mode = process.argv.includes("--ipc")
  ? "ipc"
  : process.argv.includes("--multi-room")
    ? "multi-room"
    : process.argv.includes("--bad-key")
      ? "bad-key"
      : "test-tone";
const defaultRoom = `broadcast-v3-${mode}-${Date.now()}`;
const httpPort = Number(process.env.BROADCAST_HTTP_PORT ?? 8080);
const srtPort = Number(process.env.BROADCAST_SRT_PORT ?? 8890);
const ipcPort = 39000 + Math.floor(Math.random() * 2000);
const outDir = path.join(repoRoot, "build", "broadcast-v3-local-verify");

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    stdio: "pipe",
    encoding: "utf8",
    windowsHide: true,
    ...options,
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed\n${result.stdout}\n${result.stderr}`);
  }
  return result;
}

function request(url, cookies = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const cookieHeader = Object.entries(cookies)
      .map(([name, value]) => `${name}=${value}`)
      .join("; ");
    const req = http.request(
      {
        hostname: parsed.hostname,
        port: parsed.port,
        path: `${parsed.pathname}${parsed.search}`,
        method: "GET",
        headers: cookieHeader ? { Cookie: cookieHeader } : {},
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          const setCookie = res.headers["set-cookie"] ?? [];
          for (const cookie of setCookie) {
            const [pair] = cookie.split(";");
            const [name, value] = pair.split("=");
            if (name && value) cookies[name] = value;
          }
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks),
            cookies,
          });
        });
      },
    );
    req.on("error", reject);
    req.end();
  });
}

async function get(url, cookies = {}, redirects = 5) {
  let current = url;
  for (let i = 0; i <= redirects; i += 1) {
    const response = await request(current, cookies);
    if (![301, 302, 303, 307, 308].includes(response.status)) return response;
    const location = response.headers.location;
    assert(location, `redirect without Location from ${current}`);
    current = new URL(location, current).toString();
  }
  throw new Error(`too many redirects for ${url}`);
}

async function waitForPlaylist(room) {
  const cookies = {};
  const base = `http://127.0.0.1:${httpPort}/hls/${room}`;
  const deadline = Date.now() + 25000;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const master = await get(`${base}/stream.m3u8`, cookies);
      if (master.status !== 200) {
        lastError = new Error(`master returned ${master.status}`);
        await sleep(500);
        continue;
      }
      const masterText = master.body.toString("utf8");
      const mediaName = masterText
        .split(/\r?\n/)
        .find((line) => line.trim().endsWith(".m3u8") && !line.startsWith("#"));
      if (!mediaName) {
        lastError = new Error(`master playlist missing media playlist: ${masterText}`);
        await sleep(500);
        continue;
      }

      const media = await get(`${base}/${mediaName.trim()}`, cookies);
      if (media.status !== 200) {
        lastError = new Error(`media playlist returned ${media.status}`);
        await sleep(500);
        continue;
      }
      const mediaText = media.body.toString("utf8");
      const init = /URI="([^"]+\.mp4)"/.exec(mediaText)?.[1];
      const segment = mediaText
        .split(/\r?\n/)
        .find((line) => line.trim().endsWith(".mp4") && !line.startsWith("#") && line !== init);
      if (!init || !segment) {
        lastError = new Error(`media playlist missing init/segment: ${mediaText}`);
        await sleep(500);
        continue;
      }

      const initResponse = await get(`${base}/${init}`, cookies);
      assert(initResponse.status === 200 && initResponse.body.length > 0, "init segment missing");
      const segmentResponse = await get(`${base}/${segment.trim()}`, cookies);
      assert(
        segmentResponse.status === 200 && segmentResponse.body.length > 0,
        "media segment missing",
      );
      return { masterText, mediaText, init, segment: segment.trim() };
    } catch (error) {
      lastError = error;
      await sleep(500);
    }
  }
  throw lastError ?? new Error("HLS playlist did not become ready");
}

async function waitForHealth() {
  const deadline = Date.now() + 15000;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const health = await get(`http://127.0.0.1:${httpPort}/health`);
      if (health.status === 200) return;
      lastError = new Error(`nginx health returned ${health.status}`);
    } catch (error) {
      lastError = error;
    }
    await sleep(500);
  }
  throw lastError ?? new Error("nginx health did not become ready");
}

function srtUrl(room, passphrase = publishPassphrase) {
  return `srt://127.0.0.1:${srtPort}?streamid=publish:${room}&passphrase=${passphrase}&pkt_size=1316`;
}

function startBroadcaster(room, options = {}) {
  const log = fs.openSync(path.join(outDir, `${mode}-${room}.log`), "w");
  const args =
    mode === "ipc"
      ? ["--ipc-port", String(ipcPort), "--srt-url", srtUrl(room), "--duration-ms", "22000"]
      : [
          "--test-tone",
          "--srt-url",
          srtUrl(room, options.passphrase),
          "--duration-ms",
          String(options.durationMs ?? 22000),
        ];
  const child = spawn(broadcasterExe, args, {
    cwd: repoRoot,
    stdio: ["ignore", log, log],
    windowsHide: true,
  });
  child.on("exit", () => fs.closeSync(log));
  return child;
}

async function sendSyntheticIpc() {
  const socket = dgram.createSocket("udp4");
  const sampleRate = 48000;
  const frameCount = 960;
  let sequence = 0;
  let phase = 0;
  const phaseStep = (2 * Math.PI * 440) / sampleRate;
  const deadline = Date.now() + 12000;

  while (Date.now() < deadline) {
    const header = Buffer.alloc(24);
    header.writeUInt32LE(0x4a424950, 0);
    header.writeUInt16LE(1, 4);
    header.writeUInt16LE(24, 6);
    header.writeUInt32LE(sequence++, 8);
    header.writeUInt32LE(sampleRate, 12);
    header.writeUInt16LE(1, 16);
    header.writeUInt16LE(frameCount, 18);
    header.writeUInt16LE(1, 20);
    header.writeUInt16LE(frameCount * 4, 22);

    const payload = Buffer.alloc(frameCount * 4);
    for (let i = 0; i < frameCount; i += 1) {
      payload.writeFloatLE(Math.sin(phase) * 0.15, i * 4);
      phase += phaseStep;
      if (phase > 2 * Math.PI) phase -= 2 * Math.PI;
    }

    await new Promise((resolve, reject) => {
      socket.send(Buffer.concat([header, payload]), ipcPort, "127.0.0.1", (error) =>
        error ? reject(error) : resolve(),
      );
    });
    await sleep(20);
  }
  socket.close();
}

if (!fs.existsSync(broadcasterExe)) {
  throw new Error(`missing executable: ${broadcasterExe}`);
}

fs.mkdirSync(outDir, { recursive: true });

const broadcasters = [];
try {
  run("docker", ["compose", "-f", "docker-compose.broadcast.yml", "up", "-d"]);
  await waitForHealth();

  if (mode === "multi-room") {
    const rooms = [`${defaultRoom}-a`, `${defaultRoom}-b`];
    for (const room of rooms) {
      broadcasters.push(startBroadcaster(room));
    }
    const results = await Promise.all(rooms.map((room) => waitForPlaylist(room)));
    console.log(
      `PASS broadcast V3 multi-room local verification rooms=${rooms.join(",")} segments=${results
        .map((result) => result.segment)
        .join(",")}`,
    );
  } else if (mode === "bad-key") {
    broadcasters.push(startBroadcaster(defaultRoom, { passphrase: "wrong-passphrase", durationMs: 8000 }));
    let rejected = false;
    try {
      await waitForPlaylist(defaultRoom);
    } catch {
      rejected = true;
    }
    assert(rejected, "bad publish passphrase unexpectedly produced HLS");
    console.log(`PASS broadcast V3 bad-key local verification room=${defaultRoom}`);
  } else {
    broadcasters.push(startBroadcaster(defaultRoom));
    let ipcPromise = Promise.resolve();
    if (mode === "ipc") {
      await sleep(1000);
      ipcPromise = sendSyntheticIpc();
    }

    const result = await waitForPlaylist(defaultRoom);
    await ipcPromise;
    console.log(
      `PASS broadcast V3 ${mode} local verification room=${defaultRoom} segment=${result.segment}`,
    );
  }
} finally {
  for (const broadcaster of broadcasters) {
    if (broadcaster && broadcaster.exitCode === null && !broadcaster.killed) {
      broadcaster.kill();
    }
  }
  run("docker", ["compose", "-f", "docker-compose.broadcast.yml", "down", "--remove-orphans"]);
}
