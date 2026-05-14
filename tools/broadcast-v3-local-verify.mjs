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
const mode = process.argv.includes("--ipc-stress")
  ? "ipc-stress"
  : process.argv.includes("--ipc")
    ? "ipc"
    : process.argv.includes("--multi-room")
    ? "multi-room"
    : process.argv.includes("--auth")
      ? "auth"
      : process.argv.includes("--bad-key")
        ? "bad-key"
        : "test-tone";
const defaultRoom = `broadcast-v3-${mode}-${Date.now()}`;
const httpPort = Number(process.env.BROADCAST_HTTP_PORT ?? 8080);
const mediaMtxApiPort = Number(process.env.BROADCAST_MEDIAMTX_API_PORT ?? 9997);
const mediaMtxApiUser = process.env.BROADCAST_MEDIAMTX_API_USER ?? "jam-api";
const mediaMtxApiPass = process.env.BROADCAST_MEDIAMTX_API_PASS ?? "jam-api-dev-secret";
const srtPort = Number(process.env.BROADCAST_SRT_PORT ?? 8890);
const ipcPort = 39000 + Math.floor(Math.random() * 2000);
const authPort = 18000 + Math.floor(Math.random() * 2000);
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

function request(url, cookies = {}, headers = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const cookieHeader = Object.entries(cookies)
      .map(([name, value]) => `${name}=${value}`)
      .join("; ");
    const requestHeaders = { ...headers };
    if (cookieHeader) {
      requestHeaders.Cookie = cookieHeader;
    }
    const req = http.request(
      {
        hostname: parsed.hostname,
        port: parsed.port,
        path: `${parsed.pathname}${parsed.search}`,
        method: "GET",
        headers: requestHeaders,
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

async function get(url, cookies = {}, redirects = 5, headers = {}) {
  let current = url;
  for (let i = 0; i <= redirects; i += 1) {
    const response = await request(current, cookies, headers);
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

async function waitForMediaMtxHealth() {
  const auth = Buffer.from(`${mediaMtxApiUser}:${mediaMtxApiPass}`).toString("base64");
  const headers = { Authorization: `Basic ${auth}` };
  const deadline = Date.now() + 15000;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const health = await get(
        `http://127.0.0.1:${mediaMtxApiPort}/v3/config/global/get`,
        {},
        5,
        headers,
      );
      if (health.status === 200) {
        const config = JSON.parse(health.body.toString("utf8"));
        assert(config.hls === true, "MediaMTX API reports HLS disabled");
        assert(config.srt === true, "MediaMTX API reports SRT disabled");
        return;
      }
      lastError = new Error(`MediaMTX API returned ${health.status}`);
    } catch (error) {
      lastError = error;
    }
    await sleep(500);
  }
  throw lastError ?? new Error("MediaMTX API health did not become ready");
}

function srtUrl(room, passphrase = publishPassphrase) {
  return `srt://127.0.0.1:${srtPort}?streamid=publish:${room}&passphrase=${passphrase}&pkt_size=1316`;
}

function srtAuthUrl(room, user, password, passphrase = publishPassphrase) {
  return `srt://127.0.0.1:${srtPort}?streamid=publish:${room}:${user}:${password}&passphrase=${passphrase}&pkt_size=1316`;
}

function startBroadcaster(room, options = {}) {
  const logPath = path.join(outDir, `${mode}-${room}.log`);
  const log = fs.openSync(logPath, "w");
  const targetSrtUrl = options.srtUrl ?? srtUrl(room, options.passphrase);
  const args =
    mode === "ipc" || mode === "ipc-stress"
      ? [
          "--ipc-port",
          String(ipcPort),
          "--srt-url",
          targetSrtUrl,
          "--duration-ms",
          String(options.durationMs ?? 22000),
        ]
      : [
          "--test-tone",
          "--srt-url",
          targetSrtUrl,
          "--duration-ms",
          String(options.durationMs ?? 22000),
        ];
  const child = spawn(broadcasterExe, args, {
    cwd: repoRoot,
    stdio: ["ignore", log, log],
    windowsHide: true,
  });
  child.on("exit", () => fs.closeSync(log));
  child.logPath = logPath;
  return child;
}

function startAuthServer({ room, user, password }) {
  const calls = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      let body = {};
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
      } catch {
        res.writeHead(400);
        res.end("bad request");
        return;
      }

      calls.push(body);
      const allowed =
        body.action === "publish" &&
        body.protocol === "srt" &&
        body.path === room &&
        body.user === user &&
        (body.password === password || body.token === password);
      res.writeHead(allowed ? 200 : 401);
      res.end(allowed ? "ok" : "unauthorized");
    });
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(authPort, "0.0.0.0", () => {
      server.off("error", reject);
      resolve({ server, calls });
    });
  });
}

function makeIpcPacket({ sequence, sampleRate = 48000, frameCount = 960, phase = 0 }) {
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0x4a424950, 0);
  header.writeUInt16LE(1, 4);
  header.writeUInt16LE(24, 6);
  header.writeUInt32LE(sequence, 8);
  header.writeUInt32LE(sampleRate, 12);
  header.writeUInt16LE(1, 16);
  header.writeUInt16LE(frameCount, 18);
  header.writeUInt16LE(1, 20);
  header.writeUInt16LE(frameCount * 4, 22);

  const payload = Buffer.alloc(frameCount * 4);
  const phaseStep = (2 * Math.PI * 440) / sampleRate;
  let nextPhase = phase;
  for (let i = 0; i < frameCount; i += 1) {
    payload.writeFloatLE(Math.sin(nextPhase) * 0.15, i * 4);
    nextPhase += phaseStep;
    if (nextPhase > 2 * Math.PI) nextPhase -= 2 * Math.PI;
  }
  return { packet: Buffer.concat([header, payload]), phase: nextPhase };
}

function sendUdp(socket, packet) {
  return new Promise((resolve, reject) => {
    socket.send(packet, ipcPort, "127.0.0.1", (error) => (error ? reject(error) : resolve()));
  });
}

async function sendSyntheticIpc({ stress = false } = {}) {
  const socket = dgram.createSocket("udp4");
  const sampleRate = 48000;
  const frameCount = 960;
  let sequence = 0;
  let phase = 0;
  const deadline = Date.now() + (stress ? 15000 : 12000);
  let malformedSent = 0;

  while (Date.now() < deadline) {
    if (stress && sequence % 13 === 0) {
      await sendUdp(socket, Buffer.from([0x4a, 0x42, 0x49]));
      malformedSent += 1;
    } else if (stress && sequence % 17 === 0) {
      const badHeader = Buffer.alloc(24);
      badHeader.writeUInt32LE(0x4a424950, 0);
      badHeader.writeUInt16LE(1, 4);
      badHeader.writeUInt16LE(24, 6);
      badHeader.writeUInt32LE(sequence, 8);
      badHeader.writeUInt32LE(sampleRate, 12);
      badHeader.writeUInt16LE(2, 16);
      badHeader.writeUInt16LE(frameCount, 18);
      badHeader.writeUInt16LE(1, 20);
      badHeader.writeUInt16LE(frameCount * 4, 22);
      await sendUdp(socket, badHeader);
      malformedSent += 1;
    }

    if (stress && sequence % 23 === 0) {
      sequence += 1;
    }
    const result = makeIpcPacket({ sequence, sampleRate, frameCount, phase });
    phase = result.phase;
    await sendUdp(socket, result.packet);
    sequence += 1;
    await sleep(stress ? 8 : 20);
  }
  socket.close();
  return { malformedSent };
}

function waitForExit(child, timeoutMs) {
  return new Promise((resolve, reject) => {
    if (child.exitCode !== null) {
      resolve(child.exitCode);
      return;
    }
    const timeout = setTimeout(() => {
      reject(new Error(`process did not exit within ${timeoutMs}ms`));
    }, timeoutMs);
    child.once("exit", (code) => {
      clearTimeout(timeout);
      resolve(code ?? 0);
    });
  });
}

if (!fs.existsSync(broadcasterExe)) {
  throw new Error(`missing executable: ${broadcasterExe}`);
}

fs.mkdirSync(outDir, { recursive: true });

const broadcasters = [];
let authServer;
try {
  const composeArgs = ["compose", "-f", "docker-compose.broadcast.yml"];
  if (mode === "auth") {
    composeArgs.push("-f", "docker-compose.broadcast.auth.yml");
  }
  composeArgs.push("up", "-d");

  let authContext;
  if (mode === "auth") {
    authContext = {
      room: defaultRoom,
      user: `user-${Date.now()}`,
      password: `key-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    };
    const started = await startAuthServer(authContext);
    authServer = started;
    process.env.BROADCAST_AUTH_HTTP_ADDRESS = `http://host.docker.internal:${authPort}/auth`;
  }

  run("docker", composeArgs);
  await waitForHealth();
  await waitForMediaMtxHealth();

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
  } else if (mode === "auth") {
    const valid = startBroadcaster(defaultRoom, {
      srtUrl: srtAuthUrl(defaultRoom, authContext.user, authContext.password),
      durationMs: 12000,
    });
    broadcasters.push(valid);
    const result = await waitForPlaylist(defaultRoom);
    assert(
      authServer.calls.some((call) => call.action === "publish" && call.path === defaultRoom),
      "MediaMTX did not call auth server for valid publish",
    );

    const rejectedRoom = `${defaultRoom}-bad`;
    const rejected = startBroadcaster(rejectedRoom, {
      srtUrl: srtAuthUrl(rejectedRoom, authContext.user, "wrong-key"),
      durationMs: 7000,
    });
    broadcasters.push(rejected);
    let rejectedPublish = false;
    try {
      await waitForPlaylist(rejectedRoom);
    } catch {
      rejectedPublish = true;
    }
    assert(rejectedPublish, "bad auth publish unexpectedly produced HLS");
    console.log(
      `PASS broadcast V3 auth local verification room=${defaultRoom} segment=${result.segment}`,
    );
  } else {
    const broadcaster = startBroadcaster(defaultRoom, {
      durationMs: mode === "ipc-stress" ? 18000 : 22000,
    });
    broadcasters.push(broadcaster);
    let ipcPromise = Promise.resolve();
    let malformedSent = 0;
    if (mode === "ipc" || mode === "ipc-stress") {
      await sleep(1000);
      ipcPromise = sendSyntheticIpc({ stress: mode === "ipc-stress" }).then((result) => {
        malformedSent = result.malformedSent;
      });
    }

    const result = await waitForPlaylist(defaultRoom);
    await ipcPromise;
    if (mode === "ipc-stress") {
      const exitCode = await waitForExit(broadcaster, 10000);
      assert(exitCode === 0, `broadcaster exited with ${exitCode}`);
      const logText = fs.readFileSync(broadcaster.logPath, "utf8");
      const dropped = Number(/packets_dropped=(\d+)/.exec(logText)?.[1] ?? 0);
      const received = Number(/packets_received=(\d+)/.exec(logText)?.[1] ?? 0);
      assert(received > 0, "IPC stress did not deliver valid packets");
      assert(dropped > 0, "IPC stress did not exercise drop accounting");
      assert(malformedSent > 0, "IPC stress did not send malformed packets");
    }
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
  if (authServer) {
    await new Promise((resolve) => authServer.server.close(resolve));
  }
  const downArgs = ["compose", "-f", "docker-compose.broadcast.yml"];
  if (mode === "auth") {
    downArgs.push("-f", "docker-compose.broadcast.auth.yml");
  }
  downArgs.push("down", "--remove-orphans");
  run("docker", downArgs);
  delete process.env.BROADCAST_AUTH_HTTP_ADDRESS;
}
