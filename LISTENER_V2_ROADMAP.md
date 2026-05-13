# Listener Mode V2 Roadmap

Status: native implementation complete; real-client listening validation still recommended.

Listener V2 is the public listening path for rooms after the native performer
jam path is stable. It should not affect performer-to-performer audio latency.
The listener pipeline can accept extra latency if it gives stable playback,
scalable fanout, and clean operational behavior.

The V2 target is a multi-room listener service, not one bot process per room.
One service process should be able to turn multiple active rooms into separate
HLS live streams while keeping each room pipeline isolated.

## Old Notes Assessment

`notes/listenerplan.md` is directionally correct:

- Avoiding local disk churn for HLS segments is the right goal.
- A tmpfs-backed HLS origin behind nginx and Cloudflare is the best minimum
  change from the current code.
- Cloudflare needs an origin. The app cannot simply "send to CDN" without an
  origin strategy.
- R2/S3 upload is possible later, but it adds atomic playlist, cache, upload,
  and cleanup complexity.
- Playlist cache headers must be very short or revalidated; segment files can
  be cached longer because they are immutable.

The notes are incomplete for the current repo:

- They do not cover the native room/auth protocol.
- They do not cover listener authorization or listener tokens.
- They do not cover the current `AUDIO_V2_MAGIC` packet format.
- They do not define multi-room service lifecycle, observability, or failure
  modes.
- The file appears mojibake-encoded and should not be treated as polished docs.

## Current Implementation State

Current listener code now has two paths:

- `listener_bot.cpp` joins a hardcoded `listener-bot` room.
- `listener_service.cpp` is the V2 service entry point.
- `listener_service` accepts multiple room configs, sends listener-role joins,
  supports per-room tokens, and can run with explicit insecure dev joins.
- `listener_service` handles legacy `AUDIO_MAGIC` packets and current
  `AUDIO_V2_MAGIC` Opus packets.
- The SFU protocol now distinguishes performer joins from listener joins.
  Listener joins receive room audio but are not broadcast as performer
  participant metadata.
- It mixes received participants into mono float PCM on a time-driven thread.
- `broadcast_hls.h` pipes PCM to FFmpeg and writes HLS playlists/segments to a
  filesystem path.
- The HLS output path can be pointed at tmpfs or any configured HLS root.
- The repo nginx config serves multi-room HLS paths with separate playlist and
  segment cache headers.
- The V2 service process model is multi-room. Each room owns its own UDP
  socket, participant manager, mix queue, writer thread, FFmpeg process, and
  output path.

## V2 Goal

Listener V2 should provide one stable listenable stream per active room without
destabilizing the native jam session.

The target architecture is:

1. SFU remains optimized for performer UDP audio.
2. A `listener_service` process manages many room listeners.
3. Each room listener has its own JOIN identity/token, participant state,
   decode queues, mixer, FFmpeg process, output path, and health counters.
4. Each room listener joins the SFU as a receive-only room member.
5. Each room pipeline decodes current room audio packets, mixes a listener-safe
   program feed, and writes PCM to that room's FFmpeg process.
6. FFmpeg packages HLS into a tmpfs-backed per-room origin directory.
7. nginx serves playlists and segments with correct cache headers.
8. Cloudflare can cache immutable segments while revalidating playlists.

## Service Model

Initial V2 should use static room configuration so the native service can be
proven before product orchestration is added.

Example target shape:

```text
listener_service
  --server <sfu-host>
  --port <sfu-port>
  --hls-root /dev/shm/jam-hls
  --allow-insecure-dev-joins
  --room room-a:token-a
  --room room-b:token-b
```

Each configured room produces:

```text
<hls-root>/<room-id>/stream.m3u8
<hls-root>/<room-id>/stream_<sequence>.m4s
```

Later V2 or V3 can replace static CLI room config with backend/API
orchestration. The core service should already be shaped for dynamic
start/stop, but dynamic product control is not required for the first native
implementation.

Isolation requirements:

- One room's decode backlog must not block another room.
- One room's FFmpeg backpressure must not block another room.
- One room's crash/restart should not require restarting all room streams where
  practical.
- Metrics and logs must be room-scoped.
- Output cleanup must be room-scoped.

## Workstream 1: Multi-Room Listener Service

Required behavior:

- Add a new `listener_service` target or refactor `listener_bot` into a
  service-oriented entry point.
- Service accepts shared SFU options: `--server`, `--port`, `--hls-root`,
  `--ffmpeg`, `--segment-duration`, `--playlist-size`, and `--bitrate`.
- Service accepts one or more `--room` configs.
- Each room config includes room id, room handle, listener profile id, display
  name, and join token.
- Service owns room lifecycle: start room, stop room, restart room pipeline,
  shutdown all rooms.
- Each room listener uses independent sockets or an explicitly safe multiplexing
  model. Start with one UDP socket per room unless measurement proves otherwise.
- Each room listener sends `JOIN`, `ALIVE`, and `LEAVE` using the current native
  room lifecycle rules.
- `--no-hls` and `--duration-ms` exist for local probes.

Acceptance:

- Implemented: one process starts two room listeners at once.
- Implemented: each room joins the correct SFU room.
- Implemented: each room writes to a separate HLS output path when HLS is
  enabled.
- Implemented: room pipelines are independently owned and can be stopped or
  restarted independently through validation hooks.
- Probe-covered: listener joins receive audio without creating performer
  participant metadata.
- Probe-covered: adding/removing listener-role endpoints does not corrupt
  performer routing.

## Workstream 2: Native Listener Join And Room Mapping

Required behavior:

- Listener room config maps to the same `JoinHdr` fields as native clients.
- Listener identity is distinguishable from performers in logs and future room
  policy.
- Listener tokens work in production auth mode using token role `listener`.
- In dev mode, explicit insecure joins still work for local testing.
- Listener joins must not create phantom performer strips or duplicate voice.
- The service logs room id, endpoint, profile id, and HLS output path for each
  room listener.

Acceptance:

- Implemented: listener service joins a real room by CLI/static config.
- Implemented in protocol: wrong token role is rejected in production auth mode.
- Probe-covered: listener join does not announce performer participant metadata.
- Probe-covered: listener joins are not announced as performer metadata.

## Workstream 3: Current Audio Protocol Support

Required behavior:

- Decode `AUDIO_V2_MAGIC` packets.
- Respect packet `codec`, `sample_rate`, `frame_count`, `channels`, and
  `payload_bytes`.
- Support current Opus performer packets.
- Reject malformed payload sizes before decode.
- Keep listener decode/mix work off the SFU forwarding path.
- Maintain one participant/decode state set per room.

Acceptance:

- Implemented: listener service receives current V2 packet metadata and decodes
  Opus payloads.
- Implemented: legacy `AUDIO_MAGIC` support is retained intentionally.
- Implemented: malformed packet sizes are rejected before decode.
- Probe-covered: current V2 Opus performer packets decode and produce parseable
  HLS output.

## Workstream 4: Per-Room Listener Mix Quality

Required behavior:

- Mix all active room performers into one listener program feed per room.
- Keep one independent participant manager per room.
- Use queueing that tolerates internet jitter better than performer monitoring.
- Apply headroom/limiting so multiple speakers do not clip.
- Track underruns, packet drops, decode failures, queue depth, and output write
  failures per room.
- Do not use performer low-latency jitter settings blindly for public HLS.

Acceptance:

- Implemented: one participant manager, PCM queue, mix thread, writer thread,
  and counters per room.
- Implemented: FFmpeg writes are off each room's mix timing path.
- Implemented: one room has independent PCM queue/drop counters from other
  rooms.
- Probe-covered: two active Opus sender probes produce a parseable mixed HLS
  feed, and moderate jitter does not cause decode failures.

## Workstream 5: HLS Origin V2

Required behavior:

- Support tmpfs-backed HLS output as the first production origin strategy.
- Keep FFmpeg packaging isolated from the SFU audio thread.
- Configure playlist and segment names per room.
- Run one independently restartable FFmpeg process per active room.
- Use atomic or restart-safe playlist behavior.
- Clean old room output after room shutdown.
- Document nginx cache headers:
  - `.m3u8`: `Cache-Control: no-cache, must-revalidate`
  - segments: cacheable immutable or short-lived according to retention policy

Acceptance:

- Implemented: per-room HLS path shape works with any filesystem path,
  including tmpfs.
- Implemented: room startup clears stale output and shutdown cleans room output
  unless `--keep-hls-output` is set.
- Probe-covered: nginx serves two room playlists locally and applies separate
  playlist/segment cache headers.

## Workstream 6: Product And Ops Boundaries

Required behavior:

- Listener V2 stays independent from Gate 2/Convex until native behavior is
  proven.
- Room-to-listener-service orchestration is documented before automation.
- One service per SFU or per host is the initial operational model.
- Scale-out to R2/S3 or a media origin service is deferred until tmpfs origin is
  measured.

Acceptance:

- Manual operator can start the listener service with multiple rooms.
- Listener service failure does not take down the SFU.
- One room pipeline failure does not take down other room pipelines where
  practical.
- The roadmap clearly separates native listener work from future product
  orchestration.

## Not In V2

- Cloudflare R2/S3 direct HLS upload.
- Full media-server/packager cluster.
- Listener chat, reactions, or moderation controls.
- Electron listener UI.
- Convex authoritative listener presence.
- Mobile listener product polish.
