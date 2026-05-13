# Listener Mode V2 Implementation Checklist

Status: native implementation complete.

This checklist tracks native listener/HLS work only. It should not be used to
change performer-to-performer audio behavior unless a listener-specific bug
proves that a shared protocol fix is required.

The implementation target is a multi-room listener service. `listener_bot.cpp`
is the prototype reference, not the final process model.

## 1. Notes And Architecture

- [x] Review `notes/listenerplan.md`.
- [x] Confirm tmpfs HLS origin is the recommended first production strategy.
- [x] Confirm direct-to-Cloudflare-CDN is not a valid standalone design without
  an origin.
- [x] Confirm R2/S3 object storage is deferred because live playlist consistency,
  upload timing, cache headers, and cleanup add complexity.
- [x] Decide V2 should be a multi-room listener service, not one process per
  room.
- [x] Clean up or replace the mojibake old notes if they remain user-facing.

## 2. Multi-Room Service Skeleton

- [x] Add `listener_service` target, or split reusable room-pipeline classes out
  of `listener_bot.cpp` and keep `listener_bot` as a thin compatibility entry.
- [x] Define `ListenerServiceOptions` for shared server config:
  `--server`, `--port`, `--hls-root`, `--ffmpeg`, `--segment-duration`,
  `--playlist-size`, and `--bitrate`.
- [x] Define `RoomListenerConfig` with:
  room id, room handle, listener profile id, display name, join token, playlist
  name, and output path.
- [x] Support multiple `--room` entries or a config file.
- [x] Start more than one room listener inside one process.
- [x] Stop all room listeners cleanly on shutdown.
- [x] Keep room pipelines owned independently so one room can be stopped or
  restarted without stopping the service.

Acceptance:

- [x] One service process starts two configured rooms.
- [x] Each room has its own lifecycle object and HLS output path.
- [x] Stopping one room leaves the other room running.

## 3. Listener Join V2

- [x] Replace hardcoded `listener-bot` room values with room config values.
- [x] Send the same structured `JoinHdr` fields as native clients.
- [x] Support production join tokens per room.
- [x] Support explicit insecure dev joins for local testing only.
- [x] Add room-scoped log lines for JOIN, ALIVE, LEAVE, reconnect, and shutdown.
- [x] Verify `ALIVE` and `LEAVE` behavior matches current room lifecycle.
- [x] Ensure listener join/leave does not create phantom performer strips.

Acceptance:

- [x] Listener service joins the same room as two performers.
- [x] Listener service can run against token-required SFU mode.
- [x] Invalid listener token role is rejected.
- [x] Listener join/leave does not duplicate performer audio.

## 4. Current Audio Packet Support

- [x] Add `AUDIO_V2_MAGIC` handling.
- [x] Parse `AudioHdrV2` payload fields safely.
- [x] Validate `payload_bytes <= AUDIO_BUF_SIZE`.
- [x] Validate received byte count contains the full declared payload.
- [x] Decode Opus V2 payloads using packet sample rate/frame count.
- [x] Keep independent participant/decode state per room.
- [x] Decide whether legacy `AUDIO_MAGIC` stays supported.

Acceptance:

- [x] Listener service decodes current native client Opus audio.
- [x] Malformed V2 audio is dropped without crashing a room pipeline.
- [x] Malformed traffic in one room does not affect other room pipelines.
- [x] Listener service does not decode or mix unjoined/stale participants.

## 5. Per-Room Mix And Buffering

- [x] Define listener-specific jitter/queue targets separately from performer
  monitoring.
- [x] Add one participant manager per room.
- [x] Add per-room and per-participant counters:
  decoded packets, decode failures, underruns, queue drops, queue depth.
- [x] Add output counters:
  mix frames, PCM queue drops, and FFmpeg write failures.
- [x] Keep FFmpeg writes off each room's mix timing path.
- [x] Validate headroom/limiter behavior with multiple active speakers.
- [x] Ensure one room's FFmpeg backpressure cannot block another room.

Acceptance:

- [x] Two active performers produce a mixed listener feed.
- [x] Moderate jitter does not cause listener decode failures.
- [x] FFmpeg backpressure drops listener frames or restarts that room pipeline
  instead of blocking the SFU, performers, or other rooms.

## 6. HLS Origin V2

- [x] Add documented tmpfs output path for `/hls`.
- [x] Generate per-room output:
  `<hls-root>/<room-id>/stream.m3u8`.
- [x] Use room-scoped segment prefixes.
- [x] Run one independently restartable FFmpeg process per active room.
- [x] Document nginx route for room HLS paths.
- [x] Document cache headers:
  `.m3u8` no-cache/revalidate, segments cacheable.
- [x] Verify FFmpeg restart behavior does not leave stale playlists.
- [x] Add cleanup for old room output on room shutdown.

Acceptance:

- [x] HLS playlist and segments are generated under a configured HLS root.
- [x] nginx serves multiple room playlists locally.
- [x] Browser/player can play each room stream independently.
- [x] Restarting one room pipeline recovers without stale playlist lockup.

## 7. Validation

- [x] Add a local service smoke test or probe for two room joins.
- [x] Add a packet decode probe for current V2 Opus audio.
- [x] Add a malformed V2 packet test.
- [x] Run one SFU plus two protocol-level native performer probes plus
  `listener_service`.
- [x] Run at least two rooms in one `listener_service` process.
- [x] Confirm performer-to-performer protocol routing remains clean.
- [x] Confirm generated HLS listener output is parseable for each room.
- [x] Record server host, room ids, codec, RTT range, HLS segment duration,
  playlist size, tmpfs path, and observed latency.

## Deferred

- Dynamic Convex/API room orchestration.
- R2/S3 upload origin.
- Dedicated media server or packager.
- Cloudflare production cache rule automation.
- Convex listener presence.
- Electron listener controls.
- Mobile/web listener UI.
