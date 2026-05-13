# Listener Mode V3 Roadmap

Status: planned.

V3 turns the V2 native listener service into a product feature. V2 proved that
one `listener_service` process can join multiple rooms, mix each room, write
per-room HLS output, and serve it through nginx. V3 should make that automatic:
room owners enable listener mode, the backend starts/stops the room listener,
and Cloudflare CDN can sit in front of the nginx origin.

## Goal

Listener V3 should let a room owner enable a public listen-only stream without
manually starting native commands.

Target flow:

```text
room owner enables listener mode
-> backend marks listener_enabled=true
-> listener orchestrator starts room pipeline
-> listener_service joins the SFU as listener role
-> HLS URL becomes available
-> no performers remain or owner disables listener mode
-> listener pipeline stops and HLS output is cleaned
```

## Scope

### 1. Backend Listener State

- Add room-level listener settings:
  - `listener_enabled`
  - `listener_status`: `stopped`, `starting`, `live`, `error`
  - `listener_url`
  - `listener_started_at`
  - `listener_last_heartbeat_at`
  - `listener_error`
- Restrict enable/disable controls to room owner or authorized moderators.
- Generate listener-role join tokens for `listener_service`.
- Store enough room metadata for orchestration:
  room id, room handle, server id, SFU host, HLS path, and owner id.

### 2. Listener Orchestrator

- Add a small service or worker that watches enabled rooms.
- Start a listener room pipeline when:
  - room has `listener_enabled=true`
  - at least one performer is present, or owner explicitly starts preview
  - no active listener pipeline exists
- Stop a room pipeline when:
  - owner disables listener mode
  - room has no performers for a grace period
  - join token expires and cannot be refreshed
  - repeated FFmpeg/listener failures exceed retry policy
- Update backend status on start, live, error, retry, and stop.
- Keep orchestration independent from the SFU audio forwarding path.

### 3. Dynamic `listener_service` Control

V2 supports multiple rooms through CLI config. V3 needs runtime control.

Options:

- Local control API:
  - `POST /rooms/start`
  - `POST /rooms/stop`
  - `GET /rooms`
- Config watcher:
  - service watches a backend-generated config file
  - starts/stops rooms when config changes
- Backend polling:
  - service periodically fetches desired room state

Preferred first implementation: local control API, because it is explicit and
easy to observe.

Required behavior:

- Start room without restarting the whole service.
- Stop one room without affecting other rooms.
- Refresh listener tokens before expiry.
- Expose per-room health:
  packets received, decoded packets, underruns, queue drops, FFmpeg failures,
  latest segment time, playlist path.

### 4. Auto-Disable Empty Rooms

- Define performer presence source of truth.
- If room has no performers for N seconds, stop the listener pipeline.
- Recommended initial grace period: 60-120 seconds.
- Keep room setting enabled or disabled as a product decision:
  - `listener_enabled` can remain true and auto-start when performers return, or
  - backend can turn it off after long idle timeout.
- Always clean stale HLS output after a room stops.

### 5. CDN In Front Of nginx

V3 CDN should use nginx as the origin. Do not upload HLS directly to object
storage in V3.

Recommended path:

```text
listener_service -> tmpfs HLS root -> nginx origin -> Cloudflare CDN
```

Origin requirements:

- HLS root on tmpfs on Linux, for example `/dev/shm/jam-hls`.
- nginx serves:
  - `/hls/<room-id>/stream.m3u8`
  - `/hls/<room-id>/stream_<sequence>.m4s`
- CORS allows app/player origin.
- Health endpoint exposes origin availability.

Cloudflare cache rules:

- `.m3u8`: no-cache, must-revalidate
- `.m4s`: cacheable, short TTL or immutable while retained
- Do not cache error responses for long.
- Keep cache purge optional; segment filenames are monotonic and immutable.

### 6. App Surface

- Room owner toggle: `Listener mode`.
- Show listener status:
  - starting
  - live
  - stopped
  - error
- Show public/listener URL when live.
- Provide copy link action.
- Optionally show basic stats:
  listeners count later, stream uptime, last error.

### 7. Validation

- Enable listener mode from app and verify the pipeline starts.
- Disable listener mode from app and verify the room pipeline stops.
- Leave a room empty and verify auto-stop after the grace period.
- Rejoin after auto-stop and verify behavior matches the product decision.
- Verify two rooms can be active through orchestration at the same time.
- Verify one room error does not stop other rooms.
- Verify Cloudflare serves segments and revalidates playlists correctly.
- Verify browser playback through CDN URL.
- Verify native performer audio remains clean while listener mode is active.

## Not In V3

- Direct R2/S3 HLS upload.
- Dedicated media server or packager cluster.
- WebRTC listener fanout.
- Multi-region listener origins.
- Listener chat, reactions, or moderation UI.
- Listener analytics beyond basic status/health.

## Open Decisions

- Should `listener_enabled` remain true after the room becomes empty, allowing
  auto-start when performers return?
- What is the empty-room grace period?
- Where should the listener orchestrator run: same VPS as SFU, separate worker,
  or backend-adjacent service?
- Should the listener URL be public, unlisted, or token-gated?
- What Cloudflare domain/path will be used for listener streams?
