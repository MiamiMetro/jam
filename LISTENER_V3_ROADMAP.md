# Listener Mode V3 Roadmap

Status: native local path, `jam-app` process launch, local Convex adapter, and
MediaMTX publish-auth overlay are implemented. The current development HLS URL
is local: `http://127.0.0.1:8080/hls/<room>/stream.m3u8`. VPS/domain HLS
remains the next production-facing step.

V3 pivots listener mode away from the server-side listener-bot model. V2 proved
that a bot can join rooms, mix audio, and write HLS, but that model is awkward
for the product: it behaves like a hidden client, adds room lifecycle edge
cases, and makes listener mode feel tied to server-side room state.

V3 is a host-push broadcast model:

```text
performers jam through the native SFU as usual
-> room owner enables Listener Mode
-> app/backend creates a short-lived ingest session
-> desktop app starts a separate broadcaster process
-> client.exe sends the host broadcast mix over localhost UDP IPC
-> jam_broadcaster.exe encodes that feed and pushes it by SRT
-> MediaMTX receives SRT and produces HLS
-> nginx exposes public HLS on listen.<domain>
-> listeners play the HLS URL from jam-app
```

This is closer to the OBS/Twitch model: the broadcaster pushes one live stream
to ingest, while viewers receive HLS from an origin/CDN. Jam's real-time
performer path remains separate and higher priority.

## Locked V3 Decisions

- Listener Mode V3 is host broadcast, not neutral room broadcast.
- Only the room owner can broadcast in V3.
- Broadcast stops when the owner leaves or disables listener mode.
- `client.exe` remains the real-time jamming process.
- `jam_broadcaster.exe` is a separate process and should stay separate.
- `client.exe` does not launch `jam_broadcaster.exe`; terminal scripts launch
  both first, then `jam-app` owns process launch later.
- `client.exe` exposes broadcast PCM only when listener mode is enabled.
- Local IPC is localhost UDP.
- Broadcast IPC must be non-blocking and may drop frames.
- Broadcast audio is mono in V3.
- Stream latency is not critical; 5+ seconds is acceptable.
- Jamming quality and stability always win over broadcast continuity.
- The broadcast mix mirrors what the owner is broadcasting:
  - existing owner output mix
  - plus owner mic
  - owner participant volume/mute/pan affects stream
  - owner master output volume affects stream
  - OS/headphone mute or device volume does not affect stream
  - owner mute mutes owner mic in the stream
  - metronome is never included
- `jam_broadcaster.exe` encodes outside `client.exe`.
- Ingest uses SRT first, not RTMP.
- MediaMTX is the first ingest/HLS server.
- nginx sits in front of MediaMTX.
- Public HLS origin is local during development and a subdomain later, for example:
  `http://127.0.0.1:8080/hls/<room-id>/stream.m3u8`
  `https://listen.<domain>/hls/<room-id>/stream.m3u8`.
- Playback is public/unlisted in V3.
- Publish authorization uses short-lived per-broadcast session keys.
- MediaMTX must enforce publish authorization at ingest time before VPS
  production/demo hardening is complete.
- The VPS exposes a public SRT UDP ingest port.
- V3 is audio-only.
- Docker Compose owns the ingest/HLS stack.
- The broadcast Docker Compose stack is listener/broadcast-only and does not
  start the SFU/server.
- Same-VPS SFU plus ingest/HLS is acceptable for demo; separate ingest VPS can
  come later.

## Goal

Room owners should be able to turn on a public listener stream without a
server-side listener bot joining the jam room.

Success means:

- performer-to-performer jamming stays on the existing low-latency native SFU
  path
- listener mode adds no blocking work to the jam-critical audio path
- the owner client produces a host broadcast mix from already-available audio
- a separate broadcaster process encodes and pushes SRT to local/VPS ingest
- MediaMTX/nginx produce browser-playable HLS
- multiple room owners can broadcast concurrently
- `jam-app` launches/stops the broadcaster and shows listener status
- Convex/app code prepares product config, and native broadcaster binaries stay
  backend-agnostic

## Architecture

### Owner Machine

```text
client.exe
  - joins SFU as performer
  - owns real-time input/output
  - builds the normal owner output mix
  - adds owner mic for broadcast
  - excludes metronome
  - writes mono PCM to a non-blocking broadcast ring buffer
  - background sender emits localhost UDP packets only when enabled

jam_broadcaster.exe
  - separate process
  - reads localhost UDP PCM packets
  - encodes audio outside client.exe
  - pushes SRT to VPS ingest
  - reconnects on network drops
  - exposes local HTTP health later for app integration
```

Hard rule:

```text
broadcast path may drop audio
jam path must never wait for broadcast
```

No broadcast code should allocate, encode, retry, or do network I/O inside the
real-time audio callback.

### VPS

```text
server
  - existing UDP SFU for performers
  - deployed through VPS_SETUP.md

MediaMTX
  - internal ingest/HLS server
  - accepts SRT publishers
  - enforces publish auth through the explicit auth compose overlay
  - outputs HLS

nginx
  - public HTTPS edge for listen.<domain>
  - proxies HLS from MediaMTX
  - sets HLS cache/CORS headers
```

Expected public playback URL:

```text
https://listen.<domain>/hls/<room-id>/stream.m3u8
```

`jam-app` can be hosted separately. It only needs the HLS URL and CORS from the
stream origin.

### App And Backend

V3 terminal-first implementation works before app integration. `jam-app` now
owns local process orchestration:

```text
owner starts/join jam
-> app launches client.exe for performer jamming
-> owner enables Listener Mode
-> app asks backend for short-lived ingest config
-> app launches jam_broadcaster.exe
-> app monitors broadcaster health
-> owner disables Listener Mode or leaves room
-> app stops jam_broadcaster.exe
```

Convex is the first product adapter, not a native dependency.

Implemented room/session fields:

- `listenerStatus`
- `listenerSessionId`
- `listenerStartedAt`
- `listenerUpdatedAt`
- `listenerExpiresAt`
- `listenerError`
- `streamUrl`
- `listener_publish_sessions` rows with hashed publish keys

Backend responsibilities:

- authorize the room owner
- create short-lived publish credentials
- return broadcaster launch config
- store listener URL and status
- revoke/expire publish credentials when disabled
- reconcile stale live state if broadcaster/app disappears

Do not put long-lived ingest secrets in client-visible room records.

The default local compose keeps the previously verified static SRT passphrase
for terminal smoke tests. The app-backed path should run with
`docker-compose.broadcast.auth.yml`, which enables MediaMTX HTTP auth against
the Convex `/broadcast/auth` endpoint. `node tools\broadcast-v3-local-verify.mjs
--auth` verifies the MediaMTX auth behavior with a local test auth server.

## Protocol And Media

### Client To Broadcaster IPC

Use localhost UDP for V3:

```text
client.exe --broadcast-ipc-port 39000
jam_broadcaster.exe --ipc-port 39000 --srt-url ...
```

The UDP payload should carry small mono PCM frames plus enough metadata to
detect format/version mismatches and dropped sequence numbers.

Initial target:

- mono
- 48 kHz
- 16-bit PCM over localhost UDP, or float PCM if that fits existing buffers
  better
- 20 ms or similarly convenient frame size
- non-blocking send from a background thread
- drops are acceptable

### Broadcaster To VPS

Use SRT for ingest:

```text
jam_broadcaster.exe --srt-url "srt://listen.<domain>:<port>?..."
```

`jam_broadcaster.exe` should encode before SRT so owner upload stays low.
Exact codec/bitrate is an implementation decision, but the output must be
compatible with the MediaMTX -> HLS path. Browser playback compatibility matters
more than codec preference.

Recommended V3 target:

- audio-only
- mono
- low bitrate, roughly 64-96 kbps if practical
- higher SRT latency is acceptable for stability

### HLS Playback

MediaMTX/nginx should provide browser-playable HLS. AAC HLS is acceptable and
likely the safest compatibility target if transcoding/packaging is needed on
the VPS.

Playback policy:

- public/unlisted URL
- no signed playback tokens in V3
- secure publish path instead of secure playback path

## Implementation Phases

### Phase 1 - Local Ingest/HLS Proof

Use Docker Compose to run MediaMTX and nginx locally.

Prove:

```text
jam_broadcaster.exe --test-tone
-> SRT
-> MediaMTX
-> nginx
-> local browser HLS playback
```

This phase must work without `client.exe`, `jam-app`, or Convex.

### Phase 2 - Local IPC Proof

Add `jam_broadcaster.exe --ipc-port`.

Prove:

```text
synthetic localhost UDP PCM source
-> jam_broadcaster.exe
-> SRT
-> MediaMTX/nginx
-> local browser HLS playback
```

This proves broadcaster IPC mode before touching client audio.

### Phase 3 - Client Broadcast IPC

Add explicit `client.exe` CLI support:

```text
client.exe ... --broadcast-ipc-port 39000
```

Behavior:

- broadcast IPC disabled unless the flag is present
- no extra work when not broadcasting
- broadcast frames come from existing owner output mix plus owner mic
- metronome excluded
- owner mute and volumes respected
- OS/device mute ignored
- non-blocking ring buffer between audio path and sender thread
- sender thread uses localhost UDP and drops on pressure

### Phase 4 - Local Full Native Proof

Prove:

```text
server
-> two native clients jamming locally
-> owner client sends broadcast IPC
-> jam_broadcaster.exe pushes SRT
-> MediaMTX/nginx serves HLS
-> browser hears stream
-> performer-to-performer audio remains clean
```

Status: verified locally on May 14, 2026 with a macOS SFU, Windows owner
client, macOS performer client, `jam_broadcaster.exe`, and local
MediaMTX/nginx. The Windows owner client sent broadcast IPC on port `39000`,
the HLS stream played in a browser, and the stream included macOS performer
audio. Local HLS tuning is currently 1 second segments, 4 retained segments,
and 250 ms parts, which produced about 3.5 seconds of manual playback delay.

### Phase 5 - VPS Same-Server Demo

Deploy MediaMTX/nginx compose on the same VPS as the existing SFU/server.

Prove:

- SFU/server still follows `VPS_SETUP.md`
- broadcast compose does not start or publish the SFU/server
- SRT UDP ingest is reachable
- HLS is reachable at `https://listen.<domain>/hls/<room-id>/stream.m3u8`
- Windows owner can broadcast
- macOS performer still hears clean jam audio
- browser listener can play HLS
- idle SFU plus ingest/HLS stack has acceptable resource usage

### Phase 6 - jam-app Process Launch

After native terminal proof:

- app launches `client.exe`
- app launches/stops `jam_broadcaster.exe`
- app passes ingest config to broadcaster
- app shows `starting`, `live`, `reconnecting`, `error`, `stopped`
- app polls local broadcaster health endpoint
- app stops broadcaster when owner leaves or disables Listener Mode

### Phase 7 - Convex Product State

After app process launch works:

- add room listener fields
- authorize owner-only Listener Mode
- create short-lived publish session keys
- return broadcaster launch config to desktop app
- store public HLS URL
- revoke/expire publish session on stop
- reconcile stale states when broadcaster/app disappears

## Validation Requirements

Native:

- `client.exe` can jam normally with broadcast disabled.
- Broadcast flag adds no network/encoding work to the audio callback.
- Broadcast path drops frames instead of blocking.
- Owner mic is included.
- Owner mute mutes owner mic in broadcast.
- Metronome is excluded.
- OS/device mute does not affect broadcast.
- `jam_broadcaster.exe` crash does not break jamming.
- SRT reconnect works without restarting `client.exe`.

Ingest/origin:

- bad publish key is rejected.
- expired/revoked publish key cannot start a stream.
- one room publishes playable HLS.
- two rooms publish concurrently to separate HLS outputs.
- duplicate publisher behavior is explicit.
- HLS playlist headers are no-cache.
- HLS segment headers are cacheable with short TTL or immutable semantics.
- CORS allows `jam-app` playback.

App/backend:

- only owner can enable/disable Listener Mode.
- app can launch and stop broadcaster.
- app shows useful error when broadcaster or ingest fails.
- disabling Listener Mode stops/revokes publish session.
- listener URL is public/unlisted and copyable.

Manual acceptance:

- Windows owner broadcasts to local stack.
- Windows owner broadcasts to VPS stack.
- macOS performer still hears clean audio during broadcast.
- browser listener plays HLS from `listen.<domain>`.

## Not In V3

- Server-side listener bot joining rooms.
- Neutral server-side room mix.
- WebRTC listener delivery.
- Video broadcasting.
- Direct R2/S3 HLS upload.
- Multi-region ingest/origin.
- Host handoff between multiple broadcasters.
- Signed listener playback URLs.
- Listener chat, reactions, or analytics beyond basic status.

## Remaining Open Decisions

- Exact SRT URL/stream-id/auth format for MediaMTX.
- Production publish-auth enforcement for short-lived per-broadcast keys.
- Whether `jam_broadcaster.exe` needs a local HTTP health endpoint before
  `jam-app` integration, or whether process status is enough for the first app
  adapter.
- Final `listen.<domain>` hostname.
