# Listener Mode V3 Implementation Checklist

Status: native terminal path in progress. `jam-app` and Convex adapter work is
deferred and has not been started in this repo.

This checklist implements the host-push broadcast roadmap in
`LISTENER_V3_ROADMAP.md`. V3 is audio-only, SRT ingest, MediaMTX/nginx HLS
delivery, and a separate `jam_broadcaster.exe`.

Latest native verification:

- `cmake --build build --config Release --target client jam_broadcaster` passed.
- `node tools\broadcast-v3-local-verify.mjs` passed for test tone -> SRT -> HLS.
- `node tools\broadcast-v3-local-verify.mjs --ipc` passed for synthetic UDP IPC -> SRT -> HLS.
- `node tools\broadcast-v3-local-verify.mjs --ipc-stress` passed for sustained
  IPC with malformed packets and sequence gaps; latest run received 969 valid
  packets, counted 172 dropped packets, and had 0 write failures/reconnects.
- `node tools\broadcast-v3-local-verify.mjs --multi-room` passed for two
  concurrent room paths.
- `node tools\broadcast-v3-local-verify.mjs --bad-key` passed for bad SRT
  passphrase rejection.
- Manual one-client local broadcast worked with server + client
  `--broadcast-ipc-port 39000` + `jam_broadcaster.exe`.
- Manual two-client native local broadcast worked with macOS SFU, Windows owner
  client, macOS performer client, `jam_broadcaster.exe`, and local
  MediaMTX/nginx. The HLS stream included macOS performer audio.
- Local HLS tuning in `broadcast/mediamtx.yml` uses 1 second segments, 4
  retained segments, and 250 ms parts. Browser/player delay was about 3.5
  seconds after refresh in manual testing.
- Automated verifier runs clean up Docker containers and native broadcaster
  processes after completion.
- `git diff --check` passed.

## Phase 0 - Confirm Baseline

- [x] Confirm `client.exe` normal jamming still works before broadcast work.
      Manual Windows/macOS native room test passed on this branch.
- [x] Confirm V2 listener-bot code remains available but is not the V3 path.
      Existing `listener_service.cpp` and listener V2 docs remain untouched.
- [x] Confirm branch is `v3-host-broadcast-listener`.
      Verified with `git status --short --branch`.
- [x] Confirm no `jam-app` or Convex changes are required before native proof.
      `C:\Users\Berkay\Downloads\jam-app` is clean on `main`; V3 native proof runs
      from this repo.

## Phase 1 - Local MediaMTX/nginx Stack

- [x] Add broadcast-only Docker Compose file for MediaMTX and nginx.
      Added `docker-compose.broadcast.yml`.
- [x] Pin MediaMTX to a known public-HLS-compatible version.
      `bluenviron/mediamtx:1.17.1` is pinned because `latest`/v1.18.x added HLS
      session-cookie behavior that broke normal public/CDN-style HLS playback.
- [x] Ensure compose does not start the SFU/server.
      Compose contains only `mediamtx` and `nginx` services.
- [x] Configure MediaMTX SRT ingest.
      Added `broadcast/mediamtx.yml` with SRT enabled on port `8890`.
- [x] Configure MediaMTX HLS output.
      Added fMP4 HLS output in `broadcast/mediamtx.yml`.
- [x] Tune local HLS latency for manual browser playback.
      MediaMTX uses `hlsSegmentDuration: 1s`, `hlsSegmentCount: 4`, and
      `hlsPartDuration: 250ms`; manual local playback was about 3.5 seconds.
- [x] Configure nginx as public HLS proxy in front of MediaMTX.
      Added `/hls/<room>/stream.m3u8` and segment proxy routes in
      `broadcast/nginx.conf`.
- [x] Configure nginx CORS for app/browser playback.
      HLS routes send `Access-Control-Allow-Origin: *`.
- [x] Configure nginx playlist no-cache headers.
      Playlist route sends `Cache-Control: no-cache, must-revalidate`.
- [x] Configure nginx segment cache headers.
      Segment route sends `Cache-Control: public, max-age=60, immutable`.
- [x] Add local health check for nginx.
      `GET /health` returns `ok`.
- [x] Add local health check for MediaMTX.
      `tools/broadcast-v3-local-verify.mjs` checks the MediaMTX API through a
      localhost-only compose port using local dev API credentials.
- [x] Verify compose starts and stops cleanly.
      Both local verifier modes bring compose up and down successfully.

## Phase 2 - `jam_broadcaster.exe` Test Tone

- [x] Add `jam_broadcaster.exe` target.
      Added CMake target in `CMakeLists.txt`.
- [x] Add `--test-tone` input mode.
      Implemented in `jam_broadcaster.cpp`.
- [x] Add SRT output configuration.
      `jam_broadcaster.exe` requires `--srt-url`.
- [x] Encode audio outside `client.exe`.
      Added `ffmpeg_srt_publisher.h`; FFmpeg encodes AAC and publishes MPEG-TS
      over SRT from the broadcaster process.
- [x] Push audio-only stream to local MediaMTX by SRT.
      Covered by `node tools\broadcast-v3-local-verify.mjs`.
- [x] Verify local nginx serves HLS playlist and media segments.
      The verifier fetches master playlist, media playlist, init segment, and
      media segment through nginx.
- [x] Add automated verifier for test tone -> SRT -> HLS.
      Added `tools/broadcast-v3-local-verify.mjs`.
- [x] Verify audible browser playback locally.
      Manual browser playback worked against
      `http://127.0.0.1:8080/hls/room-a/stream.m3u8`.

## Phase 3 - Localhost UDP IPC Input

- [x] Define broadcast IPC packet version/header.
      Added `jam_broadcast_ipc.h`.
- [x] Choose PCM payload format.
      Chosen format is mono Float32 little-endian.
- [x] Choose initial frame size.
      Current sender/receiver path supports up to 960 frames, matching 20 ms at
      48 kHz.
- [x] Add `jam_broadcaster.exe --ipc-port`.
      Implemented in `jam_broadcaster.cpp`.
- [x] Add sequence/drop accounting.
      Broadcaster logs received, dropped, written, write failures, and reconnects.
- [x] Add synthetic UDP PCM sender test utility.
      Implemented inside `tools/broadcast-v3-local-verify.mjs --ipc`.
- [x] Verify synthetic UDP PCM -> broadcaster -> SRT -> HLS.
      `node tools\broadcast-v3-local-verify.mjs --ipc` passed.
- [x] Verify invalid/short IPC packets do not crash broadcaster.
      Header and payload validation drops bad packets in `jam_broadcaster.cpp`.
- [x] Stress-test IPC packet loss under sustained pressure.
      `node tools\broadcast-v3-local-verify.mjs --ipc-stress` sends sustained
      valid IPC frames with malformed packets and sequence gaps. Latest run:
      969 packets received, 172 dropped counted, 969 frames written, 0 write
      failures, 0 reconnects.

## Phase 4 - `client.exe` Broadcast IPC

- [x] Add `client.exe --broadcast-ipc-port <port>`.
      Added startup parsing, validation, and config smoke logging in `client.cpp`.
- [x] Keep broadcast IPC disabled unless flag is present.
      Broadcast thread starts only through `enable_broadcast_ipc`.
- [x] Build mono broadcast mix from existing owner output mix plus owner mic.
      Added `enqueue_broadcast_mix`.
- [x] Exclude metronome from broadcast mix.
      Broadcast mix is enqueued before `mix_metronome_click`.
- [x] Respect owner mute for owner mic.
      Owner mic is included only when `mic_muted_` is false.
- [x] Respect owner participant volume/mute/pan.
      Broadcast starts from the existing owner output mix.
- [x] Respect owner master output volume.
      Broadcast starts from the already-scaled output mix.
- [x] Ignore OS/device/headphone mute and volume.
      Broadcast uses internal audio buffers, not device output capture.
- [x] Add non-blocking ring buffer between audio path and broadcast sender.
      Added bounded `moodycamel::ConcurrentQueue`.
- [x] Ensure audio callback never does SRT, encode, retry, or blocking socket I/O.
      Audio callback only prepares a small frame and calls `try_enqueue`.
- [x] Add localhost UDP sender thread.
      Added `broadcast_ipc_sender_loop`.
- [x] Drop broadcast frames when buffer/socket is pressured.
      Queue enqueue failures and UDP send failures are counted as drops.
- [x] Log basic broadcast frame/drop counters.
      `disable_broadcast_ipc` logs produced/sent/drop counters.
- [x] Build-check client broadcast IPC path.
      `cmake --build build --config Release --target client jam_broadcaster`
      passed.
- [x] Manually verify client broadcast IPC with real native audio.
      Verified with Windows owner client sending broadcast IPC to
      `jam_broadcaster.exe`; macOS performer audio was included in HLS.

## Phase 5 - Local Full Native Validation

- [x] Start local SFU/server.
      Verified with macOS SFU on `192.168.1.102:9999`.
- [x] Start one local SFU/server and one native owner client.
      Manual smoke test accepted JOIN with token and published owner broadcast
      IPC to local HLS.
- [x] Start two native clients in one room.
      Verified Windows owner and MacBook performer in `room-a`.
- [x] Start owner client with `--broadcast-ipc-port`.
      Windows owner used `--broadcast-ipc-port 39000`.
- [x] Start `jam_broadcaster.exe --ipc-port ...`.
      Broadcaster consumed localhost UDP IPC on port `39000` and published SRT
      to local MediaMTX.
- [x] Verify browser hears HLS.
      Manual browser playback worked from local nginx HLS.
- [x] Verify owner mic is included.
      Manual local stream included live room audio from the broadcasting owner
      path.
- [x] Verify owner mute mutes owner mic in broadcast.
      Manually confirmed in local Windows-owner/macOS-performer HLS test.
- [x] Verify metronome is not included.
      Manually confirmed: native jam clients can receive metronome sync, but HLS
      broadcast did not include the click.
- [x] Verify owner volume/mute changes affect stream.
      Manually confirmed participant strip volume/mute changes on the Windows
      owner affected the streamed macOS performer audio.
- [ ] Verify broadcaster crash does not break native jam audio.
- [ ] Verify broadcaster reconnect resumes HLS.
      Basic FFmpeg restart logic exists in `jam_broadcaster.cpp`, but it has not
      caused transient client send errors and one macOS rebuffer during manual
      kill/restart testing. HLS returned after restart, but this is not accepted
      as a clean pass yet.
- [x] Verify performer-to-performer audio remains clean.
      Manual Windows/macOS native jam audio stayed clean while broadcast was
      running.

## Phase 6 - VPS Same-Server Demo

- [ ] Keep SFU/server deployment governed by `VPS_SETUP.md`.
- [ ] Add separate broadcast/ingest VPS setup docs.
- [ ] Deploy MediaMTX/nginx compose on same VPS as SFU.
- [ ] Open required SRT UDP port.
- [ ] Configure `listen.<domain>` for nginx HLS.
- [x] Verify bad publish key is rejected.
      `node tools\broadcast-v3-local-verify.mjs --bad-key` passed against the
      local static SRT passphrase.
- [ ] Verify valid publish key creates HLS.
      Local static passphrase is verified, but production per-session keys are
      deferred.
- [ ] Verify Windows owner broadcasts to VPS.
- [ ] Verify macOS performer still hears clean jam audio.
- [ ] Verify browser listener plays HLS from `listen.<domain>`.
- [ ] Verify idle SFU plus ingest/HLS stack is lightweight enough for demo.

## Phase 7 - Multi-Room And Auth

- [x] Support concurrent SRT publish paths for different rooms in local stack.
      MediaMTX path regex accepts separate room paths and `overridePublisher: no`.
- [x] Verify room A and room B produce separate HLS outputs concurrently.
      `node tools\broadcast-v3-local-verify.mjs --multi-room` passed.
- [x] Define duplicate publisher behavior for same room.
      `overridePublisher: no` rejects replacing an active publisher.
- [ ] Enforce short-lived per-broadcast publish keys.
      Deferred until product/backend integration.
- [ ] Reject expired/revoked publish keys.
      Deferred until product/backend integration.
- [ ] Prevent publishing to another room's HLS path.
      Deferred until product/backend integration.

## Phase 8 - jam-app Process Launch

Deferred by current scope. Do not start this until native terminal validation is
accepted.

- [ ] Add app-side broadcaster launch config model.
- [ ] Launch `client.exe` for jamming as today.
- [ ] Launch `jam_broadcaster.exe` when owner enables Listener Mode.
- [ ] Stop broadcaster when owner disables Listener Mode.
- [ ] Stop broadcaster when owner leaves room.
- [ ] Add local broadcaster HTTP health endpoint if needed for app UI.
- [ ] Show listener status: stopped, starting, live, reconnecting, error.
- [ ] Show/copy public HLS URL.
- [ ] Surface useful broadcaster/ingest errors.

## Phase 9 - Convex Adapter

Deferred by current scope. Do not start this until native terminal validation and
jam-app process launch are accepted.

- [ ] Add room listener state fields.
- [ ] Authorize owner-only Listener Mode.
- [ ] Create short-lived ingest publish sessions.
- [ ] Return native broadcaster launch config to authenticated desktop app.
- [ ] Store public/unlisted HLS URL.
- [ ] Revoke/expire publish session when disabled.
- [ ] Reconcile stale live/error state when broadcaster/app disappears.
- [ ] Keep native binaries backend-agnostic.

## Out Of Scope For V3

- [x] Server-side listener bot joining rooms.
- [x] Neutral server-side room mix.
- [x] WebRTC listener delivery.
- [x] Video broadcasting.
- [x] Direct object-storage HLS upload.
- [x] Multi-region ingest/origin.
- [x] Host handoff.
- [x] Signed playback URLs.
