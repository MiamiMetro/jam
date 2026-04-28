# Jam Engine Phase 3 Plan

## Phase

Phase 3 is Performer SFU Room And Auth Contract.

The goal is to add standalone room-aware routing and local signed-token validation inside this repo.

Convex and Electron remain out of scope.

## Scope

Included:

- extended JOIN metadata
- SFU-local in-memory room routing
- same-room forwarding
- different-room isolation
- short-lived signed JOIN tokens
- local token generation tool or script
- SFU-local token validation
- explicit insecure dev joins
- tests/probes for routing and token rejection
- room-local participant metadata for ImGui names
- JS dev join-token helper for pasteable local client commands
- bounded unknown UDP handling and log throttling

Excluded:

- Convex token minting
- Electron process launching
- official server deployment
- production-grade UDP DDoS protection
- community server registration
- listener/HLS mode
- product room UI
- backend presence
- moderation controls

## Current Baseline

Accepted from prior phases:

- Windows WASAPI audio baseline works.
- macOS/CoreAudio audio baseline works.
- PCM mode is stable.
- Opus mode is stable after macOS TX/RX frame pacing fix.
- Listener/HLS is intentionally outside the performer-jamming path.

Current SFU behavior before Phase 3:

- server forwards audio between clients without product room isolation.
- plain join exists for local/probe style use.
- permanent rooms do not exist in the SFU.
- auth/token validation is not active in the jam server.

## Implementation Checklist

- [x] Define the extended JOIN wire shape.
- [x] Add client startup parsing for room/user/token fields if missing.
- [x] Send extended JOIN metadata from client to SFU.
- [x] Update probes to use the same structured JOIN path as clients.
- [x] Add SFU client state for room id, profile id, display name, join mode, join time, and last alive.
- [x] Change SFU forwarding so audio is sent only to clients in the same room.
- [x] Add timeout cleanup for room/client state.
- [x] Define signed token format in C++ code or a small shared helper.
- [x] Add local token generator script.
- [x] Add SFU configuration for `--server-id`, `--join-secret`, and `--allow-insecure-dev-joins`.
- [x] Validate secure JOINs locally.
- [x] Reject missing/expired/wrong-room/wrong-user/malformed/signature-invalid tokens.
- [x] Log denial reasons without logging full tokens.
- [x] Preserve insecure local audio testing behind explicit dev flag.
- [x] Update docs with exact dev commands.
- [x] Broadcast same-room participant metadata for ImGui display names.
- [x] Replace compiled token issuer with JS dev join-token helper.
- [x] Add bounded unknown UDP handling so unjoined packet spam is dropped without per-packet log floods.
- [x] Document that Phase 3 hardening is application-level only, not public-internet DDoS protection.

## Hardening Boundary

Phase 3 should handle unauthorized UDP safely enough for development and controlled testing:

- unknown audio packets must not create client, performer, or room state
- repeated unknown UDP traffic should be dropped with bounded memory use
- repeated unknown UDP traffic should use throttled or summarized logs, not one warning per packet
- valid joined audio traffic should keep the performer alive even if an ALIVE packet is delayed

This is not production-grade UDP DDoS protection.

Full public-internet server hardening is deferred to the roadmap's pre-production SFU hardening gate before official or community servers are exposed publicly.

## Validation Log

2026-04-28:

- Built `client` successfully in Debug.
- Built `latency_probe` successfully in Debug.
- Built `room_routing_probe` successfully in Debug.
- Built `server` successfully in Release. Debug server link was blocked because `build\Debug\server.exe` was already running.
- Ran `latency_probe` with structured JOIN against insecure-dev server on port `10099`: exit `0`, received `220/220` packets.
- Ran `room_routing_probe` against insecure-dev server on port `10100`: exit `0`, `same_room_received=1`, `different_room_received=0`.
- Ran `room_routing_probe` against secure-default server with no token/secret on port `10101`: exit `2` as expected, server rejected JOIN packets for missing token and dropped unjoined audio.
- Built the compiled token tool successfully in Debug before replacing it with the JS dev helper.
- Ran the token tool before replacement: emitted `v1.<expiresAtMs>.local-dev.room-a.user-a.performer.<nonce>.<signature>`.
- Ran `room_routing_probe` against secure signed-token server on port `10102`: exit `0`, `same_room_received=1`, `different_room_received=0`.
- Ran token rejection probes against secure server on port `10103`: invalid signature, wrong server id, expired token, wrong room id, wrong profile id, and malformed token all failed with exit `2` and clear server denial logs.
- Rebuilt `latency_probe` successfully in Debug after auth changes.
- Debug `server` link remains blocked by a running `build\Debug\server.exe`; Release `server` builds successfully.
- Pinned PicoSHA2 to `v1.0.1` and reran secure signed-token room routing on port `10104`: exit `0`, `same_room_received=1`, `different_room_received=0`.

2026-04-28 stabilization rerun:

- Built `server` successfully in Release.
- Built `server` successfully in Debug after the previous executable lock cleared.
- Built `client`, `latency_probe`, and `room_routing_probe` successfully in Debug.
- Ran `latency_probe` against insecure-dev server on port `10200`: exit `0`.
- Ran `room_routing_probe` against insecure-dev server on port `10211`: exit `0`, `same_room_received=1`, `different_room_received=0`.
- Ran `room_routing_probe` against secure-default server with no token on port `10212`: exit `2` as expected; server rejected missing token and dropped unjoined audio.
- Ran `room_routing_probe` against secure signed-token server on port `10213`: exit `0`, `same_room_received=1`, `different_room_received=0`.
- Ran token rejection probes against secure server on port `10214`: invalid signature, wrong server id, expired token, wrong room id, wrong profile id, and malformed token all failed with exit `2` and clear denial logs.
- Ran `room_routing_probe` with signed tokens against server without `--join-secret` on port `10215`: exit `2` as expected; server rejected joins with `join secret not configured`.
- Scanned stabilization server logs for `v1.`, `dev-secret`, and `wrong-secret`; no token or secret values were logged.
- Replaced the compiled token issuer with `tools/dev-join-token.mjs`, which prints a token and pasteable client command.
- Added same-room participant metadata broadcast so ImGui can show `display_name` when known, with `User #<id>` fallback.
- Rebuilt `server` Release, `client` Debug, and `room_routing_probe` Debug after participant metadata changes.
- Ran secure signed-token room routing after metadata changes on port `10221`: exit `0`, `same_room_received=1`, `different_room_received=0`.
- Fixed `room_routing_probe` to ignore control metadata packets while waiting for audio packets.
- Removed the separate performer/legacy join split. Client, listener bot, latency probe, and room routing probe now all use the same structured `JOIN` packet.
- Ran `latency_probe` with structured `JOIN` against insecure-dev server on port `10232`: exit `0`, received `220` packets.
- Ran `room_routing_probe` with structured signed-token `JOIN` against secure server on port `10233`: exit `0`, `same_room_received=1`, `different_room_received=0`.
- Fixed client control sends so JOIN/ALIVE/LEAVE use owned async buffers instead of the shared control buffer.
- Rebuilt `client`, `server`, and `room_routing_probe` in Debug after the control-buffer fix.
- Ran `room_routing_probe` with structured signed-token `JOIN` against secure server on port `10240`: exit `0`, `same_room_received=1`, `different_room_received=0`.
- Added `tools/dev-jam.mjs` so local dev can use `node tools/dev-jam.mjs server` and `node tools/dev-jam.mjs client a|b|c` with editable defaults at the top of the script.
- Ran `node --check tools/dev-jam.mjs` and `node --check tools/dev-join-token.mjs`: both passed.
- Added bounded unknown UDP tracking in the SFU so repeated unjoined audio packets are dropped with summarized logs instead of per-packet warnings.
- Added `node tools/dev-jam.mjs spam` for local unknown UDP spam validation. `JAM_DEV_PORT` can override the default port for isolated test runs.
- Rebuilt `server` successfully in Release after unknown UDP hardening. Debug `server.exe` was locked by a running process during this build attempt.
- Rebuilt `client`, `latency_probe`, and `room_routing_probe` successfully in Debug after unknown UDP hardening.
- Ran `latency_probe` against insecure-dev Release server on port `10300`: exit `0`, received `220/220` packets.
- Ran `room_routing_probe` against insecure-dev Release server on port `10300`: exit `0`, `same_room_received=1`, `different_room_received=0`.
- Ran `room_routing_probe` against secure signed-token Release server on port `10303` before spam: exit `0`, `same_room_received=1`, `different_room_received=0`.
- Ran `JAM_DEV_PORT=10303 node tools/dev-jam.mjs spam`: sent `1000` unjoined audio packets. Server emitted one endpoint warning and periodic summary logs (`303` then `363` drops), not one warning per packet.
- Ran `room_routing_probe` against the same secure Release server on port `10303` after spam: exit `0`, `same_room_received=1`, `different_room_received=0`.
- Ran auth rejection probes against secure Release server on port `10304`: missing token, wrong secret, and malformed token all failed with exit `2`.
- Scanned Phase 3 validation logs for `v1.`, `dev-secret`, and `wrong-secret`; no token or secret values were logged.

## Test Plan

Build:

```bash
cmake --build build --target server
cmake --build build --target client
cmake --build build --target latency_probe
cmake --build build --target room_routing_probe
```

Routing tests:

- same-room two-client audio forwards
- different-room clients do not receive each other
- three clients split across two rooms route only within room
- disconnect/timeout removes endpoint from room state

Auth tests:

- valid token accepted
- expired token rejected
- wrong room id rejected
- wrong profile/user id rejected
- wrong server id rejected
- malformed token rejected
- invalid signature rejected
- missing token rejected when secure JOIN is required
- missing token accepted only with explicit insecure dev flag

Abuse guard tests:

- unjoined audio spam does not create room/client state
- unjoined audio spam does not produce per-packet warning logs
- secure same-room routing still works after unjoined audio spam

Audio regression tests:

- Opus accepted mode still works after room/auth changes.
- PCM accepted mode still works after room/auth changes.
- macOS Opus normalized-buffer behavior is not changed by room/auth work.
- Windows build still passes.

## Dev Command Shape

Secure local server:

```bash
./build/Debug/server.exe --port 9999 --server-id local-dev --join-secret dev-secret
```

Insecure local server for audio debugging:

```bash
./build/Debug/server.exe --port 9999 --allow-insecure-dev-joins
```

Token generation shape:

```bash
node tools/dev-join-token.mjs --secret dev-secret --server-id local-dev --room room-a --user user-a --display-name "User A"
```

Simple local launcher:

```bash
node tools/dev-jam.mjs server
node tools/dev-jam.mjs client a
node tools/dev-jam.mjs client b
node tools/dev-jam.mjs client c
node tools/dev-jam.mjs spam
```

For isolated local test ports:

```bash
JAM_DEV_PORT=10303 node tools/dev-jam.mjs spam
```

Client join shape:

```bash
./build/Debug/client.exe --server 127.0.0.1 --port 9999 --room room-a --user-id user-a --display-name "User A" --join-token <token> --codec opus --frames 120
```

## Acceptance

Phase 3 is accepted when:

- jam SFU can host multiple in-memory rooms
- same-room clients hear each other
- different-room clients are isolated
- secure signed JOINs work without Convex
- invalid secure joins are rejected clearly
- insecure dev joins require an explicit flag
- ImGui shows display names for performer participants when metadata is known
- accepted Phase 1/2 audio modes still work
- docs contain exact standalone dev commands

## Completion Rule

Do not start Electron/Convex integration until this standalone room/auth contract passes.

Do not start official/community server productization until this contract is stable enough to deploy manually.

Do not include listener/HLS mode in this phase.
