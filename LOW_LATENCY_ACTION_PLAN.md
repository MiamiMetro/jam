# Low-Latency Production Action Plan

Source: `LOW_LATENCY_AUDIT.md` rev b, verified against `main` at `23aebf8`.
Structure: this file is the phase tracker. Each phase gets its own detailed, executable
implementation plan under `docs/superpowers/plans/` when it is next up; phases are not
executed from this file directly.

Detailed plans:

- Phase 0 + 1: `docs/superpowers/plans/2026-07-02-phase0-1-ci-rt-safety.md` (written)
- Phase 2: `docs/superpowers/plans/2026-07-02-phase2-participant-snapshot.md` (written)
- Phase 5 Track A: `docs/superpowers/plans/2026-07-03-phase5-track-a-security.md` (written)
- Phase 5 Track B: `docs/superpowers/plans/2026-07-03-phase5-track-b-network.md` (written)
- Phase 5 Track C: `docs/superpowers/plans/2026-07-03-phase5-track-c-operations.md` (written)
- Phase 5 Track D: `docs/superpowers/plans/2026-07-03-phase5-track-d-testing.md` (written)
- Phase 5 Track E: `docs/superpowers/plans/2026-07-03-phase5-track-e-devices.md` (written)
- Ready-to-paste prompts for the sessions that finish each phase:
  `docs/superpowers/plans/2026-07-02-session-prompts.md`

## Current State

- Release build passes; full test suite passes 52/52 locally for Phase 5 Track C
  operations (verified 2026-07-03).
- Receive-side jitter/playout policy is in good shape and regression-tested.
- Phase 3 end-to-end latency is measurable in loopback smoke and device-backed baseline logs.
- CI exists and is green for the Phase 0+1 and Phase 2 PRs.

## Phase 0: CI (do this first)

Status: Done (2026-07-02, 32/32 tests, CI green)
Why first: it is the cheapest item in the whole plan and it gates every other phase.
The original ordering (CI inside the final phase) meant Phases 1–4 would land unguarded.

Work: GitHub Actions workflow — Windows Release build + full `ctest`, with `build/_deps`
cached. Windows-only initially (matches the dev platform); extend the matrix later.

Acceptance: a PR that breaks the build or any test shows a red check.

## Phase 1: RT Safety

Status: Done (2026-07-02, 32/32 tests, CI green)

Goal: make the audio callback trustworthy under participant churn, log storms, and queue
pressure. Detailed tasks, code, and per-task verification are in the Phase 0+1 plan doc.

Work (summary — the plan doc is authoritative):

- Logger: async overflow `block` → `overrun_oldest` (`logger.h:182`).
- De-log the callback-reachable decoder methods: `decode_into`, `decode_plc(float*, int)`,
  `reset` (`opus_decoder.h`). The vector-based overloads have no callers and are untouched.
- Remove every `Log::*` call from `audio_callback` (`client.cpp:4359, 4462-4469, 4475-4482,
  4503-4512, 4614-4645, 4668-4700, 4808-4823`); replace with atomic counters drained and
  logged by the io-thread cleanup timer.
- Pre-size RT-side queues and switch callback-side `enqueue` → `try_enqueue` with drop
  counters (`client.cpp:2066, 2091, 4998-4999`; `recording_writer.h:126, 294`).
- Deferred participant reclamation: removals park the `shared_ptr` in a graveyard; an
  io-thread reap destroys entries only when no callback snapshot references them
  (`participant_manager.h`), so destruction (heap free + `opus_decoder_destroy`) can never
  run on the audio thread. Covered by a new `participant_manager_self_test`.
- Assert the stream-stopped precondition in `clear_audio_path_queues()` (`client.cpp:1633`).

Acceptance (all mechanically checkable — see plan doc for exact commands):

- Zero `Log::`/`Logger` references inside the `audio_callback` function body (scoped grep).
- `opus_decoder.h` hot methods contain no `Log::` calls (scoped grep with expected output).
- New reclamation self-test passes, including the "live snapshot defers destruction" case.
- No allocating `enqueue(` remains in `client.cpp`/`recording_writer.h` callback paths.
- Release build passes; `ctest` passes 32/32 (31 existing + new self-test).

## Phase 2: Participant Snapshot

Status: Done (2026-07-02, 32/32 tests, CI green)

Goal: the audio callback never acquires `ParticipantManager::mutex_`.

Work (summary - the plan doc is authoritative): the io/control thread rebuilds immutable
participant snapshots on membership changes and publishes them via atomic `shared_ptr`
store; the audio callback loads the callback snapshot without taking
`ParticipantManager::mutex_`. GUI/stats read an uncapped published participant snapshot
plus immutable metadata snapshot, so they no longer contend with manager membership locks.
Decoder creation and registration logging now run outside the registration critical
section, and the Phase 1 graveyard still defers destruction until no published snapshot can
reference retired participants.

Acceptance: scoped grep proves no mutex acquisition in the callback path; participant
join/leave/timeout/metadata behavior covered by extending `participant_manager_self_test`;
build + full ctest + CI green.

## Phase 3: E2E Latency Measurement

Status: Done (2026-07-02, Release build + full ctest green, E2E loopback smoke green)

Goal: mouth-to-ear latency measurable in real sessions and asserted in tests.

Design decisions to make in the plan doc:

- Wire format: extend audio packets with a capture timestamp. Precedent for negotiation
  exists (`AUDIO_CAP_REDUNDANCY` capability bit, `protocol.h:43`); add a capability bit so
  mixed-version rooms keep working — the server relays payloads opaquely, so only clients
  must agree.
- Clock domain: sender stamps in server-clock domain using its existing offset
  (`server_clock_offset_ns_`, `client.cpp:3799-3821`); receiver converts with its own
  offset. Accuracy is bounded by RTT asymmetry — good enough for ms-level reporting.

Acceptance: per-participant one-way capture→playout latency in the Path panel and baseline
snapshots; a loopback smoke asserting steady-state one-way latency ≤ jitter target +
1 packet + callback + margin; build + full ctest.

Baseline for Phase 4 comparison: 2026-07-02 local loopback E2E smoke,
`node tools/e2e-latency-smoke.mjs --server-exe build/Release/server.exe --probe-exe build/Release/latency_probe.exe --frames 120 --jitter 4 --packets 650 --margin-ms 8`.
Budget: 23.0 ms (10.0 ms jitter target + 2.5 ms packet + 2.5 ms callback + 8.0 ms margin).
Phase 3 comparison baseline uses the first accepted direct smoke result: measured steady one-way capture-to-playout last 9.1425 ms, avg 9.90777 ms, max 11.5601 ms, steady_max 11.5601 ms; configured margin 8.0 ms, budget headroom 11.4399 ms. A logged rerun of the same command is recorded in `validation_logs/phase3-e2e-baseline/e2e-smoke.log`.
Device-backed snapshot also passed with Release binaries using `JAM_SERVER_EXE=build/Release/server.exe` and `JAM_CLIENT_EXE=build/Release/client.exe`; `validation_logs/phase3-e2e-baseline/client-a.log` and `client-b.log` contain `Baseline participant` lines with `e2e_ms last/avg/max=`.

## Phase 4: TX Path Collapse

Status: Done (2026-07-03, TX collapse merged in PR #13, CI green, Release
build green, full `ctest` 39/39 passed locally, E2E loopback smoke within
budget, 2h real-client churn soak stable)

Goal: capture-to-wire without the `asio::post` hop; bounded allocations; prioritized sender.

Implemented: audio packets are encoded and synchronously sent from the sender
thread on the existing UDP socket under `socket_mutex_`; no second socket was
introduced, so the server still observes the joined source `ip:port`. Control
traffic remains on the existing io-thread send path. The sender hot path uses a
fixed reusable packet pool for primary and redundant Opus packets instead of
per-packet vector allocation, and the sender thread enters MMCSS "Pro Audio" on
Windows when available.

Task 7 wake decision: `pcm_sender_cv_.notify_one()` remains enabled. The
no-notify validation regressed 30s Opus send-queue p99 from `0.211 ms` to
`2.592 ms` on client A and from `0.203 ms` to `3.124 ms` on client B, so the
callback wake was kept.

Validation snapshot (2026-07-03):

- Before baseline: pre-collapse commit `cd9a275`, built in
  `C:\Users\Berkay\Downloads\udpstuff-phase4-before`; logs in
  `validation_logs/phase4-tx-collapse/before`.
- After baseline: current Phase 4 code; logs in
  `validation_logs/phase4-tx-collapse/after`.
- 30s Opus send-queue p99 from `Baseline snapshot` logs:
  client A `0.189 ms -> 0.212 ms`, client B `0.247 ms -> 0.209 ms`.
  The p99 signal is mixed on this local device-backed run; client A regressed
  by `0.023 ms` while client B improved by `0.038 ms`. Opus max send-queue age
  decreased on both clients (`0.453 ms -> 0.412 ms`, `0.518 ms -> 0.426 ms`).
- Phase 3 accepted E2E baseline: last `9.1425 ms`, avg `9.90777 ms`, max
  `11.5601 ms`, steady_max `11.5601 ms`.
- Phase 4 local E2E rerun:
  `validation_logs/phase4-tx-collapse/e2e-smoke.log` reports last
  `9.4238 ms`, avg `9.98548 ms`, max `11.5315 ms`, steady_max `11.5315 ms`
  against the `23 ms` budget.
- Release build command logged in
  `validation_logs/phase4-tx-collapse/release-build.log`.
- Full test command logged in
  `validation_logs/phase4-tx-collapse/ctest-release.log`: `100% tests passed,
  0 tests failed out of 39` in `25.09 sec`.
- CI: green on PR #13 merge run
  `https://github.com/MiamiMetro/jam/actions/runs/28653147027`.
- Closure soak: `validation_logs/phase5-track-d/soak-2h-20260703-140217`
  ran the 7200s real-client churn soak with one stable client and one churn
  client, `summary.json` status `ok`, `1492` baseline snapshots, `1419`
  participant snapshots, `maxOverDeadline=0`, max absolute queue drift
  `2.05` packets against the `4` packet budget. Parsed Phase 4 fields from the
  same client logs show max baseline `opus_p99=2.144 ms`; the final stable
  7200s snapshot reports `opus_p99=0.158 ms`, Opus send-queue max `6.276 ms`,
  and participant `e2e_ms last/avg/max=10.0/10.0/10.8`.

Acceptance: closed. Structural TX collapse items are complete (no audio
`asio::post`, bounded packet reuse, sender-thread synchronous send on the
original socket, and MMCSS priority). The short before/after p99 signal was
mixed and is recorded above; the 2h soak accepts the phase as stable/bounded
rather than claiming a universal p99 improvement.

## Phase 5: Production Hardening

Status: Track A Done (2026-07-03, Release build + full `ctest` 45/45 passed
locally, signed security smokes passed), Track B Done (2026-07-03, Release
build + full `ctest` 47/47 passed locally), Track C Done (2026-07-03, Release
build + full `ctest` 52/52 passed locally), Track D Done (2026-07-03, 2h
real-client churn soak passed and CI green on PR #14), and Track E Done
(2026-07-03, Release build + full `ctest` 52/52 passed locally). Phase 5
remained split into independent tracks; Track E was executed alone in its own
session.

- Track A (security): Done on branch `phase5-track-a-security`. Signed JOINs
  now derive a per-session audio key from the validated HMAC join token;
  signed sessions reject plaintext audio, authenticate/decrypt secure audio,
  drop packet nonce replays, and re-encrypt relayed audio per recipient.
  The server tracks join-token nonce ownership and rejects reuse from a
  different endpoint. Protocol-aware rate limiting allows authenticated
  low-latency audio cadence while limiting unknown, malformed, replay,
  unknown-session, control, and abusive traffic. Insecure dev joins remain
  plaintext for local smokes only.
- Track B (network): Done on branch `phase5-track-b-network`. UDP sockets now
  prefer IPv6 dual-stack binds with IPv4 fallback, clients resolve both IPv4
  and IPv6 endpoints, IPv4 destinations are normalized to IPv4-mapped IPv6
  when needed, and outbound UDP flows request EF QoS via qWAVE on Windows or
  `IP_TOS`/`IPV6_TCLASS` elsewhere. qWAVE flow failures are cached per
  endpoint so unsupported paths warn once instead of retrying at packet rate.
- Track C (operations): Done on branch `phase5-track-c-operations`. The server
  can export machine-readable JSONL metrics snapshots with
  `--metrics-jsonl <path>`, including connected-client counts, drop counters,
  and the existing ingress/forward/ping sequence diagnostics. File logging now
  uses spdlog rotating sinks with defaults of `10 MiB` and `5` retained files,
  configurable via `--log-max-bytes` and `--log-max-files`; `basic_file_sink`
  is gone from `logger.h`. Normal server startup installs local crash reporting
  to `crash_reports/server` by default, with Windows minidumps through
  `DbgHelp` for unhandled exceptions and JSON metadata for explicit reports.
- Track D (testing): Done on branch `phase5-track-d-testing` from `f75eff7`,
  merged as PR #14. Added a repeatable impairment matrix harness, room-scale
  relay load benchmark, and real-client soak runner with log-budget assertions.
  CI-safe smokes are registered in CTest; the required multi-hour real-client
  soak passed locally.
- Track E (devices): Done on branch `phase5-track-e-devices`. JUCE device
  scans now query real channel counts and supported sample rates from created
  JUCE devices instead of fabricating 2-channel/48 kHz capabilities. Device
  inventory prints sample-rate lists, stream start rejects selected devices
  whose non-empty rate lists do not include the app's required 48 kHz clock,
  and input capture opens the selected physical input channel while preserving
  the existing mono network pipeline. The selected input channel is available
  through the bottom-bar `Ch:` picker, `--input-channel` /
  `--input-channel-index`, and persisted `jam_client.ini` preferences.

Track A local validation snapshot (2026-07-03):

- Release build command logged in `validation_logs/phase5-track-a/release-build.log`.
- Full test command logged in `validation_logs/phase5-track-a/ctest-release.log`:
  `100% tests passed, 0 tests failed out of 45` in `38.29 sec`.
- Security smoke logged in
  `validation_logs/phase5-track-a/server-security-smoke.log`; it verifies
  signed sessions reject plaintext audio, secure audio relays after
  per-recipient encryption, packet nonce replay is dropped, and join-token
  nonce replay from another endpoint is rejected.
- Session crypto self-test logged in
  `validation_logs/phase5-track-a/session-crypto-self-test.log`; status `ok`.
- Server rate limiter self-test logged in
  `validation_logs/phase5-track-a/server-rate-limiter-self-test.log`;
  status `ok`.
- Signed latency probe logged in
  `validation_logs/phase5-track-a/signed-latency-probe.log`: signed-token
  secure probe traffic delivered `120/120` packets with `0` invalid audio
  packets and steady E2E max `11.217 ms`.
- Signed room routing probe logged in
  `validation_logs/phase5-track-a/signed-room-routing-probe.log`: same-room
  secure audio and listener delivery passed, different-room leakage stayed
  false, stale duplicate forwarding stayed false, and rejoined sender
  forwarding passed.

Track D local validation snapshot (2026-07-03):

- Release build command logged in `validation_logs/phase5-track-d/release-build.log`.
- Full test command logged in `validation_logs/phase5-track-d/ctest-release.log`:
  `100% tests passed, 0 tests failed out of 42` in `42.20 sec`.
- Quick impairment matrix logged in
  `validation_logs/phase5-track-d/impairment-quick/summary.json`; status `ok`.
  Rows:
  - `low/clean`: steady E2E `11.3205 ms <= 29 ms`, queue drift `0.0125`
    packets, max queue `5`, max gap PLC run `0`.
  - `low/reorder`: steady E2E `11.5112 ms <= 29 ms`, queue drift `-0.13125`
    packets, max queue `5`, max gap PLC run `0`.
  - `balanced/burst`: steady E2E `62.983 ms <= 70 ms`, queue drift `2.62229`
    packets, max queue `6`, max gap PLC run `0`; burst loss produced `3`
    empty PLC frames inside budget.
- Quick relay load benchmark logged in
  `validation_logs/phase5-track-d/load-quick/summary.json`; status `ok`.
  Run shape: `8` clients, `4` senders, `3 s`, `480` frames. Sent `1200`
  packets, expected `8400` forwards, received `8400`, delivery ratio `1.0`,
  forward rate `2800 packets/s`, max receive gap `16.336 ms`.
- Soak parser smoke logged in `validation_logs/phase5-track-d/soak-parser-smoke.log`.
- Short real-client churn soak logged in
  `validation_logs/phase5-track-d/soak-short/summary.json`; status `ok`.
  Run shape: `20 s`, one stable client, one churn client, `8 s` churn interval.
  Parsed `9` baseline snapshots and `4` participant snapshots with
  `maxOverDeadline=0` and max absolute queue drift `0.92` packets.
- 2h real-client churn soak logged in
  `validation_logs/phase5-track-d/soak-2h-20260703-140217/summary.json`;
  status `ok`. Run shape: `7200 s`, one stable client, one churn client,
  `120 s` churn interval. Parsed `1492` baseline snapshots and `1419`
  participant snapshots with `maxOverDeadline=0` and max absolute queue drift
  `2.05` packets against the `4` packet budget. All `60` churn client runs and
  the stable client exited `0`.
- CI: green on PR #14 merge run
  `https://github.com/MiamiMetro/jam/actions/runs/28655644950`.

Track D accepted command:

```powershell
node tools/phase5-track-d-soak.mjs --server-exe build/Release/server.exe --client-exe build/Release/client.exe --seconds 7200 --churn-interval-seconds 120 --stable-clients 1 --churn-clients 1 --max-queue-drift-packets 4 --out-dir validation_logs/phase5-track-d/soak-2h-20260703-140217
```

Track E local validation snapshot (2026-07-03):

- Release build command: `cmake --build build --config Release --parallel 8`;
  passed.
- Full test command: `ctest --test-dir build -C Release --output-on-failure`;
  passed `52/52` in `307.70 sec`.
- Startup channel smoke command:
  `build\Release\client.exe --startup-config-smoke --input-channel 2 --log-file validation_logs\phase5-track-e\startup-config-smoke.log`;
  passed and logged `input_channel=1`, verifying the one-based CLI maps to the
  zero-based stored config on this two-channel input.
- Structural check:
  `rg -n "max_input_channels = input \? 2|max_output_channels = input \? 0 : 2|default_sample_rate = FALLBACK_SAMPLE_RATE" juce_audio_backend.cpp`;
  returned no matches.
- Local inventory output from the startup smoke showed non-fabricated device
  capabilities, including a 1-channel/44.1 kHz Steam Streaming microphone and
  an 8-channel Realtek digital output, plus explicit sample-rate lists.

Track B local validation snapshot (2026-07-03):

- Release build command: `cmake --build build --config Release`; passed.
- Targeted network smoke command:
  `ctest --test-dir build -C Release -R "udp_socket_config_self_test|server_dual_stack_relay_smoke|server_security_smoke|server_redundancy_relay_smoke|client_udp_endpoint_guard_smoke" --output-on-failure`;
  passed `5/5` in `2.48 sec`.
- Full test command:
  `ctest --test-dir build -C Release --output-on-failure`; passed `47/47` in
  `38.44 sec`.

Track C local validation snapshot (2026-07-03):

- Release build command: `cmake --build build --config Release`; passed.
- Targeted operations smoke command:
  `ctest --test-dir build -C Release -R "server_metrics_self_test|server_metrics_export_smoke|logger_self_test|crash_reporter_self_test|server_crash_report_smoke" --output-on-failure`;
  passed `5/5`.
- Full test command:
  `ctest --test-dir build -C Release --output-on-failure`; passed `52/52` in
  `38.72 sec`.
- Structural check: `rg -n "basic_file_sink" logger.h` returned no matches.
- Server metrics export is enabled with `--metrics-jsonl <path>` and writes
  JSONL snapshots using schema `jam_server_metrics_v1`.
- Server crash reporting writes JSON metadata using schema
  `jam_crash_report_v1`; Windows unhandled exceptions also attempt `.dmp`
  minidumps via `DbgHelp`.

## Deferred Follow-ups

- **Swap the session crypto primitive to libsodium ChaCha20-Poly1305** (noted 2026-07-03).
  Track A's `session_crypto.h` uses a hand-rolled HMAC-SHA256 keystream + HMAC tag over
  picosha2. It is functionally sound (encrypt-then-MAC, constant-time compare, nonce
  replay window) and its latency cost is unmeasurable at jam scale — signed-probe steady
  E2E max `11.217 ms` vs `11.53–11.56 ms` unsigned baselines — so this is NOT urgent.
  Swap it when either trigger fires:
  - Rooms grow beyond ~8 participants: the server decrypts + re-encrypts per recipient,
    and the picosha2-based keystream is roughly 10–100× slower than ChaCha20-Poly1305,
    making the relay the first throughput ceiling.
  - The project wants audited rather than home-grown crypto before wider hosting.
  Scope: replace the keystream/tag internals of `seal_audio_packet` / `open_audio_packet`
  in `session_crypto.h` (and key derivation if desired) with libsodium
  `crypto_aead_chacha20poly1305_ietf`; the wire format changes, so bump the secure-audio
  capability/version so old clients fail loudly at JOIN. Keep `session_crypto_self_test`
  and `server --security-smoke` green; rerun the signed latency probe to confirm the
  latency claim still holds. Effort: Small (one header + one FetchContent dependency).

## Production Gate

Do not call the app production-ready until all of these are true:

- Phase 0–2 complete (CI green, RT-safe callback, no callback mutex).
- E2E latency measured in real sessions (Phase 3).
- Packet authentication, payload encryption for signed audio sessions, token nonce replay
  protection, and joined-client rate limiting implemented (Track A).
- Device latency warnings or adaptation exist (audit "granted vs requested" finding).
- Soak/load/impairment tests pass against defined budgets (Track D).
- Server metrics, log rotation, and crash reporting exist (Track C).

## Execution Rules

- One branch per phase; one commit per task; build + full ctest after every task.
- Line numbers in plan docs are anchored to the commit named in that doc — match on the
  quoted code, not the number, once earlier tasks have shifted lines.
- A phase is "Done" only when its plan doc's acceptance commands have been run and their
  output recorded in the phase's PR description.
