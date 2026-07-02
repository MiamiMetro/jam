# Low-Latency Production Audit

Date: 2026-07-02 (rev b: corrected device-buffer default after cross-review — the client requests 120 frames, not 240; see the "Defaults" finding)
Scope: `main` @ `23aebf8` ("Build native release dependencies statically"), Windows 11, fresh Release build.
Method: full source read of the hot paths (`client.cpp`, `server.cpp`, `participant_info.h`, `participant_manager.h`, `juce_audio_backend.cpp`, `opus_encoder.h`, `opus_decoder.h`, `logger.h`, `jitter_policy.h`, `protocol.h`), pattern sweeps for locks/sleeps/allocations, a full Release build, and a full `ctest` run (31/31 pass). Older artifacts (`docs/audio-latency-stability-audit.md` @ `b539a85`, `archive/`) were treated as historical claims and re-verified against HEAD, not trusted.

Important context: the 2026-06-12 audit's critical findings (rate-controller targeting `queue_limit/2`, gap-wait of ~32 callbacks, packet-denominated jitter defaults, upward-only auto-jitter ratchet) are **genuinely fixed at HEAD** — I verified this in code, not just in the tracker: the playout rate controller now targets the jitter floor with a ±1-packet deadband and a ±0.5 % clamp (`client.cpp:2190-2233`), gap-wait is one packet interval (`client.cpp:2437-2446`), the queue is trimmed to `target + 3` (`client.cpp:2576-2606`), PLC runs are capped at 2 (`protocol.h:31`), and defaults are ms-denominated (20 ms jitter floor, 120 ms age limit, `protocol.h:23,32`). This audit is about what is *still* in the way.

---

## Executive Summary

**Verdict: strong prototype, not production-ready.** The architecture (client-side capture → Opus RESTRICTED_LOWDELAY → UDP → stateless SFU relay → receiver-side jitter buffer with rate-controlled playout) is fundamentally capable of ultra-low-latency jamming (~25–40 ms mouth-to-ear on a good WAN path with the `low` profile). The receive-side playout policy — historically the dominant problem — is now in good shape and regression-tested.

What still blocks "lowest practical latency":

1. **The real-time audio callback is not real-time-safe.** It takes a `std::mutex` shared with the GUI thread, can log through an async logger configured to *block* on overflow, can free heap memory (including an Opus decoder) when it drops the last `shared_ptr` to a removed participant, and enqueues to allocating queue variants. Each of these is a low-probability, high-cost stall (one missed 5 ms deadline = an audible dropout, which the auto-jitter controller then converts into permanently higher latency).
2. **The TX path takes two thread hops and ~4 heap allocations per packet** through unprioritized threads, adding avoidable scheduling latency and tail jitter between capture and the wire.
3. **There is no end-to-end latency measurement.** Audio packets carry no capture timestamp, so the single most important number — one-way mouth-to-ear latency — cannot be measured, asserted in tests, or shown to users.

What blocks production: no CI, no transport authentication/encryption (identity is IP:port), no metrics export, IPv4-only sockets, no rate limiting of joined clients, and a 7,300-line client god-file that concentrates all policy risk.

---

## Top Blockers

1. **RT-unsafe audio callback** (mutex, blocking logger, deallocation, allocating enqueues) — the remaining source of nondeterministic dropouts that no jitter policy can fix. *(Latency + correctness)*
2. **No capture timestamps / no E2E latency measurement** — you cannot optimize or regress-test what you cannot measure; today only per-segment proxies exist. *(Measurement)*
3. **TX pipeline: callback → sender thread → io thread**, all default-priority except the callback, with per-packet heap allocation — avoidable capture-to-wire latency and tail jitter. *(Latency)*
4. **No CI** — 31 good tests exist but nothing runs them automatically; latency-policy regressions (which this repo has demonstrably had) will re-enter silently. *(Production)*
5. **Unauthenticated, unencrypted transport** — spoofable endpoints, injectable audio, plaintext content, replayable join tokens. Fine for friends, disqualifying for a hosted product. *(Security)*
6. **Device latency is requested but not enforced or surfaced**: the client requests a 120-frame (2.5 ms) buffer, but shared-mode WASAPI typically grants far more; the granted size is read back and displayed but nothing warns or adapts when it blows the budget. Default packets are 480 frames (10 ms) vs the 120-frame callback, and the JUCE backend fabricates device capabilities (2 ch / 48 kHz hardcoded). *(Latency + production)*

---

## Findings

### [High] Audio callback can block on an async logger configured with a blocking overflow policy
- Severity: High
- Category: Real-time correctness / Latency
- Evidence: `logger.h:180-184` builds the spdlog async logger with `spdlog::async_overflow_policy::block` and `flush_on(warn)`. Log calls reachable from inside the audio callback: `client.cpp:4359` (`Log::info` "Jitter buffer ready"), `client.cpp:4818` ("rebuffering", fires on 1st and every 10th underrun), `client.cpp:4466/4478/4507` (`Log::warn` on PCM shape/size mismatch and decode failure, rate-limited mod 100 but still fired from the callback), `client.cpp:4641-4644/4674-4677` (`Log::debug` speaking transitions — filtered at the runtime `info` level set in `client.cpp:7012-7013`, but only after entering the logger), and `opus_decoder.h:91,111` (`Log::error` on every failed decode, called from the callback's decode path).
- Why it matters: spdlog's async enqueue takes the thread-pool queue mutex; with the `block` policy, a full 8192-slot queue (e.g., during a log storm from network churn) makes the TIME_CRITICAL audio thread **wait on the logging worker**. Even the uncontended case adds a lock and formatting-adjacent work to a 5 ms-deadline thread. One blocked callback = dropout; each dropout feeds `observe_auto_jitter_instability` (`client.cpp:4774`) which can raise steady-state latency.
- Recommendation: make the callback logging-free. Replace in-callback log sites with atomic event counters (most already exist) drained and logged by the GUI/io thread. If callback logging must stay, switch to `overrun_oldest` and a dedicated non-blocking sink — but removal is better.
- Validation: grep audit proving no `Log::`/`Logger` symbol is reachable from `audio_callback`; soak run with forced log-flood (e.g., unplug network) while asserting `callback_max_ns_` (`client.cpp:4306`) stays under deadline.
- Effort: Small

### [High] Audio callback takes a non-priority-inheriting mutex shared with GUI and network threads
- Severity: High
- Category: Real-time correctness / Latency
- Evidence: `client.cpp:4344` → `ParticipantManager::for_each` locks `mutex_` (`participant_manager.h:227`). The same mutex is held by: `get_all_info()` (`participant_manager.h:94-182`) — called per GUI frame via `client.cpp:519-521` and from stats paths `client.cpp:694, 2782, 3422` — which performs heap-allocating work under the lock (two `std::string` copies + `std::vector` growth per participant); `register_participant` (`participant_manager.h:23-51`) which calls `opus_decoder_create` **and `Log::info`/`Log::error` while holding the lock**; and `remove_timed_out_participants`/`exists`/`with_participant` on the io thread (per received audio packet, `client.cpp:3885, 3909, 3924`).
- Why it matters: Windows/macOS mutexes have no priority inheritance. The TIME_CRITICAL callback (`client.cpp:4326`) can sit behind a normal-priority GUI thread doing heap allocation (worst case: heap lock contention, page faults) or behind decoder creation. The hold time in the callback is short (≤32 pointer copies), but the *wait* time is unbounded.
- Recommendation: replace the locked map with an RCU-style snapshot: io thread mutates a copy and publishes an immutable `std::shared_ptr<const ParticipantArray>` via atomic store; callback does a lock-free acquire-load. At minimum: move logging and decoder creation outside the lock, and stop calling `get_all_info()` under the same mutex the callback uses (or make GUI reads use a periodically-published snapshot).
- Validation: assert no mutex acquisition in the callback (e.g., Tracy zones or a debug "RT-context" flag that aborts on lock); `callback_max_ns_` over a 1-hour GUI-heavy session.
- Effort: Medium

### [High] Participant teardown can run inside the audio callback (heap free + `opus_decoder_destroy` on the RT thread)
- Severity: High
- Category: Real-time correctness
- Evidence: `for_each` copies `shared_ptr<ParticipantData>` into a stack snapshot (`participant_manager.h:222-239`). Concurrently, the cleanup timer (10 s, `client.cpp:265`) calls `remove_timed_out_participants` (`participant_manager.h:185-205`), which erases the map entry. If the callback's snapshot holds the last reference when it goes out of scope, `~ParticipantData` runs **on the audio thread**: `unique_ptr<OpusDecoderWrapper>` → `opus_decoder_destroy` (`opus_decoder.h:56-63`) plus freeing a ~10 KB struct and two `std::string`s.
- Why it matters: deallocation takes the process heap lock and can fault; `opus_decoder_destroy` is not RT-safe. This fires exactly during participant churn — when the network is already misbehaving.
- Recommendation: on removal, move the `shared_ptr` onto a "graveyard" list owned by the io thread and reclaim it there after the callback has published a grace-period tick (or simply reclaim after N ms). Never let the callback's reference be the last.
- Validation: targeted test — join/leave a participant in a loop while the stream runs, assert zero over-deadline callbacks; ASan/TSan run of the same.
- Effort: Small

### [Medium] TX path: two thread hops, per-packet heap allocations, unprioritized threads
- Severity: Medium (typ. +0.1–2 ms, tail much worse under load)
- Category: Latency
- Evidence: capture callback packs samples and enqueues (`client.cpp:4962`, `enqueue_opus_send_samples` `client.cpp:2115-2168`) → `pcm_sender_loop` thread dequeues (`client.cpp:1938-1986`, condvar `wait_for(lock, 1ms, …)` at `client.cpp:1980-1984`) → Opus encode into a **freshly allocated** `std::vector` per packet (`client.cpp:1961-1963`) → `create_audio_packet_v2` allocates a `shared_ptr<vector>` per packet (`audio_packet.h:341-345`) → redundancy wrap allocates again (`client.cpp:2011, 2024-2025`) → `send()` does `asio::post` to the io thread (`client.cpp:1594`) which takes `socket_mutex_` (`client.cpp:1600`) and calls `async_send_to` (`client.cpp:1607`). Neither the sender thread nor the io thread sets priority — the only `SetThreadPriority` in the codebase is the callback's own (`client.cpp:4326`, grep confirmed). The callback also calls `notify_one()` per packet (`client.cpp:2170-2173`), a kernel call from the RT thread.
- Why it matters: every hop is a scheduler handoff a busy Windows box can delay by milliseconds; the encode+send threads compete at normal priority with GUI rendering. Per-packet allocations (≥4 with redundancy on) create heap traffic that also collides with finding #2. The 1 ms condvar timeout is only a fallback (the notify covers the normal path), but Windows timer granularity (15.6 ms default; no `timeBeginPeriod`/MMCSS anywhere — grep confirmed) makes that fallback poor.
- Recommendation: collapse to one hop — encode **and** `send_to` synchronously on the sender thread with a preallocated buffer pool (UDP `send_to` on a non-blocking socket effectively never blocks); raise the sender thread to time-critical / MMCSS "Pro Audio"; drop the `asio::post` for audio packets (keep it for control traffic). Alternatively encode in the callback (Opus complexity 5 @ 480 frames is well under 1 ms) and hand a ready datagram to a send-only thread.
- Validation: existing metrics already measure this — `observe_opus_send_queue_age` (`client.cpp:2644-2654`) and `observe_audio_packet_send_pacing` (`client.cpp:2674`): assert p99 send-queue age < 0.5 ms before/after.
- Effort: Medium

### [Medium] RX path: per-datagram allocation and single outstanding receive
- Severity: Medium
- Category: Latency
- Evidence: `do_receive` allocates a `std::make_shared<ReceiveState>` (~2 KB struct, `client.cpp:1483-1487`) **per datagram** and takes `socket_mutex_` per re-arm (`client.cpp:1558-1572`); only one receive is ever outstanding, and all parsing/validation/enqueue happens inline on the io thread before the next receive is armed (`client.cpp:1555`). Each accepted packet is then copied by value (~600 B `OpusPacket`) into the moodycamel queue (`client.cpp:3924-3995`, `participant_info.h:69`).
- Why it matters: at 100–400 pps/sender this works, but every datagram costs an allocation + lock, and a burst arriving while the io thread is busy (token validation, stats logging, GUI-triggered sends) waits in the socket buffer. The 4 MB `SO_RCVBUF` (`protocol.h:16`) prevents loss but converts overload into latency.
- Recommendation: recycle a fixed pool of `ReceiveState`s; keep parsing on the io thread but move anything slow (crypto, formatting) off it; optionally post several concurrent receives.
- Validation: packet-age-at-dequeue metrics already exist (`packet_age_last/avg/max_ns`); compare under a 4-participant flood via `multi_participant_jitter_probe`.
- Effort: Small–Medium

### [Medium] No end-to-end latency measurement; audio packets carry no capture timestamp
- Severity: Medium (High for a latency-focused project)
- Category: Production readiness / Measurement
- Evidence: `AudioHdrV2` has sequence, rate, frame count, codec — no timestamp (`protocol.h:125-134`). Receiver "packet age" starts at *arrival* (`client.cpp:3930`). NTP-style server clock sync exists (`client.cpp:3788-3821`, `SyncHdr` `protocol.h:55-60`) but is only consumed by the metronome (`client.cpp:4034-4055`). `latency_probe.cpp` measures synthetic pipeline segments, not a real session; `get_latency_info()` reports device latency (`juce_audio_backend.cpp:237-265`) but nothing composes the full chain.
- Why it matters: the project's success metric (mouth-to-ear ms) is invisible. Regressions like the ones fixed in `d07d566` were only found by ear plus manual runs. You also cannot honestly label presets ("~20 ms") without measuring.
- Recommendation: add a capture timestamp (server-clock domain, using the existing offset) to audio packets (extend V2 or add V3 alongside — the version plumbing already exists); surface per-participant one-way `capture→playout` in the Path panel and baseline snapshots; add a CI-runnable loopback assertion (sender+receiver in one process share a clock, no sync needed).
- Validation: loopback E2E number matches the analytic budget (§Latency Path) within ~2 ms; assertion added to a smoke test.
- Effort: Medium

### [Medium] No CI or automated test gate
- Severity: Medium
- Category: Testing / Production readiness
- Evidence: no `.github/` directory (checked); no other CI config found. The suite itself is decent: 31 tests including policy smokes and two network-impairment scenarios through `udp_impair_proxy` (`CMakeLists.txt:94-208`). I ran it: **31/31 pass in 23.65 s** on this machine.
- Why it matters: this codebase has already demonstrated that latency policy regresses silently (the entire 2026-06-12 audit cycle). The tests that would catch it exist but only run when someone remembers.
- Recommendation: GitHub Actions (or equivalent): Windows + macOS + Linux matrix, Release build, `ctest`, with the impairment smokes included. Cache `_deps`.
- Effort: Small

### [Medium] Transport security: unauthenticated, unencrypted audio; identity is IP:port; replayable join tokens
- Severity: Medium (Critical if hosted publicly)
- Category: Security
- Evidence: server accepts audio from any source whose `ip:port` matches a registered endpoint (`server.cpp:370-373`); client accepts server traffic by endpoint match only (`client.cpp:1507-1520`). Audio payloads are plaintext Opus. Join tokens are HMAC-SHA256 with expiry and constant-time compare (`performer_join_token.h:124-172` — well done), but the server keeps no nonce record, so a captured token replays until expiry (default TTL in dev tooling: 10 min, `tools/dev-jam.mjs`); claims are joined with unescaped `.`/`|` delimiters (`performer_join_token.h:76-79, 97-101`). Positive notes: `allow_insecure_dev_joins` defaults to false (`server.cpp:70`), empty-token joins are rejected (`server.cpp:315-319`), JOIN_REQUIRED replies to unknown endpoints are rate-limited to 1/s and the unknown-endpoint table is capped at 4096 (`server.cpp:520-525`, `server_config.h:15`).
- Why it matters: on-path or NAT-shared attackers can inject audio into a room or eavesdrop on performances; a leaked token grants room access until expiry. There is also no packet-rate limit on *joined* clients — one client can flood a room with the server amplifying ×(N−1).
- Recommendation: derive a per-session key at join (the HMAC infrastructure is already there) and add a per-packet auth tag; consider full encryption (libsodium secretbox fits datagrams well; DTLS is heavier). Track nonces server-side. Add a token-bucket per sender on the server.
- Validation: replay/inject test scripts against a local server; fuzz the packet parsers (validators exist — `audio_packet.h`, `message_validator.h` — and are a good start).
- Effort: Medium–Large

### [Medium] Granted device latency is measured but never enforced, surfaced as a warning, or acted on
- Severity: Medium
- Category: Latency / Configurability
- Evidence: *(rev b — an earlier version of this finding claimed a 240-frame default; that was wrong.)* The client requests a **120-frame (2.5 ms) device buffer** in its constructor (`client.cpp:279`, overriding the generic `audio_backend.h:19` default of 240), and that config flows unmodified into `start_audio_stream` (`client.cpp:435-446`); `--frames` overrides it (`client.cpp:7125-7126`). However, the *granted* buffer size is backend-dependent — shared-mode WASAPI commonly quantizes to ~10 ms periods — and the code reads the actual size back (`juce_audio_backend.cpp:199-203`) and displays it (`get_latency_info`, `print_latency_info` `client.cpp:450`) without warning or adapting when it far exceeds the request. Other defaults: 480-frame packets (10 ms, `opus_network_clock.h:13`), 20 ms jitter floor / 120 ms age limit (`protocol.h:23,32`), auto-jitter off at startup (verified by `client_startup_config_adaptive_smoke`, `CMakeLists.txt:159-163`). API ranking prefers ASIO → WASAPI Low Latency → Exclusive → Shared (`audio_backend_policy.h:19-33`; the name mismatch from the old audit is fixed), but absent ASIO the user lands on whichever WASAPI type JUCE exposes.
- Why it matters: the request is already lowest-latency; the gap is that a user on shared-mode WASAPI silently runs with 10–30 ms of device latency per direction while the app knows the granted numbers. Device latency is the largest controllable term left in the budget.
- Recommendation: at stream start, compare granted vs requested buffer and measured device latency against the active latency profile's budget; warn in the UI and suggest the lower-latency API/mode when available (Exclusive/Low-Latency WASAPI, ASIO); consider auto-selecting the best granted configuration.
- Validation: `--low-latency-check` (already exists, `client.cpp:6556-6557, 7033-7037`) extended to assert granted-buffer and device-latency budget, not just enumeration.
- Effort: Small

### [Medium] No network QoS marking (DSCP) on audio sockets
- Severity: Medium
- Category: Latency / Production readiness
- Evidence: grep for `IP_TOS|DSCP|qwave|QOS` across all sources — zero matches. Sockets get big buffers only (`client.cpp:1618-1627`, `server.cpp:89-97`).
- Why it matters: on home routers and managed networks, unmarked UDP competes with bulk traffic; EF/DSCP-46 marking measurably reduces queueing delay and jitter on the first hop (the usual bottleneck).
- Recommendation: set DSCP EF on client and server sockets (qWAVE `QOSAddSocketToFlow` on Windows — plain `IP_TOS` is ignored there; `setsockopt(IP_TOS, 0xB8)` on POSIX). Hypothesis to verify: benefit depends on the user's first-hop gear honoring DSCP; measure before claiming.
- Effort: Small

### [Medium] Allocating queue variant used from the RT callback; fragile stream-stop invariant
- Severity: Medium
- Category: Real-time correctness
- Evidence: `enqueue_pcm_send_frame`/`enqueue_opus_send_frame` call `moodycamel::ConcurrentQueue::enqueue` (`client.cpp:2066, 2091`), which allocates a new block when none is free (the broadcast path correctly uses `try_enqueue`, `client.cpp:4227`); `recording_writer_.enqueue` similarly enqueues ~4 KB `Block`s from the callback (`client.cpp:4163-4165`, `recording_writer.h:103-130`). Separately, `clear_audio_path_queues()` resets non-atomic callback-owned state (`opus_pcm_buffered_frames`, `decoder->reset()`, `client.cpp:1646-1664`); its single caller stops the audio stream first (`client.cpp:1411-1417`), so there is **no active race today** — but the safety depends on an undocumented invariant one refactor away from concurrent `opus_decode_float`/`opus_decoder_ctl` (UB).
- Why it matters: steady-state moodycamel recycles blocks, so allocations are rare — but "rare allocation on the RT thread" is still a dropout lottery ticket; the invariant issue is a latent correctness bug.
- Recommendation: pre-size the queues and use `try_enqueue` (drop-oldest on failure, counters exist); assert/document the stream-stopped precondition in `clear_audio_path_queues` (e.g., `assert(!audio_.is_stream_active())`).
- Effort: Small

### [Low] Server scale ceiling and per-packet overhead
- Severity: Low (fine for rooms of ≤ ~8; Medium at product scale)
- Category: Architecture / Latency
- Evidence: single io thread; per audio packet: one full copy (`server.cpp:390-391`), a heap-allocated endpoint vector (`client_manager.h:189-205`), 4–5 mutex acquisitions on `client_manager_` (uncontended — single thread — but per-packet), per-recipient stats map lookups (`server.cpp:709-806`), and for redundant datagrams a re-walk of children per recipient (`server.cpp:722-728`). Forward stats maps grow per (sender,target) pair with no eviction visible.
- Why it matters: relay work is O(room²) in packets×recipients; per-packet allocation and map churn put a ceiling in the low hundreds of pps×recipients per core and add relay jitter under load. The design itself (immediate relay, no re-encode, no batching) is correct for latency.
- Recommendation: keep the architecture; when scale matters, cache the room roster (invalidate on join/leave instead of rebuilding per packet), pool forward buffers, and add an eviction policy for stats maps. Benchmark: `multi_participant_jitter_probe` against a saturated room.
- Effort: Medium (deferred until scale is a goal)

### [Low] JUCE backend fabricates device capabilities; input constrained to mono, ≤2 channels
- Severity: Low
- Category: Production readiness / Cross-platform
- Evidence: `scan_devices` hardcodes `max_input_channels = 2`, `max_output_channels = 2`, `default_sample_rate = 48000` for every device (`juce_audio_backend.cpp:376-387`); input is opened with ≤2 channels and delivered to the pipeline as 1 channel (`juce_audio_backend.cpp:159-163`); channel selection beyond "first 1–2" doesn't exist.
- Why it matters: musicians' interfaces are routinely 4–18 channels; the guitarist whose instrument is on input 3 cannot use the app. Fabricated sample rates hide devices that only do 44.1 kHz (the resampler and `opus_network_clock` assume 48 kHz, `opus_network_clock.h:8`).
- Recommendation: enumerate real channel counts/rates from the created device; add an input-channel picker; decide explicitly what happens on 44.1 kHz-only hardware.
- Effort: Medium

### [Low] Client is a 7,295-line god-file; smokes live inside the shipping binary
- Severity: Low (Medium for velocity/risk)
- Category: Architecture
- Evidence: `client.cpp` = 7,295 lines / 344 KB containing network, playout policy, GUI glue, options parsing, and seven embedded smoke tests (`client.cpp:6540-6556`); by contrast the well-factored parts (`participant_info.h`, `jitter_policy.h`, `sequence_tracker.h`, `audio_packet.h`) each have real self-tests.
- Why it matters: the highest-risk code (playout policy, callback) is the least isolated; every change rebuilds and risks the whole client. Embedded smokes are actually a pragmatic plus — keep them — but the policy code they exercise should be extractable headers like the rest.
- Recommendation: continue the existing extraction pattern (policy → header + self-test). Do not rewrite; extract incrementally when touching code anyway.
- Effort: Large (amortized)

### [Low] Repo/runtime hygiene
- Severity: Low
- Category: Production readiness
- Evidence: stale root artifacts `server-watch-20260606-*.log` (106 KB), `imgui.ini`, `validation_logs/`, `archive/` (all untracked — `git ls-files` confirms none are committed); 20+ stale branches; sockets are IPv4-only (`client.cpp:254`, `server.cpp:86` — `udp::v4()`); logger `flush_every(3s)` thread and JUCE runtime intentionally leaked at exit (`juce_audio_backend.cpp:26-31`, commented, acceptable).
- Why it matters: IPv6 absence will bite CGNAT/mobile users; stale artifacts mislead future audits (this one included, by design of the exercise).
- Recommendation: delete/relocate stale artifacts, prune branches, add dual-stack socket support when hosting matters.
- Effort: Small

### [Info] What is already good (keep it)
- Category: Architecture
- Evidence: bounded lock-free jitter queue with sequence-aware admission and late-packet exception (`participant_info.h:47-419`); PLC capped at 2 + decoder reset + skip-to-newest on big gaps (`protocol.h:31`, `participant_info.h:228-252`); playout rate controller with deadband and drift-scale clamp (`client.cpp:2190-2233`); latency trim to target+3 (`client.cpp:2576-2606`); age-limit drain loop at dequeue (`client.cpp:4404-4419`); MTU-budgeted redundancy with depth policy (`protocol.h:35-40`, `client.cpp:1988-2028`); windowed symmetric auto-jitter (200-callback windows, `client.cpp:120-121, 2480-2554`); UDP rebind on sustained loss with cooldown (`client.cpp:1667-1775`); NTP-style clock sync (`client.cpp:3788-3821`); rich in-app metrics including callback deadline tracking (`client.cpp:4288-4320`) and TX/RX stage timings; impairment proxy + scripted smokes; static release linking (`CMakeLists.txt:14-19`). The server is a clean stateless relay — architecturally right for latency.

---

## Latency Path Analysis

One direction, performer A's instrument → performer B's ears, defaults (`balanced`: 120-frame *requested* device buffer `client.cpp:279`, 480-frame/10 ms Opus packets, 20 ms jitter floor, redundancy auto=2). Note: the *granted* device buffer is backend-dependent; shared-mode WASAPI commonly grants ~10 ms periods regardless of the 2.5 ms request, which shifts cost between rows 1/2 (bigger callback, less accumulation wait) without much changing the total.

| # | Stage | Mechanism | Cost (default, 120-frame callbacks granted) | Cost (`low` profile + ASIO) |
|---|-------|-----------|----------------|------------------------------------------------|
| 1 | Capture device buffer | JUCE callback; requested 120 frames (`client.cpp:279`), granted size read back at `juce_audio_backend.cpp:199-203` | 2.5 ms + device input latency (shared WASAPI ~10–20 ms; ASIO ~1–3 ms) | ~2.5 ms + ~1–3 ms |
| 2 | TX packetization | `opus_tx_accumulator_` fills 480 from 120-frame callbacks (`client.cpp:2145-2167`) | 0–7.5 ms (mean ~3.75) | ~0 (packet = callback = 120) |
| 3 | Send queue hop | callback → moodycamel → `pcm_sender_loop` (cv wake) (`client.cpp:1938-1986`) | ~0.05–1 ms (unprioritized thread) | same — **fix via TX collapse** |
| 4 | Opus encode | RESTRICTED_LOWDELAY, CBR, complexity 5 (`opus_encoder.h:65-74`) | 2.5 ms lookahead + <1 ms CPU | same |
| 5 | Post to io thread + send | `asio::post` + `socket_mutex_` + `async_send_to` (`client.cpp:1594-1614`) | ~0.05–1 ms | same — **fix via TX collapse** |
| 6 | Network → server | UDP, 4 MB socket buffers, no DSCP | path-dependent | path-dependent |
| 7 | Server relay | validate → copy → per-recipient `async_send_to` (`server.cpp:354-394, 667-690`), single thread | <0.5 ms | same |
| 8 | Network → receiver | UDP | path-dependent | path-dependent |
| 9 | RX io processing | parse/validate/copy → jitter queue (`client.cpp:3827-4011`) | <0.5 ms | same |
| 10 | **Jitter buffer** | floor 2×10 ms packets (`protocol.h:23,25`); age ceiling 120 ms; auto-jitter off | **~20 ms** | ~10 ms (4×2.5 ms) |
| 11 | Decode + PCM remainder | in-callback decode; leftover decoded frames carry over (`opus_pcm_buffer`, `client.cpp:4521-4608`) | <0.5 ms CPU + 0–7.5 ms buffered remainder (mean ~3.75; a 480-frame packet drains over four 120-frame callbacks) | ~0–2.5 ms |
| 12 | Playout device buffer | JUCE output | 2.5 ms + device output latency (shared WASAPI 10–30 ms) | ~2.5 ms + ~1–3 ms |

**Analytic total (excluding network): defaults ≈ 35–40 ms + 15–50 ms device latency on shared WASAPI ⇒ 50–90 ms; `low` profile + ASIO ≈ 18–25 ms.** Every buffer/queue in the chain is bounded and most are instrumented; the unbounded terms are gone. The dominant *controllable* remaining terms are device latency (stage 1/12 — API/mode choice) and the jitter floor (stage 10 — network-quality dependent). Stages 3 and 5 are pure overhead that the TX-collapse fix removes.

Async boundaries: audio callback ⇄ moodycamel queues (TX frames, RX packets, recording blocks, broadcast frames) ⇄ sender thread ⇄ io thread (asio) ⇄ GUI thread (mutex — finding #2). Copies per audio packet: TX ≈ 3 (accumulator, frame struct, packet vector) + redundancy re-copy; RX ≈ 3 (recv buffer → OpusPacket struct → queue → decode buffer).

---

## Measurement Gaps

- **One-way E2E latency**: no capture timestamps in audio packets (`protocol.h:125-134`) → mouth-to-ear latency is unmeasurable in real sessions. The clock-sync machinery to do it already exists.
- **Acoustic/full-loop verification**: nothing measures analog-out→analog-in round trip (the number users feel); `latency_probe` is synthetic.
- **Continuous callback-health assertion**: `callback_over_deadline_count_` exists at runtime but no test/soak asserts it stays 0 under stress (GUI churn, participant churn, log storms).
- **Impairment coverage**: `udp_impair_proxy` supports loss/jitter/bursts, but only two scripted scenarios run (`CMakeLists.txt:125-146`); no matrix over loss %, reorder, duplication, bandwidth caps; no assertion tying impairment level → resulting added latency.
- **Soak/drift**: clock-drift diagnostics exist (`client.cpp:2348-2424`) but no multi-hour automated soak validating stability (memory, queue depth, drift compensation).
- **Scale/load**: no benchmark of server relay throughput or client mixing with 8+ senders (`MAX_AUDIO_CALLBACK_PARTICIPANTS = 32`, `participant_manager.h:18`, is untested at limit).
- **CPU profiling**: no tracing hooks (Tracy/ETW) around the callback and io thread; deadline stats are aggregate only.
- **Metrics export**: all observability is spdlog text + in-app ImGui panel; nothing machine-scrapable for a hosted server (no Prometheus/JSON stats endpoint).

---

## Production Readiness Checklist

- [x] Low-latency codec path (Opus RESTRICTED_LOWDELAY, CBR, FEC off, DTX off — `opus_encoder.h:65-74`)
- [x] Bounded jitter buffer with loss concealment, age limit, latency trim, and regression tests
- [x] Playout rate control (±0.5 %) for drift/queue management
- [x] Packet redundancy with MTU budget and depth policy
- [x] Sequence tracking, gap/recovery/reorder accounting on both client and server
- [x] Join authentication (HMAC-SHA256 tokens, expiry, constant-time compare)
- [x] Reconnect/rejoin logic (JOIN_REQUIRED, rebind-on-loss with cooldown, join retry timer)
- [x] Network impairment test tooling (`udp_impair_proxy`) wired into tests
- [x] In-app latency/health metrics (callback deadlines, stage timings, RTT, queue depths)
- [x] Self-test suite (31 tests; all passing on this machine)
- [x] Static release linking for distribution
- [ ] RT-safe audio callback (no locks/logs/allocs/frees) — **findings 1–3**
- [ ] End-to-end latency measurement (capture timestamps) — **finding 6**
- [ ] CI (build + ctest on 3 platforms)
- [ ] Per-packet transport auth/encryption; token replay protection
- [ ] Per-client rate limiting on the server
- [ ] DSCP/QoS marking
- [ ] IPv6 / dual-stack sockets
- [ ] Metrics export for hosted servers (beyond text logs)
- [ ] Crash reporting / minidumps
- [ ] Real device-capability enumeration (channels > 2, non-48 kHz rates)
- [ ] Soak tests, load tests, impairment matrix
- [ ] Deployment story for the server beyond `docker-compose.broadcast.yml` (restart policy, log rotation — `basic_file_sink` never rotates, `logger.h:147`)

---

## Recommended Roadmap

### 1. Immediate (days) — make the callback trustworthy and the number visible
1. Strip all `Log::*` calls from the audio-callback call graph; replace with counters (finding 1). Change logger overflow policy to `overrun_oldest` regardless.
2. Deferred participant reclamation — never free on the RT thread (finding 3).
3. Switch RT-side `enqueue` → `try_enqueue` with pre-sized queues; assert stream-stopped in `clear_audio_path_queues` (finding: allocating enqueues).
4. At stream start, compare granted device buffer / measured device latency against the active profile's budget; warn and suggest a lower-latency API/mode when the grant blows it (the 120-frame request at `client.cpp:279` is already right — enforcement/surfacing is what's missing).
5. Add a soak assertion mode: run 30 min, exit non-zero if `callback_over_deadline_count_ > 0` or queue depth drifts.

### 2. Architectural (1–2 weeks)
6. Replace `ParticipantManager`'s mutex with a published immutable snapshot (RCU-style) for the callback; GUI reads a periodic snapshot (finding 2).
7. Collapse the TX path: encode + synchronous `send_to` on one MMCSS-boosted thread with a buffer pool; audio packets stop traversing `asio::post`/`socket_mutex_` (finding 4).
8. Add capture timestamps (server-clock domain) to audio packets and surface one-way latency per participant in the Path panel and baseline snapshots (finding 6). This is the keystone for everything after.
9. Recycle `ReceiveState`s on the RX path (finding 5).

### 3. Measurement and testing (parallel with #2)
10. Stand up CI: 3-OS matrix, Release build, full ctest including impairment smokes.
11. E2E latency assertion test using the new timestamps (loopback, single clock): fail if steady-state one-way > jitter_target + packet + callback + margin.
12. Impairment matrix (loss 0/1/5 %, reorder, 100 ms bursts) × profiles, asserting bounded PLC runs and bounded added latency.
13. Multi-hour soak with drift + participant churn; server relay load benchmark.

### 4. Production hardening
14. Session-key per-packet authentication (extend the existing HMAC join flow), then payload encryption; server-side nonce tracking; per-sender token-bucket rate limiting.
15. DSCP EF marking (qWAVE on Windows); dual-stack sockets.
16. Metrics export on the server (JSON/Prometheus endpoint or structured stat lines), log rotation, crash reporting.
17. Real device-capability enumeration and input-channel selection in the JUCE backend.
18. Continue extracting policy from `client.cpp` into tested headers as those areas are touched.

---

## Commands Run

| Command | Purpose | Result |
|---|---|---|
| `ls -la` (root), `ls docs tools archive desktop build cmake` | Map repo structure | C++ app + Electron shell remnants + probes/tools; stale root logs present |
| `git log --oneline -20`, `git branch -a` | Establish HEAD and history | HEAD `23aebf8`; audit-fix commit `d07d566` after prior audit `5c92296`; 20+ stale branches |
| `wc -l` on 17 key sources | Size the hot files | `client.cpp` 7,295 lines; `server.cpp` 1,230 |
| `rg` sweeps: `sleep_for\|Sleep(`, `std::mutex\|lock_guard`, `async_receive_from\|send_to`, `SetThreadPriority\|timeBeginPeriod\|AvSetMmThreadCharacteristics`, `IP_TOS\|DSCP\|qwave`, `Logger::instance().init`, `audio_callback`, `create_audio_packet_v2`, `clear_audio_path_queues` | Locate locks, sleeps, RT hazards, socket options, entry points | Findings above; notable absences: no MMCSS/timeBeginPeriod, no DSCP, one `SetThreadPriority` (callback only) |
| Full reads of `protocol.h`, `participant_info.h`, `participant_manager.h`, `jitter_policy.h`, `opus_encoder.h`, `opus_decoder.h`, `juce_audio_backend.cpp`, `logger.h`, `client_manager.h`, `server_config.h`, `performer_join_token.h`, `audio_backend.h`, `opus_network_clock.h`, `audio_backend_policy.h`, `recording_writer.h` (partial), `gui.cpp` (loop), targeted reads of `client.cpp` (receive/send/callback/policy/main) and `server.cpp` (relay/join/stats) | Verify behavior at HEAD, re-check prior audit claims | Prior critical findings confirmed fixed; new findings as listed |
| `git ls-files \| grep -E "server-watch\|validation_logs\|imgui.ini\|\.log$"` | Check whether log artifacts are committed | None committed (untracked clutter only) |
| `cmake --build build --config Release --parallel 8` | Fresh full Release build | Succeeded (exit 0) |
| `ctest --test-dir build -C Release --output-on-failure` | Run the full suite | **31/31 passed, 23.65 s** |
| `head` of `tools/baseline.mjs`, `tools/dev-jam.mjs` | Assess measurement tooling | Loopback dev-jam + baseline snapshot harness exist (dev secret hardcoded — dev-only) |

Unverified items are labeled as hypotheses in their findings (DSCP benefit depends on first-hop gear; shared-WASAPI device latency figures are typical values, not measured on this machine — run `client --low-latency-check` and read the Path panel on target hardware to fill them in).
