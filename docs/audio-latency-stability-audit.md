# Audio Latency / Stability Audit

Date: 2026-06-12
Scope: `main` @ `b539a85` (user confirmed: other branches are stale — main is the only source of truth).
All 24 ctest tests pass on a fresh Release build (`ctest -C Release`, 25.3 s, 0 failures).

---

## 1. Summary

The app cannot currently hit both goals because **the receive-side playout policy — not the network and not the codec — dominates both the latency floor and the audio corruption**. Three client-side control loops interact badly:

1. The **playout rate controller targets `queue_limit / 2` (= 32 packets ≈ 320 ms at the default 10 ms packets)** instead of the jitter target. With any normal queue depth it pins the resampler at its 0.95× clamp, which (a) plays everything ~5 % slow and ~0.9 semitone flat, and (b) makes the receive queue grow until the 180 ms packet-age limit starts discarding packets.
2. Every age-drop / PLC / underrun / decoder-reset counts as an "instability event" that **raises the jitter target by +1 packet and forces a rebuffer pause** — so the system's own latency creep (from item 1) feeds the jitter ratchet.
3. The jitter buffer is denominated in **packets**, so the "stable" packetization choices (10/20 ms frames) silently multiply jitter latency: the default auto-start of 14 packets is 140 ms at 10 ms packets, 280 ms at 20 ms packets.

The evidence points **primarily at jitter/Opus playout policy and configuration defaults**, with the VPS path loss/reorder bursts (documented in `archive/md-artifacts/root/VPS_ROBOTIC_AUDIO_HANDOFF.md`) as a real but *secondary* aggravator. This is consistent with the user's observation that running the server locally on `0.0.0.0` did not fix latency: the dominant latency terms are identical on LAN and VPS because they are client-side policy, not network.

The Opus frame-count adaptation commits (`bbf188a`, `a0d4f17`, `5928970`) are now **measure-only** at HEAD ("manual mode" — they log but never act, after revert `f474ee4`). That was the right call: as shipped they were three upward-only ratchets sharing one knob with no de-escalation path.

---

## 2. Findings

| # | Severity | Finding | Evidence | Likely cause | Confidence | Recommended action |
|---|----------|---------|----------|--------------|------------|--------------------|
| F1 | **Critical** | Playout rate controller targets `queue_limit/2` = 32 packets (~320 ms @10 ms packets), not the jitter target. Resampler pins at the 0.95 clamp → constant −5 % speed/pitch, receive queue grows until the age limit fights back. | `opus_playout_rate_ratio()` `client.cpp:1999-2012`: `queue_error = queued − target`, `target = opus_playout_target_queue_packets()` `client.cpp:2230-2238` = `max(jitter_floor, min(32, opus_queue_limit/2))`; default queue limit 64 ⇒ target 32. With queue ≈ 6–14, `ratio = clamp(1 + error·0.01, 0.95, 1.04) = 0.95`. Introduced by `9cddd37 Target Opus playout to receive headroom` after `f002518 Stop trimming Opus receive queue to target` removed the trim. | Target meant "headroom midpoint" was wired into a controller that needs the *desired depth*. | High (static analysis; runtime confirmation pending — see §7 diagnostics step 1) | Make the controller target `jitter_buffer_min_packets` with a deadband; tighten the ratio clamp to drift-scale (≈ ±0.5 %); handle bursts by skipping packets, not by 5 % resampling. |
| F2 | **Critical** | Latency-creep / age-drop / instability feedback loop: queue grows (F1) → packets exceed `DEFAULT_JITTER_PACKET_AGE_MS = 180` → age-drop at dequeue → `observe_auto_jitter_instability()` → jitter target +1 **and** `buffer_ready = false` (rebuffer pause) → repeat. Latency saturates at the age limit (~180 ms) with periodic glitches; jitter target ratchets toward 32. | Age check + instability call `client.cpp:3786-3799`; instability raises target and forces rebuffer `client.cpp:2262-2292` (`buffer_ready.store(false)` at `client.cpp:2286`); age default `protocol.h:30`. | The instability detector cannot distinguish "network got worse" from "my own controller overfilled the queue". | High | After F1 is fixed, only count instability events whose cause is network-side (PLC from real gaps), and never force a rebuffer just because the target rose by 1. |
| F3 | **High** | Jitter defaults are far above jamming budget and are denominated in packets: auto mode starts at 14 packets (140 ms @ default 10 ms frames) and can only decay to floor 6 (60 ms). Auto jitter is on by default. | `DEFAULT_OPUS_AUTO_START_JITTER_PACKETS = 14`, `DEFAULT_OPUS_JITTER_PACKETS = 6` `protocol.h:23-24`; `opus_auto_start_jitter_packets()` `jitter_policy.h:12-16`; default frame count 480 = 10 ms `opus_network_clock.h:11-13` (changed from 240 in `f336349`). | Defaults tuned for VPS robustness after the robotic-audio episodes; never re-tuned for jamming feel. | High | Re-denominate jitter in ms; default floor ~20–30 ms, auto-start ~40 ms; scale packet count from ms when frame count changes. |
| F4 | **High** | Asymmetric auto-jitter ratchet: +1 packet *instantly* per event vs −1 packet per **2000 consecutive clean callbacks** (≈10 s @5 ms callbacks; any single PLC resets the counter). Going 14→6 needs ~80 s of flawless audio. Under any periodic disturbance the target only climbs (cap 32 = 320 ms @10 ms packets — above the 180 ms age limit, i.e. unreachable, which keeps the F2 loop alive forever). | `STABLE_CALLBACKS_BEFORE_DECREASE = 2000` `client.cpp:2305`; raise path `client.cpp:2273-2289`; PLC-on-empty also counts (`1518052`, `client.cpp:~3365`). | Standard ratchet-up design without rate-based decay. | High | Replace event-count ratchet with windowed loss-rate control (e.g. target = p99 jitter over last 30 s) with symmetric adjustment. |
| F5 | **High** | Gap-wait stall: when the next sequence is missing, playout waits up to `opus_playout_target_queue_packets()` = **32 dequeue attempts** (~160–320 ms) playing concealment tail before starting PLC, then plays up to 6 PLC packets (60 ms synthetic @10 ms) and hard-resets the decoder. This is the most direct "robotic stretch" mechanism. | `playout_gap_wait_packets` `client.cpp:3779-3782`; wait/PLC/reset state machine `participant_info.h:184-244`, `should_wait_for_gap()` `participant_info.h:344-365`; PLC cap `protocol.h:29` (`3ca5042`), reset (`b541538`). | Gap-wait was coupled to the same `queue_limit/2` value as F1. | High | Gap-wait should be 1–2 packet intervals (just enough for redundancy/reorder to arrive); on larger gaps skip to the newest contiguous run instead of synthesizing 6 PLC frames. |
| F6 | **Medium** | Frame-count adaptation is dead weight at HEAD: three promote-only escalators (server ingress gap ≥5 %/25 % `client.cpp:2669-2688`; ping gap ≥10 %/25 % or RTT ≥250 ms `client.cpp:2690-2714`; ping-timeout promote `client.cpp:3115-3141`) now only log "manual mode keeps current Opus packet at N frames" (`client.cpp:3106-3112,3137-3140,3180-3183`). The de-escalation path existed only in reverted `2d21d8e` (`CLEAN_INTERVALS_BEFORE_DECREASE = 6`). UDP rebind (`5928970`) is dead code — `request_udp_path_rebind()` `client.cpp:1502` has no callers. | Commits `bbf188a`, `a0d4f17`, `5928970`, `2d21d8e`, revert `f474ee4`, `b539a85`. | Adaptation was reverted wholesale after it fought the user (one-way ratchet to 20 ms packets + 15 s rebind churn). | High | Keep manual mode for now. If re-enabled later: single arbiter for the frame-count knob, hysteresis both directions, and fix F7 first so it reacts to *unrecovered* loss only. |
| F7 | **Medium** | Server ingress feedback over-reports loss: `AudioPathStatsHdr` carries gross `sequence_gaps_interval` — recoveries are tracked but never subtracted (`server.cpp:616-618`, recovery fields `server.cpp:187-192`), and for redundant datagrams only the outer (newest) packet is recorded (`server.cpp:428-434`), so loss already repaired by redundancy still counts. Reordering also transiently counts as gaps. Any future adaptation based on this signal punishes latency for inaudible loss. | `server.cpp` as cited; redundancy wrap `client.cpp:1820-1848`. | Stats designed for diagnostics, reused as a control signal. | High | Report net-unrecovered gap rate (gaps − recoveries, after unpacking redundant children) before any adaptation consumes it. |
| F8 | **Medium** | Redundancy is always-on and aggressive: every datagram carries current + up to 11 previous packets within 1200 B (`MAX_AUDIO_REDUNDANT_PACKETS = 12`, `AUDIO_REDUNDANT_TARGET_BYTES = 1200` `protocol.h:33-34`, raised from 2 in `74e2d14`). At 120-frame packets that is ~400 pps × ~1.2 kB ≈ 3.8 Mbps uplink per sender — can self-congest weak uplinks and inflate the very loss it protects against. No policy knob on main (it was in reverted `2d21d8e`). | `maybe_wrap_opus_packet_with_redundancy()` `client.cpp:1820-1848`. | Good loss armor, no budget control. | Medium (bandwidth math is solid; whether it self-congests the user's uplink is unverified) | Expose redundancy depth (off/1/2/auto); scale with packet rate so uplink cost stays roughly constant. |
| F9 | **Medium** | Packetization default (480 frames = 10 ms, `f336349`) couples into every packet-denominated setting: switching 120→480→960 multiplies jitter ms, age-limit packet capacity, and gap-wait time by 4–8× with no GUI hint. At 960 frames the auto-start target (14 pkts = 280 ms) exceeds the max age limit (250 ms) — unconditionally unstable configuration. | `opus_network_clock.h:9-13`, `protocol.h:24,32`, GUI APPLY path `client.cpp:5567-5599`. | Packets-as-unit design. | High | Convert user-facing jitter/age settings to ms (F3) and validate combinations (reject target_ms > age_limit_ms). |
| F10 | **Low-Med** | Windows API ranking never matches JUCE's WASAPI type names: `rank_api_for_platform()` looks for `"WASAPI"` but JUCE device types are named "Windows Audio", "Windows Audio (Exclusive Mode)", "Windows Audio (Low Latency Mode)". ASIO still ranks first when present, but among non-ASIO types the selection is arbitrary — the app may open shared-mode WASAPI when exclusive/low-latency modes are available. | `audio_backend_policy.h:17-43`; JUCE types created in `JuceAudioBackend()` `juce_audio_backend.cpp:38-40`. | Name mismatch after the RtAudio→JUCE migration (`9c5b89f`). | Medium (name strings from JUCE docs; verify with `get_apis()` output) | Match JUCE names; prefer Exclusive/Low-Latency mode; surface the active mode in the Path panel. |
| F11 | **Low** | O(n) scans inside the audio callback: `earliest_index_locked()` per dequeue and `discard_stale_packets_locked()` are linear over `sequenced_` (≤128), `has_sequence()` linear per enqueue. Bounded but burns callback headroom exactly when the queue is deep. | `participant_info.h:246-342`. | Simplicity-first queue. | High (code), Low (that it causes audible underruns today) | Acceptable for now; revisit if buffer sizes shrink below 128 samples. |
| F12 | **Info** | Server is architecturally clean and is *not* a latency contributor: per-packet immediate relay, no decode/re-encode, no pacing/batching, sender-id embed + copy + `async_send_to` per recipient (`server.cpp:354-394`, `forward_audio_to_others` `server.cpp:658-681`). Ingress/forward stats every 5 s (`server_config.h:9`). | Explore-agent read of `server.cpp`; clean `server-watch-20260606` log. | — | High | None for latency. Keep. |
| F13 | **Info** | The test suite (24/24 green) validates mechanisms, not the product goal: no test asserts end-to-end mouth-to-ear latency, playout rate ≈ 1.0 at steady state, or absence of sustained PLC under realistic impairment. `latency_probe_large_gap_smoke` even *requires* ≥1 decoder reset — it locks in the current gap policy. | `CMakeLists.txt:111-139`, ctest run 2026-06-12. | Tests grew around incidents. | High | Add the tests in §7. |

---

## 3. Latency Budget

End-to-end (one direction, A's mouth → B's ears), with **out-of-the-box defaults** (480-frame packets, auto jitter on, 240-frame device buffer):

| Stage | Defaults today | Tuned best case (after fixes) | Notes |
|---|---|---|---|
| Capture device buffer | 5 ms (240 frames requested, `audio_backend.h:19`) | 2.7 ms (128) | Actual granted size + device input latency visible via `get_latency_info()` `juce_audio_backend.cpp:237-265` — **unknown at runtime until measured** (Path panel shows it). |
| Device input latency | **Unknown** (shared-mode WASAPI typically adds 10–20 ms; see F10) | ~1–5 ms (ASIO/exclusive) | App-controllable via device-type choice. |
| Packetization accumulate | 0–10 ms, mean 5 ms (`opus_tx_accumulator_` fills 480 frames from 240-frame callbacks, `client.cpp:1924-1977`) | 0 ms (packet = callback size) | |
| Opus encode | ~2.5 ms lookahead + <1 ms CPU (RESTRICTED_LOWDELAY, CBR, complexity 5, `opus_encoder.h:65-74`) | same | |
| Send queue + pacing | ~0–2 ms (measured: "TX q"/"Pace" in Path panel, `b539a85`) | same | |
| Network one-way + server relay | LAN <1 ms; VPS ≈ RTT/2 (**unknown — user's typical RTT not on record**) | same | Server adds <1 ms (F12). |
| **Jitter buffer** | **start 140 ms → floor 60 ms; observed equilibrium ≈ 180 ms** (age-limit ceiling, F1/F2) | 10–30 ms (1–2 packets of 5–10 ms + headroom) | The dominant term, entirely policy. |
| Decode + resample | <1 ms | same | |
| Playout buffer | 5 ms + device output latency (**unknown**, shared WASAPI often 10–30 ms) | 2.7 ms + ~1–5 ms | |
| **Total** | **≈ 90–200+ ms even on LAN** | **≈ 15–25 ms + network** | Jamming target is ≤ ~25–30 ms mouth-to-ear. |

The budget shows why local `0.0.0.0` testing didn't help: removing the VPS removes ~10–40 ms of network, while ~150 ms of client-side policy latency stays.

---

## 4. Robotic Audio Failure Modes

Ranked by likelihood given the code:

1. **Constant −5 % resample (F1).** `ratio = 0.95` pins continuously, shifting all remote audio ~0.9 semitone flat and time-stretching it. Music sounds subtly-to-obviously "wrong/harsh"; combined with linear interpolation (`mix_resampled_opus_pcm` `client.cpp:2046-2080`, no anti-aliasing) it adds grit. This is *always on*, not loss-dependent.
2. **Age-drop skip cycle (F2).** During creep-equilibrium the playout discards ~one 10 ms packet every ~200 ms (the 5 % surplus), each a forward skip with a waveform discontinuity → periodic clicking/garbling that tracks the rate controller, not the network.
3. **PLC runs + decoder reset (F5, `3ca5042`/`b541538`).** A real unrecovered gap produces: up to ~32-callback gap-wait playing the concealment tail, then up to 6 consecutive Opus PLC frames (60 ms of synthetic signal — CELT PLC degrades audibly after ~1–2 frames on music), then `OPUS_RESET_STATE` (a hard spectral discontinuity), then a jump forward. On the VPS during bad windows (`seq_gap`/`seq_late` ≈ 50 % per the handoff doc) this fires repeatedly → the classic "robot voice".
4. **Rebuffer pauses (F2/F4).** Every instability event sets `buffer_ready = false`; playout emits silence until the queue refills to the (just-raised) target — audible dropouts that get *longer* as the ratchet climbs.
5. **Callback underruns / scheduling** — *not currently implicated*: the receive path is lock-free (moodycamel queue + atomics), decode is in-callback but cheap, and capture-side encode/send was moved to a sender thread (`pcm_sender_loop` `client.cpp:1770-1818`). The old mutex-in-callback problem from `archive/.../LATENCY_FINDINGS.md` no longer exists on main. Low confidence residual: O(n) queue scans (F11) at very small buffers.
6. **Clock drift between peers** — handled: per-participant resampler exists, and drift is measured (`observe_receiver_clock_drift` `client.cpp:2147-2220`, ppm stats in `participant_info.h:473-476`). Drift is *not* the problem; the controller driving the resampler is (F1).

---

## 5. Configuration Audit

GUI/configurable surface at HEAD (all live-apply unless noted):

| Setting | Default | Safe range | Risky range | Effect | Keep exposed? |
|---|---|---|---|---|---|
| Opus packet frames (120/240/480/960) | 480 (10 ms) | 240–480 WAN, 120 LAN | 960 with auto-jitter (target > age limit, F9) | Packet rate, encode delay, and a hidden ×multiplier on every packet-unit setting | Yes, as part of presets; show ms |
| Opus jitter buffer (packets) | 6 | 1–4 (LAN), 3–6 (WAN) at ≤5 ms frames | >8 at ≥10 ms frames (≥80 ms) | Playout delay floor | Yes, but in **ms** |
| Auto jitter | on (starts at 14) | on *after* F1/F2/F4 fixes | on today (ratchet + 140 ms start) | Adaptive target | Yes, fixed semantics |
| Opus queue limit (packets) | 64 | 8–16 | any value, because it **secretly sets the rate-controller target and gap-wait to limit/2** (F1, F5) | Burst capacity | **No** — derive from jitter target + headroom; this is the most dangerous knob in the GUI |
| Packet age limit (ms) | 180 | 60–120 | 0 (disabled) or 250 with deep buffers | De-facto max latency ceiling; also feeds the instability ratchet | Yes, but validated against jitter target |
| Device buffer frames | 240 | 128–240 | <128 until F11 revisited | Callback cadence; capture/playout granularity | Yes (APPLY/restart, `client.cpp:5567-5599`) |
| Bitrate / complexity | 96 kbps / 5 | 64–128k / 3–7 | very high bitrate on weak uplinks (with 12× redundancy, F8) | Quality vs CPU/bandwidth | Advanced only |
| Audio API / devices | auto (F10 ranking) | explicit ASIO when available | shared-mode default | Device latency | Yes |
| Per-participant jitter override + auto toggle | inherit | — | easy to fight global auto | Per-peer tuning | Advanced only |
| Mic gain/mute, self-monitor, participant gain/pan/mute | 1.0/off | — | — | Mixing only | Yes |
| Redundancy | always-on (server-negotiated) | — | 12× depth at 400 pps on thin uplinks | Loss armor vs uplink load | Add a knob (F8) |

**Recommended presets** (replace the raw knobs for normal users; numbers assume F1/F2/F4 fixed):

| Preset | Packet | Jitter target | Age limit | Redundancy | Expected added latency |
|---|---|---|---|---|---|
| **Lowest latency (LAN/great net)** | 120 (2.5 ms) | 5–10 ms (2–4 pkts) | 60 ms | 1 previous | ~8–12 ms |
| **Balanced jam (default)** | 240 (5 ms) | 15 ms (3 pkts) | 100 ms | 2 previous | ~20 ms |
| **Stable WAN** | 480 (10 ms) | 40 ms (4 pkts) | 150 ms | 2–3 previous | ~50 ms |
| **Unstable network (listen-first)** | 960 (20 ms) | 80–120 ms auto | 250 ms | depth-capped | not jam-grade; honest "rhythm reference only" mode |

---

## 6. VPS vs Local Diagnosis

**What would prove the VPS is the bottleneck:** during a bad-audio window, server ingress diagnostics (already logged every 5 s, `server.cpp:832-922`) showing high *net-unrecovered* gap rate (`seq_gap − seq_recovered`) for traffic that the *sender's* client log shows leaving cleanly (TX pace stable, no `BUG: refusing malformed`). The 2026-06-09 handoff doc already captured exactly this signature once (`seq_gap≈1391/2820` during robotic periods, clean otherwise) — so the VPS path **does** have real loss/reorder episodes. That explains *instability spikes*, not the baseline latency.

**What proves it is NOT the VPS:** the user's own local `0.0.0.0` test — latency stayed bad with the network removed. The budget in §3 shows why: ~150 ms of the total is client policy (jitter start 140 ms, rate-controller equilibrium ~180 ms) that is identical on loopback. Robotic-audio mechanisms 1, 2 and 4 in §4 are also network-independent.

**Exact measurements to collect next (in priority order):**
1. Two clients on one machine via `tools/dev-jam.mjs`, loopback server. Record the Path panel (`b539a85`): `RX q cur/avg/max`, `Opus … J… Q…`, playout rate ratio, PLC/underrun counts over 5 minutes. *Prediction from F1: RX q avg drifts to ≈ age-limit ÷ packet-ms (≈18 @10 ms) and rate ratio reads ≈ 0.95.* This single run confirms or kills the critical finding.
2. Same run with `--baseline-snapshot-seconds 60` to get the logged latency breakdown (`total_input/opus/network/jitter/output_ms`).
3. `build/Release/latency_probe` (and `udp_impair_proxy` for controlled loss/reorder/burst) against loopback, then against the VPS, same settings: compare *unrecovered* gap rate and PLC runs. This isolates path quality from policy.
4. On the VPS during a real session: `journalctl -u jam-server` ingress diag — record interval gap-rate AND recovery counts; compute net loss. If net loss < ~1 % while audio is robotic, the path is exonerated for that window.
5. Client RTT min/avg/max from the Path panel per session (VPS vs LAN) to fill the unknown network term in §3.

---

## 7. Recommended Plan

### Diagnostics to run/add (first — cheap and decisive)
1. **Run §6 measurement 1** (loopback dev-jam, read Path panel). Confirms F1 empirically in minutes.
2. Add the playout **rate ratio and RX-queue-depth to the baseline snapshot log** if missing fields block step 1 (they appear to be present via `ParticipantInfo::opus_playout_rate_ratio`).
3. Add a **net-unrecovered loss** counter to server ingress diag (gaps − recoveries after unpacking redundant children) — needed before any future adaptation, and to settle VPS-vs-local per session (F7).

### Tests to add
4. Self-test: `opus_playout_rate_ratio ≈ 1.0` when queue depth == jitter target, for jitter targets 1–8 and queue limits 8–128 (would have caught F1).
5. Self-test: auto-jitter decay reaches the floor within N seconds of clean input; instability events during *self-inflicted* age drops don't raise the target (after F2 fix).
6. `latency_probe` end-to-end assertion: steady-state added latency ≤ jitter_target + 1 packet under 0 % loss; bounded PLC-run length (≤2 frames) under 1 % random loss with redundancy on. Replace `latency_probe_large_gap_smoke`'s "≥1 decoder reset" expectation when the gap policy changes (F13).

### Code areas to change later (priority order — do not implement yet)
7. **`opus_playout_rate_ratio()` (`client.cpp:1999`)**: target = jitter target, deadband ±1 packet, clamp ≈ ±0.5 % (drift-scale); drain bursts by dropping/skipping, not resampling. *Single highest-leverage change in the codebase.*
8. **`opus_playout_target_queue_packets()` (`client.cpp:2230`)**: stop deriving gap-wait and rebuffer thresholds from `queue_limit/2`; gap-wait = 1–2 packet intervals (F5).
9. **Auto-jitter (`client.cpp:2262-2325`)**: windowed-rate controller with symmetric decay; no forced rebuffer on +1; exclude self-inflicted age drops (F2, F4).
10. **Gap policy (`participant_info.h:184-244`)**: cap PLC at 1–2 frames, then skip to newest contiguous sequence; decoder reset only on actual discontinuity jump.
11. **Units**: jitter/age in ms end-to-end; recompute packets on frame-count change (F3, F9).
12. **Presets** (§5) replacing raw knobs; remove queue-limit from the GUI; add redundancy depth policy (F8); fix JUCE API ranking names (F10).

### Configuration/default changes (interim, before any code change)
13. For the user's next jam **today**: manual jitter override ON, packet 240 (5 ms), jitter 3–4 packets, age limit 100 ms, queue limit **8** (this drags the broken rate-controller target down to `8/2 = 4` packets ≈ the jitter target — a config-only workaround for F1), auto jitter OFF. On LAN: packet 120, jitter 2, queue limit 8 (target 4 ⇒ 10 ms).
14. Defaults after fixes: auto-start 14 → 4 packets; floor 6 → 2; age 180 → 120 ms; default preset = "Balanced jam".

---

## 8. Open Questions

1. **Runtime confirmation of F1**: does the Path panel show rate ratio ≈ 0.95 and RX queue avg ≈ 18 during a normal session? (§6 step 1 — single most important data point.)
2. What are the **actual granted device latencies** on the user's machine (JUCE `get_latency_info()` per API/device — which "Windows Audio" mode is in use, is ASIO available)?
3. What is the user's **typical VPS RTT and net-unrecovered loss** during real sessions (needs the F7 counter)? Is the bad-period loss bursty (consecutive datagrams, defeating redundancy) or random (redundancy should fully cover it)?
4. What **uplink bandwidth** do participants have — is the 12× redundancy at 400 pps (≈3.8 Mbps) self-congesting anyone's uplink (F8)?
5. Does the production VPS server build **negotiate `AUDIO_CAP_REDUNDANCY`** (i.e., is redundancy actually active in real sessions, or only in local tests)?
6. What latency does the user consider playable — standard jamming threshold is ~25–30 ms mouth-to-ear; that bounds which presets are honest to label "jam".
7. When adaptation returns: should frame-count auto-switch mid-session at all (it forces an encode-clock change both sides must follow, `9d61b09`), or should the choice be a join-time preset only?
