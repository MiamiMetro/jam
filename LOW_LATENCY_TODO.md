# Low Latency Implementation Todo

Date: 2026-04-26

## Rule For This Work

This file is the source of truth for the latency work. Update it before and after each implementation step so decisions, progress, and verification are not floating only in chat.

## Control Board

This section is the plan to follow. Older detailed notes below are history/evidence and should not create new work unless a control-board item says so.

### Current Phase

Phase 2 closeout: stabilize, review, and decide whether the low-latency PCM client path is acceptable to commit.

### Phase Status

- [x] Phase 1: RtAudio backend swap and backend observability.
- [x] Phase 2: Low-latency PCM client path closeout.
- [ ] Phase 3: Real low-latency backend/device validation.
- [ ] Phase 4: Deeper playout correction/resampling, only if justified by Phase 2 or Phase 3 evidence.

### Phase 2 Done Criteria

- [x] `120` frames is default and clear.
- [x] `96` frames is available as Ultra and clear.
- [x] `64` frames remains hidden/experimental because it is robotic/corrupt.
- [x] `32` frames is documented as invalid/bad on this setup.
- [x] Bad low-buffer configurations can trigger health warnings from counters, not only human listening.
- [x] Bounded PCM hold/drop behavior is implemented and visible in diagnostics.
- [x] Extended `96` run is documented.
- [x] Current code diff is reviewed for hacks, regressions, and accidental broad changes.
- [x] Phase 2 acceptance decision is written down.
- [ ] Commit/no-commit decision is made after review and user testing.

### Current Allowed Work

Only these tasks are allowed before Phase 2 is accepted or rejected:

- [x] Clean this todo so it is phase-based and followable.
- [x] Review the current diff.
- [x] Decide whether bounded PCM hold/drop is acceptable as a Phase 2 implementation or needs rework.
- [x] Run only targeted verification needed for that review.
- [x] Update `LOW_LATENCY_AUDIO_AUDIT.md` with evidence, not future tasks.

### Current Blockers

- Real ASIO validation is blocked on this machine because no ASIO input/output devices are visible.
- `64` frame promotion is blocked because it still sounds robotic/corrupt.
- Mixed PCM frame sizes between clients are not supported in Phase 2; clients should use the same frame setting until a real resampling/playout layer exists.
- Further latency reduction below stable `96` is blocked until Phase 2 closeout is accepted.

### Current Product Decision Draft

- Default: `120` frames.
- Ultra: `96` frames.
- Experimental CLI-only: `64` frames.
- Invalid/bad on current setup: `32` frames.
- Network/SFU is not the current bottleneck in local tests.
- Client/backend/playout is the current bottleneck.
- Normal UI buffer choices are limited to packet-safe PCM sizes: `96`, `120`, `128`, `240`, `256`.

### Next Step

Run targeted verification after the review fixes, then decide commit/no-commit after user testing.

### Phase 2 Acceptance Decision

Draft decision: accept bounded PCM hold/drop for Phase 2 as a limited, visible stabilization mechanism.

Rationale:
- `120` and `96` are clear in manual tests.
- Extended `96` run is warning-free.
- Hold/drop counters and rates make the stopgap visible instead of hidden.
- `64` is still rejected, so the stopgap is not being used to falsely promote an unstable tier.
- A real resampler belongs to a later phase because it is a larger algorithmic change.

Required before closing Phase 2:
- Targeted post-review smoke/verification is complete.
- User confirms the reviewed build still sounds clear at `96` or `120`.
- User decides whether this state is acceptable to commit.

### Post-Review Verification

- [x] `cmake --build build --target client`
- [x] `cmake --build build --target latency_probe`
- [x] `client --audio-open-smoke --require-api WASAPI --frames 96`
- [x] `client --backend-check --require-api WASAPI --frames 96`
- [x] `client --backend-check` fails clearly because ASIO has no visible input/output devices.
- [x] User listening confirmation on reviewed build.
  - Result: two reviewed-build clients at `96` sounded clear.

### Phase 2 Final Acceptance

Accepted.

Reason:
- Reviewed build passes targeted smoke checks.
- User confirmed reviewed-build `96` audio is clear.
- `120` remains the safe default.
- `96` remains Ultra.
- `64` remains CLI-only experimental and is not promoted.
- Remaining backend/device validation is external to Phase 2.

Remaining decision:
- Commit/no-commit after user decides this tested state is ready to preserve.

## Historical Work Log

Implement the first production raw PCM int16 path with explicit packet metadata while keeping the server as a dumb UDP/SFU forwarder.

Current next implementation: `latency_probe` v1 diagnostic executable.

Locked `latency_probe` v1 scope:
- Separate diagnostic executable, not a GUI/RtAudio client.
- Assumes `server.exe` is already running.
- Uses real UDP through `127.0.0.1:9999`.
- Uses current Opus path first.
- Uses current packet format and jitter constants.
- Uses a minimal headless playout loop.
- Test signal is silence, then short click, then silence.
- Prints latency samples/ms and corruption indicators.
- Does not enforce pass/fail thresholds yet.

Current next implementation: `latency_probe` config sweep.

Locked `latency_probe` sweep scope:
- Sweep multiple frame sizes and jitter minimums.
- Keep using real UDP through `server.exe`.
- Keep using Opus first.
- Report latency and corruption indicators per configuration.
- Do not change production client behavior yet.
- Do not enforce hard pass/fail thresholds yet.

Current next implementation: raw PCM mode in `latency_probe`.

Locked raw PCM probe scope:
- Add raw PCM only to `latency_probe` first, not production client.
- Keep using real UDP through `server.exe`.
- Reuse existing server forwarding unchanged.
- Use a probe-local packet payload mode because production `AudioHdr` has no codec field yet.
- Sweep the same frame sizes and jitter settings.
- Compare raw PCM results against Opus sweep.
- Use findings to decide production protocol changes.

Current next decision: production low-latency path.

Recommended answer:
- Implement production raw PCM int16 first, with explicit packet metadata and a bounded jitter/playout queue.
- Do not try to make 64-frame standard Opus work; the probe proves the current Opus API rejects that frame size.
- Keep Jamulus-style Opus as a later compressed-mode transplant only if raw PCM proves the client/backend path can hit the target.

Current implementation: production `AudioHdrV2` plus raw PCM int16 mode. Completed.

Current implementation: remove global participant-manager lock from callback mixing. Completed.

Current interruption: fix left-only output. Completed.

Finding:
- The client forced output streams to one channel even when the selected playback device supported stereo.
- Mono remote audio was therefore opened as a one-channel output stream and could appear only on the left side.

Fix:
- Keep input/network audio mono.
- Open output as two channels when the output device supports at least two channels.
- Existing mono-to-stereo mixing now duplicates mono playback into left and right.

Verification:
- `cmake --build build --target client`
- Smoke log now reports `1 input channel(s), 2 output channel(s) at 48000 Hz`.

Current implementation: callback timing metrics. Completed.

Locked callback metrics scope:
- Add diagnostic atomics only.
- Track last, max, moving average, callback count, over-deadline count, and deadline ms.
- Display the metrics in the existing master strip.
- Do not change audio behavior in this step.

Current implementation: Gate 2 packet age metrics. Completed.

Locked packet age scope:
- Use existing packet enqueue timestamp.
- Measure age when a packet is dequeued for playout.
- Track last, max, and smoothed average packet age per participant.
- Show packet age in existing participant stats.
- Do not change jitter behavior in this step.

Current implementation: Gate 2 queue-depth metrics per participant. Completed.

Locked queue metrics scope:
- Track current, max, and smoothed average queue depth per participant.
- Reuse existing queue depth observations from enqueue/playout.
- Display average and max queue depth in participant stats.
- Do not change adaptive jitter behavior in this step.

Current implementation: Gate 2 device latency metrics. Completed.

Locked device latency scope:
- Report requested buffer frames.
- Report actual buffer frames.
- Report buffer duration in ms.
- Keep existing RtAudio stream latency reporting, but label zero/unknown backend latency clearly.
- Do not change backend/device selection in this step.

Current implementation: Gate 3 move Opus encode/send out of callback. Completed.

Locked Opus callback cleanup scope:
- Keep Opus behavior available for future codec switch.
- Callback may prepare one fixed-size float frame and enqueue it.
- Opus encoder, packet construction, and socket send must happen on sender thread.
- Remove callback `std::vector` allocations from the Opus send path.
- Do not add UI codec switching in this step.

Current implementation: Gate 4 sequence-aware receive diagnostics. Completed.

Locked sequence diagnostics scope:
- Use `AudioHdrV2.sequence`.
- Track sequence gaps and late/out-of-order packets per participant.
- Expose counts in participant stats.
- Keep old V1 packets compatible with no sequence diagnostics.
- Do not replace jitter buffer policy in this step.

Current implementation: Gate 4 bounded jitter buffer. Completed.

Locked bounded jitter scope:
- Keep the existing queue-based playout model for this pass.
- Make latency bounds explicit with queue-depth and max packet-age drops.
- Drop oldest packets when the queue exceeds target depth.
- Drop packets that are too old at playout instead of playing hidden latency.
- Count and display jitter drops.

Current implementation: Gate 5 minimal codec mode switch. Completed.

Locked codec switch scope:
- Keep PCM int16 as the default.
- Add only a simple PCM/Opus selector.
- Use existing `audio_codec_` routing.
- Do not add latency presets or frame-size switching in this step.

Current implementation: Gate 6 Opus jamming defaults and frame validation. Completed.

Locked Opus settings scope:
- Mark encoder ownership outside callback as complete.
- Disable FEC by default for jamming mode.
- Use CBR-style packet pacing.
- Reject illegal Opus frame sizes before calling `opus_encode_float`.
- Do not implement Jamulus custom Opus modes in this step.

Current implementation: Gate 7 ASIO-first default selection. Completed.

Locked ASIO preference scope:
- Prefer ASIO defaults when ASIO input/output devices are present.
- Fall back to existing RtAudio default device behavior when ASIO is unavailable.
- Keep manual API/device selection unchanged.

Current implementation: Gate 7 buffer-size controls. Completed.

Locked buffer-size scope:
- Add selectable requested buffer sizes: 64, 96, 120, 128, 240, 256, 512.
- Keep actual accepted buffer reporting through existing device latency metrics.
- Restart active stream when applying a new buffer size.
- Do not claim all sizes are supported by every backend/device.

Current implementation: Gate 7 WASAPI vs ASIO documentation. Completed.

Locked documentation scope:
- Document current build support.
- Document current runtime observation on this machine.
- Document expected ASIO requirement: installed ASIO driver/device.
- Document WASAPI caveat: usable fallback, not final lowest-latency target.

Current implementation: Gate 8 receive buffer fill drift metrics.

Locked drift metrics scope:
- Measure only; do not change playout, resampling, frame slip, or jitter policy in this step.
- Track per-participant queue depth trend relative to `TARGET_OPUS_QUEUE_SIZE`.
- Display the smoothed signed drift in the existing participant stats.
- Verify with client build and two-client local smoke.

Current implementation: Gate 8 automated long-run drift probe.

Locked long-run probe scope:
- Extend `latency_probe`, not the GUI client.
- Add configurable probe length.
- Report queue fill average/min/final and drift relative to jitter target.
- Do not add adaptive correction in this step.
- Verify with short local run first; 10-minute run remains a follow-up because it is intentionally long.

Current implementation: Gate 8 10-minute baseline drift run.

Locked 10-minute baseline scope:
- Run the automated PCM probe through local `server.exe`.
- Use `240` frames and jitter target `3` first, matching the stable default.
- Record exact probe output in the audit.
- Do not change correction behavior until the baseline is known.
- Finding: first 10-minute attempt was invalid because `latency_probe` clients sent `JOIN` but not periodic `ALIVE`, so the server timed out the synthetic endpoints.
- Fix scope: add periodic `ALIVE` from both probe endpoints during long runs, then rerun.

Current implementation: Gate 8 10-minute real RtAudio client baseline.

Locked real-client baseline scope:
- Run local `server.exe` plus two real `client.exe` processes.
- Use current default settings first: PCM, `240` requested frames, jitter target `3`.
- Verify log-level stability: join, jitter ready, no steady-state rebuffer/decode/send errors.
- Do not commit or change correction behavior in this step.

Current implementation: automate real-client lower-buffer tests.

Locked lower-buffer automation scope:
- Add a minimal `client --frames N` startup override.
- Keep UI behavior unchanged.
- Use the override only for repeatable local test runs at `120` and `128`.
- Do not add presets or correction logic in this step.

Finding:
- Normal visible baseline at default `240` transfers audio correctly.
- WASAPI accepts `120` and `128` actual buffers, but both settings immediately rebuffer after jitter ready in the current playout policy.
- Do not treat `120/128` as usable yet; next code work must target startup/playout stability for smaller callback periods.
- Update: keeping PCM playback ready after a transient empty queue fixed the "one second then gone" failure at `120`.
- Remaining issue: `120` is audible but occasionally broken; diagnostics show `ready=true`, `underruns=0`, and rising queue-depth drops, so the receive cap is too tight for this smaller callback period.

Current implementation: make validated `120` the explicit low-latency default.

Locked default/preset scope:
- Change default requested buffer from `240` to `120`.
- Keep `240` available as the safe fallback.
- Add minimal UI presets/labels for `Low Latency 120` and `Safe 240`.
- Keep manual buffer selection available.
- Verify default startup opens actual `120`.

Current implementation: test next-lower PCM buffer candidate.

Locked lower-than-120 scope:
- Test `96` frames with the current PCM path before touching adaptive correction.
- Use real clients through local `server.exe`.
- Treat this as exploratory; do not change the default away from validated `120` unless `96` gets the same quality proof.
- Record whether the backend accepts actual `96`, whether audio is audible, and whether counters stay clean.

Current implementation: expose validated `96` as Ultra.

Locked 96-exposure scope:
- Keep default at validated `120`.
- Label `96` as `Ultra`.
- Keep `120` as `Low`.
- Keep `240` as `Safe`.
- Document that `96` is device-dependent and validated on this machine, not universally guaranteed.
- Verify default startup still opens `120`.

Current implementation: find lower buffer failure boundary.

Locked lower-boundary scope:
- Test below `96`, starting with `64`.
- Confirm actual backend buffer, not just requested value.
- Treat this as falsification: if lower values keep working, investigate hidden buffering and packet age before changing defaults.
- Do not promote any lower value without listening and clean counters.

Locked participant snapshot scope:
- Keep participant lifecycle behavior unchanged.
- Store participants behind stable shared ownership.
- `for_each()` snapshots participant references under the manager mutex, then releases the mutex before decode/mix work.
- Do not redesign per-participant synchronization in this slice.
- Verify with client build and two-client local smoke.

Locked production PCM scope:
- Add a new audio packet version rather than mutating `AudioHdr` silently.
- Include codec, frame count, channel count, payload bytes, and sequence number in the packet metadata.
- Keep server forwarding unchanged except for accepting/rewriting the sender ID in the new header.
- Keep Opus compatibility for existing clients.
- Add minimal client-side mode selection in code first; do not build UI presets yet.
- Do not move Opus/network work out of the callback in this slice unless required for compilation.

## Roadmap Summary

The work is split into gates. Do not start a later gate until the earlier gate has been verified or explicitly waived.

| Gate | Goal | Why It Exists | Exit Criteria |
|------|------|---------------|---------------|
| Gate 0 | Document and preserve decisions | Prevent another vague rewrite attempt | This todo and audit stay updated before/after work |
| Gate 1 | Backend swap to RtAudio | Create a backend path closer to JackTrip-style configuration | Client builds with RtAudio and no PortAudio symbols |
| Gate 2 | Measurement | Stop guessing about latency sources | Logs/UI show device latency, callback time, queue depth, packet age |
| Gate 3 | Real-time callback cleanup | Remove the most likely robotic/corrupt audio cause | Callback has no heap allocation, locks, Opus encode, or socket send |
| Gate 4 | Packet timing and jitter foundation | Make playback deterministic and diagnosable | Audio packets include sequence/frame/codec metadata and jitter buffer uses it |
| Gate 5 | Raw PCM mode | Prove lowest-latency path without codec delay | Raw PCM works through current SFU with bounded playout |
| Gate 6 | Opus rebuild | Reintroduce compressed mode safely | Opus runs outside callback with legal frame sizes and sane loss behavior |
| Gate 7 | Driver/backend low-latency polish | Reach practical jamming settings | ASIO/JACK/CoreAudio/WASAPI-exclusive style settings exposed and verified |
| Gate 8 | Clock drift handling | Prevent slow buffer growth/underruns in real sessions | Long session keeps receive buffer near target without periodic robotic artifacts |

## Decision Tree

### Decision A: Copy Code vs Copy Architecture

Recommended answer: copy architecture first, copy code only when adopting its contracts too.

- If copying JackTrip code:
  - Also adopt its assumptions around raw/uncompressed packet timing, small buffers, preallocation, and backend configuration.
  - Best fit: raw PCM low-latency mode and backend/device handling.
- If copying Jamulus code:
  - Also adopt sequence numbers, fixed audio block assumptions, jitter-buffer window behavior, and Opus framing expectations.
  - Best fit: sequence-aware jitter and Opus low-delay behavior.
- If copying SonoBus/AOO code:
  - Also adopt per-peer codec/buffer controls and dynamic resampling assumptions.
  - Best fit: hybrid PCM/Opus and per-peer receive settings.

Decision status: Open. We started with a controlled RtAudio swap, not a wholesale engine transplant.

### Decision B: Backend Strategy

Recommended answer: keep RtAudio for now, then add explicit ASIO/JACK preference after measurement.

- Short-term:
  - RtAudio replaces PortAudio.
  - Current build supports WASAPI only.
- Required for serious Windows jamming:
  - Enable ASIO in RtAudio build or integrate a direct ASIO/JACK path.
  - Expose buffer sizes supported by the selected backend/device.
- Risk:
  - RtAudio/WASAPI alone may still have too much device latency.

Decision status: Partially resolved. RtAudio swap completed; ASIO enabling remains open.

### Decision C: Next Implementation Gate

Recommended answer: measurement before callback rewrite.

Reason:
- We need objective baseline numbers after RtAudio:
  - requested vs actual buffer frames
  - stream latency frames/ms
  - callback duration vs deadline
  - packet queue depth and packet age
- Without these, another rewrite can pass tests and still sound bad.

Decision status: Open. This is the next grill-me question.

### Decision D: Raw PCM Timing

Recommended answer: raw PCM should be implemented before deeper Opus work.

Reason:
- It removes codec delay from the experiment.
- It proves or disproves audio backend/device + UDP/SFU latency independent of Opus.
- Competitors validate this path: JackTrip is built around uncompressed audio; SonoBus supports PCM modes.

Decision status: Open, but recommended for Gate 5.

### Decision E: Packet Format Compatibility

Recommended answer: introduce a protocol version or new packet type when adding sequence/codec/frame metadata.

Reason:
- Existing `AudioHdr` has only magic, sender ID, encoded byte count, and payload.
- Adding sequence/codec/frame fields breaks old clients unless versioned.
- The cleanest path is a new audio packet version while keeping server forwarding dumb.

Decision status: Open.

### Decision F: Testing Strategy

Recommended answer: unit tests for packet/jitter logic, runtime instrumentation for audio behavior.

Reason:
- Tests can prove packet parsing, sequence gaps, queue bounds, and jitter decisions.
- Tests cannot prove real-time callback safety or perceived audio quality by themselves.
- For audio, the important verification is instrumentation plus listening.

Decision status: Open.

## Comprehensive Execution Plan

### Gate 0: Documentation Discipline

- [x] Create audit document.
  - File: `LOW_LATENCY_AUDIO_AUDIT.md`
- [x] Create implementation todo.
  - File: `LOW_LATENCY_TODO.md`
- Historical discipline note: keep this file updated before and after every code step.
  - Verification: every completed code step has a checked item and finding.

### Gate 1: RtAudio Backend Swap

- [x] Replace PortAudio dependency with RtAudio.
- [x] Replace `AudioStream` internals with RtAudio.
- [x] Remove direct PortAudio usage from `client.cpp`.
- [x] Build client.
- [x] Runtime smoke test client device enumeration/start/stop.
  - Command: run `build/Debug/client.exe`.
  - Verify: devices appear, stream starts, no immediate crash.
  - Verification: process started, enumerated WASAPI devices, auto-started RtAudio stream, survived 8 seconds, then was force-stopped by the smoke script.
  - Finding: selected default input was `Headset Microphone (DualSense Wireless Controller)` over WASAPI.
  - Finding: selected default output was `Headset Earphone (HyperX Virtual Surround Sound)` over WASAPI.
  - Finding: requested and actual buffer were both 240 frames.
  - Finding: RtAudio reported `0.000 ms` input/output latency through the current wrapper, so Gate 2 must improve device latency instrumentation; this value is not trustworthy yet.
  - Finding: smoke test exposed and fixed two RtAudio wrapper bugs:
    - default input selection must require actual input channels;
    - `DeviceInfo` pointers from repeated scans must be copied before the next scan invalidates them.

### Gate 2: Measurement Baseline

- [x] Add `latency_probe` config sweep.
  - Sweep candidate frame sizes: 240, 120, 96, 64.
  - Sweep candidate jitter minimum packets: 3, 2, 1, 0.
  - Output per combination:
    - latency samples/ms
    - sent/received/decoded packets
    - max queue depth
    - underruns
    - PLC frames
    - decode failures
    - decoded size mismatches
    - non-finite/out-of-range samples
    - repeated blocks
    - max discontinuity
    - detection failure
  - Verification: built with `cmake --build build --target latency_probe`.
  - Verification: ran `latency_probe --server 127.0.0.1 --port 9999 --sweep` against local `server.exe`.
  - Findings:
    - `240` frames, jitter `3`: stable, `27.4375 ms`, no encode/decode/PLC/underrun indicators.
    - `240` frames, jitter `2/1/0`: lower measured latency (`17.4375-22.4375 ms`) but PLC/underrun indicators appear.
    - `120` frames: Opus encodes and decodes, measured latency around `16.0833-18.5833 ms`, but every jitter setting in this run showed PLC/underrun indicators.
    - `96` frames: Opus encode failed for all 220 packets; zero packets sent.
    - `64` frames: Opus encode failed for all 220 packets; zero packets sent.
  - Interpretation:
    - The current standard Opus path supports `120` and `240` sample frames at 48 kHz, but not arbitrary `96` or `64` sample frames.
    - Lower jitter does reduce measured latency, but the probe sees the mechanical cause of robotic/corrupt audio: underruns and Opus PLC.
    - Trying 64-sample Opus with this encoder path is not a valid low-latency setting; it requires a different codec mode/packetization strategy, such as Jamulus-style custom Opus mode or raw PCM.

- [x] Add `latency_probe` v1 diagnostic executable.
  - Target: `latency_probe`.
  - Inputs: server host/port optional CLI arguments.
  - Output: measured click latency and diagnostic counters.
  - Verification: builds with `cmake --build build --target latency_probe`.
  - Verification: ran 3 times against local `server.exe` through real UDP.
  - Baseline result, 3/3 runs:
    - Sent packets: 220
    - Received packets: 220
    - Decoded packets: 220
    - Detected output sample: 6117
    - Latency: 1317 samples / 27.4375 ms
    - Jitter minimum: 3 packets
    - Max queue depth: 6-8 packets
    - Underruns: 0
    - PLC frames: 0
    - Decode failures: 0
    - Decoded size mismatches: 0
    - Non-finite samples: 0
    - Out-of-range samples: 0
  - Finding: v1 originally counted end-of-test drain as underruns/PLC; fixed by stopping playout after all expected packets are received and drained.
  - Finding: v1 sends `LEAVE` for both synthetic clients so repeated runs do not leave stale server participants.

- [x] Add callback timing metrics.
  - Record `frame_count`, deadline ms, callback duration ms, max duration, and over-deadline count.
  - Show in logs first; UI later if useful.
  - Verify: run client and observe metrics during idle, mic input, and remote audio.
  - Changed: `client.cpp`.
  - Implementation: added callback timing atomics for last, max, smoothed average, deadline, callback count, and over-deadline count.
  - UI: master strip now shows average callback duration vs deadline, max callback duration, and late-callback count when nonzero.
  - Verification: `cmake --build build --target client`.
  - Verification: two hidden local clients connected through local `server.exe`; both registered the other participant and reached jitter buffer ready with no filtered packet/decode/rebuffer errors.

- [x] Add packet age metrics.
  - Stamp receive enqueue time.
  - Measure age when decoded/played.
  - Verify: log/diagnostic can explain how much latency comes from receive queue.
  - Changed: `participant_info.h`, `participant_manager.h`, `client.cpp`.
  - Implementation: each participant tracks last, max, and smoothed average packet age from enqueue timestamp to callback dequeue/playout.
  - UI: participant stats now show average packet age and max packet age.
  - Verification: `cmake --build build --target client`.
  - Verification: two hidden local clients connected through local `server.exe`; both registered the other participant and reached jitter buffer ready with no filtered packet/decode/rebuffer errors.

- [x] Add queue-depth metrics per participant.
  - Track min/avg/max queue depth and underruns.
  - Verify: current 3-packet minimum is visible as latency.
  - Changed: `participant_info.h`, `participant_manager.h`, `client.cpp`.
  - Implementation: each participant tracks current, max, and smoothed average queue depth from enqueue and playout observations.
  - UI: participant stats now show current queue plus average/max queue depth.
  - Verification: `cmake --build build --target client`.
  - Verification: two hidden local clients connected through local `server.exe`; both registered the other participant and reached jitter buffer ready with no filtered packet/decode/rebuffer errors.

- [x] Add device latency metrics for RtAudio.
  - Log requested buffer frames, actual buffer frames, stream latency frames/ms.
  - Verify: output identifies if WASAPI/device layer is already too high.
  - Changed: `audio_stream.h`, `client.cpp`.
  - Implementation: `LatencyInfo` now includes requested buffer frames, actual buffer frames, buffer duration ms, and whether backend latency is available.
  - UI: master strip now shows actual/requested buffer frames and buffer duration.
  - Verification: `cmake --build build --target client`.
  - Smoke result: selected WASAPI stream opened with `240` requested frames, `240` actual frames, `5.000 ms` buffer duration.
  - Finding: RtAudio backend latency still reports `0.000 ms`; this is now explicitly logged as unavailable or zero rather than treated as trustworthy.

### Gate 3: Real-Time-Safe Callback

- [x] Define allowed callback work.
  - Allowed: copy input PCM to preallocated queue, mix already-ready output PCM, update atomics.
  - Forbidden: allocation, locks, Opus encode, packet building, socket send, blocking I/O.
  - Current scope: applied to the new PCM int16 send path first. Opus still needs the same cleanup.

- [x] Add mic PCM SPSC queue.
  - Callback writes fixed-size frames.
  - Sender thread reads frames.
  - Overflow policy: drop oldest to bound latency.
  - Changed: `client.cpp`.
  - Implementation: added a bounded `pcm_send_queue_`; callback converts to PCM int16 and enqueues; sender thread builds/sends V2 packets.
  - Finding: initial sender loop used `sleep_for(1ms)` when idle and caused repeated rebuffering in the two-client smoke. Replaced it with `yield()` to avoid Windows sleep granularity causing packet jitter.
  - Verification: two hidden local clients connected through local `server.exe`; both registered the other participant and reached jitter buffer ready with no filtered rebuffer/send/packet errors.

- [x] Move Opus encode and UDP send to sender thread.
  - Sender thread owns encoder and packet buffer.
  - Sender thread paces packet sends.
  - Verify: callback body no longer calls `audio_encoder_.encode`, `audio_packet::create_audio_packet`, or `send`.
  - Changed: `client.cpp`.
  - Implementation: added `opus_send_queue_`; callback enqueues fixed-size float frames, and sender thread performs Opus encode, V2 packet construction, and socket send.
  - Verification: `cmake --build build --target client`.
  - Verification: search shows `audio_encoder_.encode` and Opus packet construction now occur in sender thread, not callback.
  - Verification: two hidden local clients connected through local `server.exe`; both registered the other participant and reached jitter buffer ready with no filtered packet/decode/rebuffer errors.

- [x] Remove callback allocations.
  - Replace callback `std::vector` silence buffers with fixed buffers.
  - Replace packet allocation with fixed/preallocated sender buffer.
  - Verify: search callback body for `std::vector`, `make_shared`, and `new`.
  - Changed: `client.cpp`, `participant_manager.h`.
  - Implementation: removed Opus callback vector/silence-frame allocations by enqueueing fixed-size float frames to sender thread.
  - Implementation: replaced `ParticipantManager::for_each()` heap-allocated snapshot vector with a fixed-size stack snapshot for the callback path.
  - Verification: `cmake --build build --target client`.
  - Verification: search shows remaining `std::vector` and packet allocation sites are outside callback path or in the sender/UI/lifecycle code.
  - Verification: two hidden local clients connected through local `server.exe`; both registered the other participant and reached jitter buffer ready with no filtered packet/decode/rebuffer errors.

- [x] Remove callback participant mutex.
  - Replace `ParticipantManager::for_each()` use in callback.
  - Candidate: fixed participant slots or RCU snapshot with stable per-participant queues.
  - Verify: callback does not lock `ParticipantManager::mutex_`.
  - Changed: `participant_manager.h`.
  - Implementation: participants are now stored as `std::shared_ptr<ParticipantData>`. `for_each()` snapshots shared references while holding the manager mutex, then releases it before invoking decode/mix work.
  - Verification: `cmake --build build --target client`.
  - Verification: two hidden local clients connected through local `server.exe`; both registered the other participant and reached jitter buffer ready with no filtered rebuffer/send/packet/decode errors.
  - Caveat: per-participant fields are still shared between network/UI/audio threads. This removes the global manager mutex from callback work but does not make every participant field lock-free or atomic.

### Gate 4: Packet Timing and Jitter

- [x] Design `AudioHdrV2`.
  - Fields: magic/type, version, sender ID, sequence number, codec, sample rate, frame count, channel count, payload bytes.
  - Server remains dumb forwarder.
  - Changed: `protocol.h`, `packet_builder.h`, `audio_packet.h`.
  - Implementation: added `AUDIO_V2_MAGIC`, `AudioCodec`, and `AudioHdrV2` with sender ID, sequence, sample rate, frame count, payload bytes, channels, codec, and fixed payload buffer.
  - Compatibility: old `AUDIO_MAGIC` Opus packets still parse on receive; new packets use `AUDIO_V2_MAGIC`.
  - Verification: `cmake --build build --target client`, `server`, and `latency_probe` succeeded.

- [x] Implement sequence-aware receive path.
  - Detect loss, late packets, reordering.
  - Do not silently grow latency.
  - Changed: `participant_info.h`, `participant_manager.h`, `client.cpp`.
  - Implementation: V2 receive path now tracks expected sequence per participant and counts sequence gaps plus late/out-of-order packets.
  - UI: participant stats show sequence gap/late counts when nonzero.
  - Compatibility: old V1 packets continue without sequence diagnostics.
  - Verification: `cmake --build build --target client`.
  - Verification: two hidden local clients connected through local `server.exe`; both registered the other participant and reached jitter buffer ready with no filtered packet/decode/rebuffer errors.

- [x] Implement bounded jitter buffer.
  - Target playout delay in packets/ms.
  - Explicit drop policy for late or excess packets.
  - Verify: packet age stays bounded under artificial queue growth.
  - Changed: `protocol.h`, `participant_info.h`, `participant_manager.h`, `client.cpp`.
  - Implementation: queue depth is now explicitly capped at `TARGET_OPUS_QUEUE_SIZE + 1` after enqueue, and packets older than `MAX_JITTER_PACKET_AGE_MS` are dropped at playout.
  - UI: participant stats show queue-depth drops and age drops when nonzero.
  - Finding: strict cap at exactly `TARGET_OPUS_QUEUE_SIZE` caused immediate startup rebuffering; corrected to allow one packet of headroom.
  - Verification: `cmake --build build --target client`.
  - Verification: two hidden local clients connected through local `server.exe`; both registered the other participant and reached jitter buffer ready with no filtered packet/decode/rebuffer errors after the headroom correction.

### Gate 5: Raw PCM Mode

- [x] Add raw PCM mode to `latency_probe`.
  - Verification: run raw PCM sweep against local `server.exe`.
  - Compare against Opus sweep results.
  - Implementation note: used PCM int16, not float32, because the current `AUDIO_BUF_SIZE` is 512 bytes. A 240-frame mono float32 payload would exceed the current packet cap, while 240-frame mono int16 fits.
  - Verification: built with `cmake --build build --target latency_probe`.
  - Verification: ran `latency_probe --server 127.0.0.1 --port 9999 --sweep --codec pcm` through local `server.exe`.
  - Findings:
    - `240` frames, jitter `3`: stable, `25 ms`, no encode/decode/underrun indicators.
    - `240` frames, jitter `2/1/0`: `20 ms`, but underruns appear.
    - `120` frames: `15-17.5 ms`, but underruns appear in every tested jitter setting.
    - `96` frames: `16 ms`, packets send/decode successfully, but underruns appear.
    - `64` frames: `14.6667-16 ms`, packets send/decode successfully, but underruns appear.
  - Interpretation:
    - Raw PCM proves the current SFU can forward 64/96-frame audio packets without codec failure.
    - Raw PCM removes Opus PLC from the corruption path, but underruns remain when the jitter/playout target is too aggressive.
    - The next production problem is bounded jitter/playout and callback architecture, not UDP or codec legality.

- [x] Add codec enum.
  - `Opus`
  - `PcmInt16`
  - Optional later: `PcmFloat32` if packet size is increased.
  - Completed in `protocol.h` as `AudioCodec`.

- [x] Add raw PCM sender path.
  - No codec work.
  - Frame payload copied from mic queue.
  - Changed: `client.cpp`.
  - Implementation: client now defaults outgoing production audio to `AudioCodec::PcmInt16` and sends `AudioHdrV2` packets with incrementing sequence numbers.
  - Update: packet construction and send now run outside the callback through the sender thread.

- [x] Add raw PCM receiver path.
  - Jitter buffer outputs PCM directly.
  - Verify: local network session works through server.
  - Changed: `participant_info.h`, `client.cpp`, `server.cpp`.
  - Implementation: receive path accepts V1 Opus and V2 packets. V2 PCM int16 is converted to float in the existing playout callback.
  - Server change: server still forwards dumb packets, but now accepts `AUDIO_V2_MAGIC` and rewrites sender ID at the same offset.
  - Verification: two hidden local clients connected to local `server.exe`; each registered the other participant and reported jitter buffer ready.

- [x] Add minimal user-facing mode switch.
  - Keep simple: Opus vs Raw PCM.
  - Do not overbuild presets before timing is verified.
  - Changed: `client.cpp`.
  - Implementation: master strip has PCM/Opus radio buttons. PCM int16 remains the default.
  - Verification: `cmake --build build --target client`.
  - Verification: two hidden local clients connected through local `server.exe` with default PCM mode; both registered the other participant and reached jitter buffer ready with no filtered packet/decode/rebuffer errors.
  - Caveat: Opus switching is UI-driven and still needs manual runtime exercise.

### Gate 6: Opus Rebuild

- [x] Move encoder ownership fully outside callback.
  - Completed in Gate 3. Opus encoding now runs in the sender thread.
- [x] Disable FEC by default for jamming mode.
  - Changed: `opus_encoder.h`.
  - Implementation: `OPUS_SET_INBAND_FEC(0)` and `OPUS_SET_PACKET_LOSS_PERC(0)`.
- [x] Validate legal frame sizes.
  - Changed: `opus_encoder.h`, `client.cpp`.
  - Implementation: explicit validation for Opus frame durations of 2.5, 5, 10, 20, 40, and 60 ms.
  - Finding: `120` and `240` sample frames at 48 kHz are legal; `96` and `64` are rejected before encode.
- [x] Consider CBR/constrained mode for packet pacing.
  - Changed: `opus_encoder.h`.
  - Implementation: `OPUS_SET_VBR(0)` for CBR-style packet pacing.
  - Verification: `cmake --build build --target client` and `cmake --build build --target latency_probe`.
  - Verification: Opus sweep still sends/decodes legal `120` and `240` frame sizes; `96` and `64` fail cleanly with encode failures.
- Deferred note: consider Jamulus-style custom Opus modes only if needed for 64/128 sample compressed mode.

### Gate 7: Backend Low-Latency Polish

- [x] Enable ASIO support for RtAudio on Windows.
  - Verify CMake reports ASIO support.
  - Changed: `cmake/client.cmake`.
  - Implementation: set `RTAUDIO_API_ASIO=ON` before `FetchContent_MakeAvailable(rtaudio)`.
  - Verification: `cmake -S . -B build` reports `Compiling with support for: asio wasapi`.
  - Verification: generated RtAudio project includes `__WINDOWS_ASIO__` and builds `asio.cpp`, `asiodrivers.cpp`, `asiolist.cpp`, and `iasiothiscallresolver.cpp`.
  - Verification: `cmake --build build --target client`.
  - Runtime finding: current machine still enumerates only WASAPI devices, so no ASIO driver/device is installed or visible.
- [x] Prefer ASIO devices when available, or clearly expose API selection.
  - Changed: `audio_stream.h`.
  - Implementation: default input/output selection now prefers ASIO devices when present, then falls back to RtAudio's default device behavior.
  - Existing UI already exposes API selection manually.
  - Verification: `cmake --build build --target client`.
  - Runtime finding: current machine has no visible ASIO devices, so startup correctly falls back to WASAPI.
- [x] Expose device-supported buffer sizes.
  - Changed: `client.cpp`.
  - Implementation: bottom bar now exposes requested buffer frame candidates.
  - Caveat: RtAudio does not expose a universal supported-size list per device/API. The UI exposes candidate requests, and the master strip/logs show the actual accepted buffer after stream open.
- [x] Allow 64/128/256/512 frame choices when supported.
  - Changed: `client.cpp`.
  - Implementation: selectable requested buffer sizes are `64`, `96`, `120`, `128`, `240`, `256`, and `512`.
  - Applying a new buffer size restarts the active stream through existing device swap flow.
  - Verification: `cmake --build build --target client`.
  - Runtime smoke: default `240` request still opens as actual `240` frames / `5.000 ms` on the current WASAPI device.
- [x] Document WASAPI vs ASIO behavior.
  - Changed: `LOW_LATENCY_AUDIO_AUDIT.md`.
  - Documented: current build supports `asio` and `wasapi`.
  - Documented: current machine currently enumerates WASAPI devices only.
  - Documented: ASIO needs a visible installed ASIO driver/device.
  - Documented: WASAPI is a functional fallback, but serious Windows jamming still targets ASIO.

### Gate 8: Clock Drift Handling

- [x] Measure receive buffer fill drift over time.
  - Changed: `participant_info.h`, `participant_manager.h`, `client.cpp`.
  - Implementation: each participant now tracks a smoothed signed queue-depth drift relative to `TARGET_OPUS_QUEUE_SIZE`.
  - UI: participant stats now show `Q drift`; positive means queue growth/latency pressure, negative means underrun pressure.
  - Verification: `cmake --build build --target client`.
  - Verification: two hidden local clients connected through local `server.exe`; both opened `1` input channel and `2` output channels, reported actual `240` frames / `5.000 ms`, registered the other participant, and reached jitter buffer ready.
  - Caveat: smoke teardown still causes one peer to report a single rebuffer when the other process is force-killed; this is not a steady-state audio failure.
- [x] Add automated long-run drift probe controls.
  - Changed: `latency_probe.cpp`.
  - Implementation: added `--packets` and `--seconds` so probe length can scale from short smoke to 10-minute runs.
  - Implementation: probe now reports average queue depth, queue drift from jitter target, min queue depth after ready, max queue depth, and final queue depth.
  - Verification: `cmake --build build --target latency_probe`.
  - Verification: `latency_probe --server 127.0.0.1 --port 9999 --codec pcm --frames 240 --jitter 3 --seconds 5` ran through local `server.exe`.
  - Finding: 5-second PCM run sent/received/decoded `1000/1000/1000` packets with `15 ms` detected latency, average queue depth `3.03`, drift `+0.03`, max queue `7`, and one underrun. This proves the automated probe can catch the same underrun/corruption risk we hear when buffers are too aggressive.
- [x] Fix automated probe liveness for long runs.
  - Changed: `latency_probe.cpp`.
  - Finding: first 10-minute attempt was invalid because synthetic endpoints did not send periodic `ALIVE`, causing server timeout after only `3732` received packets.
  - Implementation: sender and receiver probe loops now send `ALIVE` roughly once per second.
  - Verification: `cmake --build build --target latency_probe`.
  - Verification: 30-second PCM run sent/received/decoded `6000/6000/6000` packets with `0` underruns.
- [x] Add simple adaptive resampling or controlled frame slip/stretch.
  - Implemented first as bounded PCM hold/drop instead of continuous resampling.
  - Rationale: use visible, limited correction before adding a more complex resampler.
- [x] Verify 10+ minute automated PCM probe does not periodically underrun.
  - Verification: corrected 10-minute probe through local `server.exe`.
  - Command: `latency_probe --server 127.0.0.1 --port 9999 --codec pcm --frames 240 --jitter 3 --seconds 600`.
  - Result: sent/received/decoded `120000/120000/120000`, underruns `0`, decode failures `0`, latency `25 ms`.
  - Queue result: average queue depth `4.10`, drift from jitter target `+1.10`, min after ready `1`, max `9`.
  - Interpretation: the local PCM path is stable for 10 minutes at default `240/3`, but the effective queue runs about one packet above the nominal jitter target.
- [x] Verify 10+ minute real RtAudio client session does not show steady-state rebuffer/decode/send errors.
  - Verification: local `server.exe` plus two real `client.exe` processes ran for about `10m37s`.
  - Settings observed: WASAPI, `1` input channel, `2` output channels, actual buffer `240` frames / `5.000 ms`.
  - Both clients registered the other participant and reached jitter buffer ready.
  - Filtered logs showed no steady-state decode failures, PCM size mismatches, send errors, invalid packets, or rebuffering during the run.
  - Caveat: one rebuffer appeared on client A exactly when the test stopped client B, matching the known teardown artifact.
- [x] Add real-client startup buffer override for repeatable tests.
  - Changed: `client.cpp`.
  - Implementation: added `client --frames N` / `client --buffer-frames N`.
  - Verification: `cmake --build build --target client`.
  - Verification: `client --frames 120` opened actual `120` frames / `2.500 ms`.
  - Verification: `client --frames 128` opened actual `128` frames / `2.667 ms`.
- [x] Test lower real-client buffers.
  - Result: `120` and `128` both reached jitter ready, then immediately logged one rebuffer per client.
  - Interpretation: backend accepts lower buffers, but current playout startup/timing policy is not stable enough there.
  - Baseline check: restarted visible default `240`; user confirmed audio transfer is correct.
- [x] Fix lower-buffer startup/playout stability enough for `120` candidate testing.
  - Changed: `client.cpp`.
  - Implementation: PCM receive misses no longer permanently disable playback; a missed PCM callback outputs silence and keeps playback armed for the next packet.
  - Implementation: receive queue cap now allows small-frame packets (`<=128`) up to `6` packets before dropping, while `240` keeps the previous tighter cap.
  - Verification: `cmake --build build --target client`.
  - Verification: visible `120` session no longer stopped after one second; user confirmed audio was audible, mostly clear, with occasional artifacts on whistle/bursty sounds.
- [x] Run extended real-client `120` candidate test.
  - Verification: two visible clients with `--frames 120` through local `server.exe` ran for about `10m45s`.
  - Result: both clients stayed `ready=true`, `underruns=0`, no sequence gaps, no decode failures, no PCM size mismatches.
  - Remaining issue: queue-depth drops and PCM sender drops still accumulate, so `120` is usable but not yet clean.
- [x] Reduce remaining `120` artifacts by addressing sender drops and receive queue drop policy.
  - In progress: increased small-frame sender queue headroom from `3` to `8` frames and receive queue headroom from `6` to `8` packets for `<=128` frame packets.
  - Verification: `cmake --build build --target client`.
  - Early `120` visible-session result: PCM sender drops fell to `0`; client B receive queue drops stayed `0`; client A had an early receive-drop burst around `284` and then stopped increasing during the sampled window.
  - User listening result: audio is clear at `120`.
  - Extended observation caveat: user accidentally closed one client around `20:07:41`, so the later single-client logs are not a valid two-client audio test.
  - Valid pre-close observation: sender drops stayed `0`, underruns stayed `0`, sequence gaps stayed `0`, and receive drops were stable rather than continuously increasing.
  - Current verification: run a clean uninterrupted 10-minute two-client `120` session before marking this item complete.
  - Final verification: clean uninterrupted two-client `120` session ran for about `10m35s`.
  - Result: both clients stayed `ready=true`; PCM sender drops `0`; receive queue drops `0`; underruns `0`; sequence gaps/late `0/0`; decode/send/packet errors `0`.
  - Teardown caveat: server logged forced-close receive errors exactly when the test processes were stopped.
- [x] Make validated `120` the explicit low-latency default while preserving `240` safe fallback.
  - Changed: `client.cpp`.
  - Implementation: default requested buffer is now `120` frames.
  - Implementation: buffer selector labels `120 Low` and `240 Safe`.
  - Verification: `cmake --build build --target client`.
  - Verification: default startup with no `--frames` opened actual `120` frames / `2.500 ms`.
  - Verification: two-client smoke stayed `ready=true` with sender drops `0`, receive drops `0`, underruns `0`, and sequence gaps/late `0/0`.
- [x] Test `96` frame PCM as next-lower candidate.
  - Verification: two visible clients with `--frames 96` through local `server.exe`.
  - Result: WASAPI accepted actual `96` frames / `2.000 ms`.
  - Result after about `4` minutes: both clients stayed `ready=true`; PCM sender drops `0`; underruns `0`; sequence gaps/late `0/0`; decode/send/packet errors `0`.
  - Receive drops: low but nonzero; not continuously exploding in the sampled window.
  - Status: promising candidate, not default. Needs user listening confirmation and clean 10-minute run before promotion.
- [x] Run clean 10-minute `96` validation.
  - User listening result: `96` sounds clear.
  - Required before promotion: uninterrupted 10-minute two-client run with clean counters.
  - Verification: two visible clients with `--frames 96` through local `server.exe` ran for about `10m35s`.
  - Result: actual `96` frames / `2.000 ms`; both clients stayed `ready=true`; PCM sender drops `0`; underruns `0`; sequence gaps/late `0/0`; decode/send/packet errors `0`.
  - Caveat: receive queue drops accumulated to about `768` and `491`, so `96` is validated as a clear ultra-low candidate on this machine, but `120` remains the safer default.
- [x] Expose `96` as Ultra while keeping `120` default.
  - Implementation: buffer selector now labels `96 Ultra`, `120 Low`, and `240 Safe`.
  - Verification: `cmake --build build --target client`.
  - Verification: default startup still opens actual `120` frames / `2.500 ms`.
- [x] Test lower-than-96 failure boundary, starting with `64`.
  - Verification: two visible clients with `--frames 64` through local `server.exe`.
  - Result: WASAPI accepted actual `64` frames / `1.333 ms`.
  - User listening result: audio sounded clear.
  - Counters: both clients stayed `ready=true`; PCM sender drops `0`; underruns `0`; sequence gaps/late `0/0`; packet age average stayed around `10.0-10.5 ms`.
  - Caveat: receive queue drops accumulated, and queue depth frequently hit `8`, so the device callback is really `64` but end-to-end playout still has hidden buffering.
- [x] Test below `64` to prove the lower boundary is real.
  - Verification: two visible clients with `--frames 32` through local `server.exe`.
  - Result: WASAPI accepted actual `32` frames / `0.667 ms`.
  - User listening result: audio became bad, corrupt, and robotic.
  - Counters: PCM sender drops appeared on both clients, receive queue drops exploded into the tens of thousands, while underruns and sequence gaps still reported `0`.
  - Finding: underrun counters alone are not enough to detect robotic/corrupt audio. Receive queue drops, send drops, and listening result are required pass/fail signals.
- [x] Decide next latency move after boundary test.
  - Current finding: lowering device callback below `64` is not useful with the current receive/sender queue policy.
  - Candidate next step: reduce hidden playout buffering and make robotic/corrupt audio detectable from counters before promoting `64`.
  - Decision: stop lowering callback size for now. Next latency move is PCM playout readiness/headroom, guarded by the new health warnings.
- [x] Reduce hidden queue headroom for `64`-frame PCM only.
  - Scope: keep `96`/`120` behavior unchanged.
  - Goal: test whether `64` can reduce packet age below the current `~10 ms` without becoming robotic/corrupt.
  - Verification: build client, run two visible clients with `--frames 64`, compare packet age, send drops, receive drops, underruns, and user listening result.
  - Result: failed. User reported robotic/corrupt audio.
  - Finding: queue cap `4` at `64` caused aggressive queue drops and unstable playout. Reverted to the previous `8`-packet small-frame headroom.
- [x] Add explicit corrupt-audio health signal.
  - Current problem: `32` and the tighter `64` run can sound bad while underruns and sequence gaps still show `0`.
  - Candidate signal: fail when PCM sender drops or receive queue drops exceed a per-second threshold after jitter is ready.
  - Verification: bad `32`/tight-`64` run should be flagged automatically; stable `96`/`120` should not.
  - Implementation: audio diagnostics now log per-second PCM send and receive queue drop rates.
  - Implementation: warnings are emitted when PCM send drops exceed `5/s`, receive queue drops exceed `100/s`, or age drops exceed `5/s`.
- [x] Verify corrupt-audio health signal.
  - Bad case: `--frames 32` should emit audio health warnings.
  - Stable case: default `120` should not emit audio health warnings in a short smoke.
  - Bad-case result: `--frames 32` emitted warnings with PCM drop rates up to about `23/s` and queue drop rates around `670-700/s`.
  - Stable-case result: default `120` emitted no audio health warnings; PCM and queue drop rates stayed `0.0/s`.
- [x] Decide whether `64` should remain experimental or be hidden.
  - Current finding: original `64` can sound clear with larger headroom, but it still has about `10 ms` packet age and accumulates receive drops.
  - Current finding: tighter `64` becomes robotic/corrupt.
  - Recommendation: do not promote `64`; keep `96` as Ultra and `120` as default until a better playout strategy is implemented.
  - Decision: hide `64` from the normal UI selector.
  - Implementation: UI buffer options are now `96`, `120`, `128`, `240`, `256`, and `512`.
  - Experimental access: `client --frames 64` remains available for explicit boundary tests.
- [x] Verify UI buffer selector after hiding `64`.
  - Build client.
  - Start default clients and confirm startup still opens `120`.
  - Confirm no accidental behavior change to `--frames 64` override.
  - Verification: `cmake --build build --target client`.
  - Result: default client opened actual `120` frames / `2.500 ms`.
  - Result: explicit `client --frames 64` still opened actual `64` frames / `1.333 ms`.
  - Caveat: this was a startup smoke with mixed frame sizes, not an audio-quality validation.
- [x] Test lower PCM playout readiness for low-latency PCM.
  - Scope: PCM only; leave Opus behavior unchanged.
  - Candidate: low-latency PCM packets (`<=120` frames) start playback after `2` packets instead of `3`.
  - Goal: reduce hidden packet age without touching device callback size.
  - Guardrail: health warnings must stay quiet in a `120` smoke before considering `96`.
  - Implementation: low-latency PCM packets now set participant jitter floor to `2`; Opus and larger packets keep the existing `3`-packet floor.
  - Implementation: adaptive jitter decrease now respects the participant's codec/frame-specific floor.
  - Verification: `cmake --build build --target client`.
  - Verification: two default clients opened actual `120` frames / `2.500 ms` and reached jitter ready at `2` packets.
  - Result: stable short smoke; no health warnings, no sender drops, no receive drops, no underruns, no sequence gaps.
  - Finding: steady packet age stayed around `9.8 ms`, because queue depth still settled around `4`; startup readiness alone is not enough.
- [x] Test tighter steady-state receive cap for `120` PCM.
  - Scope: test `120` only before touching `96`.
  - Candidate: cap low-latency PCM receive queue closer to `3` packets.
  - Goal: reduce packet age below the current `~9.8 ms`.
  - Guardrail: revert if health warnings, sender drops, receive drops, underruns, or user listening report go bad.
  - Result: failed. Queue cap `3` produced audio health warnings around `100 queue drops/s`.
  - Result: packet age stayed around `9.6-9.8 ms`, so the cap did not buy meaningful latency.
  - Decision: reverted the cap experiment; keep the previous `8`-packet small-frame receive headroom.
- [x] Investigate why packet age remains around `9-10 ms`.
  - Current finding: lowering startup readiness and tighter receive cap did not materially reduce age.
  - Candidate causes: sender queue timing, network-thread scheduling, WASAPI backend buffering, or timestamp placement.
  - Next verification: add/inspect capture-to-send and receive-to-playout timing so packet age is decomposed instead of treated as one number.
  - Implementation: PCM send frames now carry a capture timestamp.
  - Implementation: audio diagnostics now log PCM sender queue age as `sendq_age_ms last/avg/max`.
  - Clarification: existing participant packet age is receive-enqueue-to-playout, not capture-to-speaker end-to-end.
  - Verification: two default clients at `120` showed send queue average near `0.00 ms`, max about `0.23-0.51 ms`.
  - Finding: the `~9.7-9.8 ms` age is receive/playout side, not sender queue backlog.
- [x] Decide next receive/playout latency strategy.
  - Current finding: receive cap `3` caused high drop rates without improving age.
  - Current finding: sender queue is not the bottleneck.
  - Candidate A: add a real playout scheduler with target delay and controlled skip only when late.
  - Candidate B: move toward competitor-style backend/device path first: ASIO/WASAPI exclusive/JACK-style low-latency backend before deeper playout complexity.
  - Recommendation: inspect/implement backend options next because RtAudio reports WASAPI backend latency as unavailable/zero and Windows shared-mode devices can hide large latency outside our counters.
  - Finding: vendored RtAudio WASAPI initializes shared-mode streams and has TODOs for `RTAUDIO_MINIMIZE_LATENCY` direct-buffer behavior and `RTAUDIO_HOG_DEVICE` exclusive mode.
  - Decision: backend/device path is the next major latency lever. Playout changes alone are hitting guardrails.
- [x] Add backend limitation warning to docs/UI.
  - Current runtime backend: WASAPI.
  - Current limitation: RtAudio WASAPI path is shared-mode in the vendored source; ASIO is preferred when available.
  - Goal: make it visible that low callback frames do not guarantee low device/output latency on WASAPI shared mode.
  - Implementation: the latency panel now shows `Backend latency unknown` when output API is WASAPI and RtAudio reports zero/unavailable backend latency.
- [x] Verify backend limitation warning builds.
  - Build client.
  - Startup smoke is enough; no audio behavior changed.
  - Verification: `cmake --build build --target client`.
- [x] Evaluate backend alternatives for true Windows low latency.
  - Option A: ASIO driver path through current RtAudio build.
  - Option B: switch Windows backend/library if we need WASAPI exclusive/event low-latency control.
  - Option C: JACK/PipeWire-style external audio server for platforms where available.
  - Implementation: added `client --list-audio-devices` / `client --audio-devices` to print visible RtAudio APIs/devices and exit.
  - Goal: make ASIO verification repeatable after installing an ASIO driver/interface.
- [x] Verify audio backend inventory command.
  - Build client.
  - Run `client --list-audio-devices`.
  - Expected on current machine: WASAPI visible; ASIO compiled but no visible ASIO devices unless an ASIO driver is installed.
  - Verification: `cmake --build build --target client`.
  - Verification: `build/Debug/client.exe --list-audio-devices`.
  - Result: RtAudio APIs visible: `ASIO` and `WASAPI`.
  - Result: ASIO default input/output are `0`, and no ASIO devices are listed.
  - Result: current visible devices are WASAPI only.
- [x] Decide backend implementation direction.
  - Current practical path: install/use a real ASIO driver/interface and verify with `client --list-audio-devices`.
  - If ASIO is not available or not acceptable: integrate a Windows backend with explicit WASAPI exclusive/event control instead of relying on RtAudio WASAPI shared mode.
  - Recommendation: keep current RtAudio ASIO path, but treat direct WASAPI exclusive as the next code path only if hardware/driver constraints prevent ASIO.
  - Implementation: added `client --require-api NAME` / `client --api NAME` to force startup onto a specific visible API.
  - Expected use: `client --require-api ASIO` should fail fast today, and should start with ASIO after a real ASIO driver/interface is visible.
  - Final decision for current machine: do not build a direct WASAPI-exclusive client backend yet. The probe rejected exclusive initialization on all current endpoints, while ASIO support is already compiled and only needs a visible driver/device.
- [x] Verify forced audio API startup option.
  - Build client.
  - Run `client --require-api ASIO`; current machine should fail clearly because no ASIO input/output devices are visible.
  - Run `client --require-api WASAPI --frames 120`; current machine should start far enough to open the selected WASAPI devices.
  - Adjustment: missing required API now fails before constructing the client/network connection.
  - Verification: `cmake --build build --target client`.
  - Result: `client --require-api ASIO` exits `2` and prints visible APIs/devices; no ASIO input/output devices are visible.
  - Result: `client --require-api WASAPI --frames 120` starts and opens actual `120` frames / `2.500 ms`.
- [x] Document backend decision.
  - Decision: current code path is ready for ASIO validation, but this machine lacks an ASIO device.
  - Next code-heavy option would be direct WASAPI exclusive/event implementation or another library that exposes it.
  - Recommended next practical step before writing a Windows backend: test with a real ASIO driver/interface, because this path is already compiled and selectable.
- [x] Reject machine-specific backend spike as product direction.
  - User correction: this is a cross-platform app; do not proceed by adding machine-specific backend code as the main path.
  - Reverted: removed the Windows-only `wasapi_probe` target and source file.
  - Decision: backend work must stay behind the cross-platform audio abstraction unless a platform implementation is explicitly selected later.
- [x] Add cross-platform audio open smoke command.
  - Goal: validate selected API/device/buffer without opening the GUI.
  - Use existing `AudioStream` abstraction, not platform-native APIs.
  - Command shape: `client --audio-open-smoke --require-api ASIO --frames 96`.
  - Verification: exits `0` only if the stream opens, reports actual buffer/backend latency, and closes cleanly.
  - Implementation: added `client --audio-open-smoke`.
  - Implementation: smoke uses `AudioStream` directly and outputs silence through the normal callback contract.
- [x] Verify cross-platform audio open smoke command.
  - Build client.
  - Run `client --audio-open-smoke --require-api WASAPI --frames 120` on current machine.
  - Run `client --audio-open-smoke --require-api ASIO --frames 96`; current machine should fail before opening because no ASIO devices are visible.
  - Verification: `cmake --build build --target client`.
  - Result: `client --audio-open-smoke --require-api WASAPI --frames 120` opened actual `120` frames / `2.500 ms` and exited cleanly.
  - Result: `client --audio-open-smoke --require-api ASIO --frames 96` exited `2` because no ASIO input/output devices are visible.
- [x] Next practical latency step.
  - Keep RtAudio as the cross-platform backend wrapper for now.
  - Validate real low-latency APIs through `--list-audio-devices`, `--require-api`, and the planned audio-open smoke command.
  - Do not add native Windows/CoreAudio/JACK backend code unless the cross-platform abstraction fails a concrete requirement.
- [x] Add automated clock-drift stress to `latency_probe`.
  - Goal: reproduce sound-card clock mismatch without human listening.
  - Implementation: add `--playout-ppm` to run receiver playout slightly faster/slower than sender packet production.
  - Verification: build `latency_probe`; run a short PCM baseline with `--playout-ppm 0` and a drift stress with nonzero ppm.
  - Verification: `cmake --build build --target latency_probe`.
  - Result: `latency_probe --codec pcm --frames 120 --jitter 16 --seconds 20 --playout-ppm 0` stayed clean with `0` underruns and average queue `15.49`.
  - Result: `latency_probe --codec pcm --frames 120 --jitter 16 --seconds 20 --playout-ppm 500` stayed sample-clean but drained average queue to `11.54`, proving the probe can apply receiver clock pressure.
  - Constraint: run probe cases serially or isolate them by server/port; concurrent probe clients hear each other through the SFU and invalidate receive counts.
- [x] Add controlled drift correction to client playout.
  - Goal: keep low jitter buffers stable when capture and playback clocks disagree.
  - Preferred first implementation: Jamulus-style bounded frame slip/duplicate or tiny resampling adjustment inside the client playout path.
  - Verification: use `latency_probe --playout-ppm` before and after the correction, then repeat manual `96`/`120` frame listening.
  - Implementation: add bounded PCM slip by dropping exactly one queued PCM packet after a successful playout when queue depth exceeds `jitter_buffer_min_packets + 3`.
  - Implementation: keep the bounded PCM hold from the prior step for the opposite empty-queue direction.
  - Guardrail: this is not continuous resampling; it is a small, visible correction with `PCM drift drop` and `PCM hold` counters.
  - Verification: `cmake --build build --target client`.
  - Verification: `client --audio-open-smoke --require-api WASAPI --frames 120`.
  - Manual result: two-client local `120` frame test sounded clear after bounded PCM hold/drop.
- [x] Re-test `96` frame real-client path after bounded drift correction.
  - Goal: check whether the new hold/drop correction keeps Ultra mode clear.
  - Verification: two local clients at `--frames 96`; listen for robotic/corrupt artifacts and watch `PCM hold`, `PCM drift drop`, queue depth, and health warnings.
  - Manual result: two-client local `96` frame test sounded clear after bounded PCM hold/drop.
- [x] Re-test explicit `64` frame experimental path after bounded drift correction.
  - Goal: determine whether the new bounded hold/drop makes `64` usable or still risky.
  - Verification: two local clients at `--frames 64`; listen for robotic/corrupt artifacts and watch `PCM hold`, `PCM drift drop`, queue depth, and health warnings.
  - Manual result: two-client local `64` frame test still sounded robotic/corrupt.
  - Decision: keep `64` hidden/experimental. Do not promote it without a deeper playout/backend change.
- [x] Add a documented latency tier decision.
  - Goal: make the current product decision explicit instead of repeatedly retesting the same boundary.
  - Current candidate decision: `120` default, `96` Ultra, `64` experimental CLI-only, `32` invalid.
  - Verification: update audit with the evidence chain and leave UI behavior aligned with this decision.
  - Decision: current tier map is `120` default, `96` Ultra, `64` CLI-only experimental, `32` invalid/bad.
  - Evidence: post-correction `120` clear, post-correction `96` clear, post-correction `64` robotic/corrupt.
- [x] Decide next major latency lever.
  - Option A: longer stability run at `96` with the new bounded hold/drop counters.
  - Option B: backend/device work for true lower hardware latency, preferably real ASIO/JACK/CoreAudio validation through the cross-platform abstraction.
  - Option C: deeper playout algorithm with controlled resampling instead of bounded slip/hold.
  - Decision: do Option A first. `96` is the best validated latency tier, and it should get an extended run before larger backend/resampler work.
- [x] Run extended `96` validation after bounded drift correction.
  - Goal: verify `96` stays stable with the new `PCM hold` and `PCM drift drop` counters.
  - Verification: two local clients at `--frames 96` for an extended run; inspect logs for health warnings, send drops, queue drops, underruns, and hold/drop counter behavior.
  - Verification: hidden two-client `96` run with captured logs ran for about `10` minutes.
  - Result: no audio health warnings, no send/decode/packet errors, no sequence gaps or late packets.
  - Result: final client A participant stats showed `pcm_hold/drop=196/0`, queue drops `306`, age drops `0`, drop rate `pcm/q=0.0/1.0/s`.
  - Result: final client B participant stats showed `pcm_hold/drop=59/1`, queue drops `90`, age drops `0`, drop rate `pcm/q=0.0/1.6/s`.
  - Interpretation: `96` is stable and clear, but not perfectly clean internally; the bounded hold is actively smoothing occasional empty-queue gaps.
- [x] Decide whether to tune `96` hold pressure or move to backend validation.
  - Finding: `96` clear audio is now backed by an extended run, but `PCM hold` is nonzero.
  - Option A: accept occasional bounded hold because it is clear and warning-free.
  - Option B: add a deeper playout/resampling correction to reduce hold events.
  - Option C: validate lower-latency backend/device path before adding more playout complexity.
  - Decision: accept current `96` as Ultra for now and move the next major latency lever to backend/device validation.
  - Rationale: `96` is clear, warning-free, and now has visible hold/drop rates; a resampler is larger and should follow only if hold becomes audible or backend work cannot reduce hidden latency.
- [x] Add PCM hold/drift-drop rates to health diagnostics.
  - Goal: distinguish clear-but-smoothed `96` from truly corrupt lower-buffer runs.
  - Implementation: participant diagnostics now log `drop_rate pcm/q/hold/drift`.
  - Implementation: health warnings now include high PCM hold or drift-drop rates.
  - Verification: `cmake --build build --target client`.
  - Verification: `client --audio-open-smoke --require-api WASAPI --frames 96`.
  - Verification: short two-client `96` log run emitted `drop_rate pcm/q/hold/drift=...`.
- [x] Refresh audio backend inventory after `96` validation.
  - Verification: `client --list-audio-devices`.
  - Result: RtAudio APIs visible are `ASIO` and `WASAPI`.
  - Result: ASIO still has default input/output `0` and no listed ASIO devices.
  - Result: current usable devices are WASAPI only.
- [x] Backend/device validation blocker.
  - Need a real low-latency API/device path visible to RtAudio, such as ASIO on Windows or JACK/CoreAudio equivalents on other platforms.
  - Current machine cannot validate ASIO because no ASIO devices are visible.
  - Implementation: added `client --backend-check` / `client --low-latency-check`.
  - Behavior: default check targets `ASIO` at `96` frames.
  - Verification: `client --backend-check` fails clearly because ASIO has no input/output devices and prints the backend inventory.
  - Verification: `client --backend-check --require-api WASAPI --frames 96` opens, reports actual `96` frames / `2.000 ms`, and warns that backend latency is unavailable.
- Deferred external validation: real low-latency backend.
  - Need a machine/device where ASIO, JACK, CoreAudio low-latency, or equivalent is actually available.
  - Expected command: `client --backend-check --require-api ASIO --frames 96`.
  - Pass condition: command opens the stream and reports real device/backend behavior without falling back to WASAPI.
- [x] Add bounded PCM empty-queue concealment.
  - Goal: avoid a hard silent callback when PCM briefly underruns.
  - Implementation: store the last decoded PCM frame and replay it once at reduced gain when the PCM queue is empty.
  - Guardrail: the fallback is one callback only; repeated empty callbacks still go silent instead of manufacturing continuous fake audio.
  - Verification: `cmake --build build --target client`.
  - Verification: `client --audio-open-smoke --require-api WASAPI --frames 120`.

## Archived Initial Draft

The original rough phase draft that used to live here has been superseded by the Control Board at the top of this file. It contained stale unchecked items that had already been completed in the historical work log, so it was removed to avoid treating old draft tasks as active work.

Active work must now be added only to the Control Board. Detailed commands, measurements, and findings belong in `LOW_LATENCY_AUDIO_AUDIT.md`.
