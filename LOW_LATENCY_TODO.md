# Low Latency Implementation Todo

Date: 2026-04-26

## Rule For This Work

This file is the source of truth for the latency work. Update it before and after each implementation step so decisions, progress, and verification are not floating only in chat.

## Current Objective

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
- [ ] Keep this file updated before and after every code step.
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
- [ ] Consider Jamulus-style custom Opus modes only if needed for 64/128 sample compressed mode.

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
- [ ] Add simple adaptive resampling or controlled frame slip/stretch.
- [ ] Verify 10+ minute session does not grow latency or periodically underrun.

## Assumptions

- The first implementation step is a backend replacement, not a full audio architecture rewrite.
- The current SFU server behavior stays unchanged.
- The current Opus packet format stays unchanged for this step unless RtAudio build integration forces otherwise.
- Low-latency correctness will not be assumed from green tests; it must eventually be verified with callback timing, device latency, packet age, and real listening tests.

## Success Criteria For RtAudio Swap

- Client target configures and builds.
- PortAudio is no longer linked by the client target.
- `audio_stream.h` owns RtAudio usage and keeps the rest of the client mostly backend-neutral.
- Device listing, default input/output selection, start, stop, and hot-swap still compile.
- Existing Opus/SFU send/receive path remains behaviorally unchanged.
- New limitations or behavior changes are documented here.

## Phase 1: RtAudio Backend Swap

- [x] Inspect existing PortAudio usage.
  - Verification: `rg` found PortAudio usage concentrated in `audio_stream.h`, `client.cpp`, and `cmake/client.cmake`.
  - Finding: `client.cpp` still used PortAudio device IDs and callback signature directly.

- [x] Replace CMake dependency from PortAudio to RtAudio.
  - Changed: `cmake/client.cmake`.
  - Verification pending: configure/build.

- [x] Replace `AudioStream` internals with RtAudio.
  - Changed: `audio_stream.h`.
  - Current approach: keep `AudioStream` as the client-facing abstraction, add `AudioStream::DeviceIndex`, `AudioStream::NO_DEVICE`, and a backend-neutral callback type.
  - Verification pending: compile errors will drive API corrections.

- [x] Replace PortAudio-specific types/usages in `client.cpp`.
  - Replace `#include <portaudio.h>`.
  - Replace `PaDeviceIndex` with `AudioStream::DeviceIndex`.
  - Replace `paNoDevice` with `AudioStream::NO_DEVICE`.
  - Replace PortAudio callback parameters with the new `AudioStream::AudioCallback` shape.
  - Replace direct `Pa_GetHostApiInfo(...)` device metadata access with `AudioStream::DeviceInfo` fields.
  - Verification: `rg -n "Pa_|PortAudio|portaudio|paNoDevice|paContinue|PaDeviceIndex" client.cpp audio_stream.h cmake/client.cmake` returns no matches.

- [x] Configure and build the client.
  - Command: `cmake --build build --target client`
  - Verification: build succeeded and produced `build/Debug/client.exe`.
  - Finding: RtAudio configured with WASAPI support in this build. ASIO is not enabled yet.
  - Finding: first build failed because RtAudio 6.0.1 does not use the older exception/probed API shown in some examples. Fixed wrapper to use return codes/device IDs.

- [x] Update audit with RtAudio findings.
  - Add actual build/link limitations.
  - Add any RtAudio API constraints encountered.

## Phase 2: Measurement Before Architecture Changes

- [ ] Add callback duration metrics.
  - Track max callback time, average callback time, and over-deadline count.
  - Deadline is `frame_count / sample_rate`.
  - Verification: UI/log shows callback timing under current behavior.

- [ ] Add packet age and queue metrics.
  - Track enqueue timestamp, dequeue timestamp, packet age at playback, queue depth, underruns, PLC count.
  - Verification: logs/UI can explain audible latency.

- [ ] Add actual device latency reporting.
  - RtAudio exposes stream latency in frames; document whether it is combined latency or can be separated by backend.
  - Verification: log reports requested buffer, actual buffer, stream latency frames/ms.

## Phase 3: Real-Time-Safe Callback

- [ ] Move Opus encode and UDP send out of the audio callback.
  - Target design: callback pushes mic PCM to an SPSC queue; sender thread encodes/builds/sends.
  - Verification: callback contains no packet allocation and no socket send.

- [ ] Remove heap allocation from callback.
  - Eliminate `std::vector` creation in callback path.
  - Replace packet construction with fixed/preallocated buffers.
  - Verification: code review by searching callback body for vectors/shared_ptr allocations.

- [ ] Remove mutex contention from callback.
  - Replace `ParticipantManager::for_each()` callback path with lock-free or snapshot/RCU style access.
  - Verification: callback does not take `ParticipantManager` mutex.

## Phase 4: Packet/Jitter Foundation

- [ ] Add sequence numbers to audio packets.
  - Required for loss/reorder/late detection.
  - Verification: receiver logs sequence gaps and reorder events.

- [ ] Add codec/frame metadata to audio packets.
  - Required before raw PCM and variable frame sizes.
  - Verification: receiver can route packet by codec and expected frame count.

- [ ] Replace queue-only jitter behavior with sequence-aware playout.
  - Use target playout delay in packets/ms.
  - Verification: bounded latency and observable packet discard policy.

## Phase 5: Raw PCM Low-Latency Mode

- [ ] Add raw PCM packet mode.
  - First candidate: float32 mono to match current callback buffers.
  - Later candidate: int16 PCM to reduce bandwidth.
  - Verification: one local client can send/receive raw packets through existing server.

- [ ] Add latency presets.
  - Studio: raw PCM, 64 or 128 frames, minimal jitter.
  - Balanced: Opus, 128 or 240 frames, low jitter.
  - Safe: Opus, larger buffer, more jitter tolerance.
  - Verification: presets map to explicit config fields.

## Phase 6: Clock Drift Handling

- [ ] Track jitter buffer fill trend per participant.
- [ ] Add adaptive resampling or frame slip/stretch strategy.
- [ ] Verify long-running sessions do not slowly underrun or grow latency.

## Open Decisions

- [ ] Should the RtAudio swap include ASIO-first selection on Windows immediately, or only expose APIs/devices and let the user choose?
  - Recommended answer: expose devices first, then add ASIO preference after build is stable.

- [ ] Should raw PCM use float32 first or int16 first?
  - Recommended answer: float32 first for simpler integration; int16 later for bandwidth.

- [ ] Should we copy JackTrip/Jamulus code directly or copy architecture first?
  - Recommended answer: direct-copy only when adopting the surrounding contract too. Avoid isolated transplanting.

## Completed Findings

- UDP/SFU is likely not the primary bottleneck.
- Current callback architecture is not safe for smaller buffers.
- Competitors rely on tiny configurable buffers, preallocation, jitter control, and often raw PCM or carefully tuned Opus.
