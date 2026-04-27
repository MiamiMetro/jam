# Low Latency Audio Audit

Date: 2026-04-26

## Goal

Find why the current project produces clear audio but not low enough latency for live jamming, and why aggressive configuration changes produce robotic or corrupt audio. Prefer proven open-source approaches and libraries over fragile custom work.

## Working Hypotheses

- Client-side buffering, callback scheduling, or jitter handling is more likely than raw UDP network delay if the audio is clear but late.
- Robotic/corrupt audio after tuning usually points to broken frame-size assumptions, underruns/overruns, packet-loss handling, resampling drift, or Opus encode/decode configuration mismatch.
- UDP itself is unlikely to be the primary bottleneck; incorrect buffering and real-time audio integration are more common failure points.
- Opus can work for low-latency music, but configuration matters. For the lowest possible jamming latency, some competitors avoid codecs entirely and send uncompressed PCM over UDP/LAN-quality links.

## Repo Snapshot

- Language: C++
- Audio stack candidates: PortAudio, Opus
- Network model candidates: UDP client/server, SFU-style forwarding
- Existing latency notes: `LATENCY_FINDINGS.md`
- Existing roadmap: `FEATURE_ROADMAP.md`

## Live Findings

### 2026-04-27 Pass 22: Buffer-size controls

- Added requested buffer-size controls to the bottom bar.
- Selectable frame sizes:
  - `64`
  - `96`
  - `120`
  - `128`
  - `240`
  - `256`
  - `512`
- Applying a new buffer size restarts the active stream through the existing device swap/start flow.
- Existing master strip/logs show actual accepted buffer frames and buffer duration after stream open.
- Important caveat:
  - RtAudio does not expose a universal per-device supported-buffer-size list.
  - The UI exposes candidate requests; the device/backend may accept, adjust, or reject them.
- Build verification:
  - `cmake --build build --target client`
- Runtime smoke:
  - Default request remains `240` frames.
  - Current WASAPI device opened with actual `240` frames / `5.000 ms`.

### 2026-04-27 Pass 21: ASIO-first default selection

- Added ASIO-first default device selection.
- Changed `audio_stream.h`:
  - Default input selection prefers ASIO devices when available.
  - Default output selection prefers ASIO devices when available.
  - If no ASIO device is present, fallback remains RtAudio's default input/output behavior.
- Manual API/device selection was already exposed in the bottom bar and remains unchanged.
- Build verification:
  - `cmake --build build --target client`
- Runtime smoke:
  - Current machine still enumerates only WASAPI devices.
  - Client correctly fell back to WASAPI and auto-started.
- Interpretation:
  - On a machine with a visible ASIO driver, the app should now auto-prefer ASIO.
  - On this machine, ASIO is compiled in but no ASIO runtime device is visible.

### 2026-04-27 Pass 20: RtAudio ASIO build support

- Enabled RtAudio ASIO backend in the client CMake path.
- Changed `cmake/client.cmake`:
  - `RTAUDIO_API_ASIO=ON`
- Configure verification:
  - `cmake -S . -B build`
  - CMake reports `Compiling with support for: asio wasapi`.
- Build verification:
  - `cmake --build build --target client`
  - RtAudio compiled ASIO sources:
    - `asio.cpp`
    - `asiodrivers.cpp`
    - `asiolist.cpp`
    - `iasiothiscallresolver.cpp`
- Generated project verification:
  - `RTAUDIO_API_ASIO:BOOL=ON`
  - RtAudio build defines `__WINDOWS_ASIO__` and `__WINDOWS_WASAPI__`.
- Runtime smoke:
  - Client still auto-started successfully through WASAPI.
  - Device enumeration on this machine still showed only WASAPI devices.
- Interpretation:
  - ASIO support is now compiled in.
  - A real ASIO device/driver still needs to be installed and visible before the app can use ASIO at runtime.

### 2026-04-27 Pass 19: Opus jamming defaults and frame validation

- Updated Opus settings for jamming-oriented behavior.
- Changed `opus_encoder.h`:
  - Disabled in-band FEC with `OPUS_SET_INBAND_FEC(0)`.
  - Set expected packet loss to `0`.
  - Switched to CBR-style packet pacing with `OPUS_SET_VBR(0)`.
  - Kept restricted low-delay and music signal configuration.
- Added explicit Opus frame-size validation:
  - Legal durations: 2.5, 5, 10, 20, 40, 60 ms.
  - At 48 kHz, `120` and `240` sample frames are legal.
  - `96` and `64` sample frames are rejected before calling `opus_encode_float`.
- Build verification:
  - `cmake --build build --target client`
  - `cmake --build build --target latency_probe`
- Opus sweep verification through local `server.exe`:
  - `240` frame legal settings still sent/received/decoded.
  - `120` frame legal settings still sent/received/decoded; one `120/jitter2` run completed without warning indicators.
  - `96` and `64` frame settings failed cleanly with encode failures and zero packets sent.
- Interpretation:
  - Standard Opus remains useful only for legal frame sizes.
  - Low-latency 64-frame compressed mode should not be attempted with standard `opus_encode_float`; that remains a future Jamulus-style custom-mode decision.

### 2026-04-27 Pass 18: Minimal codec mode switch

- Added a minimal user-facing codec selector in the master strip.
- Options:
  - PCM
  - Opus
- PCM int16 remains the default.
- The switch uses the existing `audio_codec_` routing:
  - PCM goes through the raw PCM sender queue.
  - Opus goes through the Opus sender queue.
- No latency presets or frame-size controls were added in this step.
- Build verification:
  - `cmake --build build --target client`
- Runtime smoke verification:
  - Started local `server.exe`.
  - Started two hidden local `client.exe` processes using default PCM mode.
  - Both clients opened `1 input channel(s), 2 output channel(s)`.
  - Both clients registered the other participant.
  - Both clients reported jitter buffer ready.
  - Filtered logs showed no rebuffering, unknown-message, invalid-packet, incomplete-packet, decode-failure, PCM-size-mismatch, send-error, or top-level exception messages.
- Caveat:
  - Opus switching is UI-driven and still needs manual runtime exercise.

### 2026-04-27 Pass 17: First bounded jitter policy

- Added explicit jitter bounds to the existing queue-based playout model.
- Bounds:
  - Queue depth is capped to `TARGET_OPUS_QUEUE_SIZE + 1` after enqueue.
  - Packets older than `MAX_JITTER_PACKET_AGE_MS` are dropped at playout.
- Added counters:
  - queue-depth drops
  - packet-age drops
- Participant stats UI shows drop counters when nonzero.
- Important iteration:
  - First attempt capped queue depth exactly at `TARGET_OPUS_QUEUE_SIZE`.
  - That caused immediate startup rebuffering because the minimum ready depth and maximum retained depth were identical.
  - Corrected policy allows one packet of headroom: target `3`, max retained after enqueue `4`.
- Build verification:
  - `cmake --build build --target client`
- Runtime smoke verification after correction:
  - Started local `server.exe`.
  - Started two hidden local `client.exe` processes.
  - Both clients opened `1 input channel(s), 2 output channel(s)`.
  - Both clients registered the other participant.
  - Both clients reported jitter buffer ready.
  - Filtered logs showed no rebuffering, unknown-message, invalid-packet, incomplete-packet, decode-failure, PCM-size-mismatch, send-error, or top-level exception messages.
- Caveat:
  - This is still a queue-based bounded jitter model, not a full sequence-indexed playout buffer.
  - The next stronger version should use sequence numbers to choose exact playout frames and late-packet discard behavior.

### 2026-04-27 Pass 16: Sequence-aware receive diagnostics

- Added sequence diagnostics for `AudioHdrV2` packets.
- Per participant, the receive path now tracks:
  - next expected sequence
  - sequence gap count
  - late/out-of-order packet count
- Participant stats UI shows sequence gap/late counts when nonzero.
- Old V1 packets remain compatible and simply do not participate in sequence diagnostics.
- Build verification:
  - `cmake --build build --target client`
- Runtime smoke verification:
  - Started local `server.exe`.
  - Started two hidden local `client.exe` processes.
  - Both clients opened `1 input channel(s), 2 output channel(s)`.
  - Both clients registered the other participant.
  - Both clients reported jitter buffer ready.
  - Filtered logs showed no rebuffering, unknown-message, invalid-packet, incomplete-packet, decode-failure, PCM-size-mismatch, send-error, or top-level exception messages.
- Caveat:
  - This is diagnostics only. The jitter buffer still does not use sequence numbers for playout decisions.

### 2026-04-27 Pass 15: Callback allocation cleanup

- Removed remaining known heap allocation patterns from the audio callback path.
- Opus send path:
  - Removed callback `std::vector<unsigned char>` packet buffer.
  - Removed callback `std::vector<float>` silence-frame allocation.
  - Callback now enqueues fixed-size float frames to the sender thread.
- Participant iteration:
  - Replaced the `std::vector` snapshot in `ParticipantManager::for_each()` with a fixed-size stack `std::array` snapshot.
  - The callback path now avoids heap allocation for participant snapshot iteration.
- Build verification:
  - `cmake --build build --target client`
- Search verification:
  - Remaining `std::vector` and packet-allocation sites are outside the callback path or in sender/UI/lifecycle code.
- Runtime smoke verification:
  - Started local `server.exe`.
  - Started two hidden local `client.exe` processes.
  - Both clients opened `1 input channel(s), 2 output channel(s)`.
  - Both clients registered the other participant.
  - Both clients reported jitter buffer ready.
  - Filtered logs showed no rebuffering, unknown-message, invalid-packet, incomplete-packet, decode-failure, PCM-size-mismatch, send-error, or top-level exception messages.
- Caveat:
  - The callback can still execute Opus decode/PLC for incoming Opus packets. The active default PCM path avoids Opus decode for PCM packets.

### 2026-04-27 Pass 14: Opus encode/send moved out of callback

- Moved Opus encode and packet send out of the audio callback.
- Added `opus_send_queue_` in `client.cpp`.
- The callback now prepares one fixed-size float frame and enqueues it when Opus mode is active.
- The sender thread now handles:
  - Opus encoding
  - `AudioHdrV2` packet construction
  - socket send through the ASIO context
- Search verification:
  - `audio_encoder_.encode` remains only in the sender thread.
  - Opus `create_audio_packet_v2` calls remain only in the sender thread.
  - Old callback `std::vector<float> silence_frame` allocations were removed.
- Build verification:
  - `cmake --build build --target client`
- Runtime smoke verification:
  - Started local `server.exe`.
  - Started two hidden local `client.exe` processes.
  - Both clients opened `1 input channel(s), 2 output channel(s)`.
  - Both clients registered the other participant.
  - Both clients reported jitter buffer ready.
  - Filtered logs showed no rebuffering, unknown-message, invalid-packet, incomplete-packet, decode-failure, PCM-size-mismatch, send-error, or top-level exception messages.
- Caveat:
  - The default active codec remains PCM int16.
  - Opus mode still needs direct runtime exercising once a codec switch exists.

### 2026-04-27 Pass 13: RtAudio device/buffer latency metrics

- Added clearer device-layer timing diagnostics.
- `AudioStream::LatencyInfo` now includes:
  - requested buffer frames
  - actual buffer frames
  - buffer duration in ms
  - backend-latency availability flag
- Master strip now shows:
  - actual/requested buffer frames
  - buffer duration in ms
- Build verification:
  - `cmake --build build --target client`
- Runtime smoke result:
  - Selected WASAPI headset output opened successfully.
  - Stream reported `1 input channel(s), 2 output channel(s)`.
  - Requested buffer: `240` frames.
  - Actual buffer: `240` frames.
  - Buffer duration: `5.000 ms`.
  - RtAudio backend latency still reported `0.000 ms`, so the code now logs it as unavailable or zero instead of treating it as reliable.
- Interpretation:
  - We can trust requested/actual buffer duration.
  - We still cannot trust RtAudio's WASAPI backend latency number in this build.

### 2026-04-27 Pass 12: Queue-depth metrics per participant

- Added per-participant queue-depth metrics.
- Metrics tracked:
  - current queue depth
  - smoothed average queue depth
  - max queue depth
- Participant stats UI now shows:
  - current queue
  - average/max queue depth
- Build verification:
  - `cmake --build build --target client`
- Runtime smoke verification:
  - Started local `server.exe`.
  - Started two hidden local `client.exe` processes.
  - Both clients opened `1 input channel(s), 2 output channel(s)`.
  - Both clients registered the other participant.
  - Both clients reported jitter buffer ready.
  - Filtered logs showed no rebuffering, unknown-message, invalid-packet, incomplete-packet, decode-failure, PCM-size-mismatch, send-error, or top-level exception messages.
- Caveat:
  - Metrics are diagnostic only. Jitter policy is unchanged.

### 2026-04-27 Pass 11: Packet age metrics at playout

- Added per-participant packet age metrics.
- Measurement definition:
  - Start: packet enqueue time in the client receive path.
  - End: packet dequeue time in the audio callback for playout.
- Metrics tracked per participant:
  - last packet age
  - smoothed average packet age
  - max packet age
- Participant stats UI now shows:
  - average packet age
  - max packet age
- Build verification:
  - `cmake --build build --target client`
- Runtime smoke verification:
  - Started local `server.exe`.
  - Started two hidden local `client.exe` processes.
  - Both clients opened `1 input channel(s), 2 output channel(s)`.
  - Both clients registered the other participant.
  - Both clients reported jitter buffer ready.
  - Filtered logs showed no rebuffering, unknown-message, invalid-packet, incomplete-packet, decode-failure, PCM-size-mismatch, send-error, or top-level exception messages.
- Important caveat:
  - The numeric packet-age values are visible in the running UI, not in redirected smoke logs.
  - This is still queue-age instrumentation, not full end-to-end acoustic latency.

### 2026-04-27 Pass 10: Callback timing metrics

- Added audio callback timing diagnostics in `client.cpp`.
- Metrics tracked:
  - last callback duration
  - max callback duration
  - smoothed average callback duration
  - callback deadline
  - callback count
  - over-deadline callback count
- Displayed in the master strip:
  - `Cb: avg/deadline ms`
  - `Max: max ms`
  - `Late: count` when any over-deadline callbacks are observed
- Build verification:
  - `cmake --build build --target client`
- Runtime smoke verification:
  - Started local `server.exe`.
  - Started two hidden local `client.exe` processes.
  - Both clients opened `1 input channel(s), 2 output channel(s)`.
  - Both clients registered the other participant.
  - Both clients reported jitter buffer ready.
  - Filtered logs showed no rebuffering, unknown-message, invalid-packet, incomplete-packet, decode-failure, PCM-size-mismatch, send-error, or top-level exception messages.
- Important caveat:
  - The metrics are visible in the running UI, not in redirected smoke logs.
  - The next useful instrumentation is packet age at playout, because that explains audible delay directly.

### 2026-04-27 Pass 9: Left-only output fix

- User reported hearing audio only on the left side.
- Root cause found in channel setup:
  - `audio_stream.h` forced `output_channel_count_` to `1`.
  - `client.cpp` reported selected output channels as `1`.
  - The selected headset device supports `2` output channels.
- Fix:
  - Keep input/network payload mono.
  - Open the output stream with `2` channels when the playback device supports stereo.
  - Existing `mix_mono_to_stereo()` now duplicates mono remote/WAV audio into left and right.
- Build verification:
  - `cmake --build build --target client`
- Runtime smoke verification:
  - Client auto-started on the selected WASAPI headset output.
  - Log now reports `1 input channel(s), 2 output channel(s) at 48000 Hz`.

### 2026-04-27 Pass 8: Participant manager snapshot for callback mixing

- Removed the global participant-manager mutex from callback decode/mix work.
- `ParticipantManager` now stores participants as `std::shared_ptr<ParticipantData>`.
- `for_each()` snapshots `(participant_id, shared_ptr)` pairs under the map mutex, then releases the mutex before invoking the callback lambda.
- Build verification:
  - `cmake --build build --target client`
- Runtime verification:
  - Started local `server.exe`.
  - Started two hidden local `client.exe` processes.
  - Both clients registered the other participant.
  - Both clients reported jitter buffer ready.
  - Filtered logs showed no rebuffering, unknown-message, invalid-packet, incomplete-packet, decode-failure, PCM-size-mismatch, send-error, or top-level exception messages.
- Important caveat:
  - This removes the global map lock from the audio callback path.
  - It does not yet make every per-participant mutable field atomic or single-thread-owned.
  - Receive queue operations are still thread-safe through `ConcurrentQueue`, but status fields such as `buffer_ready`, levels, mute/gain/pan, and counters still need a cleaner ownership model later.

### 2026-04-27 Pass 7: PCM send moved out of audio callback

- Moved the production PCM int16 packet build/send out of the audio callback.
- Added a bounded `pcm_send_queue_` in `client.cpp`.
- The callback now converts the current mixed input frame to PCM int16 and enqueues it for the sender thread.
- The PCM sender thread builds `AudioHdrV2` packets and calls the socket send path outside the audio callback.
- Changed `send()` to post socket sends onto the ASIO context, so the sender thread does not call `async_send_to` on the socket directly.
- First smoke test after the move showed repeated PCM rebuffering.
- Root cause found in this slice: the sender thread used `sleep_for(1ms)` when idle. On Windows that is too coarse for stable 5 ms packet cadence and introduced send jitter.
- Replaced idle sleep with `std::this_thread::yield()`.
- Verification after fix:
  - `cmake --build build --target client`
  - Started local `server.exe`.
  - Started two hidden local `client.exe` processes.
  - Both clients registered the other participant.
  - Both clients reported jitter buffer ready.
  - Filtered logs showed no rebuffering, unknown-message, invalid-packet, incomplete-packet, decode-failure, PCM-size-mismatch, or send-error messages.
- Important caveat:
  - This cleanup currently applies to the PCM send path.
  - Opus mode still performs encode/allocation/packet send work in the callback and remains unsafe for aggressive low-buffer settings.
  - Receive-side participant iteration still uses the existing manager lock pattern and needs a later cleanup.

### 2026-04-27 Pass 6: Production AudioHdrV2 and PCM int16 path

- Added production packet metadata instead of relying on the probe-local payload marker.
- New protocol pieces:
  - `AUDIO_V2_MAGIC`
  - `AudioCodec`
  - `AudioHdrV2`
  - sequence number
  - sample rate
  - frame count
  - channel count
  - payload byte count
- Kept old `AUDIO_MAGIC` / `AudioHdr` receive compatibility for existing Opus packets.
- Server behavior remains SFU-style dumb forwarding:
  - It now accepts both `AUDIO_MAGIC` and `AUDIO_V2_MAGIC`.
  - It still rewrites only the sender ID and forwards the packet to other clients.
- Client outgoing production audio now defaults to `AudioCodec::PcmInt16` in `AudioHdrV2` packets.
- Client receive path can decode:
  - V1 Opus packets through the existing Opus decoder.
  - V2 PCM int16 packets by converting int16 samples directly to float for playout.
  - V2 Opus packets through the existing Opus decoder.
- Build verification:
  - `cmake --build build --target client`
  - `cmake --build build --target server`
  - `cmake --build build --target latency_probe`
- Runtime verification:
  - Started local `server.exe`.
  - Started two hidden local `client.exe` processes.
  - Both clients registered the other participant.
  - Both clients reported jitter buffer ready.
  - Filtered logs showed no unknown-message, invalid-packet, incomplete-packet, decode-failure, or PCM-size-mismatch messages.
- Important caveat:
  - This is the first production PCM path, not the final low-latency architecture.
  - Encoding, packet construction, and sending are still in the audio callback. Gate 3 remains necessary before judging real jamming latency or corruption behavior.

### 2026-04-26 Pass 5: Raw PCM probe comparison

- Added `--codec pcm` to `latency_probe`.
- The raw probe uses PCM int16 instead of float32 because the current payload cap is `AUDIO_BUF_SIZE = 512` bytes. A 240-frame mono float32 payload would not fit; 240-frame mono int16 does fit.
- The probe uses a probe-local payload marker so the existing server can remain a dumb forwarder. This is diagnostic-only; production should add explicit packet metadata instead.
- Build command verified: `cmake --build build --target latency_probe`.
- Runtime sweep against local `server.exe`:
  - `240` frames, jitter `3`: stable, `25 ms`, no encode/decode/underrun indicators.
  - `240` frames, jitter `2/1/0`: `20 ms`, but underruns appear.
  - `120` frames: `15-17.5 ms`, but underruns appear in every tested jitter setting.
  - `96` frames: `16 ms`, packets send/decode successfully, but underruns appear.
  - `64` frames: `14.6667-16 ms`, packets send/decode successfully, but underruns appear.
- Re-ran Opus sweep after adding the probe-local codec marker:
  - `240` frames, jitter `3`: stable, `27.4375 ms`.
  - `120` frames: still sends/decodes but shows underrun/PLC indicators.
  - `96` and `64` frames: still fail Opus encode for all packets.
- Interpretation:
  - Raw PCM can carry 64/96-frame packets through the current UDP/SFU server. That means the current protocol/server path does not inherently block small audio frames.
  - The robotic/corrupt mechanism splits into two cases:
    - Opus at illegal frame sizes fails before sending.
    - Aggressive jitter settings cause underruns; Opus turns those underruns into PLC artifacts, while PCM exposes them as missing playout frames.
  - Next useful implementation is not a network rewrite. It is production packet metadata plus a bounded raw PCM receive/playout path outside the fragile callback work.

### 2026-04-26 Pass 3: Headless Opus latency probe baseline

- Added `latency_probe`, a diagnostic executable for automated local latency measurement.
- Probe v1 assumes `server.exe` is already running and uses real UDP through the actual SFU server.
- Probe v1 uses the current Opus wrappers, current packet format, and current jitter constants.
- Probe signal is silence, then a short click, then silence.
- Build command verified: `cmake --build build --target latency_probe`.
- Runtime baseline against local `server.exe`, 3 consecutive runs:
  - Sent packets: 220
  - Received packets: 220
  - Decoded packets: 220
  - Detected output sample: 6117
  - Latency: 1317 samples / 27.4375 ms
  - Jitter minimum: 3 packets
  - Max queue depth: 6-8 packets
  - Underruns/PLC/decode failures/size mismatches: 0
- Interpretation: even with physical devices and GUI removed, the current Opus + UDP/SFU + headless playout model measures about 27.4 ms locally. This is before real audio-device input/output latency and before the GUI client's callback overhead.
- Caveat: v1 does not yet include the real `Client::audio_callback` path. It is a baseline for protocol/Opus/jitter behavior, not a complete reproduction of RtAudio callback workload.

### 2026-04-26 Pass 4: Probe config sweep explains lower-buffer corruption

- Extended `latency_probe` with `--sweep`.
- Sweep covered frame sizes `240, 120, 96, 64` and jitter minimums `3, 2, 1, 0`.
- Results against local `server.exe`:
  - `240` frames, jitter `3`: stable, `27.4375 ms`, no corruption indicators.
  - `240` frames, jitter `2/1/0`: lower latency (`17.4375-22.4375 ms`) but PLC/underrun indicators appear.
  - `120` frames: Opus works and latency is lower (`16.0833-18.5833 ms`), but every jitter setting showed PLC/underrun indicators in this sweep.
  - `96` frames: Opus encode failed for all 220 packets; zero packets sent.
  - `64` frames: Opus encode failed for all 220 packets; zero packets sent.
- Interpretation:
  - Automated tests can reproduce key "robotic/corrupt" causes. With lower jitter, the probe sees underruns and Opus PLC. With illegal frame sizes, the probe sees encode failure.
  - The current Opus path cannot be tuned to arbitrary lower sample counts. At 48 kHz, standard Opus frame sizes include 120 samples (2.5 ms) and 240 samples (5 ms), but not 96 or 64 samples.
  - For 64-sample low-latency mode, use raw PCM or a different Opus strategy such as Jamulus-style custom modes. Do not expect the current `opus_encode_float` path to work there.

### 2026-04-26 Pass 2: RtAudio backend swap

- PortAudio was removed from the client build and replaced with RtAudio 6.0.1.
- `audio_stream.h` now owns the RtAudio integration and exposes backend-neutral `AudioStream::DeviceIndex`, `AudioStream::NO_DEVICE`, and callback types.
- `client.cpp` no longer includes PortAudio or uses `PaDeviceIndex`, `paNoDevice`, `paContinue`, or `Pa_*` metadata APIs.
- Build command verified: `cmake --build build --target client`.
- Build output: `build/Debug/client.exe`.
- Runtime smoke test verified the client starts, enumerates WASAPI devices, auto-starts the RtAudio stream, and survives 8 seconds.
- Smoke test selected `Headset Microphone (DualSense Wireless Controller)` as input and `Headset Earphone (HyperX Virtual Surround Sound)` as output, both through WASAPI.
- Smoke test requested 240 frames and RtAudio kept the actual buffer at 240 frames.
- RtAudio latency reporting currently logs `0.000 ms`, so the next measurement gate must improve latency instrumentation before trusting those numbers.
- Important limitation: current CMake configure reported RtAudio support for `wasapi` only. ASIO is not enabled yet, so this swap alone is not the Windows low-latency endpoint we ultimately want.
- RtAudio 6.0.1 API note: it uses return codes such as `RTAUDIO_NO_ERROR`; older examples using `RtAudioError` exceptions and `DeviceInfo::probed` do not apply.
- RtAudio wrapper bug fixed during smoke testing: default input selection must filter for actual input channels, and device-info pointers must be copied before repeated device scans invalidate them.
- Latency caveat: this backend swap does not fix the callback architecture. The current callback still performs Opus encode/decode, packet building, network send, and participant locking/allocation work.

### 2026-04-26 Pass 1: Client is the likely bottleneck, not UDP/SFU

Assumptions:
- Target is live jamming, not conferencing. That means one-way latency must be aggressively bounded, and occasional dropouts are preferable to hidden buffering.
- Current symptom is clear audio with too much latency; when lowering buffers/configs, audio becomes robotic/corrupt.
- The server is intended to behave like an SFU/packet forwarder, not a mixer.

Success criteria:
- The audio callback must become deterministic: no heap allocation, no locks, no blocking I/O, and ideally no codec work.
- Playback latency must be bounded by explicit user-configured buffer sizes, not by implicit queue growth.
- The app must expose practical low-latency modes: ASIO/JACK/CoreAudio/WASAPI-exclusive-friendly buffer sizes, raw PCM mode, and Opus mode.
- Any competitor code copied directly must be license-compatible and isolated enough to preserve attribution and GPL obligations.

Verdict:
- UDP is not the problem. The server's SFU design is broadly correct for latency because it forwards packets without decode/mix/re-encode.
- PortAudio is not automatically the problem, but the current PortAudio usage is probably leaving device latency on the table and the callback does too much work.
- Opus is not inherently the problem, but current Opus use adds latency/CPU, uses frame sizes that are fixed around 5 ms, and is in the real-time callback.
- The biggest current problem is the client real-time architecture.

Evidence in this repo:
- `client.cpp:80-83` hardcodes `48000 Hz`, `64000 bps`, complexity `2`, and `240` frames per buffer. At 48 kHz, `240` frames is 5 ms before codec, jitter, output, or network.
- `audio_stream.h:219-225` uses `defaultLowInputLatency` and `defaultLowOutputLatency`. Those values can be conservative and host-API-dependent. On Windows, serious jamming generally needs ASIO; on Linux, JACK/PipeWire/JACK-style low-latency; on macOS, CoreAudio with small buffers.
- `client.cpp:734-1028` performs receive mixing, Opus decode/PLC, WAV read/mix, Opus encode, packet allocation/building, and UDP async send inside the PortAudio callback.
- `participant_manager.h:130-152` allocates a `std::vector<uint32_t>` and locks a `std::mutex` during participant iteration. It also holds the mutex while invoking the decode/mix lambda at `participant_manager.h:146-149`. That means the audio callback can contend with the network thread path in `client.cpp:688-731`.
- `client.cpp:941`, `client.cpp:1005`, and `client.cpp:1015` allocate `std::vector` objects inside the callback. `audio_packet.h:14-41` allocates a `shared_ptr<vector>` and performs multiple vector inserts for every audio packet.
- `client.cpp:1023-1024` builds the packet and calls `send()` from the callback. Even async send touches ASIO/socket state and can allocate internally.
- `protocol.h:16-18` sets `TARGET_OPUS_QUEUE_SIZE = 3` and `MIN_JITTER_BUFFER_PACKETS = 3`, so the receiver intentionally waits at least 15 ms of 5 ms packets before playback.
- `client.cpp:839-847` can increase jitter buffer depth, but cannot decrease below `MIN_JITTER_BUFFER_PACKETS`, currently 3.
- `protocol.h:49` has no sequence number in `AudioHdr`. Without sequence numbers, the receiver cannot reliably detect loss, late packets, reorder, clock drift, or gap size. It only has queue depth and timestamps.
- `opus_encoder.h:64-73` configures Opus for restricted low delay and music, which is good, but also enables VBR and FEC/loss expectation. For lowest latency jamming, CBR or constrained behavior is often easier to pace/debug, and FEC is not free.

Why "robotic" happens when configs are lowered:
- The callback deadline shrinks with smaller buffers. At 128 samples, the callback has about 2.67 ms; at 64 samples, about 1.33 ms. Current callback work is too variable for that.
- Mutex contention, heap allocation, encode/decode spikes, and ASIO/socket internals can miss a callback deadline. The audible result is glitching, PLC artifacts, repeated/late frames, or robotic sound.
- Opus expects exact legal frame sizes at the configured sample rate. Arbitrary buffer changes without matching Opus frame sizing and packet framing can produce decode size mismatch or PLC-heavy audio.
- No adaptive resampling/clock drift correction means two sound cards with slightly different clocks eventually push the receive queue toward underrun or growth. Tests can stay green while real audio drifts.

Server notes:
- `server.cpp:192-196` does the right architectural thing: embed sender ID, copy packet, forward to other clients. It does not decode/mix/re-encode.
- Hot-path allocation remains: `server.cpp:194-195` allocates/copies a vector per audio packet, and `client_manager.h:91-100` allocates endpoint vectors per forward. This can add forwarding jitter under load, but it is secondary to the client callback.
- The current SFU model is lower latency than a Jamulus-style central mixer because it avoids server decode/mix/re-encode. Keep the SFU for low latency unless you specifically need server-side mix.

## Competitor Notes

### JackTrip

Sources:
- Repo: https://github.com/jacktrip/jacktrip
- README states it supports bidirectional high-quality uncompressed audio streaming.
- Support docs state real-time means roughly 25-30 ms one-way or less and recommend low buffers, wired Ethernet, good audio interfaces, and ASIO on Windows.

Code observations from local clone:
- `.cache/competitors/jacktrip/src/vs/vsAudio.h:137-170` supports JACK and RtAudio backends and exposes sample rate/buffer settings.
- `.cache/competitors/jacktrip/src/vs/vsAudio.h:369-370` exposes buffer sizes `16, 32, 64, 128, 256, 512, 1024`.
- `.cache/competitors/jacktrip/src/AudioInterface.cpp:117-170` preallocates audio packet/process buffers during setup.
- `.cache/competitors/jacktrip/src/AudioInterface.cpp:180-230` splits input callback work into processing and network handoff through existing buffers/plugins.
- `.cache/competitors/jacktrip/src/AudioInterface.cpp:283-294` explicitly drains monitor queue at startup to minimize latency.

Implication:
- JackTrip's low-latency identity comes from uncompressed audio, tiny configurable audio buffers, preallocated buffers, and real audio backends. It is closer to what this project should copy for LAN/studio mode than a voice-chat architecture.

### SonoBus

Sources:
- Repo: https://github.com/sonosaurus/sonobus
- README says it supports full uncompressed PCM and low-latency Opus, independently adjustable per connected user, with fine-grained control over latency/quality/mix.
- SonoBus user guide says round-trip latency is ping plus receive jitter buffer, audio buffer size, and Opus delay when Opus is used.

Code observations from local clone:
- `.cache/competitors/sonobus/Source/SonobusPluginProcessor.h:123-130` defines auto network buffer modes and codec modes: `CodecPCM` and `CodecOpus`.
- `.cache/competitors/sonobus/Source/SonobusPluginProcessor.h:160-174` gives PCM a minimum preferred block size of `16` and Opus a default minimum preferred block size of `120`.
- `.cache/competitors/sonobus/Source/SonobusPluginProcessor.h:410-421` exposes per-remote-peer receive buffer time, autoresize mode, and buffer fill ratio.
- `.cache/competitors/sonobus/Source/SonobusPluginProcessor.h:991` has a `mDynamicResampling` flag, which confirms clock drift/resampling is a first-class concern.
- `.cache/competitors/sonobus/Source/SonoStandaloneFilterApp.cpp:136-145` defaults standalone buffer size to 128 on macOS, 192 on Android, 256 elsewhere.

Implication:
- SonoBus validates a hybrid design: raw PCM for best latency/quality when bandwidth allows, Opus when bandwidth matters, and per-peer jitter control. The codec should be a packet-level mode, not a whole-system assumption.

### Jamulus

Sources:
- Repo: https://github.com/jamulussoftware/jamulus
- README says it runs on Windows with ASIO/JACK and uses Opus.
- Manual describes local and server jitter buffers, manual/auto modes, and the latency vs dropout tradeoff.

Code observations from local clone:
- `.cache/competitors/jamulus/src/client.cpp:77-105` uses custom Opus modes, including a 64-sample mode, disables VBR, sets restricted-lowdelay, and uses low complexity for legacy 128-sample mode.
- `.cache/competitors/jamulus/src/client.cpp:1228-1239` preinitializes codec/network buffers and sets channel stream properties during setup.
- `.cache/competitors/jamulus/src/buffer.cpp:170-225` uses sequence numbers and a moving jitter-buffer window to handle delayed/early packets and sample-rate offsets.
- `.cache/competitors/jamulus/src/buffer.cpp:414-430` avoids one-packet buffers in its auto simulation because it lacks sample-rate-offset correction at that size.
- `.cache/competitors/jamulus/src/buffer.cpp:550-666` simulates multiple jitter buffer sizes, picks the smallest size below error bounds, filters the decision, and applies hysteresis.

Implication:
- Jamulus is not just "UDP + Opus." It has custom Opus framing, sequence-aware jitter buffering, auto buffer simulation, hysteresis, preallocated buffers, and explicit low-latency host APIs.
- The important lesson is not necessarily to copy its server-mixer model. The useful pieces are sequence-aware jitter buffering, Opus custom low-delay setup, and buffer auto-tuning.

## Recommended Direction

## Backend Notes: WASAPI vs ASIO

### Current Build

- RtAudio is built with both `asio` and `wasapi` support.
- Verification:
  - CMake reports `Compiling with support for: asio wasapi`.
  - RtAudio build defines both `__WINDOWS_ASIO__` and `__WINDOWS_WASAPI__`.

### Current Machine Runtime

- Device enumeration currently shows WASAPI devices only.
- No ASIO device is visible to RtAudio on this machine during smoke tests.
- That means either:
  - no ASIO driver is installed,
  - the installed audio interface does not expose an ASIO driver,
  - or the visible devices are virtual/WASAPI-only devices.

### Expected Behavior

- If an ASIO input/output device is visible, default device selection now prefers ASIO.
- If no ASIO device is visible, the app falls back to WASAPI.
- The bottom-bar API selector still allows manual API/device selection.

### Practical Latency Interpretation

- WASAPI is now a functional fallback path and is useful for development/testing.
- WASAPI in this build still reports backend latency as `0.000 ms`, so we do not treat that number as trustworthy.
- The reliable device-side number we currently have is requested/actual callback buffer duration, for example `240` frames at 48 kHz = `5.000 ms`.
- For serious Windows jamming, a real ASIO driver/interface is still the target.
- After installing an ASIO driver, verify:
  - ASIO devices appear in the device list.
  - The selected input/output API is `ASIO`.
  - Requested low buffer sizes such as `64`, `96`, `120`, or `128` are actually accepted.
  - Callback metrics show no over-deadline spikes.
  - Packet age stays bounded without rebuffering.

### Do not rewrite language first

C++ is appropriate for this problem. Rewriting to Rust/Zig/C would not automatically fix latency; the failure mode is architecture. The first big win is to change the client audio pipeline. A language change only makes sense after deciding to embed/reuse a proven engine wholesale.

### Keep or replace PortAudio?

Short answer: keep it temporarily, but do not treat it as the final lowest-latency backend.

PortAudio can be acceptable if configured correctly, especially with ASIO support on Windows, but this project currently uses default low latencies and a fixed 240-frame callback. For "lowest possible" mode:
- Windows: prefer ASIO directly or ensure PortAudio ASIO is built/enabled and expose ASIO devices/buffer sizes.
- Linux: prefer JACK or PipeWire/JACK.
- macOS: CoreAudio is fine through a good API if buffer size is controlled.
- Cross-platform app route: JUCE or RtAudio may be more practical than handwritten backend logic.

### Keep or replace Opus?

Use two modes:
- Raw PCM mode for LAN/studio/lowest-latency. This avoids codec delay and avoids codec CPU in the hot path.
- Opus mode for internet/bandwidth-limited sessions. Use legal Opus frame sizes and low-delay settings; consider Jamulus-style custom modes if you need 64/128-sample behavior.

Opus is not the root cause, but putting Opus encode in the audio callback is a root cause.

### Keep UDP/SFU?

Yes. UDP is the correct transport for this class of app. The current server forwarding model is latency-friendly. Improve allocation behavior later, but do not start by replacing UDP or SFU.

### Highest-value implementation phases

1. Instrument before big changes.
   - Log actual `Pa_GetStreamInfo()` input/output latency after stream open.
   - Add callback timing metrics: max/avg callback duration, over-deadline count, frame_count histogram.
   - Add per-participant queue depth, underrun, PLC, and packet age histograms.
   - Add packet sequence numbers and log loss/reorder.

2. Make the callback real-time safe.
   - Callback should only copy mic/WAV PCM into a preallocated SPSC ring and pull already-decoded PCM from receive rings.
   - Move Opus encode and packet building/sending to a sender thread.
   - Move Opus decode out of the callback if possible; if decode remains in callback temporarily, remove all locks/allocations first.
   - Replace `ParticipantManager::for_each()` in the callback with a lock-free or RCU-style participant snapshot.

3. Fix packet timing and jitter model.
   - Add a sequence number to `AudioHdr`.
   - Add codec and frame-size fields to `AudioHdr`.
   - Replace "queue of Opus packets only" with a jitter buffer that understands sequence numbers and target playout delay.
   - Let jitter target be user-configurable down to 0/1 packet for raw PCM and 1/2 packets for Opus.

4. Add raw PCM mode before deeper Opus work.
   - Packet payload can be 16-bit or float PCM. For bandwidth, 16-bit mono/stereo is usually enough; for simplicity, float32 matches current callback buffers.
   - At 48 kHz mono float32, 128-sample frames are about 1.5 Mbps plus overhead. That is trivial on LAN.
   - This gives a clean baseline: if raw PCM still has high latency, the issue is audio device/backend/buffering, not codec.

5. Then make Opus mode competitive.
   - Remove encode from callback.
   - Avoid FEC by default for jamming; use PLC on decode.
   - Consider CBR/constrained packet sizes for stable pacing.
   - Investigate Jamulus custom Opus mode if 64/128-sample compressed mode is required.

6. Add clock drift handling.
   - Track receive jitter buffer fill trend per participant.
   - Use small adaptive resampling to keep buffer fill near target instead of periodic underrun/overrun.
   - Competitors treat this as core, not optional.

### Reuse strategy

Best practical reuse options:
- Reuse JackTrip concepts or integrate JackTrip for raw uncompressed low-latency audio if the goal is "known working now."
- Reuse SonoBus/AOO concepts if you want peer-to-peer, PCM/Opus hybrid, per-peer settings, and plugin-style audio behavior.
- Reuse Jamulus jitter-buffer and Opus lessons if you want Opus + central server/mixer behavior.

Direct code copying:
- Jamulus is GPL, SonoBus is GPL-3.0, JackTrip's current repo license must be checked before copying specific files. This project can use GPL-compatible code if the project is distributed under compatible GPL terms and attribution/license notices are preserved.
- Even if legally allowed, direct transplanting a whole audio engine may be faster than copying isolated functions. Jitter buffers depend on packet format, timing model, and audio callback assumptions.

My recommended path:
- Keep the current C++/UDP/SFU project.
- First build a "raw PCM + sender thread + lock-free receive/playout" mode. This will prove the audio backend and network path with the codec removed.
- Then add Opus back as a second codec path once callback timing and jitter buffering are stable.
- Use competitor code as reference for buffer strategy, not as random snippets. The hard part is the architecture around the code.

## Pass 23: Gate 8 Receive Buffer Drift Metric

Date: 2026-04-27

Scope:
- Measurement only.
- No adaptive resampling, frame slip/stretch, playout policy change, or jitter target change.

Changed:
- `participant_info.h`
- `participant_manager.h`
- `client.cpp`

What changed:
- Added `queue_depth_drift_milli` per participant.
- The metric is updated from the existing queue-depth observation path.
- Drift is a smoothed signed packet count relative to `TARGET_OPUS_QUEUE_SIZE`.
- UI participant stats now show `Q drift`.

How to read it:
- `Q drift` near `0.00`: receive queue is staying near the target.
- Positive `Q drift`: queue is trending above target, which means hidden latency pressure.
- Negative `Q drift`: queue is trending below target, which means underrun/rebuffer pressure.

Verification:
- `cmake --build build --target client`
- Two-client local smoke through `server.exe`.
- Both clients opened `1` input channel and `2` output channels at `48000 Hz`.
- Both clients reported actual buffer `240` frames / `5.000 ms`.
- Both clients registered the other participant and reached jitter buffer ready.

Teardown note:
- The smoke script force-kills clients; the peer left running for a moment can log one rebuffer exactly at teardown.
- Treat that as a script artifact unless it appears before teardown during a long run.

Next Gate 8 decision:
- The next implementation is no longer measurement-only.
- We need to choose between controlled frame slip/stretch and adaptive resampling for drift correction.
- Competitor direction: SonoBus/AOO-style adaptive resampling is cleaner for real sessions; frame slip/stretch is simpler but more likely to create small clicks or robotic artifacts if it happens too often.

## Pass 24: Automated Drift Probe Length and Queue Metrics

Date: 2026-04-27

Scope:
- Extend `latency_probe` so drift/underrun behavior can be tested without listening.
- Do not change production client playout or correction behavior.

Changed:
- `latency_probe.cpp`
- `LOW_LATENCY_TODO.md`

What changed:
- Added `--packets`.
- Added `--seconds`.
- Added queue metrics:
  - `avg_queue_depth`
  - `queue_drift_from_jitter`
  - `min_queue_depth_after_ready`
  - `max_queue_depth`
  - `final_queue_depth`

Verification:
- `cmake --build build --target latency_probe`
- `latency_probe --server 127.0.0.1 --port 9999 --codec pcm --frames 240 --jitter 3 --seconds 5`

Observed 5-second PCM result:
- Sent/received/decoded packets: `1000/1000/1000`
- Detected latency: `15 ms`
- Average queue depth: `3.03`
- Queue drift from jitter target: `+0.03`
- Max queue depth: `7`
- Underruns: `1`

Interpretation:
- The metric is now useful enough to catch underrun risk without relying on human listening.
- A short local run can still underrun at aggressive jitter settings even when every packet is received and decoded.
- This matches the project symptom: clear audio at safer buffering, robotic/corrupt behavior when buffers are tightened.

Next:
- Run a 10-minute version before and after drift correction.
- Command shape: `latency_probe --server 127.0.0.1 --port 9999 --codec pcm --frames 240 --jitter 3 --seconds 600`
- Correction should be implemented only after choosing the strategy: adaptive resampling or controlled frame slip/stretch.

## Pass 25: Correct Long-Run Probe Liveness

Date: 2026-04-27

Finding:
- The first 10-minute probe attempt was invalid.
- Probe sender reported `120000` sent packets, but receiver got only `3732`.
- Cause: synthetic probe endpoints sent `JOIN` once but did not send periodic `ALIVE`, so the server timed out the endpoints during the long run.

Changed:
- `latency_probe.cpp`

Fix:
- `ProbeReceiver` now has `send_alive()`.
- `ProbeSender` now has `send_alive()`.
- Sender and receiver loops send `ALIVE` roughly once per second during long runs.

Verification:
- `cmake --build build --target latency_probe`
- `latency_probe --server 127.0.0.1 --port 9999 --codec pcm --frames 240 --jitter 3 --seconds 30`

Observed 30-second PCM result:
- Sent/received/decoded packets: `6000/6000/6000`
- Detected latency: `25 ms`
- Average queue depth: `4.09`
- Queue drift from jitter target: `+1.09`
- Min queue after ready: `1`
- Max queue depth: `9`
- Underruns: `0`

Interpretation:
- Long-run probe liveness is fixed.
- The corrected 10-minute baseline can now be trusted for packet continuity and underrun detection.

## Pass 26: Corrected 10-Minute PCM Drift Baseline

Date: 2026-04-27

Command:
- `latency_probe --server 127.0.0.1 --port 9999 --codec pcm --frames 240 --jitter 3 --seconds 600`

Result:
- Sent packets: `120000`
- Received packets: `120000`
- Decoded packets: `120000`
- Encode failures: `0`
- Decode failures: `0`
- Underruns: `0`
- PLC frames: `0`
- Detected latency: `25 ms`
- Average queue depth: `4.10`
- Queue drift from jitter target: `+1.10`
- Min queue after ready: `1`
- Max queue depth: `9`

Interpretation:
- The local UDP/SFU/PCM probe path is stable for 10 minutes at `240` frames and jitter target `3`.
- The effective queue sits roughly one packet above the nominal jitter target. At `240` frames / `48 kHz`, one packet is `5 ms`.
- This supports the current diagnosis: UDP/SFU is not the primary local bottleneck at safe settings.
- It also shows why lower jitter settings can become fragile: even the stable setting uses occasional queue headroom up to `9` packets.

Caveat:
- This is an automated probe, not a full RtAudio hardware session.
- A real client session still includes device callback scheduling, driver buffering, and real mic/output clocks.

Next:
- Run real client listening tests at `240`, then `120` or `128` only if the driver accepts them.
- Do not implement adaptive correction blindly; first decide whether to use adaptive resampling or controlled frame slip/stretch.

## Pass 27: Real RtAudio Client 10-Minute Baseline

Date: 2026-04-27

Setup:
- Local `server.exe`.
- Two real `client.exe` GUI processes.
- Current defaults: PCM mode, requested buffer `240`, jitter target `3`.
- Runtime backend on this machine: WASAPI.

Observed startup:
- Client A and client B both opened `1` input channel and `2` output channels at `48000 Hz`.
- Both reported actual buffer `240` frames / `5.000 ms`.
- Both registered the other participant.
- Both reached jitter buffer ready at `3` packets.

Duration:
- Approximately `10m37s`.

Filtered log result:
- No steady-state decode failures.
- No PCM size mismatches.
- No invalid/incomplete audio packets.
- No send errors.
- No steady-state rebuffering during the run.

Teardown artifact:
- Client A logged one rebuffer at `19:28:04`, exactly when the test script force-stopped client B.
- Server also logged forced-close receive errors at `19:28:04`.
- Treat this as teardown behavior, not as a steady-state failure.

Interpretation:
- The real RtAudio/WASAPI path is stable at the current safe default: `240` frames, PCM, jitter `3`.
- This does not prove lowest-latency operation yet; it proves the current architecture no longer falls apart at the baseline setting.
- The next meaningful test is lower requested buffer size, probably `120` or `128`, but only if the device/backend accepts it and the user listens for artifacts.

## Pass 28: Real Client Lower Buffer Smoke

Date: 2026-04-27

Changed:
- `client.cpp`

What changed:
- Added `client --frames N`.
- Added alias `client --buffer-frames N`.
- This is only a startup override for repeatable tests; it does not change UI behavior or default settings.

Verification:
- `cmake --build build --target client`

Test: `120` frames
- Command shape: two real clients started with `--frames 120` through local `server.exe`.
- WASAPI accepted actual buffer `120` frames / `2.500 ms`.
- Both clients reached jitter buffer ready.
- Both clients immediately logged one rebuffer.

Test: `128` frames
- Command shape: two real clients started with `--frames 128` through local `server.exe`.
- WASAPI accepted actual buffer `128` frames / `2.667 ms`.
- Both clients reached jitter buffer ready.
- Both clients immediately logged one rebuffer.

Baseline restoration:
- Restarted two visible clients at default `240`.
- Logs showed actual buffer `240` frames / `5.000 ms`.
- Both clients reached jitter buffer ready.
- User confirmed audio transfer was correct.

Interpretation:
- The backend can open lower callback sizes on this machine.
- Current startup/playout policy is not stable enough at `120/128`.
- This is now a concrete failure mode: lower device buffer works, but receive playout rebuffering happens immediately.

Next:
- Fix lower-buffer startup/playout stability before any long-run `120/128` test.
- The likely area is jitter readiness and playout timing for small callback periods, not UDP/SFU.

## Pass 29: PCM 120-Frame Rebuffer Recovery

Date: 2026-04-27

Observed failure:
- User heard audio for about one second, then audio stopped.
- Diagnostics showed packets continued flowing after audio stopped.
- Participant state stayed `ready=false` with receive queue around `4`.
- Queue-depth drops increased continuously.

Fix:
- PCM underrun handling no longer permanently disables participant playback.
- For PCM, a missed callback now outputs silence for that callback and keeps playback armed for the next packet.

Verification:
- Rebuilt `client`.
- Started two visible clients with `--frames 120`.
- User reported audio is now audible and mostly clear, but sometimes broken.

Post-fix diagnostics:
- `ready=true`
- `underruns=0`
- no sequence gaps
- no decode failures
- queue-depth drops still rise during the run

Interpretation:
- The "one second then gone" bug is fixed.
- The remaining artifact is probably caused by the current queue cap dropping packets too aggressively at `120` frames.
- Next fix should allow slightly more receive headroom for <=128-frame PCM before dropping packets.

## Pass 30: Extended 120-Frame Candidate Run

Date: 2026-04-27

Changed:
- `client.cpp`

Fixes since the first 120-frame failure:
- PCM receive misses no longer permanently disable participant playback.
- Small-frame receive packets (`<=128`) can now use up to `6` queued packets before depth-drop.
- Default `240` behavior keeps the previous tighter cap.

User listening result:
- User reported audio is now audible at `120`.
- Normal speech is clear.
- Whistles or bursty sounds can still sound slightly broken.

Extended test:
- Local `server.exe`.
- Two visible `client.exe --frames 120` processes.
- Runtime: approximately `10m45s`.
- Actual device buffer: `120` frames / `2.500 ms`.

Final log state:
- Client A: `ready=true`, `underruns=0`, sequence gaps/late `0/0`, receive queue drops about `991`, PCM sender drops about `341`, average packet age about `9.8 ms`.
- Client B: `ready=true`, `underruns=0`, sequence gaps/late `0/0`, receive queue drops about `80`, PCM sender drops about `374`, average packet age about `9.7 ms`.

Interpretation:
- The `120` frame path is no longer a hard failure.
- The "audio for one second then gone" bug is fixed.
- Remaining artifacts are consistent with dropped local PCM send frames and dropped receive packets, not UDP/SFU packet loss.
- The next fix should focus on smoother sender pacing and queue policy before trying adaptive resampling.

Status:
- `240` frames: stable and clean baseline.
- `120` frames: usable candidate, lower latency, still has occasional artifacts.

## Pass 31: Reduce 120-Frame Drop Pressure

Date: 2026-04-27

Changed:
- `client.cpp`

Change:
- Small-frame PCM sender queue headroom increased from `3` frames to `8` frames.
- Small-frame receive queue headroom increased from `6` packets to `8` packets.
- This applies to `<=128` frame packets only.
- Default `240` behavior remains unchanged.

Verification:
- `cmake --build build --target client`
- Started two visible `client.exe --frames 120` processes through local `server.exe`.

Early result after about one minute:
- PCM sender drops: `0` on both clients.
- Client B receive queue drops: `0`.
- Client A receive queue drops: early burst around `284`, then stable during the sampled window.
- Both clients stayed `ready=true`.
- Underruns: `0`.
- Sequence gaps/late: `0/0`.

Interpretation:
- Sender drops were caused by too little local queue headroom for Windows scheduling at `120`.
- Increasing sender headroom fixed that part of the artifact path.
- Remaining receive drops, if audible, are now mostly receive-side burst handling rather than local send queue starvation.

Follow-up listening result:
- User reported the audio is clear at `120`.
- A longer observation was interrupted when one GUI client was accidentally closed at `20:07:41`.
- Before that close, the useful counters were stable:
  - PCM sender drops: `0`
  - underruns: `0`
  - sequence gaps/late: `0/0`
  - Client B receive drops: `0`
  - Client A receive drops: early burst around `284`, then stable

Interpretation update:
- `120` frames is now the current low-latency candidate on this machine.
- A clean uninterrupted 10-minute run is still worth doing before committing, but the subjective and diagnostic result is now positive.

## Pass 32: Clean 10-Minute 120-Frame Validation

Date: 2026-04-27

Setup:
- Local `server.exe`.
- Two visible `client.exe --frames 120` processes.
- PCM mode.
- WASAPI accepted actual buffer `120` frames / `2.500 ms`.

Duration:
- Approximately `10m35s`.

Final client state:
- Client A:
  - `ready=true`
  - PCM sender drops: `0`
  - receive queue drops: `0`
  - underruns: `0`
  - sequence gaps/late: `0/0`
  - decode/send/packet errors: `0`
  - packet age average: about `9.8 ms`
- Client B:
  - `ready=true`
  - PCM sender drops: `0`
  - receive queue drops: `0`
  - underruns: `0`
  - sequence gaps/late: `0/0`
  - decode/send/packet errors: `0`
  - packet age average: about `9.8 ms`

Teardown:
- Server logged forced-close receive errors at the moment the test script stopped the clients.
- Treat those as teardown artifacts, not steady-state failures.

Interpretation:
- `120` frames is now validated as the current low-latency candidate on this machine.
- The previous one-second cutoff and intermittent artifacts were caused by local queue policy, not UDP/SFU failure.
- Current measured device buffer is `2.500 ms`; receive packet age averages around `9.8 ms`.
- The next performance frontier is driver/backend quality, especially ASIO availability, and then deliberate drift correction if longer real sessions show queue trend problems.

## Pass 33: Make 120 the Explicit Default

Date: 2026-04-27

Changed:
- `client.cpp`

What changed:
- Default requested buffer changed from `240` to `120`.
- Buffer selector now labels:
  - `120 Low`
  - `240 Safe`
- Manual buffer choices remain available.

Verification:
- `cmake --build build --target client`
- Started two clients without `--frames`.
- Both clients opened actual buffer `120` frames / `2.500 ms`.
- Both clients reached jitter buffer ready.
- Both clients stayed `ready=true`.
- PCM sender drops: `0`
- receive queue drops: `0`
- underruns: `0`
- sequence gaps/late: `0/0`

Interpretation:
- The validated low-latency path is now the default startup path.
- `240` remains available as the safe fallback from the UI.

## Pass 34: 96-Frame Exploratory Test

Date: 2026-04-27

Setup:
- Local `server.exe`.
- Two visible `client.exe --frames 96` processes.
- PCM mode.

Result:
- WASAPI accepted actual buffer `96` frames / `2.000 ms`.
- Both clients reached jitter buffer ready.
- Runtime sampled: about `4` minutes.

Counters:
- `ready=true` on both clients.
- PCM sender drops: `0`
- underruns: `0`
- sequence gaps/late: `0/0`
- decode/send/packet errors: `0`
- receive queue drops: low but nonzero; they did not explode in the sampled window.
- packet age average: about `9.8 ms`

Interpretation:
- `96` is a promising next-lower candidate on this machine.
- It should not become the default yet.
- It needs user listening confirmation and a clean 10-minute two-client run before promotion.
- `120` remains the validated default.

## Pass 35: Clean 10-Minute 96-Frame Validation

Date: 2026-04-27

Setup:
- Local `server.exe`.
- Two visible `client.exe --frames 96` processes.
- PCM mode.
- User reported `96` sounded clear.

Duration:
- Approximately `10m35s`.

Result:
- WASAPI accepted actual buffer `96` frames / `2.000 ms`.
- Both clients stayed `ready=true`.
- PCM sender drops: `0`
- underruns: `0`
- sequence gaps/late: `0/0`
- decode/send/packet errors: `0`
- packet age average: about `9.7-9.8 ms`

Receive drops:
- Client A receive queue drops: about `768`
- Client B receive queue drops: about `491`

Teardown:
- Server logged forced-close receive errors when the test script stopped the clients.
- Treat those as teardown artifacts.

Interpretation:
- `96` is validated as a clear ultra-low candidate on this machine.
- Because receive drops still accumulate, `96` should be exposed as an "Ultra" option rather than replacing `120` as the default.
- `120` remains the safer validated default.

## Pass 36: Lower-Than-96 Boundary Test

Date: 2026-04-27

Setup:
- Local `server.exe`.
- Two visible client processes.
- PCM mode.
- First run: `client.exe --frames 64`.
- Second run: `client.exe --frames 32`.

64-frame result:
- WASAPI accepted actual buffer `64` frames / `1.333 ms`.
- User listening result: audio sounded clear.
- Both clients reached jitter buffer ready and stayed `ready=true`.
- PCM sender drops: `0`
- underruns: `0`
- sequence gaps/late: `0/0`
- packet age average: about `10.0-10.5 ms`
- receive queue drops accumulated.
- receive queue depth frequently hit `8`.

64-frame interpretation:
- The `64` request is not fake at the RtAudio callback level; the backend reported actual `64` frames.
- The audible latency does not fall proportionally with callback size because packet age remains around `10 ms`.
- Current hidden latency is likely dominated by receive/playout buffering and/or WASAPI backend buffering, not the requested callback size alone.

32-frame result:
- WASAPI accepted actual buffer `32` frames / `0.667 ms`.
- User listening result: audio became bad, corrupt, and robotic.
- PCM sender drops appeared on both clients.
- receive queue drops exploded into the tens of thousands.
- underruns still reported `0`.
- sequence gaps/late still reported `0/0`.
- packet age average stayed around `8-10 ms`.

32-frame interpretation:
- There is a real lower boundary; the system is not simply "always working".
- `32` frames is below what the current sender/receiver scheduling and queue policy can sustain.
- Underrun counters alone do not catch this failure mode. Robotic/corrupt audio correlates better with send drops plus massive receive queue drops.
- The next useful work is not lowering device buffers further. It is reducing hidden playout buffering and making the corrupt-audio condition measurable before promoting `64`.

## Pass 37: Failed 64-Frame Tight Queue Experiment

Date: 2026-04-27

Hypothesis:
- The previous clear `64` run might have sounded stable because the small-frame queue headroom was hiding too much buffering.
- Try lowering only the `64`-frame sender and receive queue caps.

Change tested:
- `64`-frame send queue cap changed from `8` to `4`.
- `64`-frame receive queue cap changed from `8` to `TARGET_OPUS_QUEUE_SIZE + 1`, which is `4`.
- `96` and `120` behavior was intended to stay unchanged.

Result:
- Rebuilt `client`.
- Started two visible clients with `--frames 64`.
- WASAPI accepted actual `64` frames / `1.333 ms`.
- User listening result: still bad and robotic.
- UI showed aggressive receive queue drops.
- One client showed `Queue: 0`, which means playout was riding the edge instead of staying safely fed.

Decision:
- Reverted the `64`-only queue-cap change.
- The prior `64` clear result depended on more queue headroom.
- Do not promote the tighter `64` policy.

Next:
- Add a direct corrupt-audio health signal based on drop rates, because underruns and sequence gaps stayed too clean during bad-sounding runs.
- Keep `120` as the default and `96` as the current validated ultra candidate.

## Pass 38: Corrupt-Audio Health Signal

Date: 2026-04-27

Problem:
- The bad `32` run and failed tight-`64` run sounded robotic/corrupt.
- Existing counters could still show `underruns=0` and `seq gap/late=0/0`.
- That made the automated diagnostics too optimistic.

Changed:
- `client.cpp`

Implementation:
- Audio diagnostics now compute per-second drop rates every alive/log interval.
- Logged participant diagnostics now include `drop_rate pcm/q=.../.../s`.
- A warning is emitted when any of these thresholds are exceeded:
  - PCM send drops greater than `5/s`
  - receive queue depth drops greater than `100/s`
  - jitter age drops greater than `5/s`

Bad-case verification:
- Started two hidden clients with `--frames 32`.
- Both clients opened actual `32` frames / `0.667 ms`.
- Audio health warnings appeared.
- Client A warning examples:
  - PCM drop rate: `6.0/s`, queue drop rate: `686.6/s`
  - PCM drop rate: `13.6/s`, queue drop rate: `673.6/s`
- Client B warning examples:
  - PCM drop rate: `3.4/s`, queue drop rate: `698.6/s`
  - PCM drop rate: `23.2/s`, queue drop rate: `690.2/s`

Stable-case verification:
- Started two hidden default clients.
- Both opened actual `120` frames / `2.500 ms`.
- No audio health warnings appeared.
- PCM drop rate: `0.0/s`
- receive queue drop rate: `0.0/s`
- underruns: `0`
- sequence gaps/late: `0/0`

Interpretation:
- The diagnostic now catches at least one automated proxy for robotic/corrupt audio.
- It is still not a full perceptual audio-quality test, but it prevents the known bad low-buffer case from looking green.
- This supports keeping `120` as the default and `96` as the validated Ultra candidate.

## Pass 39: Hide 64-Frame Mode From Normal UI

Date: 2026-04-27

Decision:
- Do not promote `64` into the normal user-facing buffer selector.

Reason:
- Original `64` opened successfully and could sound clear, but packet age stayed around `10 ms` and receive drops accumulated.
- Tighter `64` queue policy sounded robotic/corrupt.
- `96` has a cleaner validation record and is already labeled as Ultra.
- `120` remains the safer default.

Changed:
- `client.cpp`

Implementation:
- Removed `64` from the UI buffer combo options.
- Kept explicit startup override support through `client --frames 64` for future boundary tests.

Verification:
- `cmake --build build --target client`
- Default client opened actual `120` frames / `2.500 ms`.
- Explicit `client --frames 64` still opened actual `64` frames / `1.333 ms`.

Caveat:
- The startup smoke mixed a default `120` client and an explicit `64` client.
- Use it only to verify startup behavior, not audio quality.

Next:
- Stop lowering device callback size for now.
- Test lower PCM playout readiness/headroom instead, guarded by the new audio health warnings.

## Pass 40: Low-Latency PCM Two-Packet Readiness

Date: 2026-04-27

Hypothesis:
- Starting low-latency PCM playout after `2` packets instead of `3` might reduce hidden latency without changing device callback size.

Changed:
- `participant_info.h`
- `client.cpp`

Implementation:
- Added a participant jitter floor.
- PCM packets with `<=120` frames set jitter floor to `2` packets.
- Opus and larger PCM packets keep the existing `3`-packet floor.
- Adaptive jitter decrease now respects the participant's current floor.

Verification:
- `cmake --build build --target client`
- Two hidden default clients through local `server.exe`.

Result:
- Both clients opened actual `120` frames / `2.500 ms`.
- Both clients reached jitter ready at `2` packets.
- No audio health warnings.
- PCM sender drops: `0`
- receive queue drops: `0`
- underruns: `0`
- sequence gaps/late: `0/0`
- packet age average stayed around `9.8 ms`.
- queue depth stayed around `4`.

Interpretation:
- The readiness change is stable in a short `120` smoke.
- It did not reduce steady-state packet age because the receive queue still settles around `4` packets.
- The next latency experiment needs to cap steady-state receive depth, not just lower startup readiness.

## Pass 41: Failed 120-Frame Receive Cap 3 Experiment

Date: 2026-04-27

Hypothesis:
- If the `120` receive queue is capped at `3` packets, steady packet age might drop below the current `~9.8 ms`.

Temporary change:
- `max_receive_queue_packets(120)` returned `3`.

Verification:
- `cmake --build build --target client`
- Two hidden default clients through local `server.exe`.

Result:
- Both clients opened actual `120` frames / `2.500 ms`.
- Both clients reached jitter ready at `2` packets.
- Queue depth stayed at `3`.
- Packet age stayed around `9.6-9.8 ms`.
- Receive queue drop rate hovered around `100/s`.
- Audio health warnings fired on both clients.

Decision:
- Reverted the `120` cap-3 experiment.
- It did not reduce packet age meaningfully and it crossed the new corrupt-audio guardrail.

Interpretation:
- The `~9-10 ms` packet age is not explained only by receive queue cap.
- We need to decompose timing into capture-to-send, socket receive-to-playout, and backend/device latency instead of tuning one aggregate number.

## Pass 42: Sender Queue Timing Split

Date: 2026-04-27

Question:
- Is the persistent `~9-10 ms` participant packet age caused by the sender thread queue?

Changed:
- `client.cpp`

Implementation:
- PCM send frames now carry a capture timestamp from the audio callback.
- The PCM sender thread measures age when it dequeues the frame for packet creation.
- Audio diagnostics now log:
  - `sendq_age_ms last/avg/max`

Verification:
- `cmake --build build --target client`
- Two hidden default clients through local `server.exe`.

Result:
- Both clients opened actual `120` frames / `2.500 ms`.
- Both clients reached jitter ready at `2` packets.
- PCM sender drops: `0`
- receive queue drops: `0`
- underruns: `0`
- sequence gaps/late: `0/0`
- sender queue average: about `0.00-0.01 ms`
- sender queue max: about `0.23-0.51 ms`
- receive-to-playout packet age: about `9.7-9.8 ms`

Interpretation:
- The sender queue is not the source of the stubborn `~9-10 ms` age.
- Current participant packet age is receive-enqueue-to-playout time, not capture-to-speaker end-to-end.
- Remaining latency is on the receive/playout side and the device/backend side.
- Since RtAudio reports WASAPI backend latency as unavailable/zero on this machine, hidden Windows shared-mode output buffering may be significant and is not visible in current counters.

## Pass 43: RtAudio WASAPI Backend Limitation

Date: 2026-04-27

Question:
- Are our current RtAudio stream flags enough to force true low-latency WASAPI behavior?

Inspected:
- `audio_stream.h`
- `build/_deps/rtaudio-src/RtAudio.cpp`
- `build/_deps/rtaudio-src/RtAudio.h`

Current app flags:
- `RTAUDIO_SCHEDULE_REALTIME`
- `RTAUDIO_MINIMIZE_LATENCY`

Findings from vendored RtAudio source:
- WASAPI capture initializes shared-mode audio streams.
- WASAPI render initializes shared-mode audio streams.
- The source contains explicit TODOs in the WASAPI probe path:
  - `RTAUDIO_MINIMIZE_LATENCY`: provide stream buffers directly to callback
  - `RTAUDIO_HOG_DEVICE`: exclusive mode
- This means adding `RTAUDIO_HOG_DEVICE` in this build would not be a reliable path to WASAPI exclusive mode.

Interpretation:
- On this machine, the runtime backend is WASAPI.
- RtAudio can accept small callback sizes such as `120`, `96`, `64`, and `32`, but that does not prove the Windows device path has equally small end-to-end latency.
- The client-side bottleneck is now likely split between receive/playout buffering and hidden backend/output buffering.
- Competitor-style very low latency on Windows usually needs ASIO or a backend with explicit exclusive/low-latency control.

Decision:
- Do not keep pushing callback size lower.
- Keep `120` default and `96` Ultra.
- Treat ASIO or a different Windows audio backend/library as the next major latency lever.

Follow-up implementation:
- The latency panel now shows `Backend latency unknown` when the selected output API is WASAPI and RtAudio reports zero/unavailable backend latency.

## Pass 44: Audio Backend Inventory Command

Date: 2026-04-27

Purpose:
- Make backend verification repeatable without opening the GUI.
- After installing an ASIO driver/interface, this command should immediately show whether RtAudio can see it.

Changed:
- `client.cpp`

Implementation:
- Added `client --list-audio-devices`.
- Added alias `client --audio-devices`.
- The command prints visible RtAudio APIs and all visible audio devices, then exits.

Verification:
- `cmake --build build --target client`
- `build/Debug/client.exe --list-audio-devices`

Observed on this machine:
- APIs:
  - `ASIO`, default input `0`, default output `0`
  - `WASAPI`, default input `134`, default output `132`
- Visible devices are WASAPI only.
- No ASIO devices are listed.

Interpretation:
- ASIO is compiled into RtAudio and can be instantiated.
- No ASIO runtime device/driver is currently visible.
- The current machine remains on WASAPI shared-mode behavior until an ASIO driver/device is installed or a different Windows backend is implemented.

## Pass 45: Forced Audio API Startup Option

Date: 2026-04-27

Purpose:
- Make backend validation explicit.
- Avoid accidentally testing WASAPI while thinking ASIO is active.

Changed:
- `client.cpp`

Implementation:
- Added `client --require-api NAME`.
- Added alias `client --api NAME`.
- If the required API does not expose both an input and output device, startup fails before constructing the client/network connection.

Verification:
- `cmake --build build --target client`
- `build/Debug/client.exe --require-api ASIO`
- `build/Debug/client.exe --require-api WASAPI --frames 120`

ASIO result on this machine:
- Exit code: `2`
- Error: required audio API `ASIO` does not have both input and output devices.
- Inventory still shows `ASIO` as an available RtAudio API, but no ASIO devices are listed.

WASAPI result on this machine:
- Startup required audio API: `WASAPI`
- Startup requested buffer override: `120` frames.
- Actual buffer: `120` frames / `2.500 ms`.
- RtAudio backend latency remains unavailable or zero.

Interpretation:
- The current code path is ready to validate ASIO as soon as a real ASIO driver/interface is visible.
- Until then, all real client tests on this machine remain WASAPI shared-mode tests.

## Pass 46: Rejected Standalone WASAPI Probe As Product Direction

Date: 2026-04-27

Context:
- A standalone Windows Core Audio probe was briefly added to inspect WASAPI exclusive capability.
- User clarified the project is cross-platform and should not proceed through machine-specific code as the main path.

Decision:
- Removed the Windows-only `wasapi_probe` target and source file.
- Keep backend work behind the cross-platform `AudioStream` abstraction unless a platform implementation is explicitly chosen later.
- Prefer capability checks that use the same abstraction the client uses.

Resulting direction:
- Keep `client --list-audio-devices`.
- Keep `client --require-api NAME`.
- Add a cross-platform audio open smoke command through `AudioStream`.
- Do not add native WASAPI/CoreAudio/JACK code unless the cross-platform abstraction fails a concrete requirement.

## Pass 47: Cross-Platform Audio Open Smoke Command

Date: 2026-04-27

Purpose:
- Validate audio API/device/buffer selection without opening the GUI.
- Use the same cross-platform `AudioStream` abstraction as the client.

Changed:
- `client.cpp`

Implementation:
- Added `client --audio-open-smoke`.
- Supports existing options:
  - `--require-api NAME`
  - `--frames N`
- Opens the selected/default input and output device.
- Runs the regular audio callback contract with silence.
- Prints latency info.
- Closes the stream and exits.

Verification:
- `cmake --build build --target client`
- `build/Debug/client.exe --audio-open-smoke --require-api WASAPI --frames 120`
- `build/Debug/client.exe --audio-open-smoke --require-api ASIO --frames 96`

Result:
- WASAPI smoke opened actual `120` frames / `2.500 ms` through `AudioStream` and exited cleanly.
- RtAudio backend latency remained unavailable/zero on WASAPI.
- ASIO smoke exited `2` because no ASIO input/output devices are visible on this machine.

Interpretation:
- We now have a cross-platform, non-GUI way to validate real audio backend openings.
- This replaces the rejected machine-specific probe as the correct product-direction diagnostic.

## Pass 48: Latency Probe Clock-Drift Stress

Date: 2026-04-27

Purpose:
- Reproduce sound-card clock mismatch in automation before changing production playout.
- Keep this cross-platform and independent of native audio APIs.

Changed:
- `latency_probe.cpp`

Implementation:
- Added `--playout-ppm`.
- Positive values make receiver playout run faster than sender packet production.
- Negative values make receiver playout run slower.
- Existing output now reports `playout_ppm`.

Verification:
- Build: `cmake --build build --target latency_probe`.
- Invalid attempt: running two probes concurrently against the same SFU contaminates results, because each probe hears the other probe's audio.
- Clean baseline: `latency_probe --codec pcm --frames 120 --jitter 16 --seconds 20 --playout-ppm 0`.
  - `sent_packets=8000`, `received_packets=8000`, `decoded_packets=8000`.
  - `underruns=0`, `decode_failures=0`, `out_of_range_samples=0`.
  - `avg_queue_depth=15.49`, `queue_drift_from_jitter=-0.51`.
- Drift stress: `latency_probe --codec pcm --frames 120 --jitter 16 --seconds 20 --playout-ppm 500`.
  - `sent_packets=8000`, `received_packets=8000`, `decoded_packets=8000`.
  - `underruns=0`, `decode_failures=0`, `out_of_range_samples=0`.
  - `avg_queue_depth=11.54`, `queue_drift_from_jitter=-4.46`.

Interpretation:
- The probe can now simulate receiver-side clock pressure without touching platform audio APIs.
- At `+500 ppm`, the queue drains by roughly 4.5 packets over 20 seconds while samples remain clean.
- This is the right automated harness for the next production step: bounded drift correction in client playout.

## Pass 49: Bounded PCM Empty-Queue Concealment

Date: 2026-04-27

Purpose:
- PCM had no PLC path; a brief receive-queue underrun produced a hard silent callback.
- Add the smallest bounded concealment that can smooth isolated PCM underruns without hiding sustained failure.

Changed:
- `participant_info.h`
- `participant_manager.h`
- `client.cpp`

Implementation:
- Store the last successfully decoded PCM frame per participant.
- On a PCM empty-queue callback, replay that frame once at reduced gain.
- Count these events as `pcm_concealment_frames`.
- Show `PCM hold` in participant stats when it happens.
- Include the counter in periodic participant diagnostics.

Guardrail:
- The fallback is one callback only. If the queue remains empty, output returns to silence.
- This is not a full clock-drift correction; it is a bounded gap smoother before implementing controlled slip/resampling.

Verification:
- `cmake --build build --target client`
- `cmake --build build --target latency_probe`
- `client --audio-open-smoke --require-api WASAPI --frames 120`

## Pass 50: Bounded PCM Drift Slip

Date: 2026-04-27

Purpose:
- Keep PCM playout from accumulating latency when the receive queue grows.
- Match the Jamulus-style principle of bounded frame slip before attempting continuous resampling.

Changed:
- `participant_info.h`
- `participant_manager.h`
- `client.cpp`

Implementation:
- After a successful PCM playout, check the remaining queue depth.
- If the queue is above `jitter_buffer_min_packets + 3`, drop exactly one queued PCM packet.
- Count this as `pcm_drift_drops`.
- Show `PCM drift drop` in the participant stats.
- Include `pcm_hold/drop` in periodic participant diagnostics.

Guardrail:
- The correction is bounded to one packet per callback.
- Normal packet playout is unchanged when the queue is within the target range.
- This does not add platform-specific code and does not replace the RtAudio abstraction.

Verification:
- `cmake --build build --target client`
- `cmake --build build --target latency_probe`
- `client --audio-open-smoke --require-api WASAPI --frames 120`
- Manual two-client local `120` frame test: user reported clear audio.

Next:
- Run manual two-client listening at `120` and `96` frames.
- Watch `PCM hold`, `PCM drift drop`, queue depth, and health warnings while listening.

## Pass 51: Post-Correction `96` Listening Check

Date: 2026-04-27

Purpose:
- Verify the Ultra `96` frame path after bounded PCM hold/drop was added.

Setup:
- Local server.
- Two real clients.
- `client --frames 96`.

Result:
- User reported clear audio.

Interpretation:
- The bounded PCM hold/drop correction did not audibly damage the `96` frame path on this machine.
- `96` remains the current validated Ultra candidate.

## Pass 52: Post-Correction `64` Boundary Check

Date: 2026-04-27

Purpose:
- Check whether bounded PCM hold/drop makes the explicit `64` frame path usable.

Setup:
- Local server.
- Two real clients.
- `client --frames 64`.

Result:
- User reported robotic/corrupt audio.

Interpretation:
- The bounded correction is not enough to make `64` safe on this setup.
- `64` should remain hidden from the normal UI selector and available only as an explicit CLI experiment.
- The current validated low-latency choices remain `120` default and `96` Ultra.

## Current Latency Tier Decision

Date: 2026-04-27

Decision:
- `120` frames: default low-latency mode.
- `96` frames: Ultra mode.
- `64` frames: CLI-only experimental boundary test.
- `32` frames: invalid/bad on this setup.

Evidence:
- Post-correction `120`: user reported clear audio.
- Post-correction `96`: user reported clear audio.
- Post-correction `64`: user reported robotic/corrupt audio.
- Earlier `32`: user reported bad/corrupt/robotic, and health warnings fired.

Implication:
- Do not keep spending cycles trying to promote `64` with small queue tweaks.
- The next meaningful latency work is either longer validation of `96`, real low-latency backend/device validation, or a deeper playout algorithm.

## Next Lever Decision

Date: 2026-04-27

Decision:
- Run extended `96` validation first.

Rationale:
- `96` is the lowest currently clear tier.
- `64` still fails after bounded correction, so small queue tweaks are not the right next move.
- Backend validation needs a real low-latency device/API path.
- Deeper resampling is larger and should follow only if the extended `96` run shows drift/hold/drop pressure that bounded slip cannot handle.

## Pass 53: Extended `96` Validation After Bounded Drift Correction

Date: 2026-04-27

Purpose:
- Verify the current Ultra tier after bounded PCM hold/drop.
- Capture logs so the result is not only a listening report.

Setup:
- Local server.
- Two hidden real clients.
- `client --frames 96`.
- Duration: about 10 minutes.
- Logs:
  - `validation_logs/client96_A_20260427_214309.out.log`
  - `validation_logs/client96_B_20260427_214309.out.log`

Result:
- No `Audio health warning`.
- No send/decode/packet errors found in the captured logs.
- No sequence gaps or late packets.
- Final client A participant stats: `ready=true`, `q=5`, `q_max=8`, `age_avg_ms=9.8`, `underruns=196`, `pcm_hold/drop=196/0`, `drops q/age=306/0`, `drop_rate pcm/q=0.0/1.0/s`.
- Final client B participant stats: `ready=true`, `q=5`, `q_max=8`, `age_avg_ms=9.8`, `underruns=59`, `pcm_hold/drop=59/1`, `drops q/age=90/0`, `drop_rate pcm/q=0.0/1.6/s`.

Interpretation:
- `96` remains stable and warning-free in the extended run.
- The internal state is not perfectly clean: bounded `PCM hold` is actively smoothing occasional empty-queue gaps.
- Since user listening reported `96` clear, this is acceptable for the current Ultra tier, but it is evidence for a future deeper playout/resampling step if we want cleaner counters.

## Pass 54: PCM Hold/Drift-Drop Rate Diagnostics

Date: 2026-04-27

Purpose:
- Make bounded hold/drop activity visible as a rate, not just a cumulative counter.
- Let the health warning catch cases where concealment itself becomes frequent enough to risk robotic audio.

Changed:
- `client.cpp`

Implementation:
- Participant diagnostics now log `drop_rate pcm/q/hold/drift`.
- Health warnings now include high `pcm_hold_rate` or `pcm_drift_drop_rate`.
- Existing send-drop, queue-drop, and age-drop warning behavior remains.

Verification:
- `cmake --build build --target client`
- `cmake --build build --target latency_probe`
- `client --audio-open-smoke --require-api WASAPI --frames 96`
- Short two-client `96` log run emitted diagnostics such as `drop_rate pcm/q/hold/drift=0.0/0.8/0.4/0.0/s`.

## Current `96` Decision

Date: 2026-04-27

Decision:
- Accept `96` as the current Ultra tier.
- Do not add continuous resampling yet.
- Move the next major latency lever to backend/device validation.

Rationale:
- User listening reported `96` clear.
- Extended hidden run showed no health warnings, send/decode/packet errors, sequence gaps, or late packets.
- Bounded `PCM hold` is nonzero, but now visible as a rate and warning signal.
- A resampler is a larger algorithmic change and should be justified by audible artifacts or backend/device limits.

Backend Inventory Refresh:
- Command: `client --list-audio-devices`.
- RtAudio APIs visible: `ASIO`, `WASAPI`.
- ASIO default input/output: `0` / `0`.
- ASIO devices listed: none.
- Current usable devices: WASAPI only.

Implication:
- The current code is ready to force and validate ASIO, but this machine still cannot perform that validation.
- Further latency gains below stable `96` likely need a real low-latency backend/device path or a more complex playout resampler.

## Pass 55: Low-Latency Backend Readiness Command

Date: 2026-04-27

Purpose:
- Make backend validation a repeatable command instead of a chat instruction.
- Fail clearly when the requested low-latency API has no usable duplex devices.

Changed:
- `client.cpp`

Implementation:
- Added `client --backend-check`.
- Added alias `client --low-latency-check`.
- Default check targets `ASIO` at `96` frames.
- The command can target another API with `--require-api`.
- If the API has input/output devices, the command runs the existing audio-open smoke path.

Verification:
- `cmake --build build --target client`
- `client --backend-check`
  - Result: fails clearly because ASIO has no input/output devices and prints backend inventory.
- `client --backend-check --require-api WASAPI --frames 96`
  - Result: opens actual `96` frames / `2.000 ms`.
  - Result: warns that RtAudio backend latency is unavailable or zero.

Interpretation:
- The app now has a single command for validating whether a machine is ready for the next backend/device latency step.
- On this machine, the answer is still no for ASIO.

## Pass 56: Phase 2 Diff Review Findings

Date: 2026-04-27

Purpose:
- Review the current Phase 2 diff for hacks, regressions, and accidental broad changes before accepting the phase.

Findings:
- Concrete bug: WAV callback scratch buffer was `480` samples while UI allowed `512` frame buffers. Fixed by resizing the scratch buffer to `960`, matching the other callback scratch buffers.
- Concrete bug: normal UI allowed `512` frames even though PCM int16 payload would be `1024` bytes and exceed `AUDIO_BUF_SIZE=512`. Fixed by removing `512` from the normal UI buffer selector.
- Known Phase 2 limitation: PCM clients should use the same frame setting. Mixed `96`/`120` clients are not supported until a real resampling/playout layer exists.

Interpretation:
- The bounded PCM hold/drop behavior is visible and limited, but it is still a stopgap rather than a true resampler.
- The review did not find a reason to undo `120` default or `96` Ultra.

## Phase 2 Acceptance Draft

Date: 2026-04-27

Decision:
- Accept bounded PCM hold/drop for Phase 2 as a limited stabilization mechanism.

Rationale:
- `120` and `96` are clear in manual tests.
- Extended `96` run is warning-free.
- Hold/drop activity is exposed through counters and rates.
- `64` remains rejected, so the mechanism is not being used to mask an unstable lower-latency tier.
- A real resampling/playout layer is larger and should be a later phase.

Not Accepted As Final Yet:
- Needs targeted post-review verification after the `512` safety fixes.
- Needs user listening confirmation on the reviewed build.

Post-Review Verification:
- `cmake --build build --target client`
- `cmake --build build --target latency_probe`
- `client --audio-open-smoke --require-api WASAPI --frames 96`
  - Result: opened actual `96` frames / `2.000 ms`.
- `client --backend-check --require-api WASAPI --frames 96`
  - Result: opened actual `96` frames / `2.000 ms`.
- `client --backend-check`
  - Result: failed clearly because ASIO has no visible input/output devices.

Reviewed-Build Listening:
- Setup: local server plus two reviewed-build clients at `--frames 96`.
- Result: user reported clear audio.

Phase 2 Final Acceptance:
- Accepted.
- Reason: reviewed build passes targeted checks and user-confirmed `96` listening.
- Remaining non-code decision: whether to commit this state after user testing.
