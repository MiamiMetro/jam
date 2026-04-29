# PCM Cross-Platform Clock Sync Findings

Date: 2026-04-29

## Problem

Raw PCM works in same-platform tests but fails across Windows and macOS:

- Windows to Windows: PCM works.
- macOS to macOS: PCM works.
- Windows to macOS: PCM is robotic/corrupt.
- macOS to Windows: PCM is robotic/corrupt.
- Opus works across the same machines.

This points away from UDP/SFU routing and toward receiver-side PCM playout design.

The current PCM experiments that copy variable packet frame counts into a local playout buffer are not enough. They handle callback-size mismatch, but they do not solve independent audio-device clock drift between machines.

## Working Diagnosis

Each machine has its own audio clock. Even when both report `48000 Hz`, one device can effectively produce or consume slightly faster than the other.

With raw PCM, that drift must be absorbed continuously. If the receiver only drops, holds, inserts, or drains whole frames/packets, the result becomes robotic or unstable.

Correct PCM-over-network needs:

- sequence-aware jitter buffer
- packet-to-audio ring buffer
- target playout depth
- drift measurement
- adaptive sample-rate conversion or an equivalent clock-sync layer
- diagnostics for underrun, overrun, queue depth, drift, and correction rate

## Competitor Evidence From Cache

### JackTrip

Cached source: `.cache/competitors/jacktrip`.

JackTrip's documented audio path is:

- Sender: `AudioInterface -> RingBuffer -> PacketHeader -> UdpDataProtocol -> Network`
- Receiver: `Network -> UdpDataProtocol -> JitterBuffer -> RingBuffer -> Effects -> AudioInterface`

Relevant files:

- `.cache/competitors/jacktrip/src/RingBuffer.cpp`
- `.cache/competitors/jacktrip/src/JitterBuffer.cpp`
- `.cache/competitors/jacktrip/src/Regulator.cpp`
- `.cache/competitors/jacktrip/src/SampleRateConverter.cpp`
- `.cache/competitors/jacktrip/src/RtAudioInterface.cpp`

Findings:

- JackTrip has explicit jitter/ring buffering instead of direct packet-to-callback playback.
- JackTrip has a `SampleRateConverter` wrapper using `libsamplerate` when enabled.
- JackTrip's RtAudio path creates input/output sample-rate converters when a device does not support the target rate.
- JackTrip's `Regulator` is a more complex buffering strategy for mismatched packet/callback behavior. It is not a small patch to copy blindly.

### SonoBus / AOO

Cached source: `.cache/competitors/sonobus`.

SonoBus documentation states that different participants do not need the same sample rate because audio is resampled automatically.

Relevant files:

- `.cache/competitors/sonobus/doc/SonoBus User Guide.md`
- `.cache/competitors/sonobus/deps/aoo/lib/src/source.cpp`
- `.cache/competitors/sonobus/deps/aoo/lib/src/source.hpp`
- `.cache/competitors/sonobus/deps/aoo/lib/src/sink.cpp`
- `.cache/competitors/sonobus/deps/aoo/lib/src/sink.hpp`

Findings:

- AOO has `dynamic_resampler` in both source and sink paths.
- AOO tracks samplerate per block and updates the resampler before reading output.
- AOO uses a time DLL/filter to estimate real stream timing and sample rate.
- AOO intentionally passes audio through a resampling buffer even when callback sizes vary, to decouple host callback block size from codec/network block size.

### Jamulus

Cached source: `.cache/competitors/jamulus`.

Findings:

- Current Jamulus protocol documentation says Jamulus uses Opus/Opus64 and always uses 48 kHz.
- Jamulus uses jitter buffers on both client and server.
- Jamulus has a conversion buffer that assumes applied buffers are integer fractions of the total buffer size.
- Jamulus buffer logic explicitly discusses robustness against sample-rate offsets and audio-driver buffer glitches by adjusting the buffer window.

Jamulus is useful as jitter-buffer evidence, but it is not proof that arbitrary raw PCM cross-device drift is solved without a resampler.

## Resampler Latency Answer

A streaming resampler adds some algorithmic delay, but it is usually not the main latency cost.

The larger cost is the chosen receiver playout target. If the receiver targets 2 packets, 5 packets, or 10 packets of safety, that dominates the latency more than the math of resampling.

Approximate practical expectations at 48 kHz:

- Very low-latency linear/simple resampling: typically sub-millisecond to very small delay, lower quality.
- Higher-quality sinc/polyphase resampling: can add more delay and CPU, but still usually smaller than a conservative jitter buffer.
- Real jamming latency impact: mostly the playout buffer target, not the existence of a resampler.

So a proper resampler should not destroy the macOS-to-macOS "instant" feeling by itself. A too-large safety buffer would.

## Decision

Do not keep tuning whole-packet hold/drop/insert heuristics as the final PCM design.

The next PCM fix should replace the current experimental drift handling with a real streaming clock-sync/resampling design.

## Recommended Next Implementation

Implement this in the native client only:

1. Keep Opus unchanged.
2. Keep PCM packet format unchanged.
3. For each remote PCM participant, keep a receiver state:
   - jitter packet queue by sequence
   - decoded/received PCM ring buffer
   - target playout depth in frames
   - measured buffer fill level
   - estimated sender-to-local clock ratio
   - streaming resampler state
4. Feed received PCM samples into the remote participant's resampler/ring buffer.
5. On each audio callback, ask the resampler/ring buffer for exactly the local callback frame count.
6. Adjust resampling ratio slowly based on buffer fill error, not with audible whole-frame jumps.
7. Keep diagnostics visible:
   - PCM buffer fill frames/ms
   - estimated resample ratio
   - underruns
   - overruns
   - correction ppm
   - drop/hold counters should go down or disappear from the normal path

## Library Direction

Prefer a small proven resampler library instead of handwritten DSP.

Candidates:

- `libsamplerate`: JackTrip already uses it. Good evidence, simple wrapper, but quality mode must be chosen carefully for latency/CPU.
- `SpeexDSP resampler`: common for real-time audio, small, adjustable quality, good candidate for low-latency streaming correction.
- `soxr`: high quality, but may be more dependency weight than needed.

For this repo, the first candidate should be `SpeexDSP resampler` or `libsamplerate` with a low-latency mode. The implementation should be hidden behind a tiny `PcmClockResampler` wrapper so the library choice can change without rewriting the audio callback.

## Acceptance Criteria

- Windows-to-Windows PCM remains clear.
- macOS-to-macOS PCM remains clear and low-latency.
- Windows-to-macOS PCM becomes clear.
- macOS-to-Windows PCM becomes clear.
- Opus remains unchanged and clear.
- Cross-machine PCM does not rely on both clients using the same callback frame size.
- Diagnostics show stable fill level and bounded correction instead of queue-drop/hold storms.

## Non-Goals

- Do not make PCM the internet default.
- Do not replace Opus.
- Do not add Electron/Convex work.
- Do not copy JackTrip `Regulator` wholesale before proving a smaller resampler-based design.
