# JUCE Audio Backend Migration Design

Date: 2026-06-05

## Context

The client currently owns audio through `AudioStream` in `audio_stream.h`, which directly wraps RtAudio. `client.cpp` depends on that class for device selection, audio start/stop, latency reporting, GUI controls, and CLI diagnostics such as `--list-audio-devices`, `--audio-open-smoke`, and `--backend-check`.

RtAudio replaced PortAudio earlier, but real-machine testing showed that the RtAudio path is not production-ready for the target use case. The visible failures include unreliable behavior on machines with real drivers and unclear backend latency reporting. The project needs a production audio path closer to proven open-source jam products.

The cached competitor audit found these patterns:

- Jamulus uses custom native backends: ASIO on Windows, CoreAudio on macOS, JACK on Linux, and Oboe/OpenSLES on Android.
- SonoBus uses JUCE's audio device layer with ASIO, WASAPI, JACK, ALSA, and Oboe enabled.
- JackTrip supports JACK and RtAudio, but RtAudio is not the strongest production signal among these products.

## Decision

Adopt JUCE as the only client audio backend, behind a project-owned `AudioBackend` interface.

This gives the project a mature cross-platform audio device layer while avoiding another hard dependency leak into the rest of the client. RtAudio should be removed from the active client build as part of the migration, not kept as a fallback backend.

## Licensing Gate

Before JUCE code is shipped, the repository must declare an AGPLv3-compatible open-source license and include third-party notices for JUCE and ASIO-related components.

The repo currently has no active `LICENSE` file. Public source availability alone is not enough. Since the project is intended to be public open source, the migration should start by adding a compatible license and notice files rather than leaving licensing implicit.

## Goals

- Replace the production audio path with JUCE.
- Preserve the current client callback behavior while migrating.
- Keep the GUI and CLI diagnostics usable throughout the migration.
- Prefer low-latency backends by platform:
  - Windows: ASIO first, WASAPI fallback.
  - macOS: CoreAudio.
  - Linux: JACK first, ALSA fallback.
- Preserve local monitor, mute, gain, metronome, encode, decode, and jitter behavior.
- Make future backend changes local to backend implementations.

## Non-Goals

- Do not rewrite the GUI in JUCE.
- Do not copy Jamulus or SonoBus backend code.
- Do not solve Linux packaging in the first implementation pass.
- Do not change codec, network, jitter buffer, or room routing behavior as part of this migration.

## Architecture

### Backend-Neutral Interface

Add a small backend-neutral layer:

- `audio_backend.h`
  - `AudioDeviceId`
  - `AudioDeviceInfo`
  - `AudioApiInfo`
  - `AudioConfig`
  - `AudioLatencyInfo`
  - `AudioCallback`
  - `AudioBackend`

`AudioBackend` should expose:

- enumerate APIs
- enumerate input devices
- enumerate output devices
- choose default input and output
- open stream
- stop stream
- report stream state
- report actual buffer size and latency
- expose the last backend error

The interface should use plain project types, not JUCE or RtAudio types.

### AudioStream Facade

Keep `AudioStream` as the public facade initially. `client.cpp` should not need a large rewrite in the first pass.

`AudioStream` becomes responsible for:

- owning one selected backend
- forwarding static enumeration calls
- forwarding start/stop calls
- preserving existing `AudioStream::DeviceInfo`, `AudioStream::ApiInfo`, and `AudioStream::AudioConfig` compatibility where practical
- selecting JUCE by default

### JUCE Backend

Add:

- `juce_audio_backend.h`
- `juce_audio_backend.cpp`

The JUCE backend should use:

- `juce_audio_devices`
- `juce_audio_basics`
- `juce_core`
- `juce_events` if required by JUCE device management

It should enable:

- `JUCE_ASIO=1`
- `JUCE_WASAPI=1`
- `JUCE_DIRECTSOUND=0`
- `JUCE_JACK=1` and `JUCE_ALSA=1` where supported

The backend should adapt JUCE's channel-separated float buffers to the client's current interleaved float callback contract. That keeps the existing audio engine behavior stable first. After validation, a later optimization can remove unnecessary interleaving copies if profiling proves it matters.

## Data Flow

Current client path:

```text
audio device callback
  -> Client::audio_callback
  -> local input gain/mute/monitor
  -> encode/send
  -> remote decode/mix
  -> output buffer
```

Target path:

```text
JUCE AudioIODeviceCallback
  -> backend adapter converts channel buffers to interleaved input/output
  -> existing Client::audio_callback
  -> backend adapter writes interleaved output back to JUCE output channels
```

The adapter must handle mono input and stereo output because the current client records one input channel and normally renders one or two output channels.

## Device Policy

Device selection should preserve explicit user choice. Automatic selection should prefer low-latency APIs:

- Windows:
  - first ASIO device with input/output capability
  - then WASAPI device with input/output capability
- macOS:
  - CoreAudio default input/output
- Linux:
  - JACK when available
  - ALSA fallback

ASIO should enforce same-driver input/output when the backend requires it. If the user chooses incompatible input and output devices, the error must be explicit.

## Error Handling

Errors should stay user-visible and diagnostic-friendly:

- device disappeared
- input/output API mismatch
- selected device lacks input or output channels
- requested sample rate rejected
- requested buffer size rejected or adjusted
- backend failed to start
- callback reported failure

The GUI should continue showing `AudioStream::get_last_error()`. CLI commands should print the selected API/device, requested buffer, actual buffer, sample rate, and backend-reported latency when available.

## Build Plan

CMake should remove the RtAudio dependency from the client target and link JUCE audio modules directly.

The first implementation should keep the client executable name and CLI unchanged.

## Verification

Automated checks:

- build `client`
- build existing self-tests
- `client --list-audio-devices`
- `client --audio-open-smoke --frames 240`
- `client --audio-open-smoke --frames 120`
- `client --backend-check`

Hardware checks:

- Windows with real ASIO driver:
  - ASIO appears in device inventory
  - ASIO is preferred by default
  - open smoke succeeds at the driver's supported low buffer size
  - ASIO control panel remains accessible if exposed
- Windows without ASIO:
  - WASAPI fallback opens clearly
  - GUI labels fallback as non-preferred for low latency
- macOS:
  - CoreAudio device inventory works
  - default input/output opens
  - unplug/replug failure is clear
- Linux later:
  - JACK inventory/open
  - ALSA fallback inventory/open

Regression checks:

- local monitor checkbox still routes mic to local output only
- mute still stops local input from being sent and monitored
- master gain still applies
- Opus/PCM mode selection still works
- metronome still mixes to output
- listener/broadcast tap does not receive local monitor signal

## Rollout

1. Add license and notices.
2. Introduce backend-neutral interface and tests for selection policy.
3. Add JUCE dependency and compile a minimal device inventory path.
4. Implement JUCE open/close/callback adapter.
5. Remove RtAudio from the client build.
6. Validate on real Windows ASIO and macOS CoreAudio hardware.

## Risks

- JUCE callback buffers are channel-separated while the client callback is interleaved.
  - Mitigation: adapt at the backend boundary first.
- ASIO driver behavior varies by vendor.
  - Mitigation: keep explicit CLI smoke tests and require real-driver validation.
- CMake integration may pull more JUCE modules than expected.
  - Mitigation: link only audio/device/core modules needed for the backend.
- Licensing can block distribution if left implicit.
  - Mitigation: license gate comes before shipping JUCE code.
- Client code is currently large and owns GUI plus CLI plus audio lifecycle.
  - Mitigation: first preserve `AudioStream`; later split CLI diagnostics and device UI helpers.

## Approval State

The user approved JUCE as acceptable for a public open-source project, then refined the migration direction to require a full JUCE change with no RtAudio fallback.
