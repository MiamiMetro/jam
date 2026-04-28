# Native Jam Engine Phase 2 Plan

## Phase

Phase 2 is Cross-Platform Native Validation.

The goal is to validate the standalone performer jam engine on macOS/CoreAudio and confirm the Windows build remains portable after platform-specific build guards.

## Scope

Included:

- macOS/CoreAudio build validation
- macOS/CoreAudio device inventory and smoke checks
- macOS two-client performer listening tests
- macOS diagnostics for Opus `120`, PCM `120`, and PCM `96`
- Windows build sanity after platform guards
- documentation of platform-specific blockers

Excluded:

- listener/HLS mode
- Electron/Convex integration
- signed native auth tokens
- permanent room/product state
- community server registration
- mixed frame-size support

## Current Findings

Windows:

- WASAPI local baseline is validated for Phase 1.
- ASIO support is guarded to Windows in CMake.
- ASIO runtime validation is still blocked because no ASIO input/output device is visible on the current Windows machine.
- WASAPI opens at `120` and `96`, but RtAudio reports backend latency unavailable/zero.

macOS:

- PCM mode feels effectively instant on CoreAudio.
- macOS reports about `0.8 ms` input/output latency in PCM testing.
- Mouse click timing feels aligned with real life in PCM mode.
- macOS PCM is currently better than Windows WASAPI for perceived latency.
- macOS Opus TX/RX frame pacing has a targeted fix: TX accumulates CoreAudio callback chunks into legal Opus packet frames, and RX buffers decoded Opus PCM across callbacks.
- macOS Opus runtime buffer choices are intentionally limited to `128` and `240`; requests such as `96`, `120`, and `256` are normalized to `128` and logged.
- macOS Opus is stable after the TX/RX frame pacing fix.
- macOS PCM is stable.

## Done Criteria

Phase 2 is done when:

- macOS builds `server`, `client`, and `latency_probe`.
- macOS device inventory shows the expected CoreAudio devices.
- macOS audio-open smoke passes at `120` and `96`.
- macOS PCM `120` two-client listening is clear.
- macOS PCM `96` two-client listening is clear or explicitly demoted.
- macOS Opus normalized runtime buffer, normally `128` when `120` is requested, has clear two-client listening and keeps transferring.
- macOS Opus no longer stops TX.
- macOS accepted runs have diagnostics captured for drops, underruns, packet age, callback timing, and warnings.
- Windows still builds after the CMake platform guard.
- Any remaining platform differences are documented.

## macOS Validation Commands

Build:

```bash
cmake --build build --target server
cmake --build build --target client
cmake --build build --target latency_probe
```

Device inventory:

```bash
./build/client --list-audio-devices
```

Audio open smoke:

```bash
./build/client --audio-open-smoke --frames 120
./build/client --audio-open-smoke --frames 96
```

Use the API name printed by `--list-audio-devices` if forcing CoreAudio is needed:

```bash
./build/client --audio-open-smoke --require-api <CoreAudioApiName> --frames 120
./build/client --audio-open-smoke --require-api <CoreAudioApiName> --frames 96
```

Local SFU:

```bash
./build/server --port 9999
```

Manual two-client runs:

```bash
./build/client --server 127.0.0.1 --port 9999 --codec pcm --frames 120
./build/client --server 127.0.0.1 --port 9999 --codec pcm --frames 96
./build/client --server 127.0.0.1 --port 9999 --codec opus --frames 120
./build/client --server 127.0.0.1 --port 9999 --codec opus --frames 128
./build/client --server 127.0.0.1 --port 9999 --codec opus --frames 240
```

On macOS, `--codec opus --frames 120` is expected to log normalization to `128` and run with `Buf: 128/128`.

Automated probes, run serially:

```bash
./build/latency_probe --codec pcm --frames 120 --jitter 5 --seconds 10
./build/latency_probe --codec pcm --frames 96 --jitter 6 --seconds 10
./build/latency_probe --codec opus --frames 120 --jitter 6 --seconds 10
```

## Opus macOS Blocker Checklist

- [x] Capture logs from two macOS Opus `120` clients when TX stops.
  - Superseded by reproduced macOS failure and accepted frame-pacing fix.
- [x] Check whether `tx_packets` stops increasing.
  - Result: user reproduced Opus TX stop before the fix; latest build is stable.
- [x] Check whether `tx_drops pcm/opus` increases.
  - Superseded by accepted fix; final macOS Opus run is stable.
- [x] Check for Opus encode failures or illegal frame-size drops.
  - Superseded by accepted fix; illegal callback-sized Opus TX is avoided by accumulation.
- [x] Check whether actual CoreAudio callback frame count differs from requested `120`.
  - Result: macOS Opus now normalizes unsafe requested buffers to CoreAudio-friendly `128` or `240`.
- [x] Check whether Opus is being asked to encode a non-legal frame size on macOS.
  - Likely cause found in code: PCM accepts arbitrary backend callback sizes, but Opus previously dropped any callback `frame_count` that was not a legal Opus duration.
  - Fix: Opus send now accumulates backend callback samples into legal Opus frame sizes before enqueueing packets.
  - Fix: illegal Opus frame drops now log a throttled warning instead of failing silently.
- [x] Check whether input callback delivers `nullptr` or zeroed input after startup.
  - Not the accepted root cause; PCM worked on the same device path.
- [x] Check whether sender queue stops waking on macOS.
  - Not the accepted root cause; frame pacing fix resolved the user-visible stop.
- [x] Compare macOS Opus behavior against macOS PCM behavior using the same devices.
  - Result: both Opus and PCM are stable in the latest macOS test.

## Active Checklist

- [x] Record macOS PCM/CoreAudio initial result.
- [x] Record macOS Opus TX stop as current Phase 2 blocker.
- [x] Collect macOS Opus stop logs.
  - Superseded by reproduced failure and accepted latest macOS test.
- [x] Inspect and fix only the Opus/macOS issue directly blocking Phase 2.
  - Windows regression check after Opus send accumulator: `client` builds.
  - Windows regression check after Opus send accumulator: `latency_probe --codec opus --frames 120 --jitter 6 --seconds 10` passes with `0` underruns, `0` PLC, `0` encode/decode failures.
  - Windows regression check after Opus send accumulator: 30-second hidden two-client Opus `120` run had `tx_drops pcm/opus=0/0`, no underruns/PLC, no decode failures, no sequence gaps.
- [x] Re-run macOS Opus normalized-buffer two-client listening.
  - Result: user tested latest build on macOS; Opus is stable.
- [x] Re-run macOS Opus normalized-buffer 60-120 second diagnostic capture.
  - Result: user tested latest build on macOS; Opus remains stable.
- [x] Confirm macOS PCM `120` diagnostics.
  - Result: user tested latest build on macOS; PCM is stable.
- [x] Confirm macOS PCM `96` diagnostics.
  - Result: user tested latest build on macOS; PCM is stable.
- [x] Re-run Windows build sanity after any fix.
  - Result: `cmake --build build --target client` passes on Windows.

## Phase 2 Acceptance

Accepted.

Reason:

- macOS/CoreAudio PCM feels effectively instant and is stable.
- macOS/CoreAudio Opus is stable after TX/RX frame pacing fix.
- macOS Opus buffer normalization is now explicit and logged instead of silent.
- Windows client build still passes after the fix.
- Listener/HLS, native room/auth, and Electron/Convex integration remain intentionally out of scope.

## Completion Rule

Do not start native room/auth work until macOS Opus `120` is either fixed or explicitly demoted with a documented product decision.

Do not start Electron/Convex integration during Phase 2.

Do not treat listener/HLS mode as part of Phase 2.
