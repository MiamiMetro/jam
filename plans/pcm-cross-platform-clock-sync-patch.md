# PCM Cross-Platform Clock Sync Patch Plan

Date: 2026-04-29

## Goal

Make raw PCM usable between Windows and macOS without making same-platform PCM worse.

This patch exists because same-platform PCM works, but cross-machine Windows/macOS PCM is robotic/corrupt. The tracked diagnosis is `specs/pcm-cross-platform-clock-sync.md`.

## Assumptions

- UDP/SFU routing is not the root cause because Opus works over the same path.
- Callback-size mismatch is only part of the problem.
- Independent device-clock drift is the likely remaining problem.
- Opus `120` remains the production internet default.
- PCM remains LAN/reference mode only if this patch succeeds.

## Non-Goals

- Do not change Opus behavior.
- Do not change the SFU protocol.
- Do not add Electron/Convex work.
- Do not make PCM the default internet mode.
- Do not copy JackTrip `Regulator` wholesale.

## Implementation Steps

- [x] Choose the smallest proven resampler dependency that builds on Windows and macOS.
  - Decision: use `libsamplerate` first.
  - Reason: JackTrip already uses it, it has a CMake target, and it supports time-varying conversion ratios.
  - First converter mode: `SRC_LINEAR` to minimize algorithmic delay for clock-drift correction.
- [x] Add a tiny wrapper, tentatively `PcmClockResampler`.
  - Owns the library state.
  - Accepts mono float PCM input.
  - Produces exactly the local callback frame count when enough samples are available.
  - Supports slow ratio updates around 1.0 for drift correction.
- [x] Replace current PCM whole-packet drift insert/drop behavior in the normal path.
  - Keep underrun silence/one-shot concealment as fallback.
  - Keep malformed packet rejection.
- [x] Add per-participant PCM stats.
  - buffered frames
  - estimated correction ratio or ppm
  - underruns
  - overruns
  - malformed packets
- [ ] Validate locally on Windows first.
  - [x] `client` builds.
  - [x] `server` builds.
  - [x] `latency_probe` builds.
  - [x] `room_routing_probe` builds.
  - [x] Automated local PCM probe runs without encode/decode failures.
    - `--jitter 5` had `2` underruns in one 5-second run, so it is not enough proof.
    - `--jitter 6` ran clean for 5 seconds with `0` underruns and `0` decode failures.
  - [ ] Windows-to-Windows PCM still works.
- [x] Opus still works.
    - `latency_probe --codec opus --frames 120 --seconds 5 --jitter 6` ran with `0` underruns, `0` PLC, and `0` decode failures.
- [x] Remove insufficient synthetic probes.
  - Removed `pcm_clock_resampler_probe`.
  - Removed `pcm_client_playout_probe`.
  - Reason: they did not exercise the real RtAudio/CoreAudio/WASAPI client path and could create false confidence.
- [ ] Validate with user cross-machine.
  - [x] Windows to macOS PCM audible and clear after first resampler patch.
  - [ ] macOS to Windows PCM audible and clear.
    - Result: still robotic after first resampler patch.
    - Follow-up fix: resampler now generates only the requested callback frames and measures total buffered input+output frames, instead of draining the input side into a large output buffer.
  - macOS to macOS PCM remains low-latency.

## Acceptance Rule

Do not accept a patch that only reduces the symptom by adding a large fixed buffer.

The accepted patch must show stable buffer/correction diagnostics and preserve low latency as much as possible.

## Rollback Rule

If the resampler patch makes same-platform PCM worse or increases latency too much, keep Opus as the cross-platform mode and demote PCM to same-device/same-platform diagnostic mode until a stronger audio clock design is implemented.
