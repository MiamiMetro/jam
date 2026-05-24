# Native Jam Engine Phase 1 Plan

## Phase

Phase 1 is Native Audio Baseline.

The goal is stable standalone performer-to-performer jamming before product integration.

## Scope

Included:

- standalone local performer-to-performer jamming
- Opus `120` validation as production internet default candidate
- PCM validation as reference/LAN mode
- diagnostics for robotic/corrupt audio risk
- current jitter/playout behavior validation
- local server/client/probe workflow
- build and smoke commands for `server`, `client`, and `latency_probe`

Excluded:

- listener/HLS mode
- Electron launch integration
- Convex token minting
- signed join tokens
- permanent product rooms
- community server registration
- product presence
- account/auth UI

## Current Baseline

Known accepted state from prior work:

- `120` frames is the stable default.
- `120` Opus is accepted as the current production internet candidate.
- `120` PCM still works as a reference/LAN mode.
- `96` PCM works as Ultra/reference mode.
- `64` frames remains hidden/experimental because it can become robotic/corrupt.
- `32` frames is considered invalid/bad on the current setup.
- PCM and Opus send queues are moved out of the audio callback.
- Callback timing and audio health diagnostics exist.
- Power usage improved after removing sender busy-wait behavior.

Known open baseline gaps:

- macOS/CoreAudio has not been validated.
- Real ASIO-class Windows validation is blocked on the current machine because no ASIO device is visible.
- WASAPI opens, but backend latency is reported as unavailable/zero.
- Listener/HLS code exists, but is not part of this phase.
- Room/auth/product integration is intentionally paused.

## Done Criteria

Phase 1 is done when:

- `server` builds.
- `client` builds.
- `latency_probe` builds.
- standalone local two-client jamming works with Opus `120`.
- standalone local two-client jamming works with PCM `120`.
- standalone local two-client jamming works with PCM `96`.
- Opus `120` listening is clear, not robotic/corrupt.
- PCM `120` listening is clear, not robotic/corrupt.
- PCM `96` listening is clear, not robotic/corrupt.
- hidden/experimental `64` behavior remains documented and not promoted.
- diagnostics are captured for accepted Opus and PCM runs.
- no high-rate health warnings appear during accepted runs.
- no repeated Opus encode/decode failure stream appears during accepted Opus runs.
- no repeated rebuffering appears during accepted runs.
- local dev commands are documented in this plan.
- remaining blockers are explicitly documented instead of being treated as hidden work.

## Validation Commands

Build:

```powershell
cmake --build build --target server
cmake --build build --target client
cmake --build build --target latency_probe
```

List audio devices:

```powershell
.\build\Release\client.exe --list-audio-devices
```

Backend smoke:

```powershell
.\build\Release\client.exe --audio-open-smoke --require-api WASAPI --frames 120
.\build\Release\client.exe --audio-open-smoke --require-api WASAPI --frames 96
```

Current Windows ASIO check, expected to fail clearly unless a real ASIO device is visible:

```powershell
.\build\Release\client.exe --backend-check --require-api ASIO --frames 96
```

Local SFU:

```powershell
.\build\Release\server.exe --port 9999
```

Local Opus performer client:

```powershell
.\build\Release\client.exe --server 127.0.0.1 --port 9999 --codec opus --frames 120
```

Local PCM performer client:

```powershell
.\build\Release\client.exe --server 127.0.0.1 --port 9999 --codec pcm --frames 120
.\build\Release\client.exe --server 127.0.0.1 --port 9999 --codec pcm --frames 96
```

Automated probe examples:

```powershell
.\build\Release\latency_probe.exe --codec opus --frames 120 --jitter 6 --seconds 10
.\build\Release\latency_probe.exe --codec pcm --frames 120 --jitter 5 --seconds 10
.\build\Release\latency_probe.exe --codec pcm --frames 96 --jitter 6 --seconds 10
```

## Manual Listening Checks

For each accepted mode:

- run local `server.exe`
- run two local `client.exe` instances
- mute one side as needed to avoid feedback
- confirm live audio is clear
- confirm no robotic/corrupt character
- confirm no one-second-then-gone transfer failure
- confirm stereo output is not left-only
- observe diagnostics for queue, age, drops, underruns, and warnings

Manual listening result should be recorded in this file or in the current validation log.

## Diagnostic Capture

For accepted runs, capture or record:

- codec
- frames per buffer
- selected audio API
- selected input/output devices
- actual buffer size
- callback max and average timing
- queue current/average/max
- packet age average/max
- send queue age
- underruns and PLC
- queue drops and age drops
- PCM hold/drop rates for PCM runs
- Opus encode/decode failures for Opus runs
- user listening result

## Active Checklist

- [x] Confirm this spec/plan structure is accepted.
- [x] Reconcile this Phase 1 plan with `LOW_LATENCY_TODO.md` so there is no conflicting active next step.
- [x] Build `server`.
  - Result: `cmake --build build --target server` produced `build\Debug\server.exe`.
- [x] Build `client`.
  - Result: `cmake --build build --target client` produced `build\Debug\client.exe`.
- [x] Build `latency_probe`.
  - Result: `cmake --build build --target latency_probe` produced `build\Debug\latency_probe.exe`.
- [x] Run audio device inventory.
  - Result: RtAudio APIs visible are ASIO and WASAPI.
  - Result: ASIO default input/output are `0`; no ASIO devices are listed.
  - Result: WASAPI devices are visible, including DualSense microphone input and HyperX/Steam/NVIDIA outputs.
- [x] Run backend smoke for current Windows WASAPI.
  - Result: WASAPI `120` opened actual `120` frames / `2.500 ms`; backend latency reported unavailable/zero.
  - Result: WASAPI `96` opened actual `96` frames / `2.000 ms`; backend latency reported unavailable/zero.
- [x] Run or document ASIO/backend blocker.
  - Result: `--backend-check --require-api ASIO --frames 96` fails clearly because ASIO has no visible input/output device.
- [x] Run automated Opus `120` probe.
  - Invalid run: default jitter `3` reported `3` underruns/PLC in `10s`.
  - Result: jitter `6` passed with `0` underruns, `0` PLC, `0` encode/decode failures, latency `26.6042 ms`.
- [x] Run automated PCM `120` probe.
  - Invalid run: default jitter `3` reported `2` underruns in `10s`.
  - Result: jitter `5` passed with `0` underruns, `0` PLC, `0` decode failures, latency `25 ms`.
- [x] Run automated PCM `96` probe.
  - Invalid run: jitter `5` reported `3` underruns in `10s`.
  - Result: jitter `6` passed with `0` underruns, `0` PLC, `0` decode failures, latency `26 ms`.
- [x] Run manual two-client Opus `120` listening check.
  - Result: two visible local clients against `127.0.0.1:9999` sounded clear.
- [x] Run manual two-client PCM `120` listening check.
  - Result: two visible local clients against `127.0.0.1:9999` sounded clear.
- [x] Run manual two-client PCM `96` listening check.
  - Result: two visible local clients against `127.0.0.1:9999` sounded clear.
- [x] Capture diagnostics for accepted runs.
  - Opus `120` 60-second hidden two-client run captured in `validation_logs/phase1/opus120_a.out.log` and `validation_logs/phase1/opus120_b.out.log`.
  - Opus `120` result: no send drops, no underruns/PLC, no Opus encode/decode failures, no sequence gaps/late packets, no high-rate health warnings, no transfer stop.
  - Opus `120` packet age: mostly around `12-20 ms` during the captured run.
  - PCM `120` 60-second hidden two-client run captured in `validation_logs/phase1/pcm120_a.out.log` and `validation_logs/phase1/pcm120_b.out.log`.
  - PCM `120` result: no send drops, no sequence gaps/late packets, no high-rate health warnings, no transfer stop.
  - PCM `120` caveat: low nonzero underrun/PCM hold counters remain visible; user listening was clear.
  - PCM `96` 60-second hidden two-client run captured in `validation_logs/phase1/pcm96_a.out.log` and `validation_logs/phase1/pcm96_b.out.log`.
  - PCM `96` result: no send drops, no sequence gaps/late packets, no high-rate health warnings, no transfer stop.
  - PCM `96` caveat: nonzero underrun/PCM hold counters are higher than PCM `120`; manual listening result is still required for acceptance.
- [x] Document remaining Phase 1 blockers.
  - macOS/CoreAudio validation moved to `plans/native-jam-engine-phase-2.md`.
  - ASIO-class Windows validation is blocked because no ASIO input/output device is visible.
  - WASAPI opens at `120` and `96`, but RtAudio reports backend latency as unavailable/zero.
  - PCM `96` is clear by listening but shows more internal smoothing pressure than PCM `120`.
  - Listener/HLS, native room/auth, and Electron/Convex integration remain intentionally out of Phase 1.

## Completion Rule

Do not start native room/auth work until Phase 1 is closed or explicitly paused with blockers documented.

Do not start Electron/Convex integration during Phase 1.

Do not treat listener/HLS mode as part of Phase 1.
