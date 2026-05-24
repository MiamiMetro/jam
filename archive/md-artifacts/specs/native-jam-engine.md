# Native Jam Engine Spec

## Purpose

The native jam engine is the standalone low-latency performer-to-performer audio subsystem.

Its job is to prove that real-time jamming can be clear, stable, and low-latency before the system is attached to Electron, Convex, product rooms, auth UI, listener mode, or community-server product flows.

## Primary Product Path

The primary path is native performer jamming:

- performer captures live audio locally
- native client sends audio to the SFU
- SFU forwards audio to other performers in the same live jam context
- native client receives, buffers, mixes, and plays remote performer audio

Listener/HLS mode is not part of this spec's first acceptance gate. It becomes an addition after performer jamming is fully proven.

## Boundaries

This native engine owns:

- audio capture and playback
- low-latency callback behavior
- Opus and PCM transport modes
- UDP packet format and forwarding compatibility
- SFU routing behavior needed for native jamming
- jitter buffering and playout behavior
- device/backend diagnostics
- standalone local development flow
- latency and corruption validation probes

This native engine does not own yet:

- Electron launch integration
- Convex token minting
- product account authentication
- product room creation and discovery
- permanent room ownership rules
- community server registration
- listener/HLS product experience
- chat, social presence, or mobile social features

## Accepted Audio Modes

Opus at `120` frames is the production internet default candidate.

PCM remains the reference, LAN, and studio mode. PCM is useful because it proves the native client, backend, jitter, and playout path without codec bandwidth tradeoffs.

`96` PCM remains an Ultra/reference mode if it stays clear and diagnostics remain acceptable.

`64` frames and lower are not normal product modes. They remain experimental or invalid unless they become clear in both manual listening and automated diagnostics.

Low latency is not acceptable if it produces robotic, corrupt, unstable, or fatiguing audio.

## Platform Targets

Windows and macOS are both first-class targets.

macOS/CoreAudio is not secondary. The engine should not be considered ready for product integration until macOS behavior is validated.

Windows validation should include the available cross-platform backend path and, where possible, real low-latency device/API validation.

## Diagnostics And Validation Principles

The engine must expose audio risk instead of hiding it.

Important diagnostics include:

- actual frames per buffer
- selected API/backend and devices
- callback timing
- send queue age
- jitter queue depth
- packet age
- underruns and PLC events
- queue drops and age drops
- PCM hold/drop counters
- Opus encode/decode failures
- packet loss, sequence gaps, and late packets

Manual listening remains a release gate. Automated tests can catch regressions and corruption proxies, but they cannot fully replace hearing whether the result is playable for jamming.

## Product Integration Gate

Electron and Convex integration stay paused until the native performer jam engine reaches the standalone acceptance gate.

The acceptance gate requires:

- local two-client performer jamming is clear and stable
- local multi-client performer jamming is clear enough to continue
- Opus `120` is validated as the bandwidth-realistic default candidate
- PCM remains available as a reference/LAN mode
- unsafe low-buffer modes are hidden or explicitly experimental
- robotic/corrupt audio has visible diagnostic signals
- Windows validation is documented
- macOS/CoreAudio validation is documented
- basic standalone server/client/probe workflows are documented
- future room/auth work can build on a stable native foundation

## Later Product Additions

After performer jamming is fully proven, the later order is:

1. Cross-platform performer validation.
2. Native room/auth contract for performers.
3. Electron/Convex performer integration.
4. Listener/HLS mode as an addition.
5. Official and community server productization.

Existing listener/HLS code should not be intentionally broken, but it is not part of the native performer-jamming acceptance gate.

