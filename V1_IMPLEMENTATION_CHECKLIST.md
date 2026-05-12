# V1 Implementation Checklist

This checklist tracks the first implementation block: native-only music workflow
features before production gates or Convex-backed work.

## Order

1. Shared metronome.
2. Tap tempo.
3. Local multitrack recording.
4. Gate 1: SFU production hardening.
5. Gate 2: SFU-authoritative presence and capacity.
6. Gate 7: room lifecycle, rules, and moderation.
7. Dockable modular UI.

## 1. Shared Metronome

- [x] Add a room-scoped metronome CTRL packet with BPM, beat number, running
  state, and sender timestamp.
- [x] Relay metronome CTRL packets through the SFU only to clients in the same
  room, excluding the sender.
- [x] Store client metronome state in atomics usable by the audio callback.
- [x] Generate the click locally in the audio callback instead of streaming click
  audio over the network.
- [x] Use a distinct downbeat click so a 4-beat bar is clear.
- [x] Add UI controls for BPM, start/stop, and current beat.
- [x] Log or expose sent/received sync counters for debugging.

Acceptance:

- [x] Starting/stopping or changing BPM on one client updates the other clients
  in the same room.
- [x] The metronome click works without microphone input and does not require
  audio packets from another client.
- [x] Metronome state does not touch Convex or Electron state.

## 2. Tap Tempo

- [x] Add a tap button in the metronome UI.
- [x] Keep recent tap intervals only; reset after a long pause.
- [x] Calculate BPM from averaged tap intervals after enough taps.
- [x] Clamp tap-derived BPM to the supported metronome range.
- [x] Feed tap-derived BPM into the shared metronome state and sync packet.

Acceptance:

- [x] Four or more steady taps produce a usable BPM.
- [x] Tapping can update BPM before or during a running metronome.
- [x] The tap window resets cleanly after a pause.

## 3. Local Multitrack Recording

- [x] Add recording start/stop controls and visible recording state.
- [x] Create one timestamped folder per session.
- [x] Write `master_mix.wav`, `self.wav`, and `user_<id>.wav` files.
- [x] Keep disk I/O off the audio callback using a queue and writer thread.
- [x] Enqueue bounded fixed-size blocks from the callback.
- [x] Patch WAV headers when recording stops.
- [x] Stop and close files cleanly when audio stops or the client exits.

Acceptance:

- [x] Start/stop works while audio is running.
- [x] Track files are created for sources that produce audio during the session.
- [x] Stopped recordings are valid WAV files.
- [x] Recording state and output folder are visible in the client UI.

## 4. Gate 1: SFU Production Hardening

- [x] Keep handling for unknown UDP endpoints bounded.
- [x] Throttle logs for unauthorized/unjoined audio packets.
- [x] Add per-IP packet and byte rate limits.
- [x] Add per-room packet rate limits.
- [x] Add per-participant packet rate limits.
- [x] Add server capacity limits.
- [x] Add max active room limits.
- [x] Enforce max performers per room at the SFU.
- [x] Track malformed packet, unauthorized drop, rate-limit drop, capacity
  reject, join, RX, and TX counters.
- [x] Keep token values out of abuse/reject logs.
- [x] Add periodic SFU metrics logging.
- [x] Add a focused hardening probe for SFU room capacity rejection.
- [x] Keep Gate 1 implementation native-only in `udpstuff`.

Acceptance:

- [x] Server builds with hardening controls enabled.
- [x] Existing room routing behavior still passes.
- [x] A performer rejected by the room-capacity limit cannot send audio into
  the room.
- [x] No Convex or Electron changes are required for Gate 1.

## Deferred Gates

### Gate 2: SFU-Authoritative Presence And Capacity

- [ ] Deferred. This will touch `jam-app`/Convex later, but it is out of scope
  for the current Gate 1-only slice.

### Gate 7: Room Lifecycle, Rules, And Moderation

- [ ] Deferred until after Gate 2, because these rules depend on reliable
  SFU-authoritative room state.
