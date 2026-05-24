# V1 Implementation Checklist

Status: not merge-ready.

This checklist tracks the native V1 work in the current pass. Gate 1 hardening
is intentionally out of scope until the native participant lifecycle and timing
model are correct. Checked items indicate implemented prototype behavior or
validated current behavior; they do not imply production readiness unless the
acceptance item is also checked.

## 1. Shared Musical-Time Metronome

Current prototype:

- [x] Add a room-scoped metronome CTRL packet with BPM, beat number, running
  state, and sender timestamp.
- [x] Relay metronome CTRL packets through the SFU only to clients in the same
  room, excluding the sender.
- [x] Generate the click locally in the audio callback.
- [x] Add UI controls for BPM, start/stop, tap, current beat, and sync counters.
- [x] Manual Windows/Mac smoke test confirms start/stop and BPM propagation.

Required before merge:

- [x] Replace packet-arrival reset behavior with shared-time scheduling.
- [ ] Add room-level authoritative metronome state for late joiners.
- [x] Add server-stamped metronome sequence/version.
- [x] Schedule start/stop/BPM changes for future shared time.
- [x] Estimate server clock offset on each client.
- [x] Generate click phase from shared timeline inside the audio callback.
- [ ] Add drift correction that slews small errors and realigns large errors at
  musical boundaries.
- [ ] Add cross-machine timing logs or a probe that measures metronome alignment.

Acceptance:

- [ ] Starting from either client schedules both clients on the same beat.
- [ ] BPM changes occur at deterministic beat or bar boundaries.
- [ ] RTT spikes do not move the click by packet arrival time.
- [ ] Voice jitter buffer changes do not control metronome accuracy.

## 2. Tap Tempo

Current prototype:

- [x] Add a tap button in the metronome UI.
- [x] Keep recent tap intervals and reset after a long pause.
- [x] Calculate BPM from averaged tap intervals after enough taps.
- [x] Clamp tap-derived BPM to the supported range.
- [x] Manual Windows/Mac smoke test confirms tap updates propagate.

Required before merge:

- [x] Route tap-derived BPM through the metronome command path.
- [x] Apply accepted tap tempo changes at scheduled shared time.
- [x] Add version/sequence handling for competing BPM updates.

Acceptance:

- [ ] Tapping on either client produces one converged BPM for the room.
- [ ] Remote clients do not reset click phase when the tap packet arrives.
- [ ] Fast repeated taps do not leave clients in divergent BPM state.

## 3. Local Multitrack Recording

Current implementation:

- [x] Add recording start/stop controls and visible recording state.
- [x] Create one timestamped folder per session.
- [x] Write `master_mix.wav`, `self.wav`, and `user_<id>.wav` files.
- [x] Keep disk I/O off the audio callback using a queue and writer thread.
- [x] Patch WAV headers when recording stops.
- [x] Stop and close files when audio stops or the client exits.
- [x] Add `recording_writer_self_test`.
- [x] Manual Windows/Mac smoke test confirms recording workflow works.

Required before merge:

- [x] Expose or log dropped recording blocks.
- [x] Preserve participant metadata for remote tracks.
- [ ] Verify recording during active metronome and two-way voice.
- [ ] Verify shutdown finalization behavior.

Acceptance:

- [x] Track files are valid WAV files after normal stop.
- [ ] Recording does not add audible artifacts or callback underruns.
- [ ] Recording remains usable when remote participants join/leave.

## 4. Participant Lifecycle Correctness

Current status:

- [x] Original Gate 1 hardening implementation was reverted.
- [x] Revert kept this pass focused on native V1 features.
- [x] Known phantom participant / duplicate voice bug documented in
  `V1_ROADMAP.md`.

Bug to prevent:

- Phantom participant strip such as `User #0`.
- User count higher than the number of live clients.
- Voice multiplication or duplicated forwarding.
- Stale room state after reconnect or relaunch.

Required before merge:

- [x] Remove stale same-room/same-profile endpoints immediately on rejoin from a
  new UDP endpoint.
- [x] Preserve participant identity on same-endpoint JOIN retry.
- [x] Broadcast leave metadata for removed stale participants.
- [x] Add an audio forwarding regression test proving each live participant
  receives one copy of each remote audio packet.

Acceptance:

- [ ] No phantom participants after reconnect or relaunch.
- [x] No duplicate audio forwarding after stale endpoint cleanup.
- [x] Room isolation probe still passes.

## 5. Cross-Machine Validation

- [x] Main branch is clean in the Windows server plus Windows/Mac client setup.
- [x] V1 after Gate 1 revert has clean audio in the same setup.
- [ ] Run V1 after metronome timing rewrite.
- [ ] Run V1 after participant lifecycle fix.
- [ ] Record RTT, jitter buffer setting, Wi-Fi/Ethernet condition, and observed
  voice quality for each test.

## Out Of This V1 Branch

- Gate 2: SFU-authoritative Convex presence and capacity.
- Gate 7: lifecycle rules, moderation, host controls, and community/private
  room policy.
- Gate 1: SFU production hardening.
- Electron UI migration.
- Dockable modular UI.
