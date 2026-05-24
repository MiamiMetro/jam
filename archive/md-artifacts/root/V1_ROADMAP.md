# Native Jam V1 Roadmap

Status: not merge-ready.

This roadmap defines the native client/server work required before the V1 branch
can be considered for merge. The target is not a demo checklist. The target is a
competitive, independently usable native jam session with reliable audio,
predictable timing, and no stale session behavior.

Gate 1, Gate 2, Gate 7, Convex-backed presence, moderation, Electron UI
migration, and dockable modular UI work are not part of this pass. They should
not be used to justify shortcuts in the native audio path.

## Current Branch State

- The first native feature pass is implemented and manually tested:
  shared metronome controls, tap tempo, and local multitrack recording.
- Gate 1 hardening was implemented, then reverted so this pass can stay focused
  on native V1 features and the known participant/session bug.
- Main is clean in the same Windows/Mac test setup.
- V1 after the Gate 1 revert has clean audio again in the same test setup.
- This branch still needs a professional timing model and a known participant
  lifecycle bug fix before merge.

## Known Critical Bug

During cross-platform testing with one Windows client, one Mac client, and a
Windows-hosted SFU, stale participant state produced phantom users and duplicated
audio. This was a known bug before the Gate 1 attempt; hardening must remain out
of this pass until the native lifecycle behavior is correct.

Observed behavior:

- The room showed phantom participants such as `User #0`.
- User count increased beyond the two active clients.
- Voice was multiplied or doubled, making the session unusable.
- Restarting clients without a full cleanup could leave stale server/client
  state visible in the room.
- A full cleanup and the Gate 1 revert restored clean audio in the same
  environment, but the underlying participant lifecycle issue still needs a
  direct fix and regression coverage.

Likely fault area:

- SFU participant lifecycle handling.
- Duplicate endpoint or duplicate user handling.
- Stale endpoint cleanup.
- Capacity/rate-limit integration with join, leave, and timeout paths.
- Forwarding from participant records that should have been removed.

Required response:

- The server must have tests for join, reconnect, duplicate launch, leave, room
  cleanup, and audio forwarding after cleanup.
- No native lifecycle change is acceptable if it can create phantom participants
  or duplicate live audio paths.

## V1 Quality Bar

V1 must satisfy these conditions before merge:

- Two native clients on separate machines can join a room and hear clean
  bidirectional audio.
- Reconnects do not create phantom participants, stale strips, or duplicated
  voice.
- Wi-Fi jitter is tolerated without making the session unusable.
- Metronome timing is based on shared musical time, not packet arrival time.
- Remote voice buffering and metronome scheduling are treated as separate
  systems.
- Local recording works without blocking or destabilizing the audio callback.
- The branch has focused validation for the behaviors above.

## Workstream 1: Shared Musical-Time Metronome

The current metronome is a useful prototype, but it is not the final V1 timing
model. It relays BPM/running/beat state and resets the receiver when a packet
arrives. That is not competitive enough for jamming.

Required V1 behavior:

- The room has one authoritative metronome state.
- Start, stop, BPM, and beat changes are versioned.
- Start and BPM-change events are scheduled for a future shared time.
- Clients estimate server clock offset instead of treating packet arrival as
  musical time.
- Each client generates the click locally from the shared timeline.
- The audio callback computes click position from timeline time and sample
  rate, not from an unsynchronized reset.
- Small drift is corrected gradually; large drift is corrected at a musical
  boundary.
- Metronome timing is measured and logged during cross-machine tests.

Acceptance:

- Starting the metronome on one client starts both clients on the same scheduled
  beat.
- BPM changes occur at a predictable beat or bar boundary.
- The click remains stable when RTT spikes.
- Reducing the voice jitter buffer must not be required for the metronome to
  feel accurate.

## Workstream 2: Tap Tempo

Tap tempo should feed the shared musical-time metronome, not only update local
state and broadcast a new BPM immediately.

Required V1 behavior:

- Tap tempo computes BPM from recent taps with pause reset.
- Tap-derived BPM changes are sent as metronome commands.
- The accepted BPM change is scheduled against the shared timeline.
- Conflicting updates use sequence/version rules so clients converge.

Acceptance:

- Tapping on either client updates the room metronome consistently.
- The remote client does not jump mid-buffer or reset at packet arrival time.
- Rapid taps or repeated updates do not create divergent BPM state.

## Workstream 3: Local Multitrack Recording

The current implementation is directionally correct and should be hardened
rather than redesigned.

Required V1 behavior:

- Record local mic, each remote participant, and the master mix as separate WAV
  files.
- Use one timestamped folder per recording session.
- Keep disk I/O outside the audio callback.
- Bound callback-to-writer queues and expose dropped recording blocks.
- Patch WAV headers correctly on stop and on client shutdown.
- Preserve enough metadata to understand which participant produced each track.

Acceptance:

- Start/stop recording works while audio is active.
- Files are playable after normal stop.
- Files are still finalized on client shutdown where practical.
- Recording does not increase callback underruns or audible artifacts.

## Workstream 4: Participant Lifecycle Correctness

Participant identity and endpoint cleanup must be correct before any production
hardening work returns.

Required V1 behavior:

- Rejoining the same profile in the same room from a new UDP endpoint removes
  the stale endpoint immediately.
- Re-sending JOIN from the same endpoint preserves the participant identity.
- Audio from stale endpoints is not forwarded.
- Remaining room members receive leave metadata for removed stale participants.
- Audio forwarding after cleanup reaches each live participant exactly once.

Acceptance:

- Reconnect and duplicate-launch tests do not produce phantom participants.
- No duplicate audio forwarding after stale endpoint cleanup.
- Room routing remains isolated.

## Merge Criteria

The V1 branch is mergeable only after:

- The known phantom participant / duplicate voice bug is fixed and covered by
  tests.
- Shared metronome is upgraded to a shared-time scheduling model.
- Tap tempo updates use the shared-time model.
- Recording passes local and cross-machine smoke tests.
- Windows/Mac cross-machine testing passes on Ethernet or documented Wi-Fi
  conditions.
- No known bug can multiply voice, leak stale users, or leave participants in a
  room after cleanup.
