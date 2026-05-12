# V1 Roadmap

This is the current launch roadmap. It combines the focused feature list with
the production gates that still matter for V1.

## Product Features

### Shared Metronome

- Shared BPM, start/stop state, beat number, and sync timestamp.
- Local click generation on each client.
- Simple room-level controls and beat indicator.

### Tap Tempo

- Tap button in the metronome UI.
- Recent-tap averaging with reset after pauses.
- Sets the shared metronome BPM.

### Local Multitrack Recording

- Separate WAV tracks for local mic, each remote participant, and master mix.
- Timestamped recording folder.
- Disk writer thread or equivalent non-audio-callback writer path.

### Dockable Modular UI

- Dockable layout after the core workflow is stable.
- Modules for mixer, master/self, metronome, recording, backing track, and
  settings.
- Simple default layout with advanced rearrangement available.

## Production Gates

### Gate 1: SFU Production Hardening

- Rate limits, capacity limits, abuse-safe logs, metrics, process supervision,
  health checks, firewall rules, and UDP abuse protection.

### Gate 2: SFU-Authoritative Presence And Capacity

- SFU heartbeat, room/performer counts, join/leave/stale events, backend live
  room state, SFU-backed `maxPerformers`, and full-room token refusal.

### Gate 7: Room Lifecycle, Rules, And Moderation

- Inactivity cleanup, global/community room rules, private room rules, host
  controls, moderation controls if needed, duplicate launch behavior, and stale
  session cleanup.

## Intended Order

1. Shared metronome.
2. Tap tempo.
3. Local multitrack recording.
4. Gate 1: SFU production hardening.
5. Gate 2: SFU-authoritative presence and capacity.
6. Gate 7: room lifecycle, rules, and moderation.
7. Dockable modular UI.
