# Feature Roadmap

This file tracks the V1 feature priorities only. Older latency, codec, and
diagnostic work has moved into the Opus completion docs.

## V1 Features

### Shared Metronome

- Shared BPM for everyone in the room.
- Start/stop controlled by the room session.
- Clients generate the click locally instead of streaming click audio.
- Sync data should include BPM, beat number, and a timestamp.
- UI needs BPM entry, start/stop, and a simple beat indicator.

### Tap Tempo

- Tap button in the metronome UI.
- Use several recent taps to estimate BPM.
- Feed the calculated BPM into the shared metronome controls.
- Reset the tap window after a pause.

### Local Multitrack Recording

- Record the local mic, each remote participant, and the master mix.
- Write separate WAV files per source.
- Create one timestamped folder per recording session.
- Keep disk writing off the audio callback.
- Recording state should be visible and hard to trigger accidentally.

### Dockable Modular UI

- Enable a dockable UI layout after the core music workflow is stable.
- Separate modules should include mixer, master/self controls, metronome,
  recording, backing track, and settings.
- Default layout should remain simple for small screens.
- Advanced users should be able to rearrange modules for large or multi-monitor
  setups.

## Intended Order

1. Shared metronome.
2. Tap tempo.
3. Local multitrack recording.
4. Dockable modular UI.
