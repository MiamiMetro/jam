# Feature Roadmap — Competitive Jamming Client

## Current State (what we have)

### UI / Controls
- Master strip: fader, level meter, mic mute
- Per-participant strip: fader, level meter, pan knob, mute
- Per-participant stats: queue size, underruns, PLC count, buffering indicator
- Device selection: API selector, input/output device combos, start/stop/apply
- WAV playback: load, play/pause, seek, volume, mute local
- Status bar: server address, RTT, user count, RX/TX bytes, connection status, FPS
- Latency info: API name, input/output latency, sample rate
- Custom widgets: UvMeter, Knob, Fader, ToggleButton, zynlab theme

### Audio / Network
- Opus encode/decode (RESTRICTED_LOWDELAY, SIGNAL_MUSIC)
- Raw UDP with custom protocol (PING/CTRL/AUDIO)
- SFU server (dumb packet forwarder)
- PortAudio with API selector
- Ping/RTT measurement
- Participant auto-discovery
- PLC (packet loss concealment)
- Adaptive jitter buffer (needs fixes, see LATENCY_FINDINGS.md)

---

## Missing Features

### Tier 1: Required for Phase 2 (after latency fixes)

**Preset Selector**
- Dropdown or radio buttons: Studio / LAN / Balanced / Safe / Advanced
- Controls: buffer_size, codec_mode, jitter_buffer_packets
- Switching restarts audio stream, does NOT reconnect to server
- Location: bottom bar next to device selectors

**Buffer Size Selector**
- Available in Advanced mode or tied to preset
- Options: 64, 128, 256, 512 samples
- Must validate against selected audio API (ASIO can do 64, WASAPI Exclusive 128+, MME 512+)
- Show actual latency in ms next to each option

**Codec Mode Selector**
- Opus / Uncompressed toggle (Advanced mode)
- Tied to presets in normal mode
- Requires codec byte in AudioHdr (see LATENCY_FINDINGS.md)

**Jitter Buffer Control**
- Slider: 0-5 packets (Advanced mode)
- Tied to presets in normal mode
- Show equivalent ms next to value

**Connection Quality Indicator**
- Green / Yellow / Red based on: RTT, packet loss %, jitter variance
- Replace or supplement the raw "RTT: X ms" text
- Yellow threshold: >30ms RTT or >2% loss
- Red threshold: >60ms RTT or >5% loss

### Tier 2: Expected in a Competitive Jamming App

**Solo Button (per participant)**
- Standard mixer feature: solo mutes all OTHER participants
- Multiple solos allowed (solo A + B = hear only A and B)
- Visual: button on each participant strip, next to mute
- Implementation: flag per participant, audio callback checks solo state

**Monitor Toggle (self-monitoring)**
- Hear your own audio through output (with latency) or not
- Important for musicians without hardware monitoring
- Toggle in master strip
- Implementation: mix own mic input into output buffer (already partially there via the callback)

**Shared Metronome**
- One person sets BPM and starts it
- Server broadcasts sync message: `{ beat_number, timestamp, bpm }`
- Each client generates click locally, aligned to sync timestamp
- UI: BPM control (tap tempo or input), start/stop, visual beat indicator (1-2-3-4)
- Click sound generated locally (sine beep or sample), not sent over network
- Protocol: new CTRL command `METRONOME_SYNC`

**Participant Names**
- Currently shows "User #ID"
- When Electron integration: pass display name via launch args
- Protocol: include name in JOIN message or separate NAME ctrl command
- Max length ~32 chars

**Local Multitrack Recording**
- Record button in top bar or master strip
- Each participant's decoded PCM written to separate WAV file
- Own mic input also written to separate WAV
- Creates folder: `recording_YYYY-MM-DD_HH-MM-SS/`
  - `master_mix.wav`
  - `self.wav`
  - `user_123.wav`
  - `user_456.wav`
- Musicians can mix/master after the session
- Implementation: ring buffer per participant drained to disk writer thread
- Killer feature -- most jamming apps don't do this well

### Tier 3: Polish / Nice to Have

**Master Limiter Indicator**
- Visual clip warning when output exceeds 0dBFS
- Red flash on master strip
- Already have the data (output buffer values in callback)

**Tap Tempo**
- Button in metronome section
- Tap 4+ times, average the intervals, set BPM
- Standard musician UX

**Input Level Test**
- "Test" button that plays back your own mic with ~50ms delay
- For users to verify their setup before joining a session
- Disable during active session

**Waveform / Spectrogram**
- Small waveform display per participant
- Helps identify who's making noise
- Performance cost: FFT per participant per frame -- only enable if CPU allows

**Dockable Modular UI**
- Enable `ImGuiConfigFlags_DockingEnable`
- Separate windows: Mixer, Master/Self, Metronome, Settings, Backing Track, Recording
- All dockable within app window, drag-outable to separate OS windows
- Default layout docks everything together (works in small windows)
- Users with big screens / multiple monitors can rearrange freely
- Standard in professional audio apps (Reaper, Ableton, FL Studio)

**Keyboard Shortcuts**
- M: toggle own mute
- 1-9: toggle mute for participant 1-9
- Space: start/stop metronome
- R: start/stop recording

---

## Protocol Additions Needed

| Feature | Protocol Change |
|---------|----------------|
| Codec mode | Add `uint8_t codec` to `AudioHdr` |
| Participant names | Add name field to JOIN or new `NAME` ctrl command |
| Shared metronome | New `METRONOME_SYNC` ctrl command with bpm + beat + timestamp |
| Room support | Add `room_id` to JOIN, new `JOIN_ROOM` command |

These are all backward-compatible additions (new fields / new command types).

---

## Implementation Order

1. Latency fixes first (see LATENCY_FINDINGS.md Phase 1-3)
2. Preset selector + buffer size + codec mode (comes naturally with Phase 2 fixes)
3. Connection quality indicator
4. Solo button + monitor toggle
5. Shared metronome
6. Participant names (when Electron integration happens)
7. Local multitrack recording
8. Polish (limiter indicator, tap tempo, shortcuts, waveform)
