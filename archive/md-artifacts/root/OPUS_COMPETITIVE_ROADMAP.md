# Opus Competitive Jamming Roadmap

Date: 2026-04-30

Status: local implementation gates complete; external promotion validation
still required.

Executable checklist: `OPUS_COMPETITIVE_IMPLEMENTATION_CHECKLIST.md`.

This file exists because the project should not move by guesses. Every product
or engine direction below is tied to one of:

- competitor source or documentation in `.cache/upstream-audio`
- public competitor documentation
- observed behavior from our own Windows/macOS tests
- an explicitly marked unknown that still needs verification

## Completion Boundary

All roadmap gates below have local implementation coverage in this branch. The
remaining work is not unchecked implementation TODOs in this file; it is
external promotion evidence that must be collected on the real Windows/macOS
setup before the branch can be called competitive or promoted to `main`.

Truthful status:

- Local implementation gates: complete.
- Local build, harness, smoke, proxy, and documentation checks: complete.
- External Windows/macOS proof: required before product-ready claims.
- Cross-machine PCM: still deferred research, not an Opus MVP blocker.

## Current Decision

Opus is the primary cross-platform and internet jamming path for now.

PCM remains important as a future premium LAN/studio path, but it is not the
blocking MVP path until cross-machine behavior is understood. Local same-machine
PCM can sound excellent, especially on macOS/CoreAudio, but cross-machine PCM has
shown robotic/corrupt behavior in our testing.

## Competitor Evidence

Public docs verified on 2026-05-12:

- SonoBus public guide still describes per-user manual/automatic receive jitter
  buffers, Initial Auto behavior, Wi-Fi sensitivity, and Opus `120` sample
  minimum frame-size latency.
- Jamulus public manual still describes jitter buffer sizing as an
  audio-quality versus delay tradeoff, exposes local and server jitter buffer
  controls, and says Auto is based on network and sound-card timing jitter
  measurements.
- JackTrip public bridge/studio docs still describe Net Queue as the receive
  network jitter buffer, defaulting to Auto, and warn that lower buffer sizes
  reduce latency while demanding more from the network and hardware.

These public-doc checks agree with the cached source/docs evidence below; they
do not replace the required external Windows/macOS validation for our own app.

### SonoBus

Sources:

- `.cache/upstream-audio/sonobus/doc/SonoBus User Guide.md`
- `.cache/upstream-audio/sonobus/Source/SonobusPluginProcessor.cpp`
- `.cache/upstream-audio/sonobus/deps/aoo/doku/aoo_protocol.rst`
- Public guide: https://www.sonobus.net/sonobus_userguide.html

Evidence:

- SonoBus exposes latency control on a per-user basis.
- It documents that each participant can need a different receive jitter buffer.
- It defaults participants into automatic jitter behavior.
- It increases buffer when drops happen and decreases it after stable periods.
- It has an "Initial Auto" mode that starts low, grows until stable, then stops
  adapting unless reset.
- Its AOO protocol notes that automatic buffering should use the shortest
  possible buffer, dynamically extend when packets arrive late, then slowly
  reduce.
- AOO also includes timing/sample-rate synchronization and resampling concepts,
  which is relevant to the future PCM path.
- SonoBus documents Opus/compressed formats as adding codec delay and having a
  minimum frame size of `120` samples, while PCM can use smaller buffers.
- SonoBus strongly recommends Ethernet because Wi-Fi adds jitter and requires
  increased buffer sizes.

Implication for us:

- A single global receive jitter value is not competitive as a final design.
- Manual jitter is useful for testing, but the competitive direction is
  per-participant receive jitter with visible auto/manual behavior.
- Wi-Fi instability is a real expected condition, not a rare edge case.

### Jamulus

Sources:

- `.cache/upstream-audio/jamulus/docs/JAMULUS_PROTOCOL.md`
- `.cache/upstream-audio/jamulus/src/clientsettingsdlg.cpp`
- `.cache/upstream-audio/jamulus/src/channel.cpp`
- `.cache/upstream-audio/jamulus/src/buffer.h`
- `.cache/upstream-audio/jamulus/src/buffer.cpp`
- Public manual: https://jamulus.io/wiki/Software-Manual

Evidence:

- Jamulus exposes jitter buffer controls for both the local client and the
  remote server.
- Its manual says jitter buffer size is a quality-versus-delay tradeoff.
- Its Auto mode is measurement-driven over the live network jitter buffer
  (sound-card buffer size affects the latency display; not directly confirmed
  as an Auto-decision input).
- Its protocol includes messages for requesting and setting jitter buffer size.
- Its `CNetBufWithStats` runs multiple simulation buffers with different depths,
  tracks error rates, and chooses an auto setting through filtering and
  hysteresis.
- It avoids treating small buffer modes as free wins; lower buffers increase
  dropout risk.

Implication for us:

- Competitive auto jitter should be measurement-driven, not a few hardcoded
  if-statements.
- Diagnostics need to distinguish network jitter, audio callback pressure, and
  bandwidth/CPU problems.
- The user-facing control should clearly show the latency/quality tradeoff.

### JackTrip

Sources:

- `.cache/upstream-audio/jacktrip/docs/Documentation/NetworkProtocol.md`
- `.cache/upstream-audio/jacktrip/src/JackTrip.cpp`
- `.cache/upstream-audio/jacktrip/src/JitterBuffer.cpp`
- `.cache/upstream-audio/jacktrip/src/Regulator.cpp`
- `.cache/upstream-audio/jacktrip/src/gui/qjacktrip.ui`
- Public bridge docs: https://support.jacktrip.com/managing-jacktrip-bridges

Evidence:

- JackTrip exposes a network queue size for the receive jitter buffer.
- It supports auto queue behavior.
- It has multiple buffer strategies, including stable-latency and
  adaptable-latency behavior.
- It has optional UDP redundancy to reduce audible artifacts from packet loss.
- Its changelog and source include packet-loss concealment, auto headroom, and
  fixes for mismatched buffer sizes.
- Its public bridge docs say smaller buffer sizes reduce latency but demand more
  from the connection, while Net Queue defaults to auto.

Implication for us:

- A professional implementation is not only "lower the buffer." It is receive
  queue strategy, packet-loss handling, diagnostics, and UX.
- Redundancy/FEC may be a later option if real loss is the dominant problem, but
  it should not be added before we prove the failure mode.

## Our Observed Baseline

Observed from our testing:

- Opus `120` works locally and across the same path where PCM has failed.
- macOS local two-client PCM feels excellent and low latency.
- Windows local two-client PCM is acceptable.
- Cross-machine Windows/macOS PCM has been robotic/corrupt in both directions.
- Local same-device Opus can sound clear even with manual jitter target `0`, but
  stats still show underruns/PLC/drop counters, so "sounds clear once" is not an
  acceptance gate.
- macOS over Wi-Fi showed unstable RTT around several milliseconds of movement.
  That can cause audible flicker even when average RTT looks low.

Known unknowns:

- We have not yet proven whether Wi-Fi flicker is packet loss, packet burst
  jitter, scheduling jitter, SFU burst forwarding, device callback timing, or a
  mix of these.
- We have deterministic receiver scenarios and a UDP impairment proxy, but we
  have not yet proven that either exactly reproduces the real Wi-Fi/tunnel
  failure heard manually.
- We have not yet proven a final Opus jitter policy from external
  Windows/macOS evidence.
- We have not yet solved cross-machine PCM.

## Current Experiment Branch

Branch: `experiment/opus-jitter-buffer-control`

Purpose:

- manual and first-pass automatic Opus receive jitter control for testing
  unstable networks
- per-participant receive jitter targets
- deterministic receiver harness, UDP impairment proxy, and local SFU probes
- receiver playout diagnostics for queue, age, target trim, PLC, and drift
- no PCM changes
- no claim that this is ready for `main` until external validation is recorded

Important boundary:

The current branch is a validation candidate. It is not final product proof
until Windows/macOS, cross-machine, and long-session evidence are captured.

## Roadmap Gates

Important: the bullets inside each gate are roadmap scope and rationale, not
unchecked implementation todos. The executable checkboxes live in
`OPUS_COMPETITIVE_IMPLEMENTATION_CHECKLIST.md`; the completion audit is in
`OPUS_COMPETITIVE_COMPLETION_AUDIT.md`.

Current gate status:

| Gate | Local implementation status | Promotion evidence status |
| --- | --- | --- |
| Gate 1: Evidence Capture | Complete locally: smoke/evidence tooling and deterministic/proxy runs exist. | Required before promotion: real Windows/macOS session evidence. |
| Gate 1.5: Latency Budget | Complete locally: readable contributors and Windows smoke exist. | Required before promotion: macOS/CoreAudio and real cross-machine latency capture. |
| Gate 1.6: Receiver Playout Correctness | Complete locally: queue/age/target-trim diagnostics, harness, and SFU/proxy probes exist. | Required before promotion: real GUI/client cross-machine validation. |
| Gate 2: Network Impairment Harness | Complete locally: deterministic scenarios and UDP impairment proxy exist. | Required before promotion: correlation with real Wi-Fi/tunnel sessions. |
| Gate 3: Per-Participant Manual Jitter | Complete locally: client state/UI and multi-participant SFU probe exist. | Required before promotion: live remote multi-participant validation. |
| Gate 4: Per-Participant Auto Jitter | Complete locally: deterministic harness and client diagnostics exist. | Required before promotion: live unstable-remote validation. |
| Gate 4.5: Receiver Clock / Sample-Rate Drift | Complete locally: measurement and decision are covered; compensation is deferred. | Required before promotion: long-session Windows/macOS drift evidence. |
| Gate 5: Network Quality UX | Complete locally: first classifier and action guidance are implemented. | Required before promotion: live wording/threshold validation. |
| Gate 6: Opus Product Defaults | Complete locally: Opus `120`, jitter `8`, queue/age limits, auto jitter, and flags are implemented. | Required before promotion: final shipped default must be validated externally. |
| Gate 7: Packet Loss Mitigation Research | Complete for this branch: FEC/redundancy are not justified by current evidence. | Reopen only if real loss evidence dominates. |
| Gate 8: PCM Premium Research Track | Complete for this branch: PCM is mapped and labeled experimental. | Deferred: premium PCM waits for cross-machine/drift work. |

The local implementation status table above summarizes the checklist outcome
without making this roadmap the executable task list. The actual implementation
checklist lives in `OPUS_COMPETITIVE_IMPLEMENTATION_CHECKLIST.md`. External
Windows/macOS promotion proof remains separate in
`OPUS_EXTERNAL_VALIDATION_RUNBOOK.md` and must pass
`tools/opus-external-evidence-check.mjs` before this branch is called
competitive/product-ready.

### Gate 1: Evidence Capture Before More Audio Policy

Goal: stop changing audio behavior without knowing which failure mode we are
addressing.

Roadmap scope:

- Do not merge the Opus jitter experiment to `main` until local
      smoke and at least one cross-machine run are recorded.
- Record Opus runs at jitter `0`, `3`, `5`, `8`, and `10`.
- For each run, capture subjective result plus the counters the client
      currently exposes or should expose (some are already in the
      `client.cpp` stats line, others may need to be added or surfaced):
  - RTT range
  - `queue_drift_packets` and queue depth in packets
  - `packet_age_avg_ms` (and a max if added)
  - `underrun_count` (covers Opus PLC fills and silence fills today)
  - `pcm_concealment_frames` when running in PCM mode
  - `jitter_depth_drops`
  - `jitter_age_drops`
  - `sequence_gaps` / late packets
- Record whether the network path is Ethernet, Wi-Fi, tunnel, or loopback.
- Do not treat local same-device success as proof for LAN/Wi-Fi/tunnel.

Acceptance:

- We can say which manual jitter settings improve Wi-Fi/tunnel instability and
  what latency they add.
- If results are inconsistent, the next gate is test harness first, not auto
  jitter first.

### Gate 1.5: End-to-End Latency Budget

Goal: know which contributor to latency dominates before tuning any one of
them. Receiver-side jitter buffer is one term in the budget, not the whole
budget. SonoBus exposes audio buffer size as a first-class user setting
because they know capture/playout dominate; we should know the same numbers
about ourselves before we keep tuning the middle term.

Roadmap scope:

- First pass: instrument the contributors we can read today (callback
      sizes, encode time, send-pacing deltas, queue depth, decode time) and
      log per-second summaries. Do not block Gate 1 testing on this; fill
      gaps incrementally.
- Subsequent passes: add the contributors that need new probes (capture
      buffer ms, network one-way delay or RTT/2, playout buffer ms) until
      every term in the budget has a measured value.
- Record the same set on macOS/CoreAudio, Windows/WASAPI, and any other
      supported backend.
- Compare measured end-to-end latency against the sum of the contributors.
      Flag any unexplained gap as its own investigation.

Acceptance:

- Every later "we lowered latency" claim has a named, measured contributor.
- The dominant contributor is known per platform, so later gates target the
  real bottleneck instead of the easy knob.

### Gate 1.6: Receiver Playout Correctness

Goal: explain and fix cases where the receiver is both near-full and
underrunning. A larger manual jitter buffer is not meaningful until packet
queue depth, decoded PCM depth, callback consumption, and drop policy all agree.

Evidence from testing:

- Opus `120` with manual jitter buffer `13` still flickered.
- Logs showed queue depth near the queue limit (`q=13-15`, `q_max=16`) while
  underruns and PLC still increased.
- Logs also showed high queue drops but no sequence gaps/late packets and no
  send drops.
- That points to receiver playout/cap/age/decode interaction before it points
  to packet loss.
- After exposing queue limit and packet age limit separately, Opus could sound
  clear with `jitter_buffer=0`, `queue_limit=64`, and `age_limit=100`, but the
  observed packet age still floated around roughly `60-95 ms`.
- Changing the manual jitter buffer from `0` to `32` did not materially change
  the observed packet age in that run.
- This means the current manual jitter value is not an ongoing playout delay
  controller. It is mostly a startup/rebuffer readiness threshold. Queue limit
  and age limit decide whether accumulated packets are thrown away.
- Competitor evidence points at ongoing receiver regulation instead: Jamulus
  simulates multiple jitter depths and chooses a measured setting, JackTrip's
  JitterBuffer/Regulator track read/write distance and tolerance, and AOO says
  automatic buffering should extend when packets are late and slowly reduce.

Roadmap scope:

- Add diagnostics for decoded Opus PCM buffered frames.
- Add diagnostics for how many Opus packets are decoded per audio callback.
- Add diagnostics for why a packet is dropped: queue limit, age limit,
      decoded-buffer overflow, or codec mismatch.
- Add diagnostics for callback frame count versus packet frame count.
- Expose manual queue limit separately from manual jitter buffer so burst
      capacity can be tested directly.
- Expose packet age limit during testing so age-drop policy can be separated
      from queue-limit policy.
- Re-test manual jitter `5`, `8`, `10`, and `13` after instrumentation.
- Replace "jitter buffer means ready threshold" with a steady-state playout
      target: the receiver should actively keep each participant near the
      chosen target delay instead of letting queue age float until the age cap.
- Keep queue limit as burst capacity and age limit as a safety guard, not as
      the primary latency control.
- Add a dedicated diagnostic for controlled target trims so those drops are
      not confused with packet loss.
- Auto jitter must build on the measured target-delay behavior; it must not
      hide latency changes or turn queue limit into the real buffer.

Branch status:

- Done: Added separate queue limit and age limit controls for testing.
- Done: Added diagnostics for queue-limit, age-limit, decoded-buffer overflow,
      and target-trim drops.
- Done: Added first-pass target trimming so Opus receive queues are trimmed toward
      the manual target instead of only waiting for the queue or age cap.
- Done: Added deterministic harness coverage for target trim, PLC, rebuffer,
      and age-limit behavior.
- Done: Added actual UDP impairment proxy evidence for low-target failure and
      jitter-5 improvement. The latest local evidence run still showed a small
      number of PLC/underruns at jitter `5`, so this is not proof that jitter
      `5` is universally clean on impaired paths.
- Promotion evidence: re-test cross-machine Opus after target trimming and
      auto jitter. This is not accepted for `main` until observed age follows
      the target and audio remains clear.

Acceptance:

- When audio flickers, logs identify whether the receiver ran out of packet
  queue, decoded PCM frames, or dropped usable packets due to policy.
- Queue drops are not treated as network loss unless sequence/loss counters
  support that.
- The next fix is chosen from measured receiver behavior, not from a larger
  buffer guess.
- Manual target changes visibly move steady-state packet age, proving the
  control affects latency and not only startup readiness.

### Gate 2: Real Network Impairment Harness

Goal: reproduce robotic/flicker/dropout behavior without relying only on human
listening.

Roadmap scope:

- Add a test mode or proxy that can inject packet delay, jitter, loss,
      burst loss, and reordering into the actual UDP audio path.
- Make the harness run long enough to catch "good for one second, then bad"
      behavior.
- Report metrics that match the client diagnostics.
- Compare harness output against manual Wi-Fi/tunnel listening.

Acceptance:

- A failing manual condition has a matching failing automated condition.
- A fix is not accepted only because a synthetic probe passes.

### Gate 3: Per-Participant Manual Jitter

Goal: match the competitor model that each incoming performer can need a
different receive buffer.

Roadmap scope:

- Move from one global Opus jitter target to per-participant effective
      targets.
- Keep a global default for new participants.
- Let the user inspect and override each participant's target.
- Show latency cost per participant.
- Keep SFU routing unchanged; this is receiver-side behavior.

Acceptance:

- One unstable incoming stream can be buffered more without increasing latency
  for stable incoming streams.

### Gate 4: Per-Participant Auto Jitter

Goal: make the receiver adapt each incoming performer independently.

Roadmap scope:

- Add per-participant auto state.
- Increase quickly on repeated underruns, PLC growth, late packets, age
      spikes, or queue starvation.
- Decrease slowly only after a stable window.
- Add hysteresis so the target does not flap.
- Make auto changes visible in the participant stats.
- Keep manual override available.
- Start from measured behavior in Gate 1 and Gate 2, not guessed thresholds.

Acceptance:

- A bad incoming stream gets more buffering without penalizing stable streams.
- Auto does not hide bad audio behind unexplained latency.
- Auto decisions can be explained from recorded diagnostics.

### Gate 4.5: Receiver Clock / Sample-Rate Drift

Goal: stop confusing soundcard drift with network instability, and stop
auto-jitter from over-buffering forever to compensate for it.

Evidence this matters:

- AOO `aoo_protocol.rst` lists timing and sample-rate synchronization as
  first-class concerns. This is the strongest external citation.
- The SonoBus User Guide notes that participants do not need a matching
  sample rate because audio is resampled automatically. That covers
  cross-rate mixing rather than long-session playout drift, but it confirms a
  resampler exists in their data path.
- JackTrip `Regulator.cpp` tracks `skew` / `broadcast_skew` and uses PLC. We
  have not confirmed an explicit drift-correction step from source, so treat
  this as "relevant timing strategies to investigate," not "they already
  solve drift."

Roadmap scope:

- Measure long-session sender vs receiver soundcard drift in ppm on each
      backend.
- Decide a compensation strategy: receiver-side resampling, an
      asynchronous playout clock, or controlled sample skip/insert.
- Make the chosen strategy visible in stats so drift events are
      distinguishable from network jitter events.
- Re-run Gate 4 auto-jitter behavior with drift compensation active to
      confirm auto no longer grows without bound on stable networks.

Acceptance:

- A 30-minute session does not require auto-jitter to grow without bound on a
  stable network.
- Drift events are reported separately from queue/age drops.
- Gate 4 per-participant auto is no longer biased by drift.

### Gate 5: Network Quality UX

Goal: make users understand what is wrong.

Roadmap scope:

- Add per-participant quality labels such as `Stable`, `Jittery`,
      `Recovering`, and `Poor`.
- Show the reason: packet age spikes, underruns, PLC, queue drops, callback
      deadline pressure, or bandwidth pressure.
- Keep advanced stats visible for development.
- Add clear Ethernet/Wi-Fi guidance in product docs or UI.

Acceptance:

- Users can tell whether they need more jitter buffer, a wired network, a closer
  server, a better audio device/backend, or a lower bandwidth mode.

### Gate 6: Opus Product Defaults

Goal: ship a sane default without hiding advanced tuning.

Roadmap scope:

- Keep Opus `120` as the default internet performer mode unless evidence
      disproves it.
- Pick default jitter/auto behavior from Gates 1-4.
- Add launch/config support only after the policy is chosen:
  - `--codec opus`
  - `--frames 120`
  - `--jitter <packets-or-ms>`
  - `--auto-jitter`
- Keep PCM selectable as reference/LAN/premium only when clearly labeled.

Acceptance:

- A normal user starts with a stable default.
- An advanced user can tune latency versus quality without editing code.

### Gate 7: Packet Loss Mitigation Research

Goal: decide whether Opus PLC alone is enough or whether redundancy/FEC is
needed.

Roadmap scope:

- Use Gate 2 to determine whether audible failures are mostly loss, burst
      loss, jitter, or scheduling.
- Decide Opus in-band FEC (LBRR) trigger thresholds from Gate 2 loss
      curves: at which packet loss rate does FEC turn on, and what is the
      bitrate cost at that threshold? Implement behind a flag, then evaluate
      whether it should ship as an adaptive default after measuring its
      latency, bitrate, and audible-quality cost end-to-end.
- Evaluate lightweight packet redundancy only if packet loss is confirmed
      to be the dominant audible failure even with LBRR active.
- Do not add bandwidth-heavy redundancy before measurement.

Acceptance:

- Any added mitigation has a measured reason and a measured latency/bandwidth
  cost.

### Gate 8: PCM Premium Research Track

Goal: keep PCM serious without blocking Opus product work.

Roadmap scope:

- Investigate PCM cross-machine corruption from first principles.
- Do not trust synthetic probes unless they reproduce the real failure.
- Map PCM capture, packetization, SFU forwarding, receive queue, playout, and
      output callback.
- Compare PCM behavior to Opus under the same network path.
- Study whether PCM needs receiver playout clocking, sample-rate drift
      correction, resampling, or a different scheduler.

Acceptance:

- PCM is either proven for premium LAN/studio mode or clearly labeled
  experimental.
- No PCM fix is accepted unless it works cross-machine without unacceptable
  latency.

## Non-Decisions

These are not decided yet:

- final Opus jitter default after external validation
- whether auto jitter remains the shipped default after external validation
- whether jitter should be configured in packets or milliseconds in product UI
- whether packet redundancy is worth the bandwidth cost
- whether PCM should ship beyond LAN/reference mode
- whether PCM needs resampling/drift correction

## Immediate Next Step

Run the external validation collector and real sessions before promoting this
branch to `main`.

Standard smoke collector:

`node tools/opus-validation.mjs smoke`

Run it on Windows and macOS, save each generated
`build/opus-validation/<timestamp>/report.md`, then run real
Windows-to-macOS and macOS-to-Windows Opus `120` sessions with auto jitter
enabled. The branch is accepted for promotion only if observed packet age,
underruns, PLC, drift, and subjective audio agree with the implementation
checklist.

Promotion evidence must be captured in the external validation manifest:

`OPUS_EXTERNAL_VALIDATION_MANIFEST.example.json`

The manifest can be initialized from the generated paths with:

`node tools/opus-external-evidence-check.mjs --init validation/opus-external-validation.json ...`

Then run:

`node tools/opus-external-evidence-check.mjs validation/opus-external-validation.json`

The checker must pass before this branch is treated as competitive evidence,
not only locally implemented.
