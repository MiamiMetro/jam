# Opus Competitive Jamming Roadmap

Date: 2026-04-30

Status: evidence-backed roadmap, not an implementation checklist.

This file exists because the project should not move by guesses. Every product
or engine direction below is tied to one of:

- competitor source or documentation in `.cache/upstream-audio`
- public competitor documentation
- observed behavior from our own Windows/macOS tests
- an explicitly marked unknown that still needs verification

## Current Decision

Opus is the primary cross-platform and internet jamming path for now.

PCM remains important as a future premium LAN/studio path, but it is not the
blocking MVP path until cross-machine behavior is understood. Local same-machine
PCM can sound excellent, especially on macOS/CoreAudio, but cross-machine PCM has
shown robotic/corrupt behavior in our testing.

## Competitor Evidence

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
- Its Auto mode is based on network and sound-card timing jitter.
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
- We have not yet created a network impairment test that reproduces the same
  failure heard manually.
- We have not yet proven a final Opus jitter policy.
- We have not yet solved cross-machine PCM.

## Current Experiment Branch

Branch: `experiment/opus-jitter-buffer-control`

Purpose:

- manual Opus receive jitter control for testing unstable networks
- no PCM changes
- no auto jitter yet
- no product default change yet

Important boundary:

The manual jitter control is a diagnostic tool first. It is not the final
competitive design.

## Roadmap Gates

### Gate 1: Evidence Capture Before More Audio Policy

Goal: stop changing audio behavior without knowing which failure mode we are
addressing.

Tasks:

- [ ] Keep the current manual Opus jitter experiment uncommitted until local
      smoke and at least one cross-machine run are recorded.
- [ ] Record Opus runs at jitter `0`, `3`, `5`, `8`, and `10`.
- [ ] For each run, capture subjective result plus:
  - RTT range
  - queue current/average/max
  - packet age average/max
  - underruns
  - PLC count
  - queue drops
  - age drops
  - send queue age
- [ ] Record whether the network path is Ethernet, Wi-Fi, tunnel, or loopback.
- [ ] Do not treat local same-device success as proof for LAN/Wi-Fi/tunnel.

Acceptance:

- We can say which manual jitter settings improve Wi-Fi/tunnel instability and
  what latency they add.
- If results are inconsistent, the next gate is test harness first, not auto
  jitter first.

### Gate 2: Real Network Impairment Harness

Goal: reproduce robotic/flicker/dropout behavior without relying only on human
listening.

Tasks:

- [ ] Add a test mode or proxy that can inject packet delay, jitter, loss,
      burst loss, and reordering into the actual UDP audio path.
- [ ] Make the harness run long enough to catch "good for one second, then bad"
      behavior.
- [ ] Report metrics that match the client diagnostics.
- [ ] Compare harness output against manual Wi-Fi/tunnel listening.

Acceptance:

- A failing manual condition has a matching failing automated condition.
- A fix is not accepted only because a synthetic probe passes.

### Gate 3: Per-Participant Manual Jitter

Goal: match the competitor model that each incoming performer can need a
different receive buffer.

Tasks:

- [ ] Move from one global Opus jitter target to per-participant effective
      targets.
- [ ] Keep a global default for new participants.
- [ ] Let the user inspect and override each participant's target.
- [ ] Show latency cost per participant.
- [ ] Keep SFU routing unchanged; this is receiver-side behavior.

Acceptance:

- One unstable incoming stream can be buffered more without increasing latency
  for stable incoming streams.

### Gate 4: Per-Participant Auto Jitter

Goal: make the receiver adapt each incoming performer independently.

Tasks:

- [ ] Add per-participant auto state.
- [ ] Increase quickly on repeated underruns, PLC growth, late packets, age
      spikes, or queue starvation.
- [ ] Decrease slowly only after a stable window.
- [ ] Add hysteresis so the target does not flap.
- [ ] Make auto changes visible in the participant stats.
- [ ] Keep manual override available.
- [ ] Start from measured behavior in Gate 1 and Gate 2, not guessed thresholds.

Acceptance:

- A bad incoming stream gets more buffering without penalizing stable streams.
- Auto does not hide bad audio behind unexplained latency.
- Auto decisions can be explained from recorded diagnostics.

### Gate 5: Network Quality UX

Goal: make users understand what is wrong.

Tasks:

- [ ] Add per-participant quality labels such as `Stable`, `Jittery`,
      `Recovering`, and `Poor`.
- [ ] Show the reason: packet age spikes, underruns, PLC, queue drops, callback
      deadline pressure, or bandwidth pressure.
- [ ] Keep advanced stats visible for development.
- [ ] Add clear Ethernet/Wi-Fi guidance in product docs or UI.

Acceptance:

- Users can tell whether they need more jitter buffer, a wired network, a closer
  server, a better audio device/backend, or a lower bandwidth mode.

### Gate 6: Opus Product Defaults

Goal: ship a sane default without hiding advanced tuning.

Tasks:

- [ ] Keep Opus `120` as the default internet performer mode unless evidence
      disproves it.
- [ ] Pick default jitter/auto behavior from Gates 1-4.
- [ ] Add launch/config support only after the policy is chosen:
  - `--codec opus`
  - `--frames 120`
  - `--jitter <packets-or-ms>`
  - `--auto-jitter`
- [ ] Keep PCM selectable as reference/LAN/premium only when clearly labeled.

Acceptance:

- A normal user starts with a stable default.
- An advanced user can tune latency versus quality without editing code.

### Gate 7: Packet Loss Mitigation Research

Goal: decide whether Opus PLC alone is enough or whether redundancy/FEC is
needed.

Tasks:

- [ ] Use Gate 2 to determine whether audible failures are mostly loss, burst
      loss, jitter, or scheduling.
- [ ] Evaluate Opus in-band FEC only if it matches the failure mode.
- [ ] Evaluate lightweight packet redundancy only if packet loss is confirmed.
- [ ] Do not add bandwidth-heavy redundancy before measurement.

Acceptance:

- Any added mitigation has a measured reason and a measured latency/bandwidth
  cost.

### Gate 8: PCM Premium Research Track

Goal: keep PCM serious without blocking Opus product work.

Tasks:

- [ ] Investigate PCM cross-machine corruption from first principles.
- [ ] Do not trust synthetic probes unless they reproduce the real failure.
- [ ] Map PCM capture, packetization, SFU forwarding, receive queue, playout, and
      output callback.
- [ ] Compare PCM behavior to Opus under the same network path.
- [ ] Study whether PCM needs receiver playout clocking, sample-rate drift
      correction, resampling, or a different scheduler.

Acceptance:

- PCM is either proven for premium LAN/studio mode or clearly labeled
  experimental.
- No PCM fix is accepted unless it works cross-machine without unacceptable
  latency.

## Non-Decisions

These are not decided yet:

- final Opus jitter default
- whether auto jitter should be on by default
- whether jitter should be configured in packets or milliseconds in product UI
- whether packet redundancy is worth the bandwidth cost
- whether PCM should ship beyond LAN/reference mode
- whether PCM needs resampling/drift correction

## Immediate Next Step

Do not implement auto jitter yet.

First, use the manual Opus jitter experiment to gather evidence across:

- local loopback
- Windows/macOS LAN
- Wi-Fi
- tunnel/community-server path

Then decide whether the next code step is:

1. per-participant manual jitter, or
2. network impairment harness first.
