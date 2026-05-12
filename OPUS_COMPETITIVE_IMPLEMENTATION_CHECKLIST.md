# Opus Competitive Implementation Checklist

Date: 2026-05-12

Purpose: executable checklist for finishing `OPUS_COMPETITIVE_ROADMAP.md`.

This file is the implementation source of truth. The roadmap explains why each
gate exists; this checklist tracks what must be built, tested, and accepted.

## Completion Rule

Do not mark a gate complete because manual listening sounds good once.

A gate is complete only when:

- the implementation exists in code,
- the relevant command(s) are documented here,
- the command output directly covers the gate's acceptance criteria,
- remaining risks are either fixed or explicitly moved to a later gate.

## Current Validation

- 9+ competitive-audio checklist:
  - Receiver rate adaptation: in progress. The Opus receiver now uses
    queue-depth-driven linear PCM resampling before mixing, so small
    sender/output clock mismatches are corrected by smooth sample-rate
    adaptation instead of whole-packet queue shedding. The default Opus burst
    capacity and packet-age guard now provide enough headroom for that
    controller to stabilize without changing the 8-packet jitter target.
    New harness coverage models 120-frame Opus packets feeding 128-frame output
    callbacks plus positive and negative receiver clock skew. Evidence required:
    Windows/macOS session logs must show materially reduced or zero steady
    queue-limit drops before this item is accepted.
  - Receiver rate damping: in progress. The live 2026-05-12 short run showed
    the first controller hitting `1.1800`, draining to rebuffer, then filling
    back to the receive cap. The controller is now damped to a narrower
    `0.95` to `1.08` range with gentler drop feedback. Evidence required:
    refreshed live logs must show the ratio no longer oscillates between the
    old hard endpoints and that underrun/PLC churn is reduced.
  - Playout diagnostics: in progress. Participant logs now include the current
    Opus playout ratio and remaining correction callbacks beside decoded packet
    and drop rates. Evidence required: refreshed cross-machine logs must explain
    whether any remaining queue drops happen while the controller is pinned,
    idle, or oscillating.
  - Benign device capability diagnostics: in progress. RtAudio callback-size
    adjustment and unavailable backend-latency reporting now log as `info`,
    not warning, because they describe host capability/fallback behavior rather
    than audio corruption. Evidence required: smoke and session logs should no
    longer contain those lines as `[warning]`.
  - Drift diagnostics: in progress. Receiver drift max now ignores the first
    warmup observations so startup scheduling does not permanently poison the
    max drift field. Evidence required: refreshed logs must show steady-state
    drift max instead of the old startup spike.
  - Strict acceptance without review exceptions: pending. The target 9+ gate is
    to remove `allowWarnings` from the external manifest and still pass
    `node tools/opus-acceptance.mjs --external-manifest validation/opus-external-validation.json`.
  - Cross-machine proof: pending refresh. After the receiver-rate change is
    committed and pulled to macOS, rerun Windows-to-macOS, macOS-to-Windows,
    and long-session evidence with the macOS client launched from Terminal.
- Latest local verification refresh:
  `node tools/opus-local-verify.mjs --out build/opus-local-verify/current`
  passed on Windows and wrote `build/opus-local-verify/current/report.md`
  with the current timestamp, platform, and source fingerprint.
- Latest Windows smoke refresh:
  `node tools/opus-validation.mjs smoke` wrote
  a timestamped `build/opus-validation/<timestamp>/report.md`; the latest
  current path is recorded in `build/opus-local-verify/current/report.md`.
  All smoke steps exited `0` (`startup-default`, `startup-no-auto`,
  `harness-self-test`, `audio-open`).
- Full completion status remains intentionally incomplete until
  `validation/opus-external-validation.json` exists and passes strict external
  evidence checking.
- `cmake --build build --config Debug` passed after adding the harness,
  Opus rebuffer hysteresis changes, and latency contributor diagnostics. Built
  `client`, `server`, `latency_probe`, `room_routing_probe`, `listener_bot`,
  and `opus_receiver_harness`.
- `cmake --build build --config Release` passed and built the Release native
  binaries, including `client`, `server`, `latency_probe`, `listener_bot`,
  `multi_participant_jitter_probe`, `opus_receiver_harness`,
  `room_routing_probe`, and `udp_impair_proxy`.
- `git diff --check` passed; only normal CRLF conversion warnings were printed.
- `OPUS_COMPETITIVE_ROADMAP.md` contains no task checkboxes; this file is the
  tracked implementation checklist.
- `validation/` and `validation_logs/` are ignored so generated command
  sheets, manifests, summaries, and runtime evidence cannot be staged as source
  by accident, and they are excluded from `Source SHA256`.
- Harness scenarios currently cover clean, scheduler, Wi-Fi-like, tunnel-like,
  reordering, callback stall, loss, burst loss, and synthetic receiver clock
  drift.
- `udp_impair_proxy` now builds as an actual UDP-path impairment tool for live
  SFU/client testing.
- `cmake --build build --target opus_receiver_harness_self_test --config Debug`
  passed and runs the core harness assertions as a build target, including the
  adaptive callback-mismatch and receiver clock-skew cases.
- `.\build\Debug\client.exe --startup-config-smoke --codec opus --frames 120 --jitter 7 --queue-limit 20 --age-limit-ms 80 --auto-jitter`
  passed and proved startup tuning flags apply without opening the GUI/audio stream.
- `tools/opus-validation.mjs` now collects cross-platform smoke evidence into
  `build/opus-validation/<timestamp>/report.md` so Windows and macOS runs use
  the same command.
- Windows smoke collector run:
  `node tools/opus-validation.mjs smoke` wrote
  a timestamped `build/opus-validation/<timestamp>/report.md`; all steps exited `0`
  (`startup-default`, `startup-no-auto`, `harness-self-test`, `audio-open`).
  The client now also writes explicit `*-client.log` files through
  `--log-file`.
- `tools/opus-local-evidence.mjs` now collects local SFU/proxy evidence and
  runs the external evidence checker self-test into
  `build/opus-local-evidence/<timestamp>/report.md`.
- The external evidence checker rejects manifests whose client logs do not
  prove Opus `120` startup and audio diagnostics at `frames=120`, or
  macOS-normalized `frames=128`; it also rejects smoke reports without
  neighboring startup client logs proving the expected platform and Opus `120`.
- `tools/opus-local-verify.mjs` runs the complete local verification set and
  writes `build/opus-local-verify/<timestamp>/report.md`.
- `tools/opus-external-commands.mjs` generates copy/paste Windows/macOS
  session commands with signed validation tokens, Opus `120`, explicit
  `--jitter 8`, explicit `--auto-jitter`, and manifest log paths. It requires
  explicit non-loopback `--server-host` so cross-machine validation does not
  accidentally target loopback. The generated packet now also lists the exact
  final log layout expected after collecting Windows/macOS logs onto one
  machine. Manifest initialization now supports `--windows-smoke latest` and
  `--mac-smoke latest`, so the checker auto-selects the newest current-source
  smoke reports after both platforms' smoke directories are copied onto the
  checker machine. Its validation-token TTL is intentionally longer than
  production join-token TTL so the external evidence run does not expire
  mid-sequence, the generated packet prints exact generated/expiry UTC
  timestamps, a regenerate-if-expiring warning, plus the current `Source SHA256`
  for preflight, rejects repo-local
  `--write`, `--out-dir`, and `--manifest` paths unless git ignores the
  generated evidence paths, and invalid or too-short TTL values fail closed.
- The local verifier checks the generated command packet with default room
  names and custom room names, proving the Windows-to-macOS, macOS-to-Windows,
  and long-session room IDs propagate into both client commands and manifest
  initialization commands.
- `tools/opus-acceptance.mjs` is the final promotion command; it requires a
  real external manifest and runs local verification, external evidence
  checking in strict mode, and the completion audit against the local verifier
  report it just generated. Repo-local external manifests must be ignored
  generated evidence, and `--local-out` must resolve to ignored generated
  verifier evidence, so real machine-specific manifests and verifier reports
  are not promoted from source-controlled paths. Skipping the local rerun
  requires the explicit `--use-saved-local-report` acknowledgement. A
  warning-allowed manifest is acceptable for review but does not pass final
  acceptance when the warning is from smoke/setup evidence. Session warning
  indicators are eligible for strict acceptance only when they are explicitly
  reviewed in the generated manifest; the 9+ target is to eliminate that
  manifest allowance from fresh external logs.
- `tools/opus-completion-audit.mjs` is the final completion audit command; it
  can pass local-only checks without claiming full completion, but full
  completion checks the saved local verifier report, rejects stale source
  fingerprints, requires non-empty companion logs for required verifier rows,
  rejects local verifier reports older than 24 hours, and requires a real
  external manifest. It also has a concise `--status` mode that reports local
  docs, local verifier, whether the external manifest is missing, failing,
  warning-only, or strict-passing, and final completion state.
- `tools/opus-local-verify.mjs` now includes an expected-failure check proving
  the final acceptance command refuses a missing external manifest.
- It also includes an expected-failure check proving the final completion audit
  refuses to claim completion without a real external manifest.
- It also includes expected-failure checks proving final acceptance and the
  completion audit refuse repo-local external manifests unless they are ignored
  generated evidence.
- It also includes expected-failure checks proving final acceptance and the
  completion audit still reject ignored generated manifests that do not contain
  real Windows/macOS evidence.
- It also includes an expected-failure check proving final acceptance refuses
  `--skip-local` unless the caller explicitly acknowledges use of a saved local
  report.
- It also includes expected-failure checks proving final acceptance refuses
  source-controlled `--local-out` paths both when rerunning local verification
  and when using `--skip-local --use-saved-local-report`.
- It also includes an expected-failure check proving saved-report final
  acceptance refuses to continue when the referenced local verifier
  `report.md` does not exist.
- It also includes an expected-failure check proving the external evidence
  checker refuses `OPUS_EXTERNAL_VALIDATION_MANIFEST.example.json`.
- It also includes expected-failure checks proving the external evidence
  checker fails closed with clear errors for missing, malformed, non-object,
  malformed-boolean, malformed-type, and unknown-field manifests.
- It also includes expected-failure checks proving external manifest
  initialization refuses source-controlled output and input paths.
- It also includes an expected-failure check proving external validation
  command generation rejects IPv4/IPv6 loopback and unspecified/unroutable
  server hosts, including bracketed and full-form IPv6 accidental host:port
  values, unless
  explicitly overridden for command-shape testing.
- It also includes expected-failure checks proving external command generation
  refuses source-controlled `--write`, `--out-dir`, and `--manifest` paths.
- The external evidence checker now requires external client logs to prove
  startup auto jitter is enabled and the expected validation room was joined;
  the manifest metadata alone is not accepted. It also requires the server log
  to prove the same validation room. It rejects loopback/same-machine network
  descriptions, including unroutable or unspecified addresses, because those
  are not external proof. It also rejects subjective
  notes that report robotic/corrupt/flickering/dropout/broken audio unless the
  session is explicitly marked as an allowed warning for review. Directional
  sessions must state the actual source/listener platforms in the subjective
  note so a Windows-to-macOS entry cannot pass from ambiguous listening notes.
  Server logs must include at least one non-loopback JOIN endpoint, including
  rejection of IPv4, bracketed IPv6, full-form IPv6, and IPv4-mapped IPv6
  loopback-only JOIN logs. Manifest
  initialization accepts explicit room names so custom generated command
  packets and generated manifests stay aligned.
- The external evidence checker now requires Windows and macOS smoke reports to
  carry matching `Source SHA256` fingerprints for the current checkout, so a
  passing manifest cannot mix logs from different source revisions.
- The external evidence checker rejects repo-local smoke-report and session-log
  input paths unless git ignores them as generated evidence, so
  machine-specific validation evidence is not accepted from source-controlled
  files.
- `OPUS_EXTERNAL_VALIDATION_MANIFEST.example.json` and
  `tools/opus-external-evidence-check.mjs` define the required external
  evidence packet for Mac/cross-machine promotion.
- `node tools/opus-external-evidence-check.mjs --self-test` verifies the
  checker accepts a complete evidence packet, accepts only an explained
  `audio-open` smoke failure, rejects placeholder notes, and rejects
  sequence-gap or drift-over-`250 ppm` fixture logs. It also verifies the
  actual `--strict` CLI path rejects a warning-allowed manifest before final
  acceptance can promote it.
- The checker self-test also rejects missing session room metadata and server
  logs that contain JOIN lines but do not prove `Runtime: role=server`; it also
  rejects loopback/same-machine or unroutable network descriptions and
  bad-audio subjective reports, and server logs whose JOIN endpoints are all
  IPv4, bracketed IPv6, full-form IPv6, or IPv4-mapped IPv6 loopback.
- `node tools/opus-external-evidence-check.mjs --init <manifest.json> ...`
  initializes the external manifest from real report/log paths while keeping
  network and subjective notes explicit. Repo-local init output and input paths
  must be ignored generated evidence. The checker self-test proves initialized
  manifests keep supplied paths/rooms but still fail until network and
  subjective notes are edited away from placeholders.
- Local evidence runner:
  `node tools/opus-local-evidence.mjs` wrote a timestamped
  `build/opus-local-evidence/<timestamp>/report.md`; all process steps exited
  `0`, including `log-summary-self-test` and
  `external-evidence-checker-self-test`. The report records exact current
  counters. Across recent runs, direct jitter `5`/`8` have had valid decode
  with no decode failures or size mismatches, but finite local probes can still
  show occasional PLC/underrun warning indicators. Proxy jitter `0` reproduces
  PLC risk, proxy jitter `5` improves but is not treated as product proof, and
  PCM remains research-only. Jitter `8` remains the conservative default
  candidate pending external validation rather than a proven clean-pass claim.
  The server wrote
  `server-file.log` through `--log-file`.
- Per-participant manual jitter code builds and has non-GUI actual-SFU
  multi-participant evidence.
- Per-participant auto jitter code builds and has deterministic harness
  evidence. Live multi-participant validation remains external validation, not
  an implementation task in this file.
- Receiver drift measurement builds and is exposed separately from network
  jitter; compensation is intentionally deferred until real drift evidence
  requires it.
- Network quality labels build and are visible in participant stats; wording
  and thresholds need live validation.
- Startup tuning flags build: `--jitter`, `--queue-limit`, `--age-limit-ms`,
  and `--auto-jitter`.
- One-command local verifier:
  `node tools/opus-local-verify.mjs --out build/opus-local-verify/current`
  wrote `build/opus-local-verify/current/report.md`; Debug and Release native
  builds plus all local
  smoke, evidence, competitor-source evidence, parser self-test, documentation
  hygiene, source fingerprinting, critical source-fingerprint coverage, source
  whitespace hygiene, and diff-check steps exited `0`.
  Documentation hygiene rejects any roadmap task checkbox, unchecked `- [ ]`
  boxes, and ambiguous `Tasks:` markers in roadmap/checklist/audit/runbook
  docs. The verifier also checks the generated
  external command packet includes
  `--codec opus`, `--frames 120`, `--jitter 8`, `--auto-jitter`, the 4-hour
  validation TTL, generated/expiry timestamp headers, the
  regenerate-if-expiring warning, generated join-token integrity,
  header/token-expiry agreement, and the log collection section
  needed before manifest checking. It also verifies the final acceptance
  command runs the completion audit, and includes the final
  `tools/opus-acceptance.mjs` command. It also checks default and custom
  validation room IDs for Windows-to-macOS, macOS-to-Windows, and long sessions
  so logs cannot be silently mixed between directions. It verifies the final
  acceptance command invokes the external checker in strict mode and then runs
  the completion audit. The generated packet uses a non-loopback host, states
  the active talker/listener direction for each 5-minute session, mentions
  strict final acceptance, and includes Windows and macOS commands to create
  the validation log directory before native processes start. It also checks
  the generated source-fingerprint preflight
  and scans every source-fingerprint file for trailing whitespace, verifying
  the critical roadmap/tool/native artifacts are included in `Source SHA256`,
  so untracked new docs/tools are covered in addition to `git diff --check`.
  It also verifies generated validation
  directories are excluded from `Source SHA256`, and the expected generated
  validation command, manifest, summary, and legacy validation-log paths are
  ignored. It also runs the concise completion status command and expects it to
  report incomplete until external validation exists, and it verifies a
  supplied failing generated manifest is reported as `external manifest: fail`.
- The local verifier also rejects repo-local `--out` paths unless the generated
  report path is ignored, so verifier evidence is not accidentally staged as
  source.
- The smoke validation and local evidence tools reject repo-local `--out` paths
  unless their generated report/log directories are ignored, so machine-specific
  smoke and probe evidence is not accidentally staged as source.
- The log summary tool rejects repo-local `--out` paths unless the generated
  summary is ignored, so external validation summaries stay out of source.
- The completion audit rejects repo-local `--local-report` paths unless the
  generated report path is ignored, so acceptance cannot rely on a
  source-controlled verifier report.
- `tools/opus-competitor-evidence-check.mjs` verifies the cached
  SonoBus/Jamulus/JackTrip/AOO files still contain the specific jitter, auto
  buffering, Wi-Fi, Opus/PCM, drift, and packet-loss evidence cited by the
  roadmap.

## Gate 1: Programmatic Opus Receiver Harness

Status: first implementation slice complete; external scripted timelines are still optional.

Deliverables:

- [x] Add deterministic `opus_receiver_harness` executable.
- [x] Run without GUI, real audio devices, SFU, or Electron.
- [x] Model Opus `120` receive/playout behavior:
  - queue target,
  - queue limit,
  - packet age limit,
  - target trimming,
  - PLC gaps,
  - full rebuffer threshold,
  - decoded-frame availability.
- [x] Accept named deterministic packet-arrival scenarios.
- [x] Accept external scripted packet-arrival timelines if named scenarios stop
      being enough.
- [x] Emit machine-readable CSV output.
- [x] Sweep jitter targets `0`, `1`, `2`, `3`, `5`, `8`, `13`, and `32`.
- [x] Include pass/fail status and reason per row.
- [x] Document which scenario replaces the previous slow manual loop.

Acceptance:

- [x] A single command reproduces the low-target failure class.
- [x] A single command shows which target becomes stable for a fixed scenario.
- [x] A future receiver change can be sanity-checked by re-running the same
      command.

Evidence:

- Build: `cmake --build build --target opus_receiver_harness --config Debug`
  passed and produced `build\Debug\opus_receiver_harness.exe`.
- Self-test target:
  `cmake --build build --target opus_receiver_harness_self_test --config Debug`
  passed.
- Clean baseline command:
  `.\build\Debug\opus_receiver_harness.exe --scenario clean --sweep`
  produced `ok` for every target and latency scaled with target depth.
- Programmatic replacement for the slow manual loop:
  `.\build\Debug\opus_receiver_harness.exe --scenario wifi --sweep`
  produced `warn,underrun_plc` for targets `0`, `1`, and `2`, and `ok` for
  targets `3`, `5`, `8`, `13`, and `32`.
- Tunnel-like command:
  `.\build\Debug\opus_receiver_harness.exe --scenario tunnel --sweep`
  produced the same boundary pattern: `0`, `1`, and `2` warned on PLC
  underruns; `3+` was stable for that deterministic scenario.
- Timeline replay command:
  `.\build\Debug\opus_receiver_harness.exe --timeline .\build\opus_timeline.csv --packets 40 --jitter 3`
  passed with `scenario=timeline` and `status=ok`, proving captured packet
  arrival timelines can be replayed without adding new named scenarios.
- This mirrors the manual finding that very low targets are unstable and `3`
  starts becoming usable while `5` remains the safer default candidate.

## Gate 1.5: End-To-End Latency Budget

Status: first diagnostic slice implemented; macOS/CoreAudio capture moved to
external validation.

Deliverables:

- [x] Add measured latency contributors for capture/callback, encode, send
      pacing, receive queue, decode, playout, and output callback.
- [x] Emit per-second summaries.
- [x] Run Windows/WASAPI on this machine and document the macOS/CoreAudio
      validation command for the Mac.

Acceptance:

- [x] Every latency claim names the measured contributor that changed.
- [x] Unexplained latency gaps are tracked as investigations.

Evidence:

- Build: `cmake --build build --target client --config Debug` passed.
- `Audio diag` remains available for frames, packet counts, send drops, bytes,
  and the legacy PCM send queue age.
- New `Latency diag` line reports:
  - callback total time and callback deadline,
  - PCM and Opus transmit queue age,
  - Opus encode time,
  - audio packet send pacing,
  - Opus decode/PLC time,
  - receive playout loop time.
- Capture-to-send queue age now starts from the audio callback timestamp for
  both PCM and Opus, including accumulated Opus transmit frames.
- Latency claim ledger:
  - Opus packet duration at `120` frames is `2.5 ms`; jitter target latency
    claims use packet count multiplied by this packet duration.
  - The local verifier records the current exact probe values in
    `build/opus-local-verify/current/report.md` and the referenced
    `build/opus-local-evidence/<timestamp>/report.md`.
  - Recent local non-GUI SFU probes at jitter `5` and jitter `8` decode
    cleanly, but jitter `5` is not treated as a pure manual target claim
    because auto jitter is enabled by default.
  - Recent proxy-impaired probes at jitter `0` reproduce PLC/underrun risk.
    The same proxy path at jitter `5` improves relative to jitter `0`, but
    this remains local proxy evidence rather than Windows/macOS product proof.
- Open latency investigations:
  - No macOS/CoreAudio latency contributor capture has been recorded in this
    branch.
  - No GUI/RtAudio client latency contributor capture has been recorded through
    the proxy path.
  - `latency_probe` reports repeated blocks on Opus probe output even when
    decode/PLC counters are clean; that probe-specific signal should not be
    treated as a user-audible claim until separately explained.
- Windows/WASAPI audio-open smoke:
  `.\build\Debug\client.exe --audio-open-smoke --frames 120` succeeded with
  input `Headset Microphone (DualSense Wireless Controller)`, output
  `Headset Earphone (HyperX Virtual Surround Sound)`, actual buffer `120`
  frames / `2.500 ms`. RtAudio reported backend latency as `0.000 ms`, so
  backend latency remains unknown on this device.
- Promotion validation still required before claiming cross-platform latency:
  run the same smoke on the Mac build, compare real GUI/client latency
  contributor logs against perceived/loopback latency, then pass
  `node tools/opus-external-evidence-check.mjs <manifest.json>`.

## Gate 1.6: Receiver Playout Correctness

Status: implemented on `experiment/opus-jitter-buffer-control`; GUI/live
comparison remains external validation.

Deliverables:

- [x] Expose queue limit separately from jitter target.
- [x] Expose packet age limit for testing.
- [x] Add queue-limit, age-limit, decoded-buffer overflow, and target-trim
      diagnostics.
- [x] Add first-pass target trimming.
- [x] Fix Opus ready/rebuffer behavior to match the harness model:
      jitter `0` waits for one packet and short empty gaps use PLC before full
      rebuffer.
- [x] Make the harness cover target trim, PLC, rebuffer counters, and age-limit
      behavior.
- [x] Decide whether current target trimming belongs in `main`.

Acceptance:

- [x] The receiver's target setting actually controls steady-state packet age.
- [x] Queue/age/target drops are distinguishable in logs and probe output.
- [x] Low jitter settings fail in the harness for the same reason they fail in
      live tests.

Evidence:

- Build: `cmake --build build --target client --target opus_receiver_harness --config Debug`
  passed.
- Client patch: Opus full rebuffer no longer happens on the first empty callback;
  it now waits for `max(3, jitter_target_or_one)` consecutive empty callbacks,
  matching the harness policy.
- Client patch: jitter `0` no longer marks a participant ready with an empty
  queue; it means no extra prebuffer, but still requires one packet.
- Harness age-limit check:
  `.\build\Debug\opus_receiver_harness.exe --scenario wifi --jitter 5 --age-limit-ms 5`
  reported `age_drops=12`, proving age-drop reporting is distinct from target
  trims and queue-limit drops.
- Decision: target trimming belongs on this experiment branch and should not be
  merged to `main` until the proxy/manual live checks below are recorded. It is
  the right receiver-side mechanism to test because queue limit is burst
  capacity and age limit is only a safety guard; neither should be the primary
  latency controller.
- Non-GUI SFU probe evidence:
  `.\build\Debug\latency_probe.exe --server 127.0.0.1 --port 19999 --codec opus --frames 120 --jitter 5 --seconds 10`
  against `server.exe --allow-insecure-dev-joins` is run by
  `tools/opus-local-evidence.mjs`; exact current values live in the latest
  generated report. Because auto jitter is enabled by default, this is kept as
  evidence for the default policy rather than proof that manual jitter `5` is
  always clean.
- Non-GUI SFU probe evidence:
  `.\build\Debug\latency_probe.exe --server 127.0.0.1 --port 19998 --codec opus --frames 120 --jitter 8 --seconds 10`
  is also run by `tools/opus-local-evidence.mjs`; recent reports show valid
  decode, but finite local runs can still produce occasional PLC/underrun
  warning indicators. Those warnings stay visible in the report instead of
  being treated as a product-ready proof.
- Interpretation: the target setting controls queue depth and measured latency
  on the actual local SFU/probe path. Live GUI client validation is still
  required because this probe does not exercise RtAudio/CoreAudio/WASAPI
  callbacks.
- Actual UDP impairment proxy evidence:
  `latency_probe --codec opus --frames 120 --jitter 0 --packets 1200` through
  `udp_impair_proxy --jitter-ms 8 --reorder-every 31 --reorder-delay-ms 8`
  reports PLC/underrun warning indicators in local evidence runs.
- The same proxy path with `--jitter 5` reported latest local evidence
  fewer PLC/underrun indicators. This ties the low-jitter failure to receiver
  underrun/PLC behavior on an actual UDP path and shows improvement relative to
  jitter `0`. Prior local runs varied, so this still does not replace real
  Windows/macOS GUI-client validation.

## Gate 2: Network Impairment Harness

Status: local impairment tooling implemented; real-client proxy sessions remain
external validation.

Deliverables:

- [x] Add deterministic scenarios for delay, burst jitter, loss, and burst loss.
- [x] Add deterministic scenarios for reordering, callback stalls, and clock drift.
- [x] Add summary sweeps across jitter targets.
- [x] Add scenarios matching Wi-Fi-like and tunnel-like behavior.
- [x] Add actual UDP path/proxy mode if deterministic scenarios stop matching
      live failures.

Acceptance:

- [x] At least one previously manual failure mode is reproduced by automation.
- [x] Fixes fail before the change and pass after the change.

Evidence:

- `wifi --sweep` and `tunnel --sweep` reproduce the low-target PLC/underrun
  failure class without opening two clients.
- `reorder --sweep` reports sequence gaps/late packets without requiring a
  live network.
- `callback_stall --sweep` reports target trims under delayed callback
  scheduling.
- Long drift command:
  `.\build\Debug\opus_receiver_harness.exe --scenario clock_drift --receiver-ppm -1000 --packets 24000 --jitter 5`
  reports `warn,underrun_plc`, showing receiver-clock skew can be separated
  from network jitter in the harness.
- This is not final product evidence because real-client proxy sessions have
  not been recorded yet and the proxy does not measure real device clock drift.
- Build:
  `cmake --build build --target udp_impair_proxy --config Debug` passed and
  produced `build\Debug\udp_impair_proxy.exe`.
- Help/smoke:
  `.\build\Debug\udp_impair_proxy.exe --help` passed and documents local bind,
  target SFU, fixed delay, jitter, loss, burst loss, and reorder knobs.
- The proxy keeps one upstream UDP socket per client endpoint, so the SFU still
  sees separate client endpoints instead of all clients collapsing into one
  proxy identity.
- Harness before/after evidence:
  `.\build\Debug\opus_receiver_harness.exe --scenario wifi --sweep` warns for
  targets `0`, `1`, and `2`, then passes for `3+`. The same scenario with
  `--auto-jitter` raises the target and reduces underruns, so future receiver
  fixes have a deterministic fail/pass path before live testing.
- Promotion validation: run two real clients through `udp_impair_proxy` and
  record whether proxy-induced jitter/loss matches the manual Wi-Fi/tunnel
  symptoms.
- Local non-GUI proxy run:
  `latency_probe --codec opus --frames 120 --jitter 0 --packets 1200` through
  `udp_impair_proxy --jitter-ms 8 --reorder-every 31 --reorder-delay-ms 8`
  produces PLC/underrun warning indicators in local evidence runs.
- The same proxy run at `--jitter 5` produced fewer underruns/PLC than jitter
  `0`. This is local proxy improvement evidence, not a universal clean-pass
  claim. It still needs real GUI/cross-machine validation before
  being treated as a product claim.

## Gate 3: Per-Participant Manual Jitter

Status: code implemented; non-GUI multi-participant SFU validation added.

Deliverables:

- [x] Store effective jitter target per participant.
- [x] Keep a global default for new participants.
- [x] Allow inspecting and overriding each participant target.
- [x] Show latency cost per participant.

Acceptance:

- [x] One unstable incoming participant can receive more buffering without
      increasing latency for stable participants.

Evidence:

- Build: `cmake --build build --target client --config Debug` passed.
- Existing global Opus jitter remains the default for new participants.
- Each participant stats panel now shows `default`/`custom`, a numeric per-user
  jitter target, a reset-to-default button, and the equivalent millisecond cost.
- Manual override is stored on the participant and is not overwritten by the
  global default update path.
- Receive queue capacity is kept at least `participant_target + 3` so a custom
  target is not immediately defeated by the global queue limit.
- Promotion validation: run at least two remote participants where only one
  participant's jitter target is raised.
- Non-GUI actual-SFU validation:
  `cmake --build build --target multi_participant_jitter_probe --config Debug`
  passed and produced `build\Debug\multi_participant_jitter_probe.exe`.
- Probe command:
  `.\build\Debug\multi_participant_jitter_probe.exe --server 127.0.0.1 --port 28330 --stable-target 3 --unstable-target 13 --packets 1200`
  against `server.exe --allow-insecure-dev-joins` is run by
  `tools/opus-local-evidence.mjs`; recent reports show the unstable source
  using the higher target with zero underruns while the stable source stays on
  the lower target and lower measured age.
- Interpretation: the unstable source received a higher playout target while
  the stable source stayed on the lower target and lower measured age. This is
  non-GUI evidence through the real SFU path; GUI/client live validation is
  still valuable before merging to `main`.

## Gate 4: Per-Participant Auto Jitter

Status: code implemented; deterministic validation complete; live validation
remains external.

Deliverables:

- [x] Add per-participant auto state.
- [x] Increase quickly on measured instability.
- [x] Decrease slowly only after a stable window.
- [x] Add hysteresis.
- [x] Make auto decisions visible in stats.
- [x] Keep manual override.

Acceptance:

- [x] Auto decisions are explainable from recorded diagnostics.
- [x] Auto improves unstable scenarios in the harness without hiding latency.

Evidence:

- Build: `cmake --build build --target client --config Debug` passed.
- Build: `cmake --build build --target opus_receiver_harness --config Debug`
  passed.
- Harness command without auto:
  `.\build\Debug\opus_receiver_harness.exe --scenario wifi --jitter 0 --packets 2400`
  reported `underruns=18`, `final_jitter=0`, `avg_age_ms=4.4955`.
- Harness command with auto:
  `.\build\Debug\opus_receiver_harness.exe --scenario wifi --jitter 0 --packets 2400 --auto-jitter`
  reported `underruns=2`, `final_jitter=4`, `auto_inc=2`,
  `avg_age_ms=9.91499`.
- Tunnel comparison improved from `underruns=29` without auto to
  `underruns=1` with auto, with `final_jitter=2`.
- Client stats now show per-participant `Auto`, current target, equivalent ms
  cost, and auto increase/decrease counters.
- Manual numeric participant override disables auto for that participant; reset
  returns to the global default.
- Promotion validation: verify auto improves an unstable remote participant
  without affecting stable participants.

## Gate 4.5: Receiver Clock / Sample-Rate Drift

Status: measurement implemented; compensation direction chosen; compensation
implementation deferred until real drift evidence requires it.

Deliverables:

- [x] Measure sender/receiver drift in ppm.
- [x] Decide compensation: resampling, async playout clock, or controlled
      skip/insert.
- [x] Report drift separately from network jitter.

Acceptance:

- [x] Stable long sessions do not require unbounded jitter growth.

Evidence:

- Build: `cmake --build build --target client --config Debug` passed.
- Each audio packet now keeps `sample_rate`, `sequence`, `frame_count`, and
  receive timestamp for drift estimation.
- Participant diagnostics now report `drift_ppm last/avg/max` separately from
  queue drift, packet age, underruns, and packet drops.
- Participant stats UI shows average drift ppm.
- Decision: if long-session drift proves audible or causes unbounded jitter
  growth, the preferred compensation path is receiver-side decoded-PCM
  resampling/time-scaling at the participant playout buffer boundary.
- Controlled skip/insert is rejected as the default jamming strategy because it
  can create clicks or timing discontinuities. It may still be useful only as a
  last-resort emergency correction.
- A separate async playout clock alone is not sufficient in this app because
  RtAudio/CoreAudio/WASAPI still call the output callback on the selected
  device clock; any correction has to happen before samples are mixed into that
  callback.
- Synthetic long-session check:
  `.\build\Debug\opus_receiver_harness.exe --scenario clean --packets 24000 --jitter 5 --auto-jitter`
  reported `final_jitter=5`, `auto_inc=0`, `auto_dec=0`, `underruns=0`,
  `plc=0`, and `status=ok`. This proves the current auto policy does not grow
  without bound on a stable synthetic session.
- Promotion validation: record real long-session drift on Windows/macOS. If that
  proves audible or causes unbounded buffering, implement the chosen
  receiver-side resampling/time-scaling compensation in a separate branch.

## Gate 5: Network Quality UX

Status: first actionable UI classifier implemented; live wording validation
remains external.

Deliverables:

- [x] Add quality states: `Stable`, `Jittery`, `Recovering`, `Poor`.
- [x] Show reason: packet age, underrun, PLC, queue drops, callback pressure, or
      bandwidth pressure.
- [x] Keep advanced stats available for development.

Acceptance:

- [x] Users can tell what to change without reading logs.

Evidence:

- Build: `cmake --build build --target client --config Debug` passed.
- Participant stats now show `Quality: Stable/Jittery/Recovering/Poor`.
- Participant stats now show a reason such as waiting for playout buffer, queue
  overflow/drop, packet age limit, underrun/PLC, packet gap/reorder, or clock
  drift.
- Participant stats now show `Action:` guidance next to the reason, such as
  raising jitter, enabling auto, raising the queue limit, using Ethernet, or
  recording long-session drift data.
- Existing advanced queue, age, PLC, drop, target trim, and drift stats remain
  visible under the same participant stats panel.
- Callback pressure remains visible in the local latency panel as `Late`.
- Bandwidth pressure remains visible through tx drop counters and logs; a
  product-level bandwidth label is deferred to product UI work.
- Promotion validation: tune exact wording and thresholds after live sessions.

## Gate 6: Opus Product Defaults

Status: tuning controls implemented; final stable-user default must still be
confirmed with live evidence before merging to `main`.

Deliverables:

- [x] Keep Opus `120` unless evidence disproves it.
- [x] Pick default jitter/auto behavior from probe results.
- [x] Add launch/config support for `--jitter` and `--auto-jitter` only after
      policy is chosen.
- [x] Keep PCM clearly labeled as reference/LAN/premium/experimental according
      to evidence.

Acceptance:

- [x] Normal users start from a stable default.
- [x] Advanced users can tune latency versus quality without editing code.

Evidence:

- Build: `cmake --build build --target client --config Debug` passed.
- Startup config smoke:
  `.\build\Debug\client.exe --startup-config-smoke --codec opus --frames 120 --jitter 7 --queue-limit 20 --age-limit-ms 80 --auto-jitter`
  reported `codec=opus frames=120 jitter=7 queue_limit=20 age_limit_ms=80 auto_jitter=true`.
- Startup flags now include `--jitter`/`--opus-jitter`,
  `--queue-limit`/`--opus-queue-limit`, `--age-limit-ms`, and
  `--auto-jitter`.
- Client and server now accept `--log-file <path>` so external validation runs
  can capture durable logs without relying on terminal scrollback.
- `tools/opus-log-summary.mjs` summarizes native `--log-file` output and marks
  logs as `warn` when they contain warning/error lines, audio health warnings,
  underruns, sequence issues, or other diagnostics needing review.
- Sidebar now includes a global `Auto jitter` default. Existing per-participant
  manual overrides remain higher priority than the global default.
- Codec selector now labels PCM as `PCM LAN/exp` and keeps Opus labeled as the
  compressed internet candidate via tooltip.
- Existing Electron/product launch can keep using `--codec opus --frames 120`;
  this branch does not change that contract.
- Current branch default remains conservative and explicit:
  - Opus `120` is the internet/cross-platform mode under test.
  - Receive jitter target defaults to `8` packets because the local and
    competitor evidence favors a conservative Opus internet default, not
    because local finite probes prove `8` is universally clean.
  - Queue limit defaults to `16` packets, giving burst capacity without using
    the queue limit as the main latency control.
  - Packet age limit defaults to `40 ms`, keeping old packets bounded while
    still allowing the default `8`-packet target room to breathe.
  - Auto jitter is enabled by default because competitor evidence favors
    automatic receive buffering and the harness shows auto reduces deterministic
    Wi-Fi/tunnel underruns without hiding the latency cost.
- Startup config smoke with no auto flag:
  `.\build\Debug\client.exe --startup-config-smoke --codec opus --frames 120`
  reported `auto_jitter=true`.
- Startup config smoke with manual opt-out:
  `.\build\Debug\client.exe --startup-config-smoke --codec opus --frames 120 --no-auto-jitter`
  reported `auto_jitter=false`.
- Advanced tuning is available without editing code through both the sidebar
  controls and startup flags: `--jitter`, `--queue-limit`, `--age-limit-ms`,
  `--auto-jitter`, and `--no-auto-jitter`.
- Final shipped stable-user default still needs live Windows/macOS and
  cross-machine evidence before merging this branch to `main`.

## Gate 7: Packet Loss Mitigation Research

Status: first harness measurement recorded; FEC/redundancy not justified for
this branch yet.

Deliverables:

- [x] Measure whether audible failures are loss, burst loss, jitter, scheduling,
      or drift.
- [x] Evaluate Opus in-band FEC behind a flag only if loss dominates.
- [x] Evaluate redundancy only if FEC is insufficient.

Acceptance:

- [x] Any mitigation has measured latency, quality, and bandwidth costs.

Evidence:

- Harness command:
  `.\build\Debug\opus_receiver_harness.exe --scenario loss --sweep`
  showed isolated packet loss still produces PLC underruns until high jitter
  targets such as `13+`.
- Harness command:
  `.\build\Debug\opus_receiver_harness.exe --scenario burst_loss --sweep`
  showed burst loss is worse: low targets hit `full_rebuffer`, and only very
  high targets such as `32` were clean in this deterministic scenario.
- Current evidence says loss/burst loss can be a real failure class, but it
  does not prove that FEC should ship yet.
- Current manual logs that motivated this branch showed queue/age/rebuffer
  behavior and no clear packet-loss dominance (`seq gap/late=0/0` in the
  reported runs). That makes jitter policy and playout correctness the first
  mitigation, not FEC.
- The current Opus encoder intentionally uses
  `OPUS_APPLICATION_RESTRICTED_LOWDELAY`, hard CBR-style pacing, and
  `OPUS_SET_INBAND_FEC(0)`. Adding in-band FEC would require a one-packet-late
  FEC decode strategy and measured latency/bitrate cost, so it should remain a
  separate experiment only after `udp_impair_proxy` proves real loss dominates.
- Redundancy is not justified before FEC because it is bandwidth-heavier and
  the current evidence does not show loss as the dominant live failure mode.
- No packet-loss mitigation is being shipped from this branch; therefore the
  current branch adds no hidden latency, quality, or bandwidth cost from FEC or
  redundancy.
- Cost gate result for this branch: no packet-loss mitigation is implemented or
  enabled. The measurement requirement reopens for the future branch that
  actually adds FEC or redundancy.

## Gate 8: PCM Premium Research Track

Status: deferred; not blocking Opus MVP path.

Deliverables:

- [x] Reproduce cross-machine-like PCM corruption programmatically.
- [x] Map capture, packetization, SFU forwarding, receive queue, playout, and
      output callback.
- [x] Compare PCM and Opus on the same impairment scenarios.
- [x] Decide whether PCM requires drift correction/resampling/scheduler changes.

Acceptance:

- [x] PCM is either proven for premium LAN/studio mode or labeled experimental.

Evidence:

- PCM is not proven for cross-machine premium LAN/studio mode yet.
- The client UI labels PCM as `PCM LAN/exp` and the tooltip says
  cross-machine PCM is still experimental.
- Current PCM path map:
  - RtAudio callback converts local mono float samples to PCM16.
  - Client sends `AudioCodec::PcmInt16` in `AudioHdrV2` with `sample_rate`,
    `frame_count`, `channels`, and `payload_bytes`.
  - SFU forwards the packet by room and overwrites sender ID; it does not
    decode, resample, mix, or re-clock.
  - Receiver enqueues by participant, uses packet metadata for frame count, and
    converts PCM16 back to float during playout.
  - Output callback mixes the decoded participant float samples into the local
    device callback.
- Same-impairment proxy comparison:
  - Opus `120`, jitter `5`, through
    `udp_impair_proxy --jitter-ms 8 --reorder-every 31 --reorder-delay-ms 8`
    improves relative to jitter `0` in local proxy evidence.
  - PCM `120`, jitter `5`, through the same proxy reported
    packet-valid output with no decode failures or size mismatches in recent
    local proxy evidence.
  - Interpretation: the local/proxy PCM path can be packet-valid but still more
    underrun-sensitive than Opus because PCM has no PLC safety net. This does
    not reproduce the cross-machine Windows/macOS robotic failure.
- Clock-skew reproduction:
  `.\build\Debug\latency_probe.exe --server 127.0.0.1 --port 19990 --codec pcm --frames 120 --jitter 5 --seconds 20 --playout-ppm 1000`
  against `server.exe --allow-insecure-dev-joins` reported `sent=8000`,
  `received=8000`, `decoded=8000`, `decode_failures=0`,
  `decoded_size_mismatches=0`, but `underruns=5` and warning indicators.
  This reproduces a PCM corruption class where packets are valid but receiver
  playout clock mismatch still creates gaps.
- Same clock-skew comparison with Opus:
  `.\build\Debug\latency_probe.exe --server 127.0.0.1 --port 19990 --codec opus --frames 120 --jitter 5 --seconds 20 --playout-ppm 1000`
  also reported `underruns=5`, but Opus had PLC (`plc_frames=5`) while PCM has
  no PLC safety net.
- Decision: cross-machine PCM should stay experimental until a receiver-side
  drift correction strategy exists. The preferred strategy is the same
  participant playout-boundary resampling/time-scaling direction chosen in
  Gate 4.5. A scheduler-only fix is not enough because the output device clock
  still owns callback cadence, and raw PCM has no Opus-style PLC fallback.
- This is a programmatic reproduction of a plausible cross-machine failure
  class, not proof that every Windows/macOS robotic report has the same root
  cause. Real Windows-to-macOS and macOS-to-Windows PCM validation remains in
  the external validation section.
- The research tasks above remain open because the Opus MVP path should not be
  blocked on the PCM investigation.

## External Promotion Validation Commands

This section is intentionally not an implementation TODO list. It is the
real-world evidence packet required before claiming the Opus path is
competitive/product-ready or promoting this branch to `main`.

These commands require the macOS machine, cross-machine audio, or a long-running
manual session. They stay unmarked until real logs exist.

- Standard smoke collector for each machine:
  `node tools/opus-validation.mjs smoke`
- macOS/CoreAudio latency contributor capture:
  `./build/client --audio-open-smoke --frames 120`
- macOS/CoreAudio Opus config smoke:
  `./build/client --startup-config-smoke --codec opus --frames 120`
- Long-session drift check:
  run two real clients for 30-60 minutes with Opus `120`, auto jitter on, and
  record `drift_ppm last/avg/max`, queue age, auto inc/dec, underruns, PLC, and
  whether jitter grows without bound.
- Summarize external client/server logs:
  `node tools/opus-log-summary.mjs --out validation/validation-summary.md <client-a.log> <client-b.log> <server.log>`
- Fill the external validation manifest from
  `OPUS_EXTERNAL_VALIDATION_MANIFEST.example.json` or initialize it with
  `node tools/opus-external-evidence-check.mjs --init validation/opus-external-validation.json ...`.
- Check the complete evidence packet:
  `node tools/opus-external-evidence-check.mjs validation/opus-external-validation.json`
- Full external validation runbook:
  `OPUS_EXTERNAL_VALIDATION_RUNBOOK.md`
- Cross-machine PCM reproduction:
  run Windows to macOS and macOS to Windows with PCM `120`, capture both client
  logs, and compare against the same path with Opus `120`.
- If PCM corruption reproduces:
  map whether the first failing stage is capture frame count, packet metadata,
  SFU forwarding, receive queue timing, playout callback size, or device clock
  drift.
