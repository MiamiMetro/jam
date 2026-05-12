# Opus Competitive Completion Audit

Date: 2026-05-12

Purpose: completion audit for the request to turn
`OPUS_COMPETITIVE_ROADMAP.md` into an executable implementation checklist,
implement the roadmap gates, and make the result evidence-backed and tested.

## Verdict

Implementation work in this branch is complete enough for local Windows/dev
review, but the goal is not fully achieved for promotion to `main` until the
external validation section is run on macOS and real cross-machine sessions.

Do not claim the Opus path is product-ready or competitor-grade from this branch
alone. Claim only that the roadmap has been converted into a checklist, the
local implementation gates are covered by code and tests, and the remaining
validation is explicitly documented.

Latest local evidence refresh:

- `node tools/opus-local-verify.mjs --out build/opus-local-verify/current`
  passed on Windows and wrote `build/opus-local-verify/current/report.md`
  with the current timestamp, platform, and source fingerprint.
- `node tools/opus-validation.mjs smoke` passed on Windows and wrote
  a timestamped `build/opus-validation/<timestamp>/report.md`; the current
  path is recorded in `build/opus-local-verify/current/report.md`.
- `node tools/opus-completion-audit.mjs --status` still reports
  `external manifest: missing`, which is the correct remaining blocker.

## Objective Restated As Deliverables

1. Keep `OPUS_COMPETITIVE_ROADMAP.md` as the roadmap, not the executable task
   list.
2. Create an implementation checklist for the roadmap.
3. Implement the roadmap gates in code where the current machine can verify
   them.
4. Back the implementation with deterministic tests, local SFU probes, and
   documented command output.
5. Preserve a clear boundary for work that cannot be verified on this Windows
   machine: macOS/CoreAudio, real cross-machine audio, and long sessions.

## Prompt-To-Artifact Checklist

| Requirement | Artifact | Evidence | Status |
| --- | --- | --- | --- |
| Roadmap stays non-executable | `OPUS_COMPETITIVE_ROADMAP.md` | File states it is an evidence-backed roadmap and points to the checklist. `rg -n -- "- \\[[ xX]\\]" OPUS_COMPETITIVE_ROADMAP.md` returns no matches. | Covered |
| Implementation checklist exists | `OPUS_COMPETITIVE_IMPLEMENTATION_CHECKLIST.md` | Contains gates 1 through 8 with deliverables, acceptance, and evidence. | Covered |
| Roadmap is not an implementation checklist | roadmap/checklist/audit/runbook docs | `tools/opus-local-verify.mjs` rejects any roadmap task checkbox, unchecked `- [ ]` boxes, and `Tasks:` markers in roadmap/checklist/audit/runbook docs. | Covered |
| Deterministic Opus receiver harness | `opus_receiver_harness.cpp` | Target builds and `opus_receiver_harness_self_test` passes. | Covered |
| Programmatic low-jitter failure reproduction | `opus_receiver_harness.cpp` | Self-test includes `wifi-low-target-fails`; checklist records Wi-Fi/tunnel sweeps. | Covered |
| End-to-end latency contributors | `client.cpp` | Checklist records callback, encode, send, queue, decode, playout, and output callback diagnostics. | Covered locally |
| Windows/WASAPI latency smoke | `client.cpp` | Checklist records `client.exe --audio-open-smoke --frames 120` result. | Covered locally |
| macOS/CoreAudio latency smoke | External Mac build | Command is documented, but has to be run on the Mac. | External validation |
| Repeatable external smoke collection | `tools/opus-validation.mjs` | `node tools/opus-validation.mjs smoke` writes timestamped logs and `report.md`. | Covered locally; run again on Mac |
| Repeatable local SFU/proxy evidence | `tools/opus-local-evidence.mjs` | `node tools/opus-local-evidence.mjs` starts a local SFU/proxy, runs direct Opus probes, impaired Opus/PCM probes, multi-participant jitter isolation, and the external checker self-test. | Covered locally |
| One-command local verifier | `tools/opus-local-verify.mjs` | Runs native build, harness self-test, JS checks, parser self-tests, smoke, local evidence, competitor evidence, doc checkbox/task-marker check, repo source fingerprinting, generated-directory source-fingerprint exclusion, critical source-fingerprint coverage, line-ending fingerprint normalization, source whitespace hygiene across source-fingerprint files, rejects source-controlled output paths for generated evidence, and `git diff --check`; wrote `build/opus-local-verify/current/report.md`. | Covered locally |
| Durable native logs for validation | `client.cpp`, `server.cpp` | Both binaries accept `--log-file <path>`; smoke/local-evidence scripts verify client/server file logs are written. | Covered locally |
| Repeatable log analysis | `tools/opus-log-summary.mjs` | Parses client/server `--log-file` output, summarizes diagnostics, marks warning indicators including drift above `250 ppm`, and rejects repo-local `--out` paths unless git ignores them as generated evidence. | Covered locally |
| External evidence packet gate | `OPUS_EXTERNAL_VALIDATION_MANIFEST.example.json`, `tools/opus-external-evidence-check.mjs` | Manifest/checker require Windows smoke with `Platform: win32`, Mac smoke with `Platform: darwin`, matching line-ending-normalized smoke `Source SHA256` fingerprints for the current checkout, neighboring smoke `startup-default-client.log` files proving expected platform and Opus `120`, Opus `120` plus `jitter: 8` session metadata, explicit validation room, explicit speaker/listener platforms for both cross-machine directions, direction-specific subjective notes proving Windows source was judged on macOS and macOS source was judged on Windows, native client runtime log lines for Windows and macOS, server runtime log for the session, client-log proof of `Startup codec override: Opus`, `Startup requested buffer override: 120 frames`, startup jitter `8`, startup auto jitter enabled, expected `Sent JOIN for room ...`, server-log proof of matching `JOIN: ... room='...'`, at least one non-loopback server JOIN endpoint with IPv4, bracketed IPv6, full-form IPv6, and IPv4-mapped IPv6 loopback-only logs rejected, and `Audio diag: frames=120`, long-session logs with Windows and macOS participants, distinct log paths per session, at least two diagnostic logs covering each session duration, real subjective/network notes that are not loopback/same-machine, unroutable/unspecified, or unreviewed bad-audio reports, minimum durations, explained warning indicators including underruns, sequence gaps/late packets, and drift above `250 ppm`, and smoke/log evidence paths that are outside the repo or ignored generated evidence. The checker can initialize a manifest from real paths and only audio-open smoke failure can be allowed with explicit explanation. | Covered as tooling; external data still required |
| External validation runbook | `OPUS_EXTERNAL_VALIDATION_RUNBOOK.md` | Gives concrete Windows/macOS smoke, session, logging, summary, and acceptance steps. | Covered as runbook |
| External command generation | `tools/opus-external-commands.mjs` | Generates Windows/macOS SFU/client commands with signed validation tokens, distinct validation rooms, Opus `120`, `--jitter 8`, `--auto-jitter`, validation-directory creation commands, `--log-file` paths, a log-collection layout, summary command, manifest init/check commands that pass the same room IDs, active talker/listener directions for each 5-minute session, generated/expiry UTC timestamp headers, a regenerate-if-expiring warning, current `Source SHA256` preflight, and the final strict `opus-acceptance` command. It fails closed without explicit non-loopback `--server-host`, rejects source-controlled `--write`, `--out-dir`, and `--manifest` paths, rejects invalid/too-short validation TTL values, uses a TTL long enough for the required validation sequence, and local verification checks generated token room/user/server/signature integrity, header/token-expiry agreement, and source-fingerprint preflight. | Covered as tooling; external data still required |
| Generated validation artifacts are not source | `.gitignore`, `tools/opus-local-verify.mjs`, `tools/opus-source-fingerprint.mjs` | `validation/` and `validation_logs/` are ignored and excluded from `Source SHA256` because generated command sheets, manifests, summaries, signed dev tokens, and runtime logs are machine-specific evidence. The local verifier includes `validation-dir-gitignored` and `source-fingerprint-generated-dirs`, and `.gitignore` is part of the repo source fingerprint. | Covered locally |
| Smoke validation output is generated evidence | `tools/opus-local-verify.mjs`, `tools/opus-validation.mjs` | The local verifier runs `opus-validation-rejects-unignored-output`, expecting smoke validation to reject repo-local `--out` paths unless git ignores the generated report/log directory. | Covered locally |
| Local evidence output is generated evidence | `tools/opus-local-verify.mjs`, `tools/opus-local-evidence.mjs` | The local verifier runs `opus-local-evidence-rejects-unignored-output`, expecting local evidence generation to reject repo-local `--out` paths unless git ignores the generated report/log directory. | Covered locally |
| External command sheet is generated evidence | `tools/opus-local-verify.mjs`, `tools/opus-external-commands.mjs` | The local verifier runs `opus-external-commands-rejects-unignored-write`, expecting command generation to reject repo-local `--write` paths unless git ignores the generated command sheet. | Covered locally |
| Log summaries are generated evidence | `tools/opus-local-verify.mjs`, `tools/opus-log-summary.mjs` | The local verifier runs `opus-log-summary-rejects-unignored-output`, expecting log summary generation to reject repo-local `--out` paths unless git ignores the generated summary. | Covered locally |
| Local verifier output is generated evidence | `tools/opus-local-verify.mjs` | The local verifier runs `opus-local-verify-rejects-unignored-output`, expecting nested verifier execution to reject repo-local `--out` paths unless git ignores the generated report. | Covered locally |
| Completion audit local report is generated evidence | `tools/opus-local-verify.mjs`, `tools/opus-completion-audit.mjs` | The local verifier runs `opus-completion-audit-rejects-unignored-local-report`, expecting the completion audit to reject repo-local `--local-report` paths unless git ignores the generated report. | Covered locally |
| Custom validation room propagation | `tools/opus-local-verify.mjs`, `tools/opus-external-commands.mjs` | The local verifier generates a second command packet with custom validation room names and checks that Windows-to-macOS, macOS-to-Windows, and long-session room IDs propagate into the command packet, manifest init command, and generated join tokens. | Covered locally |
| Final acceptance command | `tools/opus-acceptance.mjs` | Requires `--external-manifest`, rejects repo-local manifests that are not ignored generated evidence, runs local verification unless skipped with explicit `--use-saved-local-report`, requires the saved local report to exist in saved-report mode, runs the external evidence checker in strict mode, then runs the full completion audit with the same manifest and the actual local verifier report path from `--local-out`. It cannot pass from local proxy evidence alone or from a warning-allowed manifest. | Covered as tooling; external data still required |
| Completion audit command | `tools/opus-completion-audit.mjs` | Prints the restated objective and prompt-to-artifact checklist, verifies required roadmap/checklist/audit/runbook docs exist, rejects roadmap task checkboxes, has a concise `--status` mode that distinguishes missing, failing, warning-only, and strict-passing external manifests, passes only in `--local-only` mode without claiming full completion, checks the saved local verifier report for required build, syntax, self-test, local-evidence, generated-command, final-acceptance-audit wiring, token-integrity, source-fingerprint coverage, source-whitespace, fail-closed, and diff-check steps, requires non-empty companion logs for required verifier rows, rejects local reports older than 24 hours, supports `--local-report` for acceptance runs with custom output paths, rejects source-controlled local report paths, rejects stale source fingerprints, and requires a passing real external manifest for full completion. | Covered as tooling; external data still required |
| Final acceptance fails closed without external evidence | `tools/opus-local-verify.mjs` | The local verifier runs `opus-acceptance-requires-external-manifest`, expecting `tools/opus-acceptance.mjs` to fail when pointed at a missing manifest. | Covered locally |
| Final acceptance rejects source-controlled external manifests | `tools/opus-local-verify.mjs`, `tools/opus-acceptance.mjs` | The local verifier runs `opus-acceptance-rejects-unignored-external-manifest`, expecting the acceptance command to reject repo-local external manifests unless git ignores them as generated evidence. | Covered locally |
| Final acceptance rejects placeholder generated manifests | `tools/opus-local-verify.mjs`, `tools/opus-acceptance.mjs` | The local verifier runs `opus-acceptance-rejects-ignored-placeholder-manifest`, expecting the acceptance command to reject an ignored generated manifest when it lacks real Windows/macOS evidence. | Covered locally |
| Final acceptance rejects unacknowledged local-skip | `tools/opus-local-verify.mjs`, `tools/opus-acceptance.mjs` | The local verifier runs `opus-acceptance-rejects-unacknowledged-skip-local`, expecting acceptance to refuse `--skip-local` unless `--use-saved-local-report` is also provided. | Covered locally |
| Final acceptance rejects source-controlled local output | `tools/opus-local-verify.mjs`, `tools/opus-acceptance.mjs` | The local verifier runs `opus-acceptance-rejects-unignored-local-out` and `opus-acceptance-rejects-skip-local-unignored-local-out`, expecting final acceptance to reject repo-local `--local-out` paths unless git ignores the generated verifier report, including saved-report mode. | Covered locally |
| Final acceptance rejects missing saved local report | `tools/opus-local-verify.mjs`, `tools/opus-acceptance.mjs` | The local verifier runs `opus-acceptance-rejects-missing-saved-local-report`, expecting saved-report final acceptance to fail before external evidence checking when the referenced verifier report does not exist. | Covered locally |
| External checker rejects template evidence | `tools/opus-local-verify.mjs`, `OPUS_EXTERNAL_VALIDATION_MANIFEST.example.json` | The local verifier runs `opus-external-evidence-rejects-example-manifest`, expecting the evidence checker to reject the example manifest because it contains placeholders and no real logs. | Covered locally |
| External checker rejects invalid manifest files | `tools/opus-local-verify.mjs`, `tools/opus-external-evidence-check.mjs` | The local verifier runs malformed, non-object, malformed-boolean, malformed-type, unknown-field, and missing-manifest checks, expecting the evidence checker to fail closed with clear manifest errors. | Covered locally |
| External checker rejects source-controlled evidence paths | `tools/opus-local-verify.mjs`, `tools/opus-external-evidence-check.mjs` | The local verifier runs source-controlled smoke-report and session-log path checks, expecting the evidence checker to reject repo-local evidence inputs unless git ignores them as generated evidence. | Covered locally |
| External manifest init rejects source-controlled paths and placeholder notes | `tools/opus-local-verify.mjs`, `tools/opus-external-evidence-check.mjs` | The local verifier runs manifest-output, smoke-input, and log-input expected failures, expecting `--init` to reject repo-local paths unless git ignores them as generated evidence. The evidence checker self-test also proves initialized manifests preserve paths/rooms but still fail until network and subjective notes are edited. | Covered locally |
| Completion audit rejects source-controlled external manifests | `tools/opus-local-verify.mjs`, `tools/opus-completion-audit.mjs` | The local verifier runs `opus-completion-audit-rejects-unignored-external-manifest`, expecting the completion audit to reject repo-local external manifests unless git ignores them as generated evidence. | Covered locally |
| Completion audit rejects placeholder generated manifests | `tools/opus-local-verify.mjs`, `tools/opus-completion-audit.mjs` | The local verifier runs `opus-completion-audit-rejects-ignored-placeholder-manifest`, expecting the completion audit to reject an ignored generated manifest when it lacks real Windows/macOS evidence. | Covered locally |
| Receiver playout correctness | `client.cpp`, `opus_receiver_harness.cpp` | Queue limit, age limit, target trim, PLC, and rebuffer behavior are covered by harness and proxy evidence. | Covered |
| Real UDP impairment tool | `udp_impair_proxy.cpp` | Target builds; help smoke passed; local proxy probe evidence recorded. | Covered locally |
| Per-participant manual jitter | `client.cpp`, `participant_info.h`, `participant_manager.h`, `multi_participant_jitter_probe.cpp` | Non-GUI actual-SFU probe shows stable and unstable participants can use different targets. | Covered locally |
| Per-participant auto jitter | `client.cpp`, `opus_receiver_harness.cpp` | Harness shows auto increases target and reduces deterministic Wi-Fi/tunnel underruns. | Covered deterministically |
| Live remote auto-jitter validation | External two-machine run | Command/path is documented, but requires real remote participants. | External validation |
| Receiver drift measurement | `client.cpp`, `participant_info.h` | Drift ppm is reported separately from queue drift and jitter. | Covered |
| Drift compensation decision | `OPUS_COMPETITIVE_IMPLEMENTATION_CHECKLIST.md` | Decision recorded: receiver-side decoded-PCM resampling/time-scaling if real drift requires compensation. | Covered as decision |
| Drift compensation implementation | Future branch | Deferred until real long-session evidence shows it is needed. | Deferred |
| Network quality UX | `client.cpp` | Participant stats show quality, reason, action, and advanced counters. | Covered locally |
| Opus product defaults | `client.cpp`, `protocol.h` | Opus `120`, jitter default `8`, queue limit, age limit, auto jitter default, and startup flags are recorded. | Covered locally |
| Packet-loss mitigation decision | `OPUS_COMPETITIVE_IMPLEMENTATION_CHECKLIST.md` | Loss/burst-loss harness evidence recorded; FEC/redundancy not justified in this branch. | Covered as research decision |
| PCM premium research | `OPUS_COMPETITIVE_IMPLEMENTATION_CHECKLIST.md` | PCM is labeled experimental; packet-valid but drift-sensitive failure class is documented. | Covered as deferred research |
| Cross-machine PCM validation | External Windows/macOS run | Required command is documented, but real cross-machine validation still has to be run. | External validation |
| Competitor evidence exists locally | `.cache/upstream-audio`, `tools/opus-competitor-evidence-check.mjs` | SonoBus, Jamulus, JackTrip, and AOO source/docs are verified by a repeatable checker; exact references are listed below. | Covered |

## Competitor Evidence References

These local cache references back the roadmap's competitive direction:

- SonoBus per-user manual/automatic jitter control:
  `.cache/upstream-audio/sonobus/doc/SonoBus User Guide.md:16`
- SonoBus Wi-Fi warning and Ethernet recommendation:
  `.cache/upstream-audio/sonobus/doc/SonoBus User Guide.md:33`
- SonoBus per-participant optimum buffer sizing:
  `.cache/upstream-audio/sonobus/doc/SonoBus User Guide.md:150`
- SonoBus receive jitter auto behavior and initial auto:
  `.cache/upstream-audio/sonobus/doc/SonoBus User Guide.md:158`
  and `.cache/upstream-audio/sonobus/doc/SonoBus User Guide.md:160`
- SonoBus Opus/compressed minimum frame size and PCM distinction:
  `.cache/upstream-audio/sonobus/doc/SonoBus User Guide.md:213`
- AOO automatic buffer extension/reduction and resampling/time-drift direction:
  `.cache/upstream-audio/sonobus/deps/aoo/doku/aoo_protocol.rst:194`
  and `.cache/upstream-audio/sonobus/deps/aoo/doku/aoo_protocol.rst:198`
- Jamulus configurable client/server jitter buffer protocol:
  `.cache/upstream-audio/jamulus/docs/JAMULUS_PROTOCOL.md:53`,
  `.cache/upstream-audio/jamulus/docs/JAMULUS_PROTOCOL.md:63`, and
  `.cache/upstream-audio/jamulus/docs/JAMULUS_PROTOCOL.md:178`
- Jamulus simulated jitter buffers and auto setting:
  `.cache/upstream-audio/jamulus/src/buffer.cpp:414`,
  `.cache/upstream-audio/jamulus/src/buffer.cpp:537`, and
  `.cache/upstream-audio/jamulus/src/buffer.cpp:661`
- JackTrip queue buffer and auto queue behavior:
  `.cache/upstream-audio/jacktrip/src/JitterBuffer.cpp:60`,
  `.cache/upstream-audio/jacktrip/src/JitterBuffer.cpp:210`, and
  `.cache/upstream-audio/jacktrip/src/JitterBuffer.cpp:227`
- JackTrip regulator auto headroom/tolerance:
  `.cache/upstream-audio/jacktrip/src/Regulator.cpp:100`,
  `.cache/upstream-audio/jacktrip/src/Regulator.cpp:488`, and
  `.cache/upstream-audio/jacktrip/src/Regulator.cpp:589`
- JackTrip optional UDP redundancy:
  `.cache/upstream-audio/jacktrip/docs/Documentation/NetworkProtocol.md:132`
  and `.cache/upstream-audio/jacktrip/docs/Documentation/NetworkProtocol.md:134`

Source-citation verification is now automated by
`tools/opus-competitor-evidence-check.mjs`. The checker proves the referenced
files exist and contain the cited per-user jitter, auto jitter, Wi-Fi/Ethernet,
automatic buffering, resampling, Jamulus simulation-buffer, JackTrip
auto-queue, and JackTrip redundancy evidence.

## Verification Commands Run

- `node tools/opus-local-verify.mjs --out build/opus-local-verify/current`
  - wrote `build/opus-local-verify/current/report.md`
  - latest refresh records the current timestamp, Windows platform, and source
    fingerprint in that report
  - Debug and Release native builds, harness, JS syntax, smoke, local
    evidence, competitor-source evidence, parser self-test, documentation
    hygiene, source fingerprinting, generated-directory source-fingerprint
    exclusion, critical source-fingerprint coverage, source whitespace hygiene, and
    `git diff --check` steps exited `0`
  - documentation hygiene now rejects roadmap task checkboxes, unchecked
    `- [ ]` boxes, and `Tasks:` markers in roadmap/checklist/audit/runbook docs
  - generated external command packets are checked for `--codec opus`,
    `--frames 120`, `--jitter 8`, `--auto-jitter`, the 4-hour validation TTL,
    generated/expiry timestamp headers, a regenerate-if-expiring warning,
    current source-fingerprint preflight, generated join-token integrity,
    header/token-expiry agreement, strict external-checker wiring in final
    acceptance, the checker-machine preflight commands, the
    summary/init/check/final-acceptance commands, and the log collection
    section, including validation-directory
    creation commands, strict-mode final acceptance wording, and the active
    talker/listener direction for Windows-to-macOS, macOS-to-Windows, and
    long-session validation
- `cmake --build build --config Debug`
- `cmake --build build --config Release`
- `cmake --build build --target opus_receiver_harness_self_test --config Debug`
- `node tools/opus-validation.mjs smoke`
  - latest Windows refresh wrote a timestamped
    `build/opus-validation/<timestamp>/report.md`; the current path is
    recorded in `build/opus-local-verify/current/report.md`
  - `startup-default`, `startup-no-auto`, `harness-self-test`, and
    `audio-open` all exited `0`
  - client file logs were written as `startup-default-client.log`,
    `startup-no-auto-client.log`, and `audio-open-client.log`
- `node tools/opus-local-evidence.mjs`
  - wrote a timestamped `build/opus-local-evidence/<timestamp>/report.md`
  - all process steps exited `0`, including
    `log-summary-self-test` and `external-evidence-checker-self-test`
  - direct Opus jitter `5` and jitter `8` proved valid decode; occasional
    finite-probe PLC/underrun indicators are reported as warnings rather than
    hidden or treated as product proof
  - impaired Opus jitter `0` showed PLC/underrun warning indicators
  - impaired Opus jitter `5` improved relative to jitter `0`; this is local
    proxy improvement evidence, not a substitute for Windows/macOS GUI-client
    validation or a clean-pass claim
  - the PCM probe is explicitly a warning/research result, not a release gate
  - server file logging was verified in `server-file.log`
- `node tools/opus-log-summary.mjs --out build/opus-validation/<timestamp>/log-summary.md build/opus-validation/<timestamp>/startup-default-client.log build/opus-validation/<timestamp>/audio-open-client.log build/opus-local-evidence/<timestamp>/server-file.log`
  - wrote a Markdown summary and correctly surfaced warning/error lines as
    `warn`
- `node tools/opus-log-summary.mjs --out build/opus-log-summary-test/summary.md build/opus-log-summary-test/drift.log`
  - verified drift above `250 ppm` is marked `warn`
- `node --check tools/opus-external-evidence-check.mjs`
- `node --check tools/opus-validation.mjs`
- `node --check tools/opus-local-evidence.mjs`
- `node --check tools/opus-log-summary.mjs`
- `node --check tools/opus-external-commands.mjs`
- `node --check tools/opus-acceptance.mjs`
- `node --check tools/opus-completion-audit.mjs`
- `node tools/opus-external-commands.mjs --secret dev-secret --server-host 192.168.1.50 --write build/opus-external-commands-test/commands.md`
  - wrote a Markdown command packet with Windows/macOS SFU/client commands,
    Opus `120` flags, log paths, summary command, and manifest check command
- `node tools/opus-local-verify.mjs --out build/opus-local-verify/current`
  - includes `opus-acceptance-requires-external-manifest`, which passes only
    when the acceptance command refuses a missing external manifest
  - includes `opus-completion-audit-requires-external-manifest`, which passes
    only when the completion audit refuses to claim completion without a real
    external manifest
  - includes `opus-completion-audit-rejects-missing-local-report`, which passes
    only when the completion audit refuses a missing custom `--local-report`
    path with a rerun instruction
  - includes `opus-completion-audit-rejects-missing-companion-log`, which
    passes only when the completion audit refuses a verifier report whose
    required step row points at a missing companion log
  - includes `opus-completion-audit-rejects-stale-local-report`, which passes
    only when the completion audit refuses a local verifier report older than
    24 hours
  - includes `opus-completion-audit-status-incomplete`, which passes only when
    the concise status command reports incomplete before external validation
    exists
  - includes `opus-completion-audit-status-external-fail`, which passes only
    when the concise status command reports a supplied failing external
    manifest as `fail`
  - includes `opus-completion-audit-rejects-unignored-external-manifest`, which
    passes only when the completion audit refuses repo-local external manifests
    unless they are ignored generated evidence
  - includes `opus-acceptance-rejects-unignored-external-manifest`, which
    passes only when the acceptance command refuses repo-local external
    manifests unless they are ignored generated evidence
  - includes `opus-acceptance-rejects-ignored-placeholder-manifest`, which
    passes only when the acceptance command still rejects ignored generated
    manifests that lack real evidence
  - includes `opus-acceptance-rejects-unacknowledged-skip-local`, which passes
    only when final acceptance refuses an accidental local-verification skip
  - includes `opus-acceptance-rejects-unignored-local-out`, which passes only
    when final acceptance refuses source-controlled local verifier output paths
  - includes `opus-acceptance-rejects-skip-local-unignored-local-out`, which
    passes only when the same refusal applies in saved-report mode
  - includes `opus-acceptance-rejects-missing-saved-local-report`, which
    passes only when saved-report final acceptance refuses a missing verifier
    report before external evidence checking
  - includes `opus-external-evidence-rejects-example-manifest`, which passes
    only when the external evidence checker refuses the placeholder example
    manifest itself
  - includes malformed, non-object, malformed-boolean, malformed-type,
    unknown-field, and missing-manifest evidence checker checks, which pass
    only when invalid manifest files fail closed with clear manifest errors
  - includes source-controlled smoke-report and session-log path checks, which
    pass only when the external evidence checker refuses generated evidence
    inputs that could be staged as source
  - includes `opus-external-evidence-init-rejects-unignored-manifest`, which
    passes only when manifest initialization refuses source-controlled output
    paths
  - includes `opus-external-evidence-init-rejects-unignored-smoke-input` and
    `opus-external-evidence-init-rejects-unignored-log-input`, which pass only
    when manifest initialization refuses source-controlled evidence input paths
  - includes `opus-completion-audit-rejects-ignored-placeholder-manifest`,
    which passes only when the completion audit still rejects ignored generated
    manifests that lack real evidence
  - includes `opus-validation-rejects-unignored-output` and
    `opus-local-evidence-rejects-unignored-output`, which pass only when smoke
    validation and local evidence refuse source-controlled output paths
  - includes `opus-log-summary-rejects-unignored-output`, which passes only
    when log summary generation refuses source-controlled output paths
  - includes `opus-external-commands-requires-server-host`, which passes only
    when command generation refuses to silently default external clients to
    loopback
  - includes `opus-external-commands-rejects-unignored-out-dir` and
    `opus-external-commands-rejects-unignored-manifest`, which pass only when
    command generation refuses source-controlled evidence output paths
  - includes `opus-external-commands-rejects-loopback-host`,
    `opus-external-commands-rejects-ipv6-loopback-host`, and
    full-form IPv6 host:port variants plus
    `opus-external-commands-rejects-unspecified-host`, which pass only when
    command generation refuses loopback/unroutable hosts by default
  - includes `opus-external-commands-rejects-invalid-ttl` and
    `opus-external-commands-rejects-short-ttl`, which pass only when command
    generation refuses unusable validation token TTL values
- `node tools/opus-external-evidence-check.mjs --self-test`
  - passed clean manifest, explained `audio-open` smoke failure, and placeholder
    rejection cases
  - also verifies the actual `--strict` CLI path rejects a warning-allowed
    manifest before final acceptance can promote it
  - also rejects sequence-gap, large-drift, wrong-platform, missing smoke
    startup log, wrong speaker/listener role, wrong-codec, wrong client startup
    frames, wrong manifest jitter, wrong client startup jitter, wrong client
    joined validation room, wrong server joined validation room, missing client
    startup auto jitter, missing client startup codec, missing session room
    metadata, loopback/same-machine or unroutable network descriptions,
    bad-audio subjective reports, missing directional subjective notes, IPv4,
    bracketed IPv6, full-form IPv6, and IPv4-mapped IPv6 loopback-only server
    JOIN endpoints, missing server
    runtime proof, weak diagnostic-duration, and
    reused log-path fixture logs
  - rejects session logs missing the expected Windows/macOS native client
    runtime lines
- `node tools/opus-external-evidence-check.mjs --init build/opus-external-check-test/init.json --windows-smoke build/opus-validation/<timestamp>/report.md --mac-smoke build/opus-validation/<timestamp>/report.md`
  - writes an initialized manifest; it still requires real Mac paths and notes
    before promotion
- `node tools/opus-external-evidence-check.mjs OPUS_EXTERNAL_VALIDATION_MANIFEST.example.json`
  - intentionally failed because the template does not contain real Mac
    smoke reports, cross-machine logs, or long-session evidence yet
- `node tools/opus-acceptance.mjs --skip-local --external-manifest OPUS_EXTERNAL_VALIDATION_MANIFEST.example.json`
  - intentionally failed closed because the example manifest is placeholder
    evidence, not real Windows/macOS validation
- `git diff --check`
- `rg -n -- "^\\s*-\\s+\\[\\s\\]|^\\s*Tasks:\\s*$" OPUS_COMPETITIVE_ROADMAP.md OPUS_COMPETITIVE_IMPLEMENTATION_CHECKLIST.md OPUS_COMPETITIVE_COMPLETION_AUDIT.md OPUS_EXTERNAL_VALIDATION_RUNBOOK.md`
  - intentionally returned no matches, proving there are no remaining real
    roadmap task checkboxes, unchecked task items, or ambiguous `Tasks:`
    markers in those docs
- `node tools/opus-competitor-evidence-check.mjs`
  - verified the local upstream cache contains the cited competitor evidence

## Remaining External Validation

These are not implementation checklist items because they cannot be run from
this Windows-only workspace:

- Run macOS/CoreAudio smoke:
  `node tools/opus-validation.mjs smoke`
- If the smoke collector cannot find the Mac build path, pass explicit paths:
  `node tools/opus-validation.mjs smoke --client build/client --harness build/opus_receiver_harness`
- Direct macOS/CoreAudio smoke command:
  `./build/client --audio-open-smoke --frames 120`
- Run macOS/CoreAudio startup config smoke:
  `./build/client --startup-config-smoke --codec opus --frames 120`
- Run real Windows-to-macOS and macOS-to-Windows Opus sessions with auto jitter.
  Use `--log-file <path>` on each client so the session has durable evidence.
- Run one long 30-60 minute Opus session and record drift, queue age,
  underruns, PLC, and auto-jitter changes.
- Summarize the resulting logs:
  `node tools/opus-log-summary.mjs --out validation/validation-summary.md <client-a.log> <client-b.log> <server.log>`
- Initialize the external manifest from real smoke reports and session logs:
  `node tools/opus-external-evidence-check.mjs --init validation/opus-external-validation.json ...`
- Replace placeholder network descriptions and subjective notes in the generated
  manifest.
- Validate the external evidence packet:
  `node tools/opus-external-evidence-check.mjs validation/opus-external-validation.json`
- Follow the full runbook:
  `OPUS_EXTERNAL_VALIDATION_RUNBOOK.md`
- Run cross-machine PCM only as research; do not promote PCM until the failure
  is explained or corrected.

## Blocking Requirements Before Goal Completion

The original objective asked for the roadmap to be implemented and made
competitive, evidence-backed, and tested. Local implementation coverage and
local evidence tooling are complete, but local finite probes are not clean
product proof and do not replace external Windows/macOS validation. These
requirements are still blocking full goal completion:

| Blocking requirement | Why local evidence is insufficient | Required evidence |
| --- | --- | --- |
| macOS/CoreAudio Opus smoke | Windows smoke cannot prove CoreAudio startup, device opening, callback size behavior, or log output. | A macOS `node tools/opus-validation.mjs smoke` report with `Platform: darwin`, plus neighboring `startup-default-client.log` proving macOS runtime and Opus `120`. |
| Windows-to-macOS Opus session | Local Windows probes cannot prove cross-machine network, device, and scheduling behavior. | At least a 5-minute Windows-speaker/macOS-listener session manifest entry with both client logs, server log, runtime lines, Opus `120` startup lines, diagnostics, and subjective note. |
| macOS-to-Windows Opus session | The reverse direction can fail differently because sender and receiver audio stacks swap roles. | At least a 5-minute macOS-speaker/Windows-listener session manifest entry with the same log requirements. |
| Long-session stability | Short local probes cannot prove no drift, queue growth, auto-jitter runaway, or late-session instability. | A 30-60 minute external session with Windows and macOS client logs and a passing external evidence manifest. |
| Competitive/product-ready claim | Competitor-aligned design plus local probes are not the same as real cross-platform jam validation. | `node tools/opus-external-evidence-check.mjs validation/opus-external-validation.json` passes against real logs and reports. |

Until those rows are satisfied, this branch should be described as:

- local implementation gates complete
- external validation tooling complete
- Opus competitive path not yet externally proven

## Completion Rule

This audit is complete only for local implementation coverage and local
verification tooling. The active goal should not be marked fully complete until
the external validation above is either run and passes, or the goal is
explicitly narrowed to local implementation only.
