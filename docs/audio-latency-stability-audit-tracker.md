# Audio Latency / Stability Audit Tracker

Source audit: `docs/audio-latency-stability-audit.md`

Use this file as the live execution board. A finding is complete only when its
checkbox is checked and its status is `VERIFIED` or `ACCEPTED`.

Status values:

- `TODO`: not started
- `IN PROGRESS`: implementation or diagnostics underway
- `FIXED`: code/config/docs changed, but final proof is still pending
- `VERIFIED`: tests and/or runtime measurement prove the finding is handled
- `ACCEPTED`: no code change needed; rationale recorded
- `DEFERRED`: intentionally postponed with a reason

## Completion Gates

- Every `F1` through `F13` must have an explicit status.
- Critical/high findings need a regression test or runtime measurement.
- Runtime-sensitive fixes need before/after evidence from loopback or controlled impairment.
- Config/default/UI changes must include validation for unsafe combinations.
- The final closeout must include a fresh Release build and full `ctest` run.

## Findings

| Done | ID | Severity | Status | Scope | Required change | Verification gate | Notes |
|---|---:|---|---|---|---|---|---|
| [x] | F1 | Critical | VERIFIED | Client playout rate | Target jitter depth, not `queue_limit / 2`; add deadband and drift-scale clamp | Unit/self-test proves ratio is near `1.0` at target depth across jitter targets and queue limits; loopback shows no sustained `0.95` pin | Loopback baseline shows queue stays at 1-2 packets and playout ratio stays `1.0000` |
| [x] | F2 | Critical | VERIFIED | Client jitter/age-drop feedback | Stop self-inflicted age drops from raising jitter or forcing rebuffer | Test proves age-drop from local overfill does not increase target; runtime loopback shows no latency creep/rebuffer loop | Loopback baseline shows no age drops, no auto-jitter increases, and no rebuffer loop; global and participant jitter-ms setters clamp to the age limit |
| [x] | F3 | High | VERIFIED | Config/default jitter units | Express jitter in ms and compute packets from frame size; reduce default floor/start | Tests cover 120/240/480/960 frame conversion; UI/config shows ms semantics | Defaults are now 20 ms floor and 40 ms auto-start; global and participant UI edit jitter in ms; startup logs include effective ms |
| [x] | F4 | High | VERIFIED | Auto-jitter controller | Replace upward-only ratchet with windowed/symmetric adjustment; avoid forced rebuffer on target rise | Test proves clean input decays to floor within bounded time and isolated events do not permanently ratchet | `client_auto_jitter_empty_playout_smoke` proves sparse events do not raise immediately, burst windows raise by one, and clean windows decay to floor within bounded callbacks |
| [x] | F5 | High | VERIFIED | Gap wait/PLC policy | Cap gap wait to 1-2 packet intervals; skip larger gaps to newest contiguous run; reduce PLC/reset behavior | Probe test proves bounded PLC run and no long concealment stall under missing packet/reorder cases | Gap wait is now one packet interval and queue-limit independent; PLC cap is 2; `participant_packet_queue_self_test`, `client_opus_playout_policy_smoke`, and `latency_probe_large_gap_smoke` pass |
| [x] | F6 | Medium | ACCEPTED | Frame-count adaptation | Keep manual mode or remove/dead-code document inactive escalators/rebind; do not re-enable until F7 fixed | Tests/build show no active frame-count auto-promote path; tracker records future re-enable requirements | Kept manual mode; feedback handlers log diagnostics and do not call frame-count mutation or UDP rebind |
| [x] | F7 | Medium | VERIFIED | Server ingress stats | Report net-unrecovered loss after redundancy recovery, not gross sequence gaps | Server/self-test proves recovered redundant packets are subtracted from loss control signal | `server_audio_path_feedback_smoke` now sends a redundant repair and proves gross gap is reported with zero net gap; client net-loss percent uses `unrecovered / (received + gross gaps)` |
| [x] | F8 | Medium | VERIFIED | Redundancy policy | Expose redundancy depth/policy and scale cost with packet rate | Config/test proves depth choices affect wrapping; bandwidth math documented for presets | Sender policy now supports auto/off/explicit previous-packet depth; auto uses 1 previous at 120-frame packets, 2 at 240/480, and 3 at 960 |
| [x] | F9 | Medium | VERIFIED | Packetization validation | Validate jitter/age/gap settings across frame sizes; reject target above age limit | Tests cover unsafe 960-frame auto-start and frame-size transitions | `client_startup_config_jitter_ms_scaling_smoke` proves 40 ms maps to 2 packets at 960 frames; age validation keeps jitter target <= age limit |
| [x] | F10 | Low-Med | VERIFIED | Windows audio API ranking | Match JUCE Windows API names; prefer exclusive/low-latency modes; surface active mode | Unit test for ranking names; runtime/API listing check if available | Ranking now matches `Windows Audio`, `Windows Audio (Exclusive Mode)`, and `Windows Audio (Low Latency Mode)`; startup smoke confirmed those names are present locally |
| [x] | F11 | Low | ACCEPTED | Participant packet queue scans | Reassess O(n) scans only if smaller buffers expose callback pressure | Accepted if profiling/tests show no callback risk at supported buffer sizes | Loopback callback max stayed under 0.14 ms against a 10 ms deadline with zero over-deadline callbacks; no queue optimization needed now |
| [x] | F12 | Info | ACCEPTED | Server relay path | Keep server relay architecture unchanged for latency | Accepted after confirming no relay batching/pacing change was introduced | Server still relays immediately; changes were limited to diagnostics/redundancy accounting |
| [x] | F13 | Info | VERIFIED | Test coverage | Add product-goal tests for latency, playout ratio, PLC bounds; update large-gap expectation | Fresh Release build and full `ctest`; latency probe assertions reflect new policy | Final Release build and full `ctest` pass completed; suite now has 31 tests |

## Implementation Slices

1. Baseline diagnostics and missing logging.
2. F1 + F5 with focused tests.
3. F2 + F4 with auto-jitter tests.
4. F3 + F9 config/unit conversion and validation.
5. F7 server net-loss signal.
6. F8 redundancy policy.
7. F10 platform ranking.
8. F11/F12 acceptance checks.
9. F13 full verification pass.

## Runtime Evidence Log

Add entries here as runs are completed.

| Date | Scenario | Build | Settings | Key results | Linked findings |
|---|---|---|---|---|---|
| 2026-06-12 | Focused policy regression tests | Release | `ctest -R "participant_packet_queue_self_test\|client_opus_playout_policy_smoke\|latency_probe_large_gap_smoke"` | 3/3 passed; playout ratio stays ~1.0 at jitter target across queue limits; gap wait independent of queue limit; large-gap PLC run capped at 2 | F1, F5 |
| 2026-06-12 | Full regression suite after first slice | Release | `ctest --test-dir build -C Release --output-on-failure` | 25/25 passed | F1, F5 |
| 2026-06-12 | Focused age-drop feedback regression | Release | `ctest -R "client_auto_jitter_empty_playout_smoke\|client_opus_playout_policy_smoke"` | 2/2 passed; age drops no longer raise auto-jitter; target increases no longer force rebuffer | F2 |
| 2026-06-12 | Full regression suite after F2 | Release | `ctest --test-dir build -C Release --output-on-failure` | 25/25 passed | F1, F2, F5 |
| 2026-06-12 | Focused auto-jitter controller regression | Release | `ctest -R "client_auto_jitter_empty_playout_smoke\|client_opus_playout_policy_smoke"` | 2/2 passed; sparse events hold target, burst windows raise by one, clean windows decay to floor | F4 |
| 2026-06-12 | Full regression suite after F4 | Release | `ctest --test-dir build -C Release --output-on-failure` | 25/25 passed | F1, F2, F4, F5 |
| 2026-06-12 | Focused jitter-ms/default validation | Release | `ctest -R "jitter_policy_self_test\|client_startup_config_.*smoke\|client_auto_jitter_empty_playout_smoke\|client_opus_playout_policy_smoke"` | 8/8 passed; ms-to-packet conversion, startup defaults, packet-size scaling, and jitter-age validation passed | F3, F9 |
| 2026-06-12 | Full regression suite after F3/F9 | Release | `ctest --test-dir build -C Release --output-on-failure` | 27/27 passed | F1, F2, F3, F4, F5, F9 |
| 2026-06-12 | Focused Windows audio API ranking | Release | `ctest -R "audio_backend_policy_self_test\|client_startup_config_adaptive_smoke"` | 2/2 passed; JUCE Windows Audio names are ranked and present in local startup inventory | F10 |
| 2026-06-12 | Full regression suite after F10 | Release | `ctest --test-dir build -C Release --output-on-failure` | 27/27 passed | F1, F2, F3, F4, F5, F9, F10 |
| 2026-06-12 | Focused server net-loss feedback regression | Release | `ctest -R "audio_packet_self_test\|server_audio_path_feedback_smoke\|client_audio_path_feedback_smoke"` | 3/3 passed; redundant repair yields gross sequence gap with zero unrecovered gap in feedback | F7 |
| 2026-06-12 | Full regression suite after F7 | Release | `ctest --test-dir build -C Release --output-on-failure` | 27/27 passed | F1, F2, F3, F4, F5, F7, F9, F10 |
| 2026-06-12 | Focused redundancy policy regression | Release | `ctest -R "client_opus_redundancy_policy_smoke\|client_startup_config_.*smoke"` | 7/7 passed; auto/off/explicit redundancy depths and startup override are covered | F8 |
| 2026-06-12 | Full regression suite after F8 | Release | `ctest --test-dir build -C Release --output-on-failure` | 29/29 passed | F1, F2, F3, F4, F5, F7, F8, F9, F10 |
| 2026-06-12 | Loopback baseline after core fixes | Release | `node tools/baseline.mjs --seconds 15 --interval-seconds 5 --latency-profile balanced --skip-inventory --skip-smoke` with Release binaries | Queue stayed at 1-2 packets, age avg/max stayed about 20 ms, playout ratio stayed `1.0000`, age drops `0`, auto-jitter increases `0`, over-deadline callbacks `0`; logs in `validation_logs/audit-loopback-after-fixes` | F1, F2, F10, F11 |
| 2026-06-12 | Loopback clean diagnostic check | Release | `node tools/baseline.mjs --seconds 8 --interval-seconds 4 --latency-profile balanced --skip-inventory --skip-smoke` with Release binaries | Server ingress `seq_late=0`, net gap `0`; client participant `seq gap/recovered/unresolved/late=0/0/0/0`; logs in `validation_logs/audit-loopback-after-fixes-clean-diag` | F7, F8, F12 |
| 2026-06-12 | Controlled impairment and latency probes | Release | `ctest --test-dir build -C Release --output-on-failure` | `latency_probe_return_burst_smoke`, `latency_probe_large_gap_smoke`, and server net-loss feedback smoke all passed; large-gap PLC cap remains 2 | F4, F5, F7, F8, F13 |
| 2026-06-12 | Final audit closeout | Release | `cmake --build build --config Release --parallel`; `ctest --test-dir build -C Release --output-on-failure` | Build succeeded; current suite passes 31/31 | F1-F13 |
| 2026-06-12 | Post-review validation fixes | Release | `ctest -R "jitter_policy_self_test\|client_startup_config_.*smoke\|client_auto_jitter_empty_playout_smoke\|client_opus_playout_policy_smoke"`; `ctest --test-dir build -C Release --output-on-failure` | Focused tests 11/11 passed; full suite 31/31 passed; fixed per-participant age clamp, net-gap denominator, age-limit lowering, requested-ms preservation, dual jitter storage, and CLI jitter-unit conflict | F2, F7, F9, F13 |
