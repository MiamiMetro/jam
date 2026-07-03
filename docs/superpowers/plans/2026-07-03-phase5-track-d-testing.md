# Phase 5 Track D Testing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add repeatable Track D production-hardening gates for long-running client soak, room-scale server relay load, and an impairment matrix with explicit budgets.

**Architecture:** Keep realtime audio behavior unchanged and build Track D as external harnesses around the existing server, client, `latency_probe`, and `udp_impair_proxy`. CI-safe smoke tests run shortened versions of the matrix and load benchmark; long soak remains a command that can run for hours against real devices and fails by parsing client baseline logs for over-deadline callbacks and queue drift.

**Tech Stack:** C++23, ASIO UDP, CMake/ctest, Node.js `.mjs` harnesses, existing `udp_impair_proxy`, existing client baseline snapshot logs, existing `latency_probe` queue/E2E metrics.

## Global Constraints

- Current planning base: `main` at `f75eff7`.
- Exactly one Phase 5 track is in scope: Track D testing.
- Do not implement Track A security, Track B network, Track C operations, or Track E devices in this session.
- Tracker rule: one branch per phase; this work runs on branch `phase5-track-d-testing`.
- Tracker rule: one commit per task; build and full `ctest` after every task that changes buildable code or test registrations.
- Long soak must assert `over_deadline=0` in client baseline snapshots and bounded participant `queue_drift`.
- Impairment matrix must use the existing `udp_impair_proxy`.
- Load benchmark must measure server relay behavior at room scale without changing server relay policy.

---

## Current HEAD Citation Check

- `LOW_LATENCY_ACTION_PLAN.md:175-177` defines Track D as soak, room-scale relay load benchmark, and impairment matrix using `udp_impair_proxy`.
- `LOW_LATENCY_ACTION_PLAN.md:192-195` says plan line numbers are anchored to the named commit and build/full `ctest` are required after every task.
- `LOW_LATENCY_AUDIT.md:197-204` lists the matching measurement gaps: callback-health assertion, impairment coverage, soak/drift, and scale/load.
- `LOW_LATENCY_AUDIT.md:202` is stale in one detail after Phase 4: current `udp_impair_proxy.cpp:70-96` and `udp_impair_proxy.cpp:119-126` already include loss, jitter, burst, and reorder flags.
- `CMakeLists.txt:83-87` builds `udp_impair_proxy` and `multi_participant_jitter_probe`; `CMakeLists.txt:136-163` registers two impairment smokes and one E2E smoke, but not a matrix or load benchmark.
- `latency_probe.cpp:1033-1045` prints E2E latency, average queue depth, queue drift from jitter, max queue depth, and final queue depth.
- `latency_probe.cpp:1128-1152` supports `--require-clean`, `--max-gap-plc-run`, `--seconds`, `--playout-ppm`, and E2E latency budget arguments.
- `client.cpp:4425-4467` logs `Baseline snapshot` lines with `callback_count` and `over_deadline`; `client.cpp:4510-4529` logs `Baseline participant` lines with `queue_drift`.
- `server.cpp:664-675` relays audio to all other clients in the room; `client_manager.h:207-223` returns same-room endpoints except the sender; `server.cpp:960-971` logs forward diagnostics.
- `participant_manager.h:38` caps callback snapshots at 32 participants, which defines the upper room-scale target.

## File Structure

- Create `tools/phase5-track-d-common.mjs`: shared Node helpers for argument parsing, UDP port reservation, process spawning, readiness waits, child cleanup, key-value parsing, and numeric assertions.
- Create `tools/phase5-track-d-impairment-matrix.mjs`: runs `server -> udp_impair_proxy -> latency_probe` across loss/reorder/burst cases and latency profiles, parses probe metrics, and enforces budgets.
- Create `relay_load_probe.cpp`: joins N UDP clients to one room, sends audio from a configurable subset, drains all sockets, and reports expected versus observed relays and throughput.
- Create `tools/phase5-track-d-load-benchmark.mjs`: starts the server, runs `relay_load_probe`, captures logs, and enforces delivery/throughput budgets.
- Create `tools/phase5-track-d-soak.mjs`: starts a real server plus baseline clients, churns one client repeatedly, parses all baseline logs, and fails on over-deadline callbacks or queue drift beyond budget.
- Modify `CMakeLists.txt`: build `relay_load_probe` and register CI-safe Track D smoke tests.
- Modify `LOW_LATENCY_ACTION_PLAN.md`: record Track D implementation status, commands run, and long-duration acceptance state.

---

### Task 1: Impairment Matrix Harness

**Files:**
- Create: `tools/phase5-track-d-common.mjs`
- Create: `tools/phase5-track-d-impairment-matrix.mjs`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `server`, `udp_impair_proxy`, `latency_probe`, `latency_probe.cpp` text metrics, and `udp_impair_proxy` loss/reorder/burst flags.
- Produces: `node tools/phase5-track-d-impairment-matrix.mjs --server-exe ... --proxy-exe ... --probe-exe ...`, JSON summary output, and CTest `phase5_track_d_impairment_matrix_smoke`.

- [ ] **Step 1: Add shared Node helpers**

Create `tools/phase5-track-d-common.mjs` exporting these exact functions:

```js
export function parseArgs(argv, options = {}) { /* parse --flag value and boolean flags */ }
export function requireArgs(args, names) { /* throw when a required key is absent */ }
export function reserveUdpPort() { /* bind udp4 127.0.0.1:0, close, resolve port */ }
export function spawnLogged(name, command, args, logFile) { /* spawn with stdout/stderr tee */ }
export function waitForOutput(child, pattern, timeoutMs, name) { /* resolve on readiness */ }
export async function stopChild(child) { /* terminate and wait up to 5 seconds */ }
export function parseLatencyProbeOutput(text) { /* parse key: value probe metrics */ }
export function assertBudget(condition, message, failures) { /* push message on false */ }
```

The parser must recognize `e2e_latency_ms last/avg/max/steady_max: a/b/c/d`, `avg_queue_depth`, `queue_drift_from_jitter`, `max_queue_depth`, `final_queue_depth`, `underruns`, `plc_frames`, `gap_plc_frames`, `max_gap_plc_run`, `decoder_resets`, `sequence_late_or_duplicate`, `received_packets`, and `sent_packets`.

- [ ] **Step 2: Add the matrix runner**

Create `tools/phase5-track-d-impairment-matrix.mjs` with profile budgets:

```js
const PROFILES = {
  low: { frames: 120, jitter: 4, maxQueueDriftPackets: 3.0, maxQueueDepthPackets: 16, e2eMarginMs: 14 },
  balanced: { frames: 480, jitter: 2, maxQueueDriftPackets: 3.0, maxQueueDepthPackets: 12, e2eMarginMs: 30 },
  stable: { frames: 960, jitter: 4, maxQueueDriftPackets: 4.0, maxQueueDepthPackets: 14, e2eMarginMs: 45 },
};
const CASES = {
  clean: { proxy: {}, requireClean: true, maxGapPlcRun: 0 },
  loss1: { proxy: { "loss-percent": "1", "drop-direction": "server-to-client" }, maxGapPlcRun: 2 },
  reorder: { proxy: { "reorder-every": "17", "reorder-delay-ms": "12", "drop-direction": "server-to-client" }, requireClean: true, maxGapPlcRun: 2 },
  burst: { proxy: { "burst-every": "120", "burst-count": "4", "burst-offset": "35", "drop-direction": "server-to-client" }, maxGapPlcRun: 2 },
};
```

Default mode must run every profile and every case. `--quick` must run `low:clean`, `low:reorder`, and `balanced:burst`. Each run must start a fresh server/proxy pair, run `latency_probe`, save stdout/stderr under `--out-dir`, parse metrics, and write `summary.json`.

- [ ] **Step 3: Enforce matrix budgets**

For each matrix row, compute:

```js
const packetMs = (profile.frames * 1000) / 48000;
const e2eBudgetMs = profile.jitter * packetMs + packetMs + packetMs + profile.e2eMarginMs;
```

Fail a row when steady E2E exceeds `e2eBudgetMs`, `Math.abs(queue_drift_from_jitter)` exceeds `maxQueueDriftPackets`, `max_queue_depth` exceeds `maxQueueDepthPackets`, `max_gap_plc_run` exceeds the case budget, or a `requireClean` case exits nonzero.

- [ ] **Step 4: Register the smoke**

Add this CTest entry inside the existing `if(NODE_EXECUTABLE)` block:

```cmake
add_test(NAME phase5_track_d_impairment_matrix_smoke
         COMMAND ${NODE_EXECUTABLE}
                 ${CMAKE_SOURCE_DIR}/tools/phase5-track-d-impairment-matrix.mjs
                 --server-exe $<TARGET_FILE:server>
                 --proxy-exe $<TARGET_FILE:udp_impair_proxy>
                 --probe-exe $<TARGET_FILE:latency_probe>
                 --quick
                 --out-dir ${CMAKE_BINARY_DIR}/phase5-track-d/impairment-smoke)
```

- [ ] **Step 5: Run focused verification**

Run:

```powershell
cmake --build build --config Release --target server udp_impair_proxy latency_probe --parallel 8
ctest --test-dir build -C Release -R phase5_track_d_impairment_matrix_smoke --output-on-failure
```

Expected: the new smoke passes and writes `build/phase5-track-d/impairment-smoke/summary.json`.

- [ ] **Step 6: Run full verification and commit**

Run:

```powershell
cmake --build build --config Release --parallel 8
ctest --test-dir build -C Release --output-on-failure
git add CMakeLists.txt tools/phase5-track-d-common.mjs tools/phase5-track-d-impairment-matrix.mjs
git commit -m "test: add phase 5 impairment matrix harness"
```

Expected: Release build succeeds and full `ctest` passes.

---

### Task 2: Room-Scale Relay Load Benchmark

**Files:**
- Create: `relay_load_probe.cpp`
- Create: `tools/phase5-track-d-load-benchmark.mjs`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: server insecure dev joins, `audio_packet::create_audio_packet_v2`, `JoinHdr`, `CtrlHdr`, and server same-room relay behavior.
- Produces: `relay_load_probe`, `node tools/phase5-track-d-load-benchmark.mjs --server-exe ... --probe-exe ...`, CSV-like benchmark output, JSON summary output, and CTest `phase5_track_d_load_benchmark_smoke`.

- [ ] **Step 1: Add `relay_load_probe.cpp`**

Implement a C++ probe with these CLI flags:

```text
--server <host> --port <port> --clients <n> --senders <n> --seconds <n>
--frames <n> --min-delivery-ratio <ratio> --max-recv-gap-ms <ms>
```

Defaults: `clients=16`, `senders=8`, `seconds=30`, `frames=120`, `min-delivery-ratio=0.98`, `max-recv-gap-ms=250`. The probe must join all clients to room `phase5-load`, send V2 audio from the first `senders` sockets for `seconds`, drain every socket concurrently in the main loop, send `ALIVE` every second, and print:

```text
relay_load_probe v1
clients: N
senders: N
frames: N
seconds: N
sent_packets: N
expected_forwards: N
received_forwards: N
delivery_ratio: R
send_packets_per_second: R
forward_packets_per_second: R
max_receive_gap_ms: R
status: ok
```

Return `2` when delivery ratio or max receive gap misses the budget.

- [ ] **Step 2: Add the load wrapper**

Create `tools/phase5-track-d-load-benchmark.mjs`. It must reserve a UDP port, spawn `server --allow-insecure-dev-joins`, wait for `SFU server ready`, run `relay_load_probe`, save `server.log`, `probe.log`, and `summary.json`, then stop the server.

- [ ] **Step 3: Register the benchmark target and smoke**

Add to `CMakeLists.txt` near the other probes:

```cmake
add_executable(relay_load_probe relay_load_probe.cpp)
target_link_libraries(relay_load_probe PRIVATE asio token_crypto)
```

Add inside the Node test block:

```cmake
add_test(NAME phase5_track_d_load_benchmark_smoke
         COMMAND ${NODE_EXECUTABLE}
                 ${CMAKE_SOURCE_DIR}/tools/phase5-track-d-load-benchmark.mjs
                 --server-exe $<TARGET_FILE:server>
                 --probe-exe $<TARGET_FILE:relay_load_probe>
                 --clients 8
                 --senders 4
                 --seconds 3
                 --frames 480
                 --min-delivery-ratio 0.95
                 --out-dir ${CMAKE_BINARY_DIR}/phase5-track-d/load-smoke)
```

- [ ] **Step 4: Run focused verification**

Run:

```powershell
cmake --build build --config Release --target server relay_load_probe --parallel 8
ctest --test-dir build -C Release -R phase5_track_d_load_benchmark_smoke --output-on-failure
```

Expected: benchmark passes and writes `build/phase5-track-d/load-smoke/summary.json`.

- [ ] **Step 5: Run full verification and commit**

Run:

```powershell
cmake --build build --config Release --parallel 8
ctest --test-dir build -C Release --output-on-failure
git add CMakeLists.txt relay_load_probe.cpp tools/phase5-track-d-load-benchmark.mjs
git commit -m "test: add room scale relay load benchmark"
```

Expected: Release build succeeds and full `ctest` passes.

---

### Task 3: Real-Client Soak Runner

**Files:**
- Create: `tools/phase5-track-d-soak.mjs`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `client --baseline-snapshot-seconds`, client baseline log fields `over_deadline` and `queue_drift`, server join secret options, and dev HMAC token format already used by `tools/baseline.mjs`.
- Produces: a long-running soak command, a parser-only CTest smoke, and `summary.json` containing max over-deadline and max absolute queue drift.

- [ ] **Step 1: Add the soak runner**

Create `tools/phase5-track-d-soak.mjs` with these modes:

```text
--server-exe <path> --client-exe <path> --seconds <n> --churn-interval-seconds <n>
--stable-clients <n> --churn-clients <n> --max-queue-drift-packets <n>
--out-dir <path>
--parser-smoke
```

Defaults: `seconds=7200`, `churn-interval-seconds=120`, `stable-clients=1`, `churn-clients=1`, `max-queue-drift-packets=4.0`, `out-dir=validation_logs/phase5-track-d/soak-<timestamp>`.

- [ ] **Step 2: Implement client churn**

The runner must start `server --server-id local-dev --join-secret dev-secret`, then start stable clients for the full run and churn clients for repeated intervals. Each client command must include:

```text
--server 127.0.0.1 --port <reservedPort> --room phase5-soak --room-handle phase5-soak
--user-id <uniqueUser> --display-name <uniqueName> --join-token <generatedHmacToken>
--codec opus --frames 120 --latency-profile low --jitter 4
--baseline-snapshot-seconds <clientRunSeconds>
--baseline-snapshot-interval-seconds 10
--baseline-snapshot-label <label>
```

- [ ] **Step 3: Implement log-budget parsing**

Parse every `client-*.log` after the run. Fail when any `Baseline snapshot` has `over_deadline` greater than `0`, when no baseline snapshot exists, when any `Baseline participant` has absolute `queue_drift` greater than `max-queue-drift-packets`, or when a client exits nonzero. Write `summary.json` with:

```json
{
  "status": "ok",
  "snapshots": 0,
  "participants": 0,
  "maxOverDeadline": 0,
  "maxAbsQueueDrift": 0
}
```

- [ ] **Step 4: Add parser smoke to CTest**

In `--parser-smoke` mode, write a temporary synthetic log containing two passing `Baseline snapshot` lines and two passing `Baseline participant` lines, parse it, print `phase5 soak parser smoke passed`, and exit `0`. Register:

```cmake
add_test(NAME phase5_track_d_soak_parser_smoke
         COMMAND ${NODE_EXECUTABLE}
                 ${CMAKE_SOURCE_DIR}/tools/phase5-track-d-soak.mjs
                 --parser-smoke)
```

- [ ] **Step 5: Run focused verification**

Run:

```powershell
ctest --test-dir build -C Release -R phase5_track_d_soak_parser_smoke --output-on-failure
```

Expected: parser smoke passes.

- [ ] **Step 6: Run full verification and commit**

Run:

```powershell
cmake --build build --config Release --parallel 8
ctest --test-dir build -C Release --output-on-failure
git add CMakeLists.txt tools/phase5-track-d-soak.mjs
git commit -m "test: add phase 5 client soak runner"
```

Expected: Release build succeeds and full `ctest` passes.

---

### Task 4: Validation Snapshot And Tracker Update

**Files:**
- Modify: `LOW_LATENCY_ACTION_PLAN.md`
- Create during execution: `validation_logs/phase5-track-d/`

**Interfaces:**
- Consumes: Tasks 1-3 harnesses and local validation output.
- Produces: tracker status for Track D and validation logs.

- [ ] **Step 1: Run Track D short validation**

Run:

```powershell
cmake --build build --config Release --parallel 8 *> validation_logs/phase5-track-d/release-build.log
ctest --test-dir build -C Release --output-on-failure *> validation_logs/phase5-track-d/ctest-release.log
node tools/phase5-track-d-impairment-matrix.mjs --server-exe build/Release/server.exe --proxy-exe build/Release/udp_impair_proxy.exe --probe-exe build/Release/latency_probe.exe --quick --out-dir validation_logs/phase5-track-d/impairment-quick
node tools/phase5-track-d-load-benchmark.mjs --server-exe build/Release/server.exe --probe-exe build/Release/relay_load_probe.exe --clients 8 --senders 4 --seconds 3 --frames 480 --min-delivery-ratio 0.95 --out-dir validation_logs/phase5-track-d/load-quick
node tools/phase5-track-d-soak.mjs --parser-smoke
```

Expected: all commands exit `0`.

- [ ] **Step 2: Record long soak command without marking it passed**

Record this exact long-run command in the tracker as pending unless it is executed:

```powershell
node tools/phase5-track-d-soak.mjs --server-exe build/Release/server.exe --client-exe build/Release/client.exe --seconds 7200 --churn-interval-seconds 120 --stable-clients 1 --churn-clients 1 --max-queue-drift-packets 4 --out-dir validation_logs/phase5-track-d/soak-2h
```

- [ ] **Step 3: Update tracker**

Set Track D to `Implemented locally - long soak acceptance pending` unless the 2-hour soak is actually run and passes. Include the branch name, commit base, scripts added, CI-safe smoke results, quick validation log paths, and the long soak command.

- [ ] **Step 4: Commit tracker and validation logs**

Run:

```powershell
git add LOW_LATENCY_ACTION_PLAN.md validation_logs/phase5-track-d
git commit -m "docs: record phase 5 track d validation"
```

Expected: tracker accurately says Track D is not fully production-gate complete until the multi-hour soak passes.

---

## Self-Review Checklist

- [ ] Only Track D files and tracker text changed.
- [ ] Impairment matrix uses `udp_impair_proxy` for loss, reorder, and burst cases.
- [ ] Impairment budgets include E2E latency, queue drift, queue depth, and max gap PLC run.
- [ ] Relay load benchmark exercises one same-room relay with at least 8 CI-smoke clients and configurable 32-participant full run.
- [ ] Soak runner checks real client baseline logs for `over_deadline=0` and bounded `queue_drift`.
- [ ] CI-safe smokes do not require physical audio devices.
- [ ] Tracker does not mark Track D Done unless the multi-hour soak command has run and passed.
- [ ] Release build and full `ctest` pass after each committed task.
