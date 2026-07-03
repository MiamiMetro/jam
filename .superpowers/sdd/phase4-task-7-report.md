# Phase 4 Task 7 Report: Evaluate Removing Callback `notify_one()`

## Implementation Summary

- Added an explicit compile-time callback wake policy in `client.cpp`:
  `constexpr bool AUDIO_CALLBACK_NOTIFY_ENABLED = true;`
- Wrapped the per-packet sender wake notification in `wake_pcm_sender_thread()`:
  `if constexpr (AUDIO_CALLBACK_NOTIFY_ENABLED) { pcm_sender_cv_.notify_one(); }`
- Temporarily set the policy to `false` for measurement, then restored it to `true`
  because the no-notify run regressed Opus send-queue p99 well beyond the task
  threshold.
- Did not update the Phase 4 tracker status; Task 8 owns final tracker metrics.

## Measurements Attempted and Results

### Notify Enabled Baseline

Command:

```powershell
$env:JAM_SERVER_EXE='build/Release/server.exe'
$env:JAM_CLIENT_EXE='build/Release/client.exe'
node tools/baseline.mjs --seconds 30 --interval-seconds 5 --frames 120 --codec opus --latency-profile low --jitter 4 --out-dir validation_logs/phase4-tx-collapse/notify-enabled
```

Result: completed successfully with real Windows audio devices.

Key end snapshots:

- `client-a.log` at 30s: `opus_p99=0.211`, `over_deadline=0`,
  `tx_drops pcm/opus=0/0`
- `client-b.log` at 30s: `opus_p99=0.203`, `over_deadline=0`,
  `tx_drops pcm/opus=0/0`
- `client-b.log` at 35s after peer exit: `opus_p99=0.178`, `over_deadline=0`,
  `tx_drops pcm/opus=0/0`

### Notify Disabled Baseline

Temporary code state:

```cpp
constexpr bool AUDIO_CALLBACK_NOTIFY_ENABLED = false;
```

Commands:

```powershell
cmake --build build --config Release --target client server --parallel 8
$env:JAM_SERVER_EXE='build/Release/server.exe'
$env:JAM_CLIENT_EXE='build/Release/client.exe'
node tools/baseline.mjs --seconds 30 --interval-seconds 5 --frames 120 --codec opus --latency-profile low --jitter 4 --out-dir validation_logs/phase4-tx-collapse/notify-disabled
```

Result: completed successfully with the same local device class.

Key end snapshots:

- `client-a.log` at 30s: `opus_p99=2.592`, `over_deadline=0`,
  `tx_drops pcm/opus=0/0`
- `client-b.log` at 30s: `opus_p99=3.124`, `over_deadline=0`,
  `tx_drops pcm/opus=0/0`
- `client-b.log` at 35s after peer exit: `opus_p99=2.052`, `over_deadline=0`,
  `tx_drops pcm/opus=0/0`

## Decision

Keep `AUDIO_CALLBACK_NOTIFY_ENABLED = true`.

The no-notify run failed the Task 7 acceptance criterion. Comparing the 30s
snapshots, Opus send-queue p99 regressed from `0.211 ms` to `2.592 ms` on
client A and from `0.203 ms` to `3.124 ms` on client B. Both regressions are
far greater than the allowed `0.10 ms`. Callback over-deadline counts and send
drops did not increase, but the send-queue p99 regression is sufficient to keep
the callback wake notification enabled.

## Tests

- `cmake --build build --config Release --target client server --parallel 8`
  before notify-enabled baseline: passed.
- Notify-enabled baseline: passed and stored under
  `validation_logs/phase4-tx-collapse/notify-enabled`.
- `cmake --build build --config Release --target client server --parallel 8`
  before notify-disabled baseline: passed.
- Notify-disabled baseline: passed and stored under
  `validation_logs/phase4-tx-collapse/notify-disabled`.
- `cmake --build build --config Release --target client server latency_probe --parallel 8`
  after final decision: passed.
- `node tools/e2e-latency-smoke.mjs --server-exe build/Release/server.exe --probe-exe build/Release/latency_probe.exe --frames 120 --jitter 4 --packets 650 --margin-ms 8`:
  passed, steady max `11.1346 ms` under the `23 ms` budget.
- `cmake --build build --config Release --parallel 8`: passed.
- `ctest --test-dir build -C Release --output-on-failure`: passed, 39/39 tests.

## Files Changed

- `client.cpp`
- `.superpowers/sdd/phase4-task-7-report.md`
- `validation_logs/phase4-tx-collapse/notify-enabled/*`
- `validation_logs/phase4-tx-collapse/notify-disabled/*`

## Concerns

- The no-notify result is a clear local regression, so callback wake removal
  should not land in Task 7.
