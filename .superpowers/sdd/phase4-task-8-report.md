# Phase 4 Task 8 Report: Tracker Acceptance And Metrics

Date: 2026-07-03

No delegation or model switch was used.

## Commands Run

Pre-collapse before worktree:

```powershell
git worktree add --detach C:\Users\Berkay\Downloads\udpstuff-phase4-before cd9a275
cmake -S . -B build -G "Visual Studio 17 2022"
cmake --build build --config Release --target client server --parallel 8
```

Before baseline, run from `C:\Users\Berkay\Downloads\udpstuff` with temp
`cd9a275` executables:

```powershell
$env:JAM_SERVER_EXE='C:\Users\Berkay\Downloads\udpstuff-phase4-before\build\Release\server.exe'
$env:JAM_CLIENT_EXE='C:\Users\Berkay\Downloads\udpstuff-phase4-before\build\Release\client.exe'
node tools/baseline.mjs --seconds 30 --interval-seconds 5 --frames 120 --codec opus --latency-profile low --jitter 4 --out-dir validation_logs/phase4-tx-collapse/before
```

After build and baseline:

```powershell
cmake --build build --config Release --target client server latency_probe --parallel 8
$env:JAM_SERVER_EXE='build/Release/server.exe'
$env:JAM_CLIENT_EXE='build/Release/client.exe'
node tools/baseline.mjs --seconds 30 --interval-seconds 5 --frames 120 --codec opus --latency-profile low --jitter 4 --out-dir validation_logs/phase4-tx-collapse/after
```

E2E and full test validation:

```powershell
node tools/e2e-latency-smoke.mjs --server-exe build/Release/server.exe --probe-exe build/Release/latency_probe.exe --frames 120 --jitter 4 --packets 650 --margin-ms 8 *> validation_logs/phase4-tx-collapse/e2e-smoke.log
ctest --test-dir build -C Release --output-on-failure *> validation_logs/phase4-tx-collapse/ctest-release.log
```

## Parsed Values

Source values are from the 30s `Baseline snapshot` lines so both clients are
compared while both participants are connected.

- Before (`cd9a275`, `validation_logs/phase4-tx-collapse/before`):
  - `client-a.log`: `opus_p99=0.189 ms`, `opus_avg=0.092 ms`, `opus_max=0.453 ms`
  - `client-b.log`: `opus_p99=0.247 ms`, `opus_avg=0.091 ms`, `opus_max=0.518 ms`
- After (current Phase 4 code, `validation_logs/phase4-tx-collapse/after`):
  - `client-a.log`: `opus_p99=0.212 ms`, `opus_avg=0.103 ms`, `opus_max=0.412 ms`
  - `client-b.log`: `opus_p99=0.209 ms`, `opus_avg=0.103 ms`, `opus_max=0.426 ms`
- Phase 3 accepted E2E baseline from `LOW_LATENCY_ACTION_PLAN.md`:
  - last `9.1425 ms`, avg `9.90777 ms`, max `11.5601 ms`, steady_max `11.5601 ms`
- Phase 4 E2E smoke from `validation_logs/phase4-tx-collapse/e2e-smoke.log`:
  - last `9.4238 ms`, avg `9.98548 ms`, max `11.5315 ms`, steady_max `11.5315 ms`
  - budget `23 ms`, margin `8 ms`
- Task 7 notify decision:
  - kept `pcm_sender_cv_.notify_one()` enabled
  - no-notify p99 regressed from `0.211 ms` to `2.592 ms` on client A and from
    `0.203 ms` to `3.124 ms` on client B

## Tests

- Release build passed; transcript:
  `validation_logs/phase4-tx-collapse/release-build.log`
- Before baseline passed; logs:
  `validation_logs/phase4-tx-collapse/before`
- After baseline passed; logs:
  `validation_logs/phase4-tx-collapse/after`
- E2E smoke passed; log:
  `validation_logs/phase4-tx-collapse/e2e-smoke.log`
- Full Release ctest passed:
  `100% tests passed, 0 tests failed out of 39` in `25.09 sec`

## Files Changed

- `LOW_LATENCY_ACTION_PLAN.md`
- `.superpowers/sdd/phase4-task-8-report.md`
- `validation_logs/phase4-tx-collapse/before/*`
- `validation_logs/phase4-tx-collapse/after/*`
- `validation_logs/phase4-tx-collapse/e2e-smoke.log`
- `validation_logs/phase4-tx-collapse/release-build.log`
- `validation_logs/phase4-tx-collapse/ctest-release.log`

## Concerns

- The required before/after send-queue p99 signal is mixed in this local run:
  client A changed `0.189 ms -> 0.212 ms` while client B changed
  `0.247 ms -> 0.209 ms`. The tracker records this instead of claiming a clean
  p99 win. Opus max send-queue age did decrease on both clients.
- Remote CI was not available from the local workspace, so the tracker says
  `CI: pending on PR/push`.
- The temporary before worktree was left at
  `C:\Users\Berkay\Downloads\udpstuff-phase4-before` for auditability instead
  of force-removing its untracked `build` directory.
