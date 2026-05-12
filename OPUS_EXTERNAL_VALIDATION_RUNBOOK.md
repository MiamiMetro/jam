# Opus External Validation Runbook

Date: 2026-05-11

Purpose: run the validation that cannot be completed from the Windows-only
workspace. Use this before promoting the Opus competitive branch to `main`.

## Scope

This runbook validates Opus `120` performer jamming across Windows and macOS.
PCM remains a research track and should not block the Opus path unless it
breaks Opus or the shared transport.

## 1. Build Both Machines

Build the branch on Windows and macOS first.

Windows smoke paths usually use:

```powershell
cmake --build build --config Debug
```

macOS build paths may vary by generator, but the validation scripts accept
explicit binary paths if needed.

## 2. Run Machine-Local Smoke

Run this on Windows:

```powershell
node tools/opus-validation.mjs smoke
```

Run this on macOS:

```bash
node tools/opus-validation.mjs smoke
```

If the macOS script cannot find the binaries:

```bash
node tools/opus-validation.mjs smoke --client build/client --harness build/opus_receiver_harness
```

Keep each generated directory:

```text
build/opus-validation/<timestamp>/
```

Expected result:

- `report.md` exists.
- Windows `report.md` says `Platform: win32 ...`.
- macOS `report.md` says `Platform: darwin ...`.
- startup default exits `0`.
- startup no-auto exits `0`.
- harness self-test exits `0`.
- audio-open exits `0` or the failure is clearly explained by missing audio
  devices/API setup. If this is accepted, set
  `windowsSmokeAllowAudioOpenFailure` or `macSmokeAllowAudioOpenFailure` plus
  the matching failure explanation in the manifest. Startup and harness
  failures are not acceptable for promotion.
- native `*-client.log` files are present.
- `startup-default-client.log` is present beside each smoke `report.md` and
  proves `Runtime: role=client`, the expected platform, `Startup codec
  override: Opus`, `Startup requested buffer override: 120 frames`, and
  startup jitter `8` with auto jitter enabled.
- Windows and macOS smoke `report.md` files include matching `Source SHA256`
  values for the current checkout.

## 3. Run Cross-Machine Opus Sessions

You can generate the exact commands and log paths for this section:

```bash
node tools/opus-external-commands.mjs --secret <secret> --server-host <server-ip-or-host> --write validation/opus-external-commands.md
```

The generated commands use signed dev validation tokens, Opus `120`, explicit
`--jitter 8`, explicit `--auto-jitter`, and the log paths expected by the
manifest checker. `--server-host` must be a host/IP reachable from both
Windows and macOS; do not include the port there because `--port` is separate.
`127.0.0.1`, `localhost`, `localhost:<port>`, `::1`, `[::1]`,
`[::1]:<port>`, full-form IPv6 loopback such as
`0:0:0:0:0:0:0:1:<port>`, `0.0.0.0`, `[::]`, and full-form IPv6 unspecified
addresses such as `0:0:0:0:0:0:0:0:<port>` do not count as external proof
and are rejected by default. Custom `--out-dir`, `--manifest`, and `--write`
paths inside this repo must be ignored generated evidence or command
generation fails. If you do not use the generator, follow the same command
shape manually.

The generated manifest init command uses `--windows-smoke latest` and
`--mac-smoke latest` by default. After both smoke directories are copied onto
the checker machine, the checker auto-selects the newest current-source report
for each platform from `build/opus-validation`.

Before starting long validation, run the generated preflight on the machine
that will collect logs and run the manifest checker. The local-only audit must
pass, `node tools/opus-source-fingerprint.mjs` must print the same
`Source SHA256` as the generated command packet, and the generated
`git check-ignore` command must print every generated validation path so
tokens, manifests, summaries, and logs are not staged as source.

Use separate validation rooms for each session so logs cannot be accidentally
mixed between directions:

- `opus-validation-room-win-to-mac`
- `opus-validation-room-mac-to-win`
- `opus-validation-long-room`

Create the validation log directory before starting native processes on any
machine that writes `validation/...` logs:

```powershell
New-Item -ItemType Directory -Force -Path validation
```

```bash
mkdir -p validation
```

Generated validation tokens are time-limited. Before starting the external
run, check the generated and expiry timestamps at the top of
`validation/opus-external-commands.md`; regenerate the command packet if the
remaining time is not enough for setup, both 5-minute direction checks, and the
30-60 minute long session. If a client join is rejected after commands sat
unused for a while, regenerate the command packet or pass a longer validation
TTL with `--ttl-ms <milliseconds>`. The command generator defaults to a longer
validation TTL so the full sequence can be run without regenerating tokens
between every step, and rejects invalid or shorter TTL values. This is only for
the external validation helper; it does not change the production token policy.

Start the SFU with file logging for the Windows-to-macOS direction. Use the
same `server-id` and join secret that were used to mint the client tokens:

```powershell
.\build\Debug\server.exe --port 9999 --server-id local-dev --join-secret <secret> --log-file validation/win-to-mac-server.log
```

```bash
./build/server --port 9999 --server-id local-dev --join-secret <secret> --log-file validation/win-to-mac-server.log
```

Use the normal authenticated room flow if testing product integration. For
standalone dev validation, use equivalent client commands with signed
`v1...` join tokens, Opus `120`, explicit jitter `8`, auto jitter enabled,
and explicit log files.

Windows client example:

```powershell
.\build\Debug\client.exe --server <server-ip> --port 9999 --room opus-validation-room-win-to-mac --room-handle opus-validation-room-win-to-mac --user-id windows-user --display-name "Windows User" --join-token <signed-v1-token> --codec opus --frames 120 --jitter 8 --auto-jitter --log-file validation/win-to-mac-windows-client.log
```

macOS client example:

```bash
./build/client --server <server-ip> --port 9999 --room opus-validation-room-win-to-mac --room-handle opus-validation-room-win-to-mac --user-id mac-user --display-name "Mac User" --join-token <signed-v1-token> --codec opus --frames 120 --jitter 8 --auto-jitter --log-file validation/win-to-mac-macos-client.log
```

For this direction, make Windows the active talker/source and judge the
received audio on macOS for at least 5 minutes. Put that direction in the
manifest subjective note, for example: `Windows source heard clearly on macOS
for the full five minutes over wired LAN`.

For the macOS-to-Windows direction, use the same commands with
`validation/mac-to-win-macos-client.log`,
`validation/mac-to-win-windows-client.log`, and
`validation/mac-to-win-server.log`, but set both clients' `--room` and
`--room-handle` to `opus-validation-room-mac-to-win`.

For this direction, make macOS the active talker/source and judge the received
audio on Windows for at least 5 minutes. Put that direction in the manifest
subjective note.

Minimum sessions:

- Windows to macOS, listen on macOS.
- macOS to Windows, listen on Windows.
- Both directions active for at least 5 minutes.
- One long session for 30-60 minutes.

Record subjective notes next to the logs:

- clear, flicker, robotic, dropouts, or stopped audio
- network path: Ethernet, Wi-Fi, tunnel, LAN
- current jitter/auto settings
- whether either machine was on battery/power-saving mode

After the sessions, collect all generated logs and both smoke report
directories onto one machine before running the summary or manifest checker.
For example, if the checker runs on Windows, copy the macOS
`build/opus-validation/<timestamp>/` directory and macOS client/SFU logs into
the same relative paths under the Windows repo. Preserve
`startup-default-client.log` beside each smoke `report.md`; the checker reads
that neighboring file to prove platform, Opus `120`, jitter `8`, and auto
jitter startup settings.
Each smoke `report.md` also records `Source SHA256`. Windows and macOS smoke
reports must have the same source fingerprint, and that fingerprint must match
the checkout where the external evidence checker is run. The fingerprint
normalizes text line endings so Windows CRLF and macOS LF checkouts can still
match when the source content is the same. If the code changes after smoke
collection, rerun both smoke collectors before accepting the manifest.

Each native client log should include a startup line like:

```text
Runtime: role=client platform=windows arch=x64
Startup requested buffer override: 120 frames
Startup codec override: Opus
Startup Opus jitter override: 8 packets
Startup Opus auto jitter default enabled
```

or:

```text
Runtime: role=client platform=macos arch=arm64
Startup requested buffer override: 120 frames
Startup codec override: Opus
Startup Opus jitter override: 8 packets
Startup Opus auto jitter default enabled
```

The manifest checker requires both Windows and macOS client runtime lines in
each external session and a server runtime log for the same session. It also
requires the client logs to prove Opus `120` startup settings, auto jitter, the
expected validation room, and `Audio diag: frames=120` during the captured
session. The server log must prove the same room with `JOIN: ... room='...'`.
The server log must also show at least one non-loopback client endpoint; if all
server JOIN endpoints are IPv4/IPv6 loopback, IPv4-mapped IPv6 loopback, or
unspecified addresses, including full-form IPv6 variants, the evidence is
treated as same-machine and rejected. The manifest metadata alone is not
enough.

## 4. Summarize Logs

The `validation/` directory is a generated local evidence workspace. It can
contain signed dev join tokens, machine-specific paths, and runtime logs, so it
is ignored by git. Commit the tooling and docs, not the generated validation
packet.

After the session, run:

```bash
node tools/opus-log-summary.mjs --out validation/validation-summary.md validation/win-to-mac-windows-client.log validation/win-to-mac-macos-client.log validation/win-to-mac-server.log validation/mac-to-win-windows-client.log validation/mac-to-win-macos-client.log validation/mac-to-win-server.log validation/windows-client-long.log validation/macos-client-long.log validation/server-long.log
```

Then initialize the manifest with the real report/log paths:

```bash
node tools/opus-external-evidence-check.mjs --init validation/opus-external-validation.json \
  --windows-smoke latest \
  --mac-smoke latest \
  --win-to-mac-logs validation/win-to-mac-windows-client.log,validation/win-to-mac-macos-client.log,validation/win-to-mac-server.log \
  --win-to-mac-room opus-validation-room-win-to-mac \
  --mac-to-win-logs validation/mac-to-win-windows-client.log,validation/mac-to-win-macos-client.log,validation/mac-to-win-server.log \
  --mac-to-win-room opus-validation-room-mac-to-win \
  --long-logs validation/windows-client-long.log,validation/macos-client-long.log,validation/server-long.log \
  --long-room opus-validation-long-room
```

The summary and manifest paths must be ignored generated evidence. The
generated preflight checks the default `validation/validation-summary.md` and
`validation/opus-external-validation.json` paths; `opus-log-summary --out` and
manifest `--init` reject source-controlled repo-local output paths, and
manifest `--init` also rejects source-controlled repo-local smoke/log input
paths.

Edit `validation/opus-external-validation.json` to replace network and
subjective placeholders, then run:

```bash
node tools/opus-external-evidence-check.mjs validation/opus-external-validation.json
```

Replace placeholder values such as `lan-or-tunnel` and
`clear / flicker / robotic / dropout notes`; the checker rejects placeholders.
The network note must describe a real Windows/macOS path such as Ethernet,
Wi-Fi, LAN, or tunnel. Loopback, localhost, unroutable/unspecified, and
same-machine descriptions are rejected because they do not prove cross-machine
behavior.
If the subjective note reports robotic/corrupt/flickering/dropout/broken audio,
the checker rejects the session unless the manifest explicitly marks warnings
as allowed with a concrete explanation for review.

To run the final promotion gate after the manifest passes:

```bash
node tools/opus-acceptance.mjs --external-manifest validation/opus-external-validation.json
```

The final promotion gate runs the external checker in strict mode. A manifest
that passes only because warnings were explicitly allowed is enough for review,
but it is not enough to mark the Opus path accepted.

That command runs local verification, the external manifest checker, and the
completion audit. Treat it as the full Opus branch acceptance command.

Interpretation:

- `pass` means the parser found no warning indicators in the parsed log.
- `warn` means review is required.
- Warning indicators include warning/error lines, audio health warnings,
  underruns, sequence gaps/late packets, and drift above `250 ppm`.
- The log summary and manifest checker use the same `250 ppm` drift review
  threshold.
- Each session must include at least two client-side diagnostic logs that cover
  the required duration. A single long log plus empty/short companion logs is
  rejected.
- Each session must include client runtime lines for both Windows and macOS.
- Each client log must prove the actual launch used `Startup codec override:
  Opus`, `Startup requested buffer override: 120 frames`, startup jitter `8`,
  auto jitter enabled, the expected `Sent JOIN for room ...` line, and audio
  diagnostics with `frames=120`.
- Each server log must prove `Runtime: role=server` and a matching
  `JOIN: ... room='...'` line for the manifest session room.
- Do not reuse the exact same log path across different manifest sessions.
  Keep Windows-to-macOS, macOS-to-Windows, and long-session logs separate.
- The manifest checker is the promotion gate for external evidence. If it
  fails, either fix the audio path or add a concrete warning explanation in
  the manifest and review that risk before merging.
- The manifest checker rejects a Windows smoke report in the macOS slot, and
  vice versa. Do not reuse one machine's report for the other machine.
- The manifest checker also rejects smoke reports whose neighboring
  `startup-default-client.log` is missing or does not prove the expected
  platform, Opus `120`, jitter `8`, and auto-jitter startup settings.
- The manifest checker rejects stale or mismatched smoke `Source SHA256`
  fingerprints. Do not mix smoke reports from different commits or local
  source edits.
- Each directional session must declare `codec: "opus"`, `frames: 120`,
  `jitter: 8`, `room`, `speakerPlatform`, and `listenerPlatform`.
  `windows-to-macos` means Windows is the speaker/source being evaluated and
  macOS is the listener; the reverse applies to `macos-to-windows`.
- The long-session entry must also declare `codec: "opus"`, `frames: 120`,
  `jitter: 8`, `room`, and include both `windows` and `macos` in
  `participants`.

Do not use subjective listening alone as the acceptance gate.

## 5. Acceptance For Promoting Opus Branch

Promotion is reasonable only when:

- Windows smoke passes or has a documented hardware-specific reason.
- macOS smoke passes or has a documented hardware-specific reason.
- Cross-machine Opus `120` works in both directions.
- Long-session logs do not show unbounded jitter growth.
- `validation/validation-summary.md` has no unexplained warning indicators.
- `node tools/opus-external-evidence-check.mjs validation/opus-external-validation.json`
  passes.
- Any subjective flicker/robotic report has matching logs or is explicitly
  marked as unexplained follow-up.

## 6. PCM Research Boundary

Run PCM only after the Opus path is validated.

If PCM is tested, use the same `--log-file` and summary flow. PCM should remain
`PCM LAN/exp` until Windows/macOS cross-machine behavior is explained or a
drift-correction/resampling strategy is implemented and validated.
