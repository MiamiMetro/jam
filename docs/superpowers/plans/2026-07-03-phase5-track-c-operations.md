# Phase 5 Track C Operations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Track C only: machine-readable server metrics export, rotating file logs, and local crash reports for the server.

**Architecture:** Keep operations plumbing out of the UDP relay hot path by adding small headers for JSONL metrics snapshots and crash-report writing, then call them from the server's existing 5s maintenance timer and startup path. Replace the logger's `basic_file_sink` with spdlog's rotating sink while keeping the existing async non-blocking logger behavior. Crash reports are local files by default, with Windows minidumps when an unhandled exception supplies exception pointers.

**Tech Stack:** C++23, standalone Asio UDP server, spdlog 1.16 rotating file sink, Windows `DbgHelp` minidumps when built on Windows, CMake/CTest self-tests and existing server smokes.

## Global Constraints

- Current planning base: `main` at `dadf3fd`.
- Execute exactly one Phase 5 track in this session: Track C operations only.
- Do not implement Track A security, Track B network, Track D testing, or Track E devices in this session.
- Tracker rule: one branch per phase; this work runs on branch `phase5-track-c-operations`.
- Tracker rule: one commit per implementation task; build plus full `ctest` after each implementation task.
- Metrics export must be machine-readable without adding a web server to the latency relay.
- File logging must rotate by size and retained-file count; `basic_file_sink` must not remain in `logger.h`.
- Crash reporting must work without a hosted crash service; reports are written locally.

---

## Current HEAD Citation Check

- `LOW_LATENCY_ACTION_PLAN.md:198-200` defines Track C as server metrics export, log rotation, and crash reporting.
- `LOW_LATENCY_AUDIT.md:201` says observability is text logs plus ImGui only, with no machine-scrapable hosted-server metrics export.
- `server.cpp:1220-1316` currently emits interval diagnostics only as text `Log::info` lines and then resets interval counters.
- `logger.h:15`, `logger.h:89`, and `logger.h:147` still use `spdlog::sinks::basic_file_sink_mt`; there is no rotating sink.
- `rg -n "SIG|signal|terminate|exception|minidump|crash|SetUnhandledExceptionFilter|DbgHelp|stacktrace" -S .` finds no crash reporter in server startup; `server.cpp:1938-1940` only logs top-level `std::exception`.

## File Structure

- Create `server_metrics.h`: owns metrics snapshot structs, JSON escaping, JSONL rendering, and append-only JSONL export.
- Create `server_metrics_self_test.cpp`: verifies JSON escaping, snapshot rendering, and file append behavior.
- Modify `server.cpp`: adds `--metrics-jsonl`, builds snapshots from existing server counters, exports before interval counters reset, and adds `--metrics-export-smoke`.
- Modify `CMakeLists.txt`: builds/registers `server_metrics_self_test`.
- Modify `logger.h`: replaces `basic_file_sink` with `rotating_file_sink`, adds default rotation settings, and allows per-process overrides.
- Create `logger_self_test.cpp`: verifies rotating logs produce bounded rotated files.
- Modify `server.cpp`: adds `--log-max-bytes` and `--log-max-files` options and passes them to `Logger::init`.
- Modify `CMakeLists.txt`: builds/registers `logger_self_test`.
- Create `crash_reporter.h`: owns crash report metadata JSON, report file creation, process hooks, and Windows minidump writing.
- Create `crash_reporter_self_test.cpp`: verifies explicit crash-report writing creates a parseable metadata file.
- Modify `server.cpp`: installs crash reporting for normal server runs, adds `--crash-report-dir`, `--disable-crash-reports`, and `--crash-report-smoke`.
- Modify `cmake/server.cmake` and `CMakeLists.txt`: links `Dbghelp` to server and crash reporter self-test on Windows.
- Modify `LOW_LATENCY_ACTION_PLAN.md`: links the Track C plan and records local validation.

---

### Task 1: Server Metrics JSONL Export

**Files:**
- Create: `server_metrics.h`
- Create: `server_metrics_self_test.cpp`
- Modify: `server.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Produces: `server_metrics::CounterSet` with `interval`, `total`, `gaps_total`, `gap_recoveries_total`, `unresolved_gaps`, and `late_or_reordered_total`.
- Produces: `server_metrics::Snapshot` with server id, timestamp, uptime, client counts, drop counters, ingress stats, forward stats, and ping stats.
- Produces: `server_metrics::to_json_line(const Snapshot&) -> std::string`.
- Produces: `server_metrics::JsonlExporter::write(const Snapshot&, std::string*) -> bool`.
- Consumed by: `Server::export_metrics_snapshot()` in `server.cpp`.

- [ ] **Step 1: Write the failing self-test**

Create `server_metrics_self_test.cpp`:

```cpp
#include "server_metrics.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

void require(bool ok, const char* message) {
    if (!ok) {
        throw std::runtime_error(message);
    }
}

int main() {
    server_metrics::Snapshot snapshot;
    snapshot.schema = "jam_server_metrics_v1";
    snapshot.server_id = "server\"ops";
    snapshot.timestamp_unix_ms = 123456789;
    snapshot.uptime_ms = 2500;
    snapshot.connected_clients = 2;
    snapshot.unknown_endpoint_count = 1;
    snapshot.token_nonce_count = 1;
    snapshot.drops.unknown_audio_interval = 3;
    snapshot.drops.unknown_audio_total = 5;
    snapshot.drops.invalid_audio_interval = 7;
    snapshot.drops.invalid_audio_total = 11;
    snapshot.drops.rate_limited_audio_interval = 13;
    snapshot.drops.rate_limited_audio_total = 17;
    snapshot.ingress.push_back({1, "127.0.0.1:40000", {10, 20, 2, 3, 1, 4}, 120});
    snapshot.forwards.push_back({1, 2, {9, 19, 1, 2, 0, 3}});
    snapshot.pings.push_back({2, "127.0.0.1:40001", 4, 8, {6, 12, 1, 1, 0, 2}});

    const auto json = server_metrics::to_json_line(snapshot);
    require(json.ends_with('\n'), "metrics JSONL line must end in newline");
    require(json.find("\"schema\":\"jam_server_metrics_v1\"") != std::string::npos,
            "schema field missing");
    require(json.find("\"server_id\":\"server\\\"ops\"") != std::string::npos,
            "server_id was not escaped");
    require(json.find("\"connected_clients\":2") != std::string::npos,
            "connected client count missing");
    require(json.find("\"unknown_audio_interval\":3") != std::string::npos,
            "drop counters missing");
    require(json.find("\"ingress\"") != std::string::npos, "ingress array missing");
    require(json.find("\"forwards\"") != std::string::npos, "forward array missing");
    require(json.find("\"pings\"") != std::string::npos, "ping array missing");

    const auto dir = std::filesystem::temp_directory_path() / "jam_metrics_self_test";
    std::filesystem::remove_all(dir);
    server_metrics::JsonlExporter exporter(dir / "metrics.jsonl");
    std::string error;
    require(exporter.write(snapshot, &error), "first metrics write failed");
    require(exporter.write(snapshot, &error), "second metrics write failed");

    std::ifstream in(dir / "metrics.jsonl", std::ios::binary);
    std::string body((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    require(body.find("\"server_id\":\"server\\\"ops\"") != std::string::npos,
            "metrics file did not contain snapshot");
    require(body.find('\n') != body.rfind('\n'), "metrics file should contain two JSONL rows");
    std::filesystem::remove_all(dir);
    std::cout << "server metrics self-test passed\n";
}
```

- [ ] **Step 2: Run the self-test and verify it fails to build**

Run: `cmake --build build --config Release --target server_metrics_self_test`

Expected: FAIL because `server_metrics.h` and the CMake target do not exist.

- [ ] **Step 3: Add the metrics header**

Create `server_metrics.h` with the interfaces above. `to_json_line` must write exactly one JSON object plus `\n`; `JsonlExporter::write` must create parent directories, append, flush, and return an error string on failure.

- [ ] **Step 4: Register the self-test**

Add these CMake entries inside `if(JAM_BUILD_TESTS)`:

```cmake
add_executable(server_metrics_self_test server_metrics_self_test.cpp)
jam_add_executable_test(server_metrics_self_test)
```

- [ ] **Step 5: Integrate the server exporter**

In `server.cpp`, add:

```cpp
#include "server_metrics.h"
```

Extend `ServerOptions`:

```cpp
std::string metrics_jsonl_path;
```

Parse `--metrics-jsonl <path>`, add `Server::export_metrics_snapshot()`, call it from `alive_check_timer_callback()` before interval counters are reset, and add `--metrics-export-smoke` that starts a port-0 server with a temporary metrics path, calls `export_metrics_snapshot()`, and asserts the JSONL file contains `jam_server_metrics_v1`.

- [ ] **Step 6: Verify targeted tests**

Run: `ctest --test-dir build -C Release -R "server_metrics_self_test|server_metrics_export_smoke" --output-on-failure`

Expected: PASS for both tests.

- [ ] **Step 7: Run full validation and commit**

Run: `cmake --build build --config Release`

Expected: build succeeds.

Run: `ctest --test-dir build -C Release --output-on-failure`

Expected: all registered tests pass.

Commit:

```powershell
git add server_metrics.h server_metrics_self_test.cpp server.cpp CMakeLists.txt docs/superpowers/plans/2026-07-03-phase5-track-c-operations.md
git commit -m "feat: export server metrics as jsonl"
```

---

### Task 2: Rotating File Logs

**Files:**
- Modify: `logger.h`
- Create: `logger_self_test.cpp`
- Modify: `server.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Produces: `Logger::DEFAULT_ROTATING_LOG_MAX_BYTES`.
- Produces: `Logger::DEFAULT_ROTATING_LOG_MAX_FILES`.
- Produces: `Logger::init(..., size_t max_file_bytes, size_t max_files)`.
- Consumed by: server startup, client startup through default arguments, and `logger_self_test`.

- [ ] **Step 1: Write the failing self-test**

Create `logger_self_test.cpp`:

```cpp
#include "logger.h"

#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

void require(bool ok, const char* message) {
    if (!ok) {
        throw std::runtime_error(message);
    }
}

int main() {
    const auto dir = std::filesystem::temp_directory_path() / "jam_logger_self_test";
    std::filesystem::remove_all(dir);
    const auto log_path = dir / "server.log";

    Logger::instance().init(false, false, true, log_path.string(), spdlog::level::info, 512, 2);
    for (int i = 0; i < 300; ++i) {
        Log::info("rotating logger self-test line {} abcdefghijklmnopqrstuvwxyz", i);
    }
    Logger::instance().flush();
    std::this_thread::sleep_for(std::chrono::milliseconds(250));

    size_t file_count = 0;
    size_t oversized = 0;
    for (const auto& entry: std::filesystem::directory_iterator(dir)) {
        if (entry.path().filename().string().starts_with("server")) {
            ++file_count;
            if (std::filesystem::file_size(entry.path()) > 1024) {
                ++oversized;
            }
        }
    }
    require(file_count >= 2, "rotation did not create rotated log files");
    require(file_count <= 3, "rotation exceeded active plus retained file count");
    require(oversized == 0, "rotated files exceeded expected test bound");
    std::filesystem::remove_all(dir);
    std::cout << "logger rotation self-test passed\n";
}
```

- [ ] **Step 2: Run the self-test and verify it fails to build**

Run: `cmake --build build --config Release --target logger_self_test`

Expected: FAIL because the target does not exist and `Logger::init` does not accept rotation arguments.

- [ ] **Step 3: Replace the file sink**

In `logger.h`, replace `#include <spdlog/sinks/basic_file_sink.h>` with `#include <spdlog/sinks/rotating_file_sink.h>`, change the file sink member to `std::shared_ptr<spdlog::sinks::rotating_file_sink_mt>`, add defaults of `10 * 1024 * 1024` bytes and `5` retained files, and construct:

```cpp
file_sink_ = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
    file_path, max_file_bytes, max_files, false);
```

The implementation must recreate the file sink when the path or rotation settings change.

- [ ] **Step 4: Add server options**

Extend `ServerOptions` with `log_max_bytes` and `log_max_files`, parse `--log-max-bytes <bytes>` and `--log-max-files <count>`, and pass both values into `Logger::init`.

- [ ] **Step 5: Register the self-test**

Add these CMake entries inside `if(JAM_BUILD_TESTS)`:

```cmake
add_executable(logger_self_test logger_self_test.cpp)
target_link_libraries(logger_self_test PRIVATE spdlog::spdlog)
jam_add_executable_test(logger_self_test)
```

- [ ] **Step 6: Verify targeted tests**

Run: `ctest --test-dir build -C Release -R "logger_self_test" --output-on-failure`

Expected: PASS.

- [ ] **Step 7: Run full validation and commit**

Run: `cmake --build build --config Release`

Expected: build succeeds.

Run: `ctest --test-dir build -C Release --output-on-failure`

Expected: all registered tests pass.

Commit:

```powershell
git add logger.h logger_self_test.cpp server.cpp CMakeLists.txt
git commit -m "feat: rotate file logs"
```

---

### Task 3: Local Crash Reporting

**Files:**
- Create: `crash_reporter.h`
- Create: `crash_reporter_self_test.cpp`
- Modify: `server.cpp`
- Modify: `cmake/server.cmake`
- Modify: `CMakeLists.txt`
- Modify: `LOW_LATENCY_ACTION_PLAN.md`

**Interfaces:**
- Produces: `crash_reporter::Options`.
- Produces: `crash_reporter::write_report(const Options&, std::string_view, void*) -> std::filesystem::path`.
- Produces: `crash_reporter::install(const Options&)`.
- Consumed by: normal server startup and `--crash-report-smoke`.

- [ ] **Step 1: Write the failing self-test**

Create `crash_reporter_self_test.cpp`:

```cpp
#include "crash_reporter.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

void require(bool ok, const char* message) {
    if (!ok) {
        throw std::runtime_error(message);
    }
}

int main() {
    const auto dir = std::filesystem::temp_directory_path() / "jam_crash_reporter_self_test";
    std::filesystem::remove_all(dir);
    crash_reporter::Options options;
    options.report_dir = dir;
    options.process_name = "server";
    options.platform = "test-platform";
    options.arch = "test-arch";

    const auto report = crash_reporter::write_report(options, "self-test crash", nullptr);
    require(std::filesystem::exists(report), "crash metadata file was not written");
    std::ifstream in(report, std::ios::binary);
    std::string body((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    require(body.find("\"process\":\"server\"") != std::string::npos, "process missing");
    require(body.find("\"reason\":\"self-test crash\"") != std::string::npos,
            "reason missing");
    require(body.find("\"platform\":\"test-platform\"") != std::string::npos,
            "platform missing");
    std::filesystem::remove_all(dir);
    std::cout << "crash reporter self-test passed\n";
}
```

- [ ] **Step 2: Run the self-test and verify it fails to build**

Run: `cmake --build build --config Release --target crash_reporter_self_test`

Expected: FAIL because `crash_reporter.h` and the CMake target do not exist.

- [ ] **Step 3: Add the crash reporter**

Create `crash_reporter.h`. `write_report` must create a JSON metadata file with timestamp, process id, process name, platform, arch, reason, and a `minidump` field. On Windows, when exception pointers are supplied, it must also write a `.dmp` file via `MiniDumpWriteDump`.

- [ ] **Step 4: Integrate server startup**

Extend `ServerOptions`:

```cpp
bool crash_reports_enabled = true;
std::string crash_report_dir = "crash_reports/server";
```

Parse `--crash-report-dir <path>` and `--disable-crash-reports`. For normal server runs, call `crash_reporter::install` after logger initialization and before constructing `Server`. Add `--crash-report-smoke`, which writes one report to a temporary directory and asserts the JSON file exists.

- [ ] **Step 5: Register the self-test and Windows link**

Add these CMake entries inside `if(JAM_BUILD_TESTS)`:

```cmake
add_executable(crash_reporter_self_test crash_reporter_self_test.cpp)
if(WIN32)
    target_link_libraries(crash_reporter_self_test PRIVATE Dbghelp)
endif()
jam_add_executable_test(crash_reporter_self_test)
```

In `cmake/server.cmake`, add `Dbghelp` to the Windows server link line.

- [ ] **Step 6: Verify targeted tests**

Run: `ctest --test-dir build -C Release -R "crash_reporter_self_test|server_crash_report_smoke" --output-on-failure`

Expected: PASS for both tests.

- [ ] **Step 7: Update the tracker**

In `LOW_LATENCY_ACTION_PLAN.md`, add the Track C plan path to Detailed plans, mark Track C done with validation notes, and update the Production Gate so server metrics and log rotation are satisfied.

- [ ] **Step 8: Run full validation and commit**

Run: `cmake --build build --config Release`

Expected: build succeeds.

Run: `ctest --test-dir build -C Release --output-on-failure`

Expected: all registered tests pass.

Commit:

```powershell
git add crash_reporter.h crash_reporter_self_test.cpp server.cpp cmake/server.cmake CMakeLists.txt LOW_LATENCY_ACTION_PLAN.md
git commit -m "feat: add server crash reports"
```

---

## Final Acceptance

- `rg -n "basic_file_sink" logger.h` returns no matches.
- `ctest --test-dir build -C Release -R "server_metrics_self_test|server_metrics_export_smoke|logger_self_test|crash_reporter_self_test|server_crash_report_smoke" --output-on-failure` passes.
- `cmake --build build --config Release` passes.
- `ctest --test-dir build -C Release --output-on-failure` passes.
- `LOW_LATENCY_ACTION_PLAN.md` marks Track C done and does not start Track E.
