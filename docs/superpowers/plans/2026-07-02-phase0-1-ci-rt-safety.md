# Phase 0+1: CI + RT-Safe Audio Callback Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add CI, then make the audio callback real-time-safe: no logging, no lock-shared teardown, no allocating enqueues, no participant destruction on the audio thread.

**Architecture:** All changes are local hardening — no packet formats, no threading redesign, no `ParticipantManager` locking redesign (that is Phase 2). The callback keeps its current structure; we remove the four RT hazards the audit identified and route callback diagnostics through atomic counters drained by the existing io-thread cleanup timer.

**Tech Stack:** C++23, CMake + MSVC (multi-config), spdlog, moodycamel::ConcurrentQueue, Opus, ctest, GitHub Actions.

## Global Constraints

- Baseline commit: `23aebf8`. All quoted line numbers are from this commit; after earlier tasks land, anchor edits by the quoted code, not the line number.
- Build command: `cmake --build build --config Release --parallel 8` (must exit 0).
- Test command: `ctest --test-dir build -C Release --output-on-failure` (31/31 at baseline; 32/32 after Task 7).
- Cardinal rule of this phase: code reachable from `audio_callback` (`client.cpp:4281`) must not call `Log::*`/`Logger`, must not allocate, and must not take locks it doesn't already take (the `ParticipantManager` mutex stays until Phase 2).
- Match existing style: 4-space indent, `snake_case`, `.clang-format` at repo root. Commit messages are short imperative lines matching repo history (e.g. "Rejoin", "Audit").
- Do not touch: `protocol.h` wire structs, `ParticipantManager::for_each` locking, GUI code.
- Work on a branch: `git checkout -b phase1-rt-safety` (use a worktree per superpowers:using-git-worktrees if the main checkout is busy).

---

### Task 1: Windows CI workflow (Phase 0)

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: existing CMake build + ctest suite; `tools/*.mjs` smokes need `node` (preinstalled on `windows-latest`).
- Produces: a required status check future PRs can rely on.

- [ ] **Step 1: Write the workflow**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  windows-release:
    runs-on: windows-latest
    timeout-minutes: 90
    steps:
      - uses: actions/checkout@v4

      - name: Cache FetchContent dependencies
        uses: actions/cache@v4
        with:
          path: build/_deps
          key: deps-windows-${{ hashFiles('CMakeLists.txt', 'cmake/**') }}

      - name: Configure
        run: cmake -B build

      - name: Build
        run: cmake --build build --config Release --parallel

      - name: Test
        run: ctest --test-dir build -C Release --output-on-failure
```

- [ ] **Step 2: Sanity-check the suite passes locally first**

Run: `ctest --test-dir build -C Release --output-on-failure`
Expected: `100% tests passed, 0 tests failed out of 31`

- [ ] **Step 3: Commit and push the branch**

```bash
git add .github/workflows/ci.yml
git commit -m "Add Windows CI workflow"
git push -u origin phase1-rt-safety
```

- [ ] **Step 4: Verify the workflow runs green**

Run: `gh run watch --exit-status` (or `gh run list --branch phase1-rt-safety --limit 1`)
Expected: conclusion `success`. First run is slow (~20–40 min, cold FetchContent of JUCE); later runs hit the cache.
If the repo's GitHub remote has Actions disabled, stop and report — do not silently skip.

Note: all 31 tests are headless (policy/config smokes, loopback UDP probes); none open an audio device. If a test unexpectedly needs one on the runner, exclude it with a ctest label and record that in the PR description rather than deleting it.

---

### Task 2: Logger overflow policy → non-blocking

**Files:**
- Modify: `logger.h:180-182`

**Interfaces:**
- Consumes: nothing new.
- Produces: `Logger` behavior change only — under overflow, oldest messages are dropped instead of blocking the caller. No API change.

- [ ] **Step 1: Change the overflow policy**

At `logger.h:180-182`, current code:

```cpp
    logger_ = std::make_shared<spdlog::async_logger>("core", sinks.begin(), sinks.end(),
                                                     spdlog::thread_pool(),
                                                     spdlog::async_overflow_policy::block);
```

Replace with:

```cpp
    // Never block a caller on the logging worker: real-time audio threads may
    // reach this path indirectly; dropping old log lines is always preferable
    // to stalling audio.
    logger_ = std::make_shared<spdlog::async_logger>(
        "core", sinks.begin(), sinks.end(), spdlog::thread_pool(),
        spdlog::async_overflow_policy::overrun_oldest);
```

- [ ] **Step 2: Build and test**

Run: `cmake --build build --config Release --parallel 8`
Expected: exit 0.
Run: `ctest --test-dir build -C Release --output-on-failure`
Expected: 31/31 pass.

- [ ] **Step 3: Commit**

```bash
git add logger.h
git commit -m "Make async logger overflow non-blocking"
```

---

### Task 3: De-log the callback-reachable decoder methods

**Files:**
- Modify: `opus_decoder.h:65-76` (`reset`), `opus_decoder.h:100-116` (`decode_into`)

Only three `OpusDecoderWrapper` methods are callback-reachable, and grep confirms the vector-based `decode(...)`/`decode_plc(int, std::vector&)` overloads have **zero callers** in the repo — leave them untouched (removing dead code is out of scope). `decode_plc(float*, int)` at `opus_decoder.h:119-132` is already log-free — verify, don't edit.

**Interfaces:**
- Consumes: nothing new.
- Produces: same signatures (`bool reset()`, `int decode_into(...)`), now silent on failure; callers observe failure via return value (they already do — `client.cpp:4437, 4496-4498, 4503`).

- [ ] **Step 1: Rewrite `reset()` without logging**

Current code (`opus_decoder.h:65-76`):

```cpp
    bool reset() {
        if (decoder_ == nullptr) {
            Log::error("Opus decoder not initialized.");
            return false;
        }
        const int err = opus_decoder_ctl(decoder_, OPUS_RESET_STATE);
        if (err != OPUS_OK) {
            Log::error("Failed to reset Opus decoder: {}", opus_strerror(err));
            return false;
        }
        return true;
    }
```

Replace with:

```cpp
    // RT-safe: called from the audio callback; must not log or allocate.
    bool reset() {
        if (decoder_ == nullptr) {
            return false;
        }
        return opus_decoder_ctl(decoder_, OPUS_RESET_STATE) == OPUS_OK;
    }
```

- [ ] **Step 2: Rewrite `decode_into()` without logging**

Current code (`opus_decoder.h:100-116`):

```cpp
    // Decode directly into caller-provided buffer (zero-allocation)
    int decode_into(const unsigned char* input, int input_size, float* output, int frame_size) {
        if (decoder_ == nullptr) {
            Log::error("Opus decoder not initialized.");
            return -1;
        }

        int decoded_samples_per_channel =
            opus_decode_float(decoder_, input, input_size, output, frame_size, 0);

        if (decoded_samples_per_channel < 0) {
            Log::error("Opus decoding failed: {}", opus_strerror(decoded_samples_per_channel));
            return -1;
        }

        return decoded_samples_per_channel * channels_;
    }
```

Replace with:

```cpp
    // Decode directly into caller-provided buffer (zero-allocation).
    // RT-safe: called from the audio callback; must not log or allocate.
    // Callers count failures via the return value.
    int decode_into(const unsigned char* input, int input_size, float* output, int frame_size) {
        if (decoder_ == nullptr) {
            return -1;
        }

        int decoded_samples_per_channel =
            opus_decode_float(decoder_, input, input_size, output, frame_size, 0);

        if (decoded_samples_per_channel < 0) {
            return -1;
        }

        return decoded_samples_per_channel * channels_;
    }
```

- [ ] **Step 3: Verify remaining logging is control-path only**

Run: `rg -n "Log::" opus_decoder.h`
Expected output — exactly these contexts and no others:
- `create(...)`: the "Failed to create" error and "Opus decoder created" info
- vector `decode(...)` overload (uncalled dead code): its two error lines
- vector `decode_plc(int, std::vector&)` overload (uncalled dead code): its two error lines

If a line shows up inside `reset`, `decode_into`, or `decode_plc(float*, int)`, the task is not done.

- [ ] **Step 4: Build and test**

Run: `cmake --build build --config Release --parallel 8` then `ctest --test-dir build -C Release --output-on-failure`
Expected: build exit 0; 31/31 pass.

- [ ] **Step 5: Commit**

```bash
git add opus_decoder.h
git commit -m "Strip logging from RT decoder methods"
```

---

### Task 4: Remove all logging from `audio_callback`; add RT diagnostics counters

**Files:**
- Modify: `client.cpp` — callback body (`client.cpp:4281-4968`), member declarations (near `client.cpp:5010`), `cleanup_timer_callback` (`client.cpp:3658-3671`)

**Interfaces:**
- Consumes: nothing new.
- Produces: `Client` members `rt_diag_pcm_shape_mismatches_`, `rt_diag_pcm_size_mismatches_`, `rt_diag_mix_size_mismatches_`, `rt_diag_decode_failures_` (all `std::atomic<uint64_t>`), and private method `void log_rt_callback_diagnostics()` called from `cleanup_timer_callback`.

There are exactly seven log sites in the callback at baseline. Handle each as follows.

- [ ] **Step 1: Add the diagnostic members**

Next to the existing drop counters (`client.cpp:5010-5011`, `pcm_send_drops_` / `opus_send_drops_`), add:

```cpp
    // Written by the audio callback (relaxed atomics), drained and logged by
    // the io-thread cleanup timer. The callback itself must never log.
    std::atomic<uint64_t> rt_diag_pcm_shape_mismatches_{0};
    std::atomic<uint64_t> rt_diag_pcm_size_mismatches_{0};
    std::atomic<uint64_t> rt_diag_mix_size_mismatches_{0};
    std::atomic<uint64_t> rt_diag_decode_failures_{0};
    uint64_t rt_diag_logged_pcm_shape_mismatches_ = 0;  // io thread only
    uint64_t rt_diag_logged_pcm_size_mismatches_ = 0;   // io thread only
    uint64_t rt_diag_logged_mix_size_mismatches_ = 0;   // io thread only
    uint64_t rt_diag_logged_decode_failures_ = 0;       // io thread only
```

- [ ] **Step 2: Site 1 — buffer-ready log in the callback (`client.cpp:4355-4363`)**

The io-thread twin of this message (in `handle_audio_message`, `client.cpp:4002-4009`) stays. In the callback, current code:

```cpp
                if (queue_size >= ready_threshold_packets(participant)) {
                    participant.buffer_ready.store(true, std::memory_order_relaxed);
                    participant.opus_consecutive_empty_callbacks.store(0,
                                                                       std::memory_order_relaxed);
                    Log::info("Jitter buffer ready for participant {} ({} packets)",
                              participant_id, queue_size);
                } else {
```

Delete the `Log::info(...)` statement only; keep both stores.

- [ ] **Step 3: Site 2 — PCM shape mismatch (`client.cpp:4462-4471`)**

Current code:

```cpp
                    if (packet_channels != 1 ||
                        packet_frame_count > participant.pcm_buffer.size()) {
                        static int pcm_shape_mismatch_count = 0;
                        if (++pcm_shape_mismatch_count % 100 == 0) {
                            Log::warn(
                                "PCM shape mismatch for participant {}: frames={}, channels={}",
                                participant_id, packet_frame_count, packet_channels);
                        }
                        return;
                    }
```

Replace with:

```cpp
                    if (packet_channels != 1 ||
                        packet_frame_count > participant.pcm_buffer.size()) {
                        client->rt_diag_pcm_shape_mismatches_.fetch_add(
                            1, std::memory_order_relaxed);
                        return;
                    }
```

- [ ] **Step 4: Site 3 — PCM size mismatch (`client.cpp:4473-4482`)**

Current code:

```cpp
                    const size_t expected_bytes =
                        packet_frame_count * packet_channels * sizeof(int16_t);
                    if (opus_packet.get_size() != expected_bytes) {
                        static int pcm_size_mismatch_count = 0;
                        if (++pcm_size_mismatch_count % 100 == 0) {
                            Log::warn("PCM size mismatch for participant {}: got {}, expected {}",
                                      participant_id, opus_packet.get_size(), expected_bytes);
                        }
                        return;
                    }
```

Replace the `static ... Log::warn ...` block with:

```cpp
                    const size_t expected_bytes =
                        packet_frame_count * packet_channels * sizeof(int16_t);
                    if (opus_packet.get_size() != expected_bytes) {
                        client->rt_diag_pcm_size_mismatches_.fetch_add(
                            1, std::memory_order_relaxed);
                        return;
                    }
```

- [ ] **Step 5: Site 4 — decode failure (`client.cpp:4503-4512`)**

Current code:

```cpp
                if (decoded_samples <= 0) {
                    // Decode failed - use silence
                    static int decode_fail_count = 0;
                    if (++decode_fail_count % 100 == 0) {
                        Log::warn("Decode failed for participant {} ({} times)", participant_id,
                                  decode_fail_count);
                    }
                    observe_auto_jitter_instability(participant);
                    return;
                }
```

Replace with (the instability observation must stay):

```cpp
                if (decoded_samples <= 0) {
                    // Decode failed - use silence
                    client->rt_diag_decode_failures_.fetch_add(1, std::memory_order_relaxed);
                    observe_auto_jitter_instability(participant);
                    return;
                }
```

- [ ] **Step 6: Sites 5+6 — speaking-transition debug logs (two copies)**

Opus branch (`client.cpp:4640-4645`):

```cpp
                    if (is_speaking && !was_speaking) {
                        Log::debug("Participant {} started speaking (level: {:.4f})",
                                   participant_id, rms);
                    } else if (!is_speaking && was_speaking) {
                        Log::debug("Participant {} stopped speaking", participant_id);
                    }
```

Delete the whole if/else block. Then the local `was_speaking` (`client.cpp:4614-4615`) becomes unused — delete its declaration too:

```cpp
                    const bool was_speaking =
                        participant.is_speaking.load(std::memory_order_relaxed);
```

PCM/generic branch: repeat exactly the same two deletions at `client.cpp:4673-4678` (log block) and `client.cpp:4668-4669` (`was_speaking` declaration). The `is_speaking` computation and `participant.is_speaking.store(...)` stay in both branches — the UI reads that flag.

- [ ] **Step 7: Site 7 — mix size mismatch (`client.cpp:4692-4700`)**

Current code:

```cpp
                } else {
                    // Size mismatch - log warning occasionally
                    static int mismatch_count = 0;
                    if (++mismatch_count % 100 == 0) {
                        Log::warn(
                            "Audio size mismatch: participant {}, got {} samples, expected {}",
                            participant_id, decoded_samples, expected_samples);
                    }
                }
```

Replace with:

```cpp
                } else {
                    client->rt_diag_mix_size_mismatches_.fetch_add(1,
                                                                   std::memory_order_relaxed);
                }
```

- [ ] **Step 8: Site 8 — rebuffer log (`client.cpp:4808-4823`)**

Current code:

```cpp
                    if (empty_callbacks >=
                        static_cast<int>(opus_rebuffer_empty_callback_threshold(participant))) {
                        const int underruns =
                            participant.underrun_count.fetch_add(1, std::memory_order_relaxed) +
                            1;
                        observe_auto_jitter_instability(participant);
                        participant.buffer_ready.store(false, std::memory_order_relaxed);
                        participant.opus_consecutive_empty_callbacks.store(
                            0, std::memory_order_relaxed);
                        if (underruns == 1 || underruns % 10 == 0) {
                            Log::info("Participant {} rebuffering (underruns: {}, PLC: {})",
                                      participant_id, underruns,
                                      participant.plc_count.load(std::memory_order_relaxed));
                        }
                    }
```

Replace with (underrun counting stays; the counter is already surfaced in the UI and baseline snapshots):

```cpp
                    if (empty_callbacks >=
                        static_cast<int>(opus_rebuffer_empty_callback_threshold(participant))) {
                        participant.underrun_count.fetch_add(1, std::memory_order_relaxed);
                        observe_auto_jitter_instability(participant);
                        participant.buffer_ready.store(false, std::memory_order_relaxed);
                        participant.opus_consecutive_empty_callbacks.store(
                            0, std::memory_order_relaxed);
                    }
```

- [ ] **Step 9: Drain the counters on the io thread**

Add this private method to `Client` (near `cleanup_timer_callback`, `client.cpp:3658`):

```cpp
    void log_rt_callback_diagnostics() {
        const uint64_t shape = rt_diag_pcm_shape_mismatches_.load(std::memory_order_relaxed);
        const uint64_t size = rt_diag_pcm_size_mismatches_.load(std::memory_order_relaxed);
        const uint64_t mix = rt_diag_mix_size_mismatches_.load(std::memory_order_relaxed);
        const uint64_t decode = rt_diag_decode_failures_.load(std::memory_order_relaxed);
        if (shape == rt_diag_logged_pcm_shape_mismatches_ &&
            size == rt_diag_logged_pcm_size_mismatches_ &&
            mix == rt_diag_logged_mix_size_mismatches_ &&
            decode == rt_diag_logged_decode_failures_) {
            return;
        }
        Log::warn(
            "Audio callback diagnostics: pcm_shape_mismatches={} pcm_size_mismatches={} "
            "mix_size_mismatches={} decode_failures={}",
            shape, size, mix, decode);
        rt_diag_logged_pcm_shape_mismatches_ = shape;
        rt_diag_logged_pcm_size_mismatches_ = size;
        rt_diag_logged_mix_size_mismatches_ = mix;
        rt_diag_logged_decode_failures_ = decode;
    }
```

And call it at the end of `cleanup_timer_callback()` (`client.cpp:3658-3671`), after the removal loop:

```cpp
        log_rt_callback_diagnostics();
```

- [ ] **Step 10: Verify the callback body is log-free**

Run (extracts the callback body — it starts at `static int audio_callback` and ends where the member declarations begin):

```bash
awk '/static int audio_callback/,/asio::io_context& io_context_;/' client.cpp | rg -n "Log::|Logger"
```

Expected: no output. If the awk boundaries drift after edits, open the function and review manually — the acceptance criterion is zero logging statements between the function's opening brace and its `return 0;`.

- [ ] **Step 11: Build, test, commit**

Run: `cmake --build build --config Release --parallel 8` then `ctest --test-dir build -C Release --output-on-failure`
Expected: build exit 0; 31/31 pass.

```bash
git add client.cpp
git commit -m "Replace audio callback logging with drained diagnostics counters"
```

---

### Task 5: RT-side queues — pre-size and `try_enqueue`

**Files:**
- Modify: `client.cpp:4998-4999` (queue declarations), `client.cpp:2052-2067` and `client.cpp:2077-2092` (enqueue sites)
- Modify: `recording_writer.h:26` (constants), `recording_writer.h:113-127` (enqueue), `recording_writer.h:294` (queue declaration)

`moodycamel::ConcurrentQueue::enqueue` allocates a fresh block when none is free; `try_enqueue` never allocates. Pre-sizing gives `try_enqueue` its block pool. The broadcast queue already follows this pattern (`broadcast_queue_{256}` + `try_enqueue`, `client.cpp:5038, 4227`) — this task brings the other three callback-side queues in line. Note: `ParticipantOpusPacketQueue::incoming_.enqueue` (`participant_info.h:69`) is called from the **io thread**, not the callback — leave it alone.

**Interfaces:**
- Consumes: existing drop counters `pcm_send_drops_`, `opus_send_drops_` (`client.cpp:5010-5011`), `dropped_blocks_` (`recording_writer.h`).
- Produces: unchanged public APIs; overflow now drops-and-counts instead of allocating.

- [ ] **Step 1: Pre-size the send queues**

At `client.cpp:4998-4999`, current code:

```cpp
    moodycamel::ConcurrentQueue<PcmSendFrame> pcm_send_queue_;
    moodycamel::ConcurrentQueue<OpusSendFrame> opus_send_queue_;
```

Replace with:

```cpp
    // Pre-sized so the audio callback's try_enqueue never allocates
    // (max_send_queue_frames caps useful depth at 8; 64 gives block-pool slack).
    moodycamel::ConcurrentQueue<PcmSendFrame> pcm_send_queue_{64};
    moodycamel::ConcurrentQueue<OpusSendFrame> opus_send_queue_{64};
```

- [ ] **Step 2: Switch the PCM enqueue site**

At `client.cpp:2060-2067`, current tail of `enqueue_pcm_send_frame`:

```cpp
        PcmSendFrame frame;
        std::memcpy(frame.payload.data(), payload, payload_bytes);
        frame.payload_bytes = payload_bytes;
        frame.frame_count = frame_count;
        frame.sample_rate = sample_rate;
        frame.capture_time = capture_time;
        pcm_send_queue_.enqueue(frame);
        wake_pcm_sender_thread();
```

Replace the last two lines with:

```cpp
        if (!pcm_send_queue_.try_enqueue(frame)) {
            pcm_send_drops_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        wake_pcm_sender_thread();
```

- [ ] **Step 3: Switch the Opus enqueue site**

At `client.cpp:2086-2092`, same pattern — current tail of `enqueue_opus_send_frame`:

```cpp
        OpusSendFrame frame;
        std::copy_n(samples, frame_count, frame.samples.begin());
        frame.frame_count = frame_count;
        frame.sample_rate = sample_rate;
        frame.capture_time = capture_time;
        opus_send_queue_.enqueue(frame);
        wake_pcm_sender_thread();
```

Replace the last two lines with:

```cpp
        if (!opus_send_queue_.try_enqueue(frame)) {
            opus_send_drops_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        wake_pcm_sender_thread();
```

- [ ] **Step 4: Recording writer — hoist the cap, pre-size, try_enqueue**

At `recording_writer.h:26`, extend the constants:

```cpp
    static constexpr size_t MAX_FRAMES_PER_BLOCK = 960;
    // Bounded so the pre-sized queue's try_enqueue never allocates on the
    // audio thread. 1024 blocks (~4 MB) is several seconds of drain headroom
    // for the writer thread; overflow drops are counted, which is preferable
    // to allocating in the callback. (Was a function-local 4096.)
    static constexpr size_t MAX_QUEUED_BLOCKS = 1024;
```

In `enqueue()` (`recording_writer.h:113-127`): delete the local `constexpr size_t MAX_QUEUED_BLOCKS = 4096;` line (the guard now uses the class constant), and change the tail from:

```cpp
        queue_.enqueue(block);
        queued_blocks_.fetch_add(1, std::memory_order_release);
```

to:

```cpp
        if (!queue_.try_enqueue(block)) {
            dropped_blocks_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        queued_blocks_.fetch_add(1, std::memory_order_release);
```

At `recording_writer.h:294`, change the declaration:

```cpp
    moodycamel::ConcurrentQueue<Block> queue_;
```

to:

```cpp
    moodycamel::ConcurrentQueue<Block> queue_{MAX_QUEUED_BLOCKS};
```

- [ ] **Step 5: Verify no allocating enqueue remains on callback paths**

Run: `rg -n "\.enqueue\(" client.cpp recording_writer.h`
Expected output: only the `recording_writer_.enqueue(...)` call in `record_mono_block` (`client.cpp:4163` at baseline) — that is the `RecordingWriter` class API, whose internals now use `try_enqueue`. No `pcm_send_queue_.enqueue`, `opus_send_queue_.enqueue`, or `queue_.enqueue` lines remain. (`incoming_.enqueue` lives in `participant_info.h` on the io-thread path and is out of scope; `enqueue_bounded_or_reject_overflow` and `try_enqueue` calls don't match this pattern.)

- [ ] **Step 6: Build, test, commit**

Run: `cmake --build build --config Release --parallel 8` then `ctest --test-dir build -C Release --output-on-failure`
Expected: build exit 0; 31/31 pass (`recording_writer_self_test` covers the writer's drop accounting).

```bash
git add client.cpp recording_writer.h
git commit -m "Bound RT-side queues with try_enqueue"
```

---

### Task 6: Guard the `clear_audio_path_queues` precondition

**Files:**
- Modify: `client.cpp:1633` (function opening), `client.cpp` includes (ensure `<cassert>`)

The function resets `opus_pcm_buffered_frames` and calls `decoder->reset()` on state the callback mutates without synchronization; its single caller (`client.cpp:1411-1417`) stops the stream first, so this is safe today — but only by convention. Make the convention enforced.

**Interfaces:** none new.

- [ ] **Step 1: Ensure `<cassert>` is included**

Check the include block at the top of `client.cpp`; if `#include <cassert>` is absent, add it in alphabetical position among the standard includes.

- [ ] **Step 2: Add the precondition**

At `client.cpp:1633`, current code:

```cpp
    void clear_audio_path_queues() {
        PcmSendFrame discarded_pcm;
```

Replace with:

```cpp
    void clear_audio_path_queues() {
        // Precondition: the audio stream must be stopped. This resets decoder
        // and PCM state that the audio callback mutates without locks; running
        // it concurrently with the callback is undefined behavior.
        assert(!audio_.is_stream_active());
        PcmSendFrame discarded_pcm;
```

- [ ] **Step 3: Build, test, commit**

Run: `cmake --build build --config Release --parallel 8` then `ctest --test-dir build -C Release --output-on-failure`
Expected: build exit 0; 31/31 pass.

```bash
git add client.cpp
git commit -m "Assert stream is stopped before clearing audio path state"
```

---

### Task 7: Deferred participant reclamation (TDD)

**Files:**
- Create: `participant_manager_self_test.cpp`
- Modify: `participant_manager.h:65-73` (`remove_participant`), `participant_manager.h:184-205` (`remove_timed_out_participants`), `participant_manager.h:213-217` (`clear`), private members (`participant_manager.h:242-251`)
- Modify: `client.cpp:3658-3671` (`cleanup_timer_callback` — add reap call)
- Modify: `CMakeLists.txt` (new test target + registration)

**Design:** removals no longer let the `shared_ptr<ParticipantData>` die at the erase site — they move it into a `graveyard_` vector. `reap_retired_participants()` (io thread, called from the 10 s cleanup timer) destroys only entries with `use_count() == 1`. Safety argument: once an entry is graveyard-only, no new references can ever be created (only map entries are snapshotted by `for_each`), so a `use_count() == 1` observed under the lock is stable, and destruction happens on the io thread, outside the lock — never on the audio thread, and never while blocking `for_each`.

**Interfaces:**
- Produces: `size_t ParticipantManager::reap_retired_participants()` (returns number destroyed), `size_t ParticipantManager::retired_count() const`. Consumed by `Client::cleanup_timer_callback` and the new self-test.

- [ ] **Step 1: Write the failing test**

Create `participant_manager_self_test.cpp`:

```cpp
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <thread>

#include "participant_manager.h"

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        std::exit(1);
    }
}

void test_immediate_reap_without_snapshot() {
    ParticipantManager manager;
    require(manager.register_participant(1, 48000, 1), "register participant");
    manager.remove_participant(1);
    require(manager.retired_count() == 1, "removed participant is retired, not destroyed");
    require(manager.reap_retired_participants() == 1, "unreferenced retiree is reaped");
    require(manager.retired_count() == 0, "graveyard empty after reap");
}

void test_snapshot_defers_reclamation() {
    ParticipantManager manager;
    require(manager.register_participant(7, 48000, 1), "register participant");

    std::atomic<bool> snapshot_taken{false};
    std::atomic<bool> release_snapshot{false};
    std::thread holder([&]() {
        manager.for_each([&](uint32_t, ParticipantData&) {
            snapshot_taken.store(true, std::memory_order_release);
            while (!release_snapshot.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
        });
    });

    while (!snapshot_taken.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }

    manager.remove_participant(7);
    require(manager.retired_count() == 1, "removed participant parked in graveyard");
    require(manager.reap_retired_participants() == 0,
            "participant referenced by a live snapshot is NOT reaped");
    require(manager.retired_count() == 1, "still retired while snapshot lives");

    release_snapshot.store(true, std::memory_order_release);
    holder.join();

    require(manager.reap_retired_participants() == 1, "reaped after snapshot released");
    require(manager.retired_count() == 0, "graveyard empty at end");
}

void test_timeout_and_clear_route_through_graveyard() {
    ParticipantManager manager;
    require(manager.register_participant(2, 48000, 1), "register participant 2");
    require(manager.register_participant(3, 48000, 1), "register participant 3");

    const auto removed = manager.remove_timed_out_participants(
        std::chrono::steady_clock::now() + std::chrono::hours(1),
        std::chrono::seconds(1));
    require(removed.size() == 2, "both participants timed out");
    require(manager.count() == 0, "map empty after timeout");
    require(manager.retired_count() == 2, "timed-out participants retired");
    require(manager.reap_retired_participants() == 2, "timed-out participants reaped");

    require(manager.register_participant(4, 48000, 1), "register participant 4");
    manager.clear();
    require(manager.retired_count() == 1, "clear() retires instead of destroying");
    require(manager.reap_retired_participants() == 1, "cleared participant reaped");
}

}  // namespace

int main() {
    test_immediate_reap_without_snapshot();
    test_snapshot_defers_reclamation();
    test_timeout_and_clear_route_through_graveyard();
    std::printf("participant_manager_self_test passed\n");
    return 0;
}
```

Add the target to `CMakeLists.txt` — in the `JAM_BUILD_TESTS` block next to `participant_packet_queue_self_test` (`CMakeLists.txt:55-56`):

```cmake
    add_executable(participant_manager_self_test participant_manager_self_test.cpp)
    target_link_libraries(participant_manager_self_test PRIVATE concurrentqueue spdlog::spdlog opus)
```

and register it with the others (`CMakeLists.txt:102-114`):

```cmake
    jam_add_executable_test(participant_manager_self_test)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cmake --build build --config Release --parallel 8 --target participant_manager_self_test`
Expected: **compile error** — `retired_count`/`reap_retired_participants` do not exist yet. (For an API-addition task the compile failure is the red step.)

- [ ] **Step 3: Implement the graveyard in `ParticipantManager`**

Add the member (next to `participants_`, `participant_manager.h:249`):

```cpp
    // Removed participants are parked here and destroyed only by
    // reap_retired_participants() on the io thread, once no audio-callback
    // snapshot references them. Destruction frees heap memory and destroys the
    // Opus decoder, so it must never run on the audio thread.
    std::vector<std::shared_ptr<ParticipantData>> graveyard_;
```

Change `remove_participant` (`participant_manager.h:66-73`) to:

```cpp
    // Remove a participant (destruction is deferred; see graveyard_)
    void remove_participant(uint32_t id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto                        it = participants_.find(id);
        if (it != participants_.end()) {
            graveyard_.push_back(std::move(it->second));
            participants_.erase(it);
            Log::info("Participant {} left", id);
        }
    }
```

In `remove_timed_out_participants` (`participant_manager.h:190-202`), change the erase branch from:

```cpp
            if (elapsed > timeout) {
                Log::info("Participant {} timed out ({}s since last packet)", it->first,
                          elapsed.count());
                removed_ids.push_back(it->first);
                it = participants_.erase(it);
            } else {
```

to:

```cpp
            if (elapsed > timeout) {
                Log::info("Participant {} timed out ({}s since last packet)", it->first,
                          elapsed.count());
                removed_ids.push_back(it->first);
                graveyard_.push_back(std::move(it->second));
                it = participants_.erase(it);
            } else {
```

Change `clear` (`participant_manager.h:214-217`) to:

```cpp
    // Clear all participants (destruction is deferred; see graveyard_)
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [id, participant]: participants_) {
            graveyard_.push_back(std::move(participant));
        }
        participants_.clear();
    }
```

Add the two new public methods (after `clear`):

```cpp
    // Destroy retired participants that no snapshot references anymore.
    // Call from the io thread only. Destruction runs outside the lock so a
    // concurrent for_each() in the audio callback is never blocked on frees.
    // Safety: a graveyard-only entry can never gain new references (for_each
    // snapshots map entries only), so use_count()==1 observed under the lock
    // cannot race upward.
    size_t reap_retired_participants() {
        std::vector<std::shared_ptr<ParticipantData>> to_destroy;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto it = graveyard_.begin(); it != graveyard_.end();) {
                if (it->use_count() == 1) {
                    to_destroy.push_back(std::move(*it));
                    it = graveyard_.erase(it);
                } else {
                    ++it;
                }
            }
        }
        return to_destroy.size();
    }

    size_t retired_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return graveyard_.size();
    }
```

- [ ] **Step 4: Run the new test to verify it passes**

Run: `cmake --build build --config Release --parallel 8` then
`ctest --test-dir build -C Release -R participant_manager_self_test --output-on-failure`
Expected: `1/1 Test #N: participant_manager_self_test ... Passed`

- [ ] **Step 5: Wire the reap into the client's cleanup timer**

In `cleanup_timer_callback` (`client.cpp:3658-3671`), after the removal loop (and after the `log_rt_callback_diagnostics();` call added in Task 4), add:

```cpp
        participant_manager_.reap_retired_participants();
```

- [ ] **Step 6: Full build, full test run**

Run: `cmake --build build --config Release --parallel 8` then `ctest --test-dir build -C Release --output-on-failure`
Expected: build exit 0; **32/32 pass**.

- [ ] **Step 7: Commit**

```bash
git add participant_manager.h participant_manager_self_test.cpp client.cpp CMakeLists.txt
git commit -m "Defer participant reclamation off the audio thread"
```

---

### Task 8: Final verification and tracker update

**Files:**
- Modify: `LOW_LATENCY_ACTION_PLAN.md` (phase statuses)

- [ ] **Step 1: Run the full acceptance suite and record output**

```bash
cmake --build build --config Release --parallel 8
ctest --test-dir build -C Release --output-on-failure
awk '/static int audio_callback/,/asio::io_context& io_context_;/' client.cpp | rg -n "Log::|Logger"
rg -n "Log::" opus_decoder.h
rg -n "\.enqueue\(" client.cpp recording_writer.h
rg -n "async_overflow_policy" logger.h
```

Expected: build exit 0; 32/32 tests; empty callback grep; decoder greps only in `create`/dead vector overloads; no bare `.enqueue(` on the three converted queues; `overrun_oldest` in logger.h.

- [ ] **Step 2: Update the tracker**

In `LOW_LATENCY_ACTION_PLAN.md`, set Phase 0 and Phase 1 statuses to `Done (<date>, 32/32 tests, CI green)` and paste the acceptance command output summary into the phase's PR description.

- [ ] **Step 3: Commit and push**

```bash
git add LOW_LATENCY_ACTION_PLAN.md
git commit -m "Mark CI and RT-safety phases done"
git push
```

- [ ] **Step 4: Confirm CI is green on the pushed branch**

Run: `gh run watch --exit-status`
Expected: `success`. Open the PR for review (see superpowers:finishing-a-development-branch).

---

## Explicitly Out of Scope (do not drift into these)

- `ParticipantManager::for_each` mutex removal / snapshot publication → Phase 2.
- `register_participant` logging + decoder creation under the lock → Phase 2 (io-thread-only today, not an RT hazard).
- `wake_pcm_sender_thread()`'s `notify_one` syscall from the callback → absorbed by the Phase 4 TX collapse.
- Packet format changes (capture timestamps) → Phase 3.
- The dead vector-based `OpusDecoderWrapper::decode`/`decode_plc` overloads — leave them.
