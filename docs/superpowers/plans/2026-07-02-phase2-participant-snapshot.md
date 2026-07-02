# Phase 2: Participant Snapshot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make participant access from the audio callback lock-free while preserving deferred participant destruction and moving GUI/stats reads off `ParticipantManager::mutex_`.

**Architecture:** `ParticipantManager` remains the single owner of membership mutation under `mutex_`, but every membership change rebuilds and atomically publishes an immutable `std::shared_ptr<const std::vector<ParticipantEntry>>` for callback/control iteration. GUI/stats load the same participant pointer snapshot for live atomic counters and a separately published immutable metadata snapshot for names, so they do not acquire `ParticipantManager::mutex_`. Decoder creation and registration logging move outside the registration critical section, while removed participants stay in the Phase 1 graveyard until no published/callback snapshot can reference them.

**Tech Stack:** C++23, CMake + MSVC Release, `std::shared_ptr` atomic load/store free functions, Opus, spdlog, ctest, GitHub Actions.

## Global Constraints

- Baseline commit for this plan: `c836cf6`. All citations below were verified against this commit; match edits by quoted code if later steps shift line numbers.
- Current Phase 2 tracker: `LOW_LATENCY_ACTION_PLAN.md` Phase 2 says the goal is that "the audio callback never acquires `ParticipantManager::mutex_`" and records the decided design: immutable `std::shared_ptr<const std::vector<...>>` publication via `std::atomic_store`, callback `std::atomic_load`, separate GUI/stats snapshot, and decoder/log work outside registration critical sections.
- Current audit finding "Audio callback takes a non-priority-inheriting mutex" is still present at HEAD: `client.cpp:4379` calls `participant_manager_.for_each(...)`, and `participant_manager.h:253-271` takes `std::lock_guard<std::mutex> lock(mutex_)` before invoking the callback lambda.
- Current audit finding "Participant teardown can run inside the audio callback" is partially fixed by Phase 1: `participant_manager.h:65-74`, `185-207`, and `215-244` park removals in `graveyard_` and reap them outside the lock, but `for_each` still creates a temporary callback snapshot that must not become the last reference.
- Current GUI/stats contention points: `client.cpp:521`, `client.cpp:695`, `client.cpp:2793`, and `client.cpp:3433` call `participant_manager_.get_all_info()`, which currently locks and copies strings/counters under `participant_manager.h:95-182`.
- Current registration critical section: `participant_manager.h:23-50` creates `OpusDecoderWrapper`, calls `OpusDecoderWrapper::create`, and logs with `Log::error`/`Log::info` while holding `mutex_`.
- Work branch: `phase2-participant-snapshot`.
- Per tracker rules: one commit per task; run `cmake --build build --config Release --parallel 8` and `ctest --test-dir build -C Release --output-on-failure` before each task commit.
- Acceptance commands at the end of the phase must include the scoped callback-path mutex check, full Release build, full ctest, and CI status.

---

### Task 1: Lock-Free Audio Participant Snapshot

**Files:**
- Modify: `participant_manager.h:1-288`
- Modify: `participant_manager_self_test.cpp:17-85`
- Modify: `client.cpp:4316-4818`

**Interfaces:**
- Consumes: existing `ParticipantManager::for_each(Func&&)` API used by callback/control code.
- Produces: `ParticipantManager::for_each(Func&&)` implemented as an atomic load of an immutable participant array; `ParticipantManager::AudioCallbackReadScope` debug guard; membership mutations publish the new audio snapshot before releasing their lock.

- [ ] **Step 1: Add the failing snapshot coverage**

In `participant_manager_self_test.cpp`, add helpers after `require(...)`:

```cpp
std::vector<uint32_t> snapshot_ids(ParticipantManager& manager) {
    std::vector<uint32_t> ids;
    manager.for_each([&](uint32_t id, ParticipantData&) {
        ids.push_back(id);
    });
    std::sort(ids.begin(), ids.end());
    return ids;
}

bool contains_id(const std::vector<uint32_t>& ids, uint32_t id) {
    return std::find(ids.begin(), ids.end(), id) != ids.end();
}
```

Add includes:

```cpp
#include <algorithm>
#include <vector>
```

Add this test and call it from `main()` before the reclamation tests:

```cpp
void test_join_leave_timeout_update_audio_snapshot() {
    ParticipantManager manager;
    require(manager.register_participant(10, 48000, 1), "register participant 10");
    require(manager.register_participant(11, 48000, 1), "register participant 11");

    auto ids = snapshot_ids(manager);
    require(ids.size() == 2, "audio snapshot has two joined participants");
    require(contains_id(ids, 10), "audio snapshot contains participant 10");
    require(contains_id(ids, 11), "audio snapshot contains participant 11");

    manager.remove_participant(10);
    ids = snapshot_ids(manager);
    require(ids.size() == 1, "audio snapshot shrinks after leave");
    require(!contains_id(ids, 10), "audio snapshot drops participant 10");
    require(contains_id(ids, 11), "audio snapshot keeps participant 11");

    const auto removed = manager.remove_timed_out_participants(
        std::chrono::steady_clock::now() + std::chrono::hours(1),
        std::chrono::seconds(1));
    require(removed.size() == 1 && removed[0] == 11, "timeout removes participant 11");
    ids = snapshot_ids(manager);
    require(ids.empty(), "audio snapshot empty after timeout");
}
```

- [ ] **Step 2: Run the focused test and confirm it fails before implementation**

Run: `cmake --build build --config Release --target participant_manager_self_test --parallel 8`

Run: `ctest --test-dir build -C Release -R participant_manager_self_test --output-on-failure`

Expected before implementation: the new test exposes the old locked snapshot implementation in review by code inspection; it may still pass functionally. Do not commit yet.

- [ ] **Step 3: Implement the atomic audio snapshot**

In `participant_manager.h`, add includes:

```cpp
#include <algorithm>
#include <atomic>
#include <cassert>
```

Inside `public`, add:

```cpp
    class AudioCallbackReadScope {
    public:
        AudioCallbackReadScope()
            : previous_(in_audio_callback_) {
            in_audio_callback_ = true;
        }

        ~AudioCallbackReadScope() {
            in_audio_callback_ = previous_;
        }

    private:
        bool previous_;
    };
```

Add private types:

```cpp
    struct ParticipantEntry {
        uint32_t                         id = 0;
        std::shared_ptr<ParticipantData> data;
    };

    using ParticipantSnapshot = std::vector<ParticipantEntry>;
    using ParticipantSnapshotPtr = std::shared_ptr<const ParticipantSnapshot>;
```

Change the constructor to publish an empty snapshot:

```cpp
    ParticipantManager()
        : audio_snapshot_(std::make_shared<ParticipantSnapshot>()) {}
```

Add private helpers:

```cpp
    static void assert_not_audio_callback_lock() {
        assert(!in_audio_callback_);
    }

    ParticipantSnapshotPtr load_audio_snapshot() const {
        return std::atomic_load_explicit(&audio_snapshot_, std::memory_order_acquire);
    }

    void publish_audio_snapshot_locked() {
        auto snapshot = std::make_shared<ParticipantSnapshot>();
        snapshot->reserve(std::min(participants_.size(), MAX_AUDIO_CALLBACK_PARTICIPANTS));
        for (const auto& [id, participant]: participants_) {
            if (snapshot->size() >= MAX_AUDIO_CALLBACK_PARTICIPANTS) {
                break;
            }
            snapshot->push_back({id, participant});
        }
        ParticipantSnapshotPtr published = std::move(snapshot);
        std::atomic_store_explicit(&audio_snapshot_, std::move(published),
                                   std::memory_order_release);
    }
```

Call `assert_not_audio_callback_lock()` immediately before every `std::lock_guard<std::mutex> lock(mutex_)` in `ParticipantManager`.

Call `publish_audio_snapshot_locked()` after these membership mutations while still holding the lock:

```cpp
participants_[id] = std::move(new_participant);
publish_audio_snapshot_locked();
```

```cpp
participants_.erase(it);
publish_audio_snapshot_locked();
```

```cpp
it = participants_.erase(it);
changed = true;
...
if (changed) {
    publish_audio_snapshot_locked();
}
```

```cpp
participants_.clear();
publish_audio_snapshot_locked();
```

Replace `for_each` with:

```cpp
    template <typename Func>
    void for_each(Func&& func) {
        auto snapshot = load_audio_snapshot();
        for (const auto& entry: *snapshot) {
            if (entry.data) {
                func(entry.id, *entry.data);
            }
        }
    }
```

Add private members:

```cpp
    inline static thread_local bool in_audio_callback_ = false;
    ParticipantSnapshotPtr audio_snapshot_;
```

- [ ] **Step 4: Mark the callback scope**

In `Client::audio_callback`, after the `TimingScope timing_scope{...};` construction and before any participant access, add:

```cpp
        ParticipantManager::AudioCallbackReadScope participant_snapshot_scope;
```

- [ ] **Step 5: Run focused verification**

Run: `cmake --build build --config Release --target participant_manager_self_test --parallel 8`

Expected: exit 0.

Run: `ctest --test-dir build -C Release -R participant_manager_self_test --output-on-failure`

Expected: `100% tests passed, 0 tests failed out of 1`.

- [ ] **Step 6: Run full verification**

Run: `cmake --build build --config Release --parallel 8`

Expected: exit 0.

Run: `ctest --test-dir build -C Release --output-on-failure`

Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add participant_manager.h participant_manager_self_test.cpp client.cpp
git commit -m "Publish lock-free participant audio snapshots"
```

---

### Task 2: GUI/Stats Snapshot And Registration Critical Section Cleanup

**Files:**
- Modify: `participant_manager.h:23-249`
- Modify: `participant_manager_self_test.cpp:17-120`

**Interfaces:**
- Consumes: Task 1 `ParticipantSnapshotPtr` and published audio snapshot.
- Produces: `ParticipantManager::get_all_info()` that does not lock `mutex_`; `ParticipantManager::count()` that does not lock `mutex_`; immutable metadata snapshot used for `ParticipantInfo` strings; decoder creation and registration `Log::*` calls outside the registration critical section.

- [ ] **Step 1: Add metadata/info snapshot coverage**

Add this test to `participant_manager_self_test.cpp` and call it from `main()` after the audio snapshot test:

```cpp
void test_metadata_and_info_snapshot_are_published() {
    ParticipantManager manager;

    manager.set_participant_metadata(20, "profile-before", "Name Before");
    require(manager.register_participant(20, 48000, 1), "register participant 20");

    auto infos = manager.get_all_info();
    require(infos.size() == 1, "info snapshot has joined participant");
    require(infos[0].id == 20, "info snapshot has participant id");
    require(infos[0].profile_id == "profile-before", "pending profile metadata published");
    require(infos[0].display_name == "Name Before", "pending display metadata published");

    manager.set_participant_metadata(20, "profile-after", "Name After");
    infos = manager.get_all_info();
    require(infos.size() == 1, "info snapshot still has participant after metadata update");
    require(infos[0].profile_id == "profile-after", "updated profile metadata published");
    require(infos[0].display_name == "Name After", "updated display metadata published");

    manager.with_participant(20, [](ParticipantData& participant) {
        participant.gain.store(1.5F, std::memory_order_relaxed);
        participant.is_muted.store(true, std::memory_order_relaxed);
    });
    infos = manager.get_all_info();
    require(infos[0].gain > 1.49F && infos[0].gain < 1.51F,
            "info snapshot read reflects live gain atomics");
    require(infos[0].is_muted, "info snapshot read reflects live mute atomics");

    manager.remove_participant(20);
    require(manager.get_all_info().empty(), "info snapshot empty after leave");
    require(manager.count() == 0, "count reads published snapshot after leave");
}
```

- [ ] **Step 2: Add immutable metadata snapshot plumbing**

In `participant_manager.h`, add private metadata snapshot types:

```cpp
    using ParticipantMetadataSnapshot = std::unordered_map<uint32_t, ParticipantMetadata>;
    using ParticipantMetadataSnapshotPtr =
        std::shared_ptr<const ParticipantMetadataSnapshot>;
```

Change the constructor:

```cpp
    ParticipantManager()
        : audio_snapshot_(std::make_shared<ParticipantSnapshot>()),
          metadata_snapshot_(std::make_shared<ParticipantMetadataSnapshot>()) {}
```

Add private helpers:

```cpp
    ParticipantMetadataSnapshotPtr load_metadata_snapshot() const {
        return std::atomic_load_explicit(&metadata_snapshot_, std::memory_order_acquire);
    }

    void publish_metadata_snapshot_locked() {
        auto snapshot = std::make_shared<ParticipantMetadataSnapshot>();
        snapshot->reserve(participants_.size());
        for (const auto& [id, participant]: participants_) {
            snapshot->emplace(id, ParticipantMetadata{participant->profile_id,
                                                      participant->display_name});
        }
        ParticipantMetadataSnapshotPtr published = std::move(snapshot);
        std::atomic_store_explicit(&metadata_snapshot_, std::move(published),
                                   std::memory_order_release);
    }

    void publish_all_snapshots_locked() {
        publish_audio_snapshot_locked();
        publish_metadata_snapshot_locked();
    }
```

Replace Task 1 membership calls to `publish_audio_snapshot_locked()` with `publish_all_snapshots_locked()`. In `set_participant_metadata`, call `publish_metadata_snapshot_locked()` when the participant exists.

- [ ] **Step 3: Make GUI/stats reads lock-free**

Extract the existing `ParticipantInfo` field-copying body into:

```cpp
    static ParticipantInfo make_info(uint32_t id, const ParticipantData& data,
                                     const ParticipantMetadata* metadata) {
        ParticipantInfo info;
        info.id = id;
        if (metadata != nullptr) {
            info.profile_id = metadata->profile_id;
            info.display_name = metadata->display_name;
        }
        info.is_speaking = data.is_speaking.load(std::memory_order_relaxed);
        info.is_muted = data.is_muted.load(std::memory_order_relaxed);
        info.audio_level = data.current_level.load(std::memory_order_relaxed);
        info.gain = data.gain.load(std::memory_order_relaxed);
        info.pan = data.pan.load(std::memory_order_relaxed);
        info.buffer_ready = data.buffer_ready.load(std::memory_order_relaxed);
        info.queue_size = data.opus_queue.size_approx();
        info.queue_size_avg = data.queue_depth_avg.load(std::memory_order_relaxed);
        info.queue_size_max = data.queue_depth_max.load(std::memory_order_relaxed);
        info.queue_drift_packets =
            data.queue_depth_drift_milli.load(std::memory_order_relaxed) / 1000.0;
        info.jitter_buffer_min_packets =
            data.jitter_buffer_min_packets.load(std::memory_order_relaxed);
        info.jitter_buffer_floor_packets =
            data.jitter_buffer_floor_packets.load(std::memory_order_relaxed);
        info.opus_queue_limit_packets =
            data.opus_queue_limit_packets.load(std::memory_order_relaxed);
        info.opus_jitter_manual_override =
            data.opus_jitter_manual_override.load(std::memory_order_relaxed);
        info.opus_jitter_auto_enabled =
            data.opus_jitter_auto_enabled.load(std::memory_order_relaxed);
        info.opus_jitter_auto_floor_packets =
            data.opus_jitter_auto_floor_packets.load(std::memory_order_relaxed);
        info.opus_jitter_auto_increases =
            data.opus_jitter_auto_increases.load(std::memory_order_relaxed);
        info.opus_jitter_auto_decreases =
            data.opus_jitter_auto_decreases.load(std::memory_order_relaxed);
        info.opus_pcm_buffered_frames =
            data.opus_pcm_buffered_frames_observed.load(std::memory_order_relaxed);
        info.opus_packets_decoded_in_callback =
            data.opus_packets_decoded_in_callback.load(std::memory_order_relaxed);
        info.opus_queue_limit_drops =
            data.opus_queue_limit_drops.load(std::memory_order_relaxed);
        info.opus_age_limit_drops =
            data.opus_age_limit_drops.load(std::memory_order_relaxed);
        info.opus_decode_buffer_overflow_drops =
            data.opus_decode_buffer_overflow_drops.load(std::memory_order_relaxed);
        info.opus_target_trim_drops =
            data.opus_target_trim_drops.load(std::memory_order_relaxed);
        info.opus_playout_rate_ratio =
            data.opus_playout_rate_ratio_micros.load(std::memory_order_relaxed) /
            1'000'000.0;
        info.opus_rate_correction_callbacks =
            data.opus_rate_correction_callbacks_observed.load(std::memory_order_relaxed);
        info.last_packet_frame_count =
            data.last_packet_frame_count.load(std::memory_order_relaxed);
        info.last_callback_frame_count =
            data.last_callback_frame_count.load(std::memory_order_relaxed);
        info.underrun_count = data.underrun_count.load(std::memory_order_relaxed);
        info.plc_count = data.plc_count.load(std::memory_order_relaxed);
        info.packet_age_last_ms =
            data.packet_age_last_ns.load(std::memory_order_relaxed) / 1e6;
        info.packet_age_avg_ms =
            data.packet_age_avg_ns.load(std::memory_order_relaxed) / 1e6;
        info.packet_age_max_ms =
            data.packet_age_max_ns.load(std::memory_order_relaxed) / 1e6;
        info.sequence_gaps = data.sequence_gaps.load(std::memory_order_relaxed);
        info.sequence_gap_recoveries =
            data.sequence_gap_recoveries.load(std::memory_order_relaxed);
        info.sequence_unresolved_gaps =
            data.sequence_unresolved_gaps.load(std::memory_order_relaxed);
        info.sequence_late_or_reordered =
            data.sequence_late_or_reordered.load(std::memory_order_relaxed);
        info.jitter_depth_drops = data.jitter_depth_drops.load(std::memory_order_relaxed);
        info.jitter_age_drops = data.jitter_age_drops.load(std::memory_order_relaxed);
        info.pcm_concealment_frames =
            data.pcm_concealment_frames.load(std::memory_order_relaxed);
        info.pcm_drift_drops = data.pcm_drift_drops.load(std::memory_order_relaxed);
        info.receiver_drift_ppm_last =
            data.receiver_drift_ppm_last_milli.load(std::memory_order_relaxed) / 1000.0;
        info.receiver_drift_ppm_avg =
            data.receiver_drift_ppm_avg_milli.load(std::memory_order_relaxed) / 1000.0;
        info.receiver_drift_ppm_abs_max =
            data.receiver_drift_ppm_abs_max_milli.load(std::memory_order_relaxed) / 1000.0;
        return info;
    }
```

Replace `get_all_info()` with:

```cpp
    std::vector<ParticipantInfo> get_all_info() const {
        auto participants = load_audio_snapshot();
        auto metadata = load_metadata_snapshot();
        std::vector<ParticipantInfo> result;
        result.reserve(participants->size());

        for (const auto& entry: *participants) {
            if (!entry.data) {
                continue;
            }
            const ParticipantMetadata* published_metadata = nullptr;
            if (auto it = metadata->find(entry.id); it != metadata->end()) {
                published_metadata = &it->second;
            }
            result.push_back(make_info(entry.id, *entry.data, published_metadata));
        }

        return result;
    }
```

Replace `count()` with:

```cpp
    size_t count() const {
        return load_metadata_snapshot()->size();
    }
```

- [ ] **Step 4: Move registration create/log work out of lock**

Change `register_participant` to:

```cpp
    bool register_participant(uint32_t id, int sample_rate, int channels) {
        {
            assert_not_audio_callback_lock();
            std::lock_guard<std::mutex> lock(mutex_);
            if (participants_.contains(id)) {
                return true;
            }
        }

        auto new_participant = std::make_shared<ParticipantData>();
        new_participant->decoder = std::make_unique<OpusDecoderWrapper>();
        if (!new_participant->decoder->create(sample_rate, channels)) {
            Log::error("Failed to create decoder for participant {} ({}Hz, {}ch)", id,
                       sample_rate, channels);
            return false;
        }
        new_participant->pcm_buffer.fill(0.0F);
        new_participant->last_packet_time = std::chrono::steady_clock::now();

        {
            assert_not_audio_callback_lock();
            std::lock_guard<std::mutex> lock(mutex_);
            if (participants_.contains(id)) {
                return true;
            }
            auto pending = pending_metadata_.find(id);
            if (pending != pending_metadata_.end()) {
                new_participant->profile_id = pending->second.profile_id;
                new_participant->display_name = pending->second.display_name;
                pending_metadata_.erase(pending);
            }
            participants_[id] = std::move(new_participant);
            publish_all_snapshots_locked();
        }

        Log::info("New participant {} joined (decoder: {}Hz, {}ch)", id, sample_rate, channels);
        return true;
    }
```

Move existing `remove_participant` and `remove_timed_out_participants` `Log::info` calls out of their lock scopes by storing removed IDs/elapsed seconds in local variables and logging after the lock releases. This is not required for the callback path, but it keeps manager critical sections free of logger calls.

- [ ] **Step 5: Run focused verification**

Run: `cmake --build build --config Release --target participant_manager_self_test --parallel 8`

Expected: exit 0.

Run: `ctest --test-dir build -C Release -R participant_manager_self_test --output-on-failure`

Expected: `100% tests passed, 0 tests failed out of 1`.

- [ ] **Step 6: Run full verification**

Run: `cmake --build build --config Release --parallel 8`

Expected: exit 0.

Run: `ctest --test-dir build -C Release --output-on-failure`

Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add participant_manager.h participant_manager_self_test.cpp
git commit -m "Publish participant info snapshots"
```

---

### Task 3: Mechanical Acceptance And Phase Tracker

**Files:**
- Modify: `LOW_LATENCY_ACTION_PLAN.md:56-72`
- Modify: `docs/superpowers/plans/2026-07-02-phase2-participant-snapshot.md`

**Interfaces:**
- Consumes: Tasks 1 and 2 implementation.
- Produces: Phase 2 marked done only after local build, full ctest, mutex-path check, and CI check have passed or the exact blocker is documented.

- [ ] **Step 1: Run the scoped callback-path mutex check**

Run this PowerShell check:

```powershell
$body = Get-Content client.cpp
$start = ($body | Select-String -Pattern "static int audio_callback" | Select-Object -First 1).LineNumber
$end = ($body | Select-String -Pattern "return 0;" | Where-Object { $_.LineNumber -gt $start } | Select-Object -First 1).LineNumber
$callback = $body[($start - 1)..($end - 1)]
$callback | Select-String -Pattern "std::lock_guard|std::unique_lock|mutex_|with_participant|get_all_info|count\(|exists\(|register_participant|remove_participant"
```

Expected output: no matches.

Run:

```powershell
Select-String -Path participant_manager.h -Pattern "AudioCallbackReadScope|assert_not_audio_callback_lock|void for_each"
```

Expected output: lines showing the debug guard type, the lock assertion helper, and the lock-free `for_each`.

- [ ] **Step 2: Run final local verification**

Run: `cmake --build build --config Release --parallel 8`

Expected: exit 0.

Run: `ctest --test-dir build -C Release --output-on-failure`

Expected: all tests pass.

- [ ] **Step 3: Verify CI**

If the branch has been pushed, run:

```bash
gh run list --branch phase2-participant-snapshot --limit 1
gh run watch --exit-status
```

Expected: latest CI run for `phase2-participant-snapshot` concludes `success`.

If the branch cannot be pushed or GitHub CLI is not authenticated, do not claim CI green. Leave Phase 2 status short of "Done" and report the exact blocker.

- [ ] **Step 4: Update the phase tracker**

Only after Step 1, Step 2, and Step 3 are green, update `LOW_LATENCY_ACTION_PLAN.md`:

```markdown
## Phase 2: Participant Snapshot

Status: Done (2026-07-02, full ctest green, CI green)
```

Keep the design and acceptance notes below that status for historical context unless they are now inaccurate; if edited, state that the design has landed via the Phase 2 plan doc.

- [ ] **Step 5: Record acceptance evidence in this plan**

Append a short "Execution Evidence" section to this file with the exact command outputs:

```markdown
## Execution Evidence

- Callback mutex check: no matches.
- Focused participant manager test: `participant_manager_self_test` passed.
- Release build: passed.
- Full ctest: passed, N/N tests.
- CI: success, run URL or run id.
```

- [ ] **Step 6: Commit**

```bash
git add LOW_LATENCY_ACTION_PLAN.md docs/superpowers/plans/2026-07-02-phase2-participant-snapshot.md
git commit -m "Mark Phase 2 participant snapshots done"
```

---

## Self-Review

- Spec coverage: audio callback lock-free participant read is Task 1; GUI/stats non-contending snapshot is Task 2; decoder creation and registration logs outside the critical section is Task 2; Phase 1 graveyard guarantee is preserved and tested in Tasks 1 and 2; mechanical mutex check, build, ctest, CI, and tracker status are Task 3.
- Placeholder scan: no `TBD`, `TODO`, `implement later`, or unbounded "add tests" instructions remain.
- Type consistency: `ParticipantSnapshotPtr`, `ParticipantMetadataSnapshotPtr`, `publish_all_snapshots_locked`, `load_audio_snapshot`, and `load_metadata_snapshot` are introduced before use.
