#include <atomic>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <vector>

#include "participant_manager.h"

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        std::exit(1);
    }
}

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
    test_join_leave_timeout_update_audio_snapshot();
    test_immediate_reap_without_snapshot();
    test_snapshot_defers_reclamation();
    test_timeout_and_clear_route_through_graveyard();
    std::printf("participant_manager_self_test passed\n");
    return 0;
}
