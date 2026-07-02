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
