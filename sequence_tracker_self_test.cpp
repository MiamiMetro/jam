#include "sequence_tracker.h"

#include <cstdlib>
#include <iostream>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}

void test_reorder_recovers_gap() {
    SequenceArrivalTracker tracker;

    auto delta = tracker.record(1);
    require(delta.gaps_detected == 0 && tracker.unresolved_gaps() == 0,
            "first packet should initialize tracker");

    delta = tracker.record(3);
    require(delta.gaps_detected == 1, "jump should detect one missing packet");
    require(tracker.unresolved_gaps() == 1, "missing packet should be unresolved");

    delta = tracker.record(2);
    require(delta.late_or_duplicate, "late packet should be marked late/reordered");
    require(delta.gaps_recovered == 1, "late packet should recover the missing gap");
    require(tracker.unresolved_gaps() == 0, "recovered gap should not remain unresolved");
}

void test_sequence_number_comparison_handles_wrap() {
    require(sequence_number_before(UINT32_MAX, 0), "max should be before zero");
    require(sequence_number_after(0, UINT32_MAX), "zero should be after max");
    require(sequence_number_before(41, 42), "lower nearby sequence should be before");
    require(sequence_number_after(42, 41), "higher nearby sequence should be after");
    require(!sequence_number_before(42, 42), "same sequence is not before itself");
    require(!sequence_number_after(42, 42), "same sequence is not after itself");
}

void test_real_loss_stays_unresolved() {
    SequenceArrivalTracker tracker;

    tracker.record(10);
    const auto delta = tracker.record(14);
    require(delta.gaps_detected == 3, "jump should detect three missing packets");
    require(tracker.unresolved_gaps() == 3, "unseen missing packets should stay unresolved");
}

void test_duplicate_is_not_recovery() {
    SequenceArrivalTracker tracker;

    tracker.record(20);
    const auto delta = tracker.record(20);
    require(delta.late_or_duplicate, "duplicate should be marked late/duplicate");
    require(delta.gaps_recovered == 0, "duplicate should not recover a gap");
    require(!sequence_arrival_should_enqueue(delta),
            "duplicate with no recovered gap should not be enqueued");
    require(tracker.unresolved_gaps() == 0, "duplicate should not create unresolved gaps");
}

void test_reordered_recovery_should_enqueue() {
    SequenceArrivalTracker tracker;

    tracker.record(30);
    tracker.record(32);
    const auto delta = tracker.record(31);
    require(delta.late_or_duplicate, "gap recovery should be a late arrival");
    require(delta.gaps_recovered == 1, "gap recovery should report recovered gap");
    require(sequence_arrival_should_enqueue(delta),
            "late arrival that recovers a gap should still be enqueued");
}

void test_wraparound_ordering() {
    SequenceArrivalTracker tracker;

    tracker.record(UINT32_MAX - 1);
    auto delta = tracker.record(1);
    require(delta.gaps_detected == 2, "wrap jump should detect max and zero missing");
    require(tracker.unresolved_gaps() == 2, "wrap missing packets should be unresolved");

    delta = tracker.record(UINT32_MAX);
    require(delta.gaps_recovered == 1, "UINT32_MAX should recover one wrap gap");
    delta = tracker.record(0);
    require(delta.gaps_recovered == 1, "zero should recover the other wrap gap");
    require(tracker.unresolved_gaps() == 0, "wrap gaps should all be recovered");
}

void test_large_gap_recovery_beyond_small_packet_window() {
    SequenceArrivalTracker tracker;

    tracker.record(1000);
    auto delta = tracker.record(2000);
    require(delta.gaps_detected == 999, "large jump should detect all missing packets");
    require(tracker.unresolved_gaps() == 999, "large gap should be unresolved");

    delta = tracker.record(1800);
    require(delta.gaps_recovered == 1,
            "late packet deep inside a large gap should recover");
    require(tracker.unresolved_gaps() == 998,
            "large gap recovery should decrement unresolved count");

    delta = tracker.record(1799);
    require(delta.gaps_recovered == 1, "left split range should still recover");
    delta = tracker.record(1801);
    require(delta.gaps_recovered == 1, "right split range should still recover");
    require(tracker.unresolved_gaps() == 996,
            "split range recoveries should keep decrementing unresolved count");
}

void test_untracked_overflow_gap_does_not_stick_unresolved() {
    SequenceArrivalTracker tracker;

    tracker.record(0);
    for (uint32_t sequence = 2; sequence <= 128; sequence += 2) {
        const auto delta = tracker.record(sequence);
        require(delta.gaps_detected == 1, "separated jump should detect one gap");
    }
    require(tracker.unresolved_gaps() == 64,
            "first 64 separated gaps should be tracked");

    auto delta = tracker.record(130);
    require(delta.gaps_detected == 1, "overflow jump should still report detected gap");
    require(tracker.unresolved_gaps() == 64,
            "untracked overflow gap should not inflate unresolved count");

    delta = tracker.record(129);
    require(delta.late_or_duplicate, "late untracked packet should still be late");
    require(delta.gaps_recovered == 0,
            "untracked overflow packet should not report recovery");
    require(tracker.unresolved_gaps() == 64,
            "late untracked packet should not change unresolved count");

    for (uint32_t sequence = 1; sequence <= 127; sequence += 2) {
        delta = tracker.record(sequence);
        require(delta.gaps_recovered == 1, "tracked separated gap should recover");
    }
    require(tracker.unresolved_gaps() == 0,
            "all tracked gaps should recover to zero unresolved");
}

void test_full_table_middle_split_drops_untracked_half_from_unresolved() {
    SequenceArrivalTracker tracker;

    tracker.record(0);
    for (uint32_t sequence = 2; sequence <= 126; sequence += 2) {
        tracker.record(sequence);
    }
    require(tracker.unresolved_gaps() == 63,
            "first 63 separated gaps should be tracked");

    auto delta = tracker.record(137);
    require(delta.gaps_detected == 10, "large gap should be detected");
    require(tracker.unresolved_gaps() == 73,
            "large range should fill the final tracked slot");

    delta = tracker.record(132);
    require(delta.gaps_recovered == 1, "middle packet should recover one gap");
    require(tracker.unresolved_gaps() == 68,
            "untracked right split should be dropped from unresolved count");

    for (uint32_t sequence = 133; sequence <= 136; ++sequence) {
        delta = tracker.record(sequence);
        require(delta.late_or_duplicate, "right split packet should still be late");
        require(delta.gaps_recovered == 0,
                "untracked right split packet should not report recovery");
    }
    require(tracker.unresolved_gaps() == 68,
            "untracked right split arrivals should not change unresolved count");

    for (uint32_t sequence = 1; sequence <= 125; sequence += 2) {
        tracker.record(sequence);
    }
    for (uint32_t sequence = 127; sequence <= 131; ++sequence) {
        tracker.record(sequence);
    }
    require(tracker.unresolved_gaps() == 0,
            "all remaining tracked split ranges should recover");
}

}  // namespace

int main() {
    test_reorder_recovers_gap();
    test_sequence_number_comparison_handles_wrap();
    test_real_loss_stays_unresolved();
    test_duplicate_is_not_recovery();
    test_reordered_recovery_should_enqueue();
    test_wraparound_ordering();
    test_large_gap_recovery_beyond_small_packet_window();
    test_untracked_overflow_gap_does_not_stick_unresolved();
    test_full_table_middle_split_drops_untracked_half_from_unresolved();

    std::cout << "sequence tracker self-test passed\n";
    return 0;
}
