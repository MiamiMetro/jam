#include "participant_info.h"

#include <cstdlib>
#include <iostream>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}

OpusPacket make_packet(uint32_t sequence) {
    OpusPacket packet{};
    packet.sequence = sequence;
    packet.sequence_valid = true;
    packet.frame_count = 960;
    packet.size = 1;
    packet.data[0] = static_cast<uint8_t>(sequence);
    packet.timestamp = std::chrono::steady_clock::now();
    return packet;
}

OpusPacket make_unsequenced_packet(uint8_t marker) {
    OpusPacket packet{};
    packet.sequence_valid = false;
    packet.frame_count = 960;
    packet.size = 1;
    packet.data[0] = marker;
    packet.timestamp = std::chrono::steady_clock::now();
    return packet;
}

void require_dequeue(ParticipantOpusPacketQueue& queue, uint32_t expected_sequence,
                     size_t gap_wait_packets = 0) {
    OpusPacket packet{};
    require(queue.try_dequeue(packet, gap_wait_packets), "expected queued packet");
    require(!packet.loss_concealment, "expected real packet, got loss concealment");
    require(packet.sequence == expected_sequence, "unexpected packet sequence");
}

void require_dequeue_with_reset(ParticipantOpusPacketQueue& queue,
                                uint32_t expected_sequence,
                                size_t gap_wait_packets = 0) {
    OpusPacket packet{};
    require(queue.try_dequeue(packet, gap_wait_packets), "expected queued packet");
    require(!packet.loss_concealment, "expected real packet, got loss concealment");
    if (!packet.reset_decoder) {
        std::cerr << "FAIL: expected decoder reset on resumed packet, expected sequence "
                  << expected_sequence << ", got sequence " << packet.sequence << '\n';
        std::exit(1);
    }
    require(packet.sequence == expected_sequence, "unexpected packet sequence");
}

void require_loss_concealment(ParticipantOpusPacketQueue& queue,
                              uint32_t expected_sequence,
                              size_t gap_wait_packets = 0) {
    OpusPacket packet{};
    require(queue.try_dequeue(packet, gap_wait_packets), "expected loss concealment packet");
    require(packet.loss_concealment, "expected loss concealment packet");
    require(packet.sequence == expected_sequence, "unexpected loss concealment sequence");
}

void test_reorders_available_packets() {
    ParticipantData participant{};

    require(participant.opus_queue.enqueue(make_packet(1)), "packet 1 should enqueue");
    require(participant.opus_queue.enqueue(make_packet(3)), "packet 3 should enqueue");
    require(participant.opus_queue.enqueue(make_packet(2)), "packet 2 should enqueue");

    require_dequeue(participant.opus_queue, 1);
    require_dequeue(participant.opus_queue, 2);
    require_dequeue(participant.opus_queue, 3);
}

void test_waits_for_missing_packet() {
    ParticipantOpusPacketQueue queue;

    require(queue.enqueue(make_packet(1)), "packet 1 should enqueue");
    require(queue.enqueue(make_packet(3)), "packet 3 should enqueue");

    require_dequeue(queue, 1, 3);

    OpusPacket packet{};
    require(queue.dequeue(packet, 3) == ParticipantOpusDequeueStatus::WaitingForGap,
            "missing packet should report waiting below gap budget");

    require(queue.enqueue(make_packet(2)), "reordered packet 2 should still enqueue");
    require_dequeue(queue, 2, 3);
    require_dequeue(queue, 3, 3);
}

void test_skips_permanent_gap_after_budget() {
    ParticipantOpusPacketQueue queue;

    require(queue.enqueue(make_packet(1)), "packet 1 should enqueue");
    require(queue.enqueue(make_packet(3)), "packet 3 should enqueue");
    require(queue.enqueue(make_packet(4)), "packet 4 should enqueue");

    require_dequeue(queue, 1, 2);
    OpusPacket packet{};
    require(queue.dequeue(packet, 2) == ParticipantOpusDequeueStatus::WaitingForGap,
            "first gap wait should hold even when future packets are buffered");
    require(queue.dequeue(packet, 2) == ParticipantOpusDequeueStatus::WaitingForGap,
            "second gap wait should hold even when future packets are buffered");
    require_loss_concealment(queue, 2, 2);
    require_dequeue(queue, 3, 2);
    require(queue.enqueue(make_packet(2)), "producer handoff should accept late packet");
    require_dequeue(queue, 4, 2);
}

void test_skips_permanent_gap_after_wait_callbacks() {
    ParticipantOpusPacketQueue queue;

    require(queue.enqueue(make_packet(1)), "packet 1 should enqueue");
    require(queue.enqueue(make_packet(3)), "packet 3 should enqueue");

    require_dequeue(queue, 1, 3);

    OpusPacket packet{};
    require(queue.dequeue(packet, 3) == ParticipantOpusDequeueStatus::WaitingForGap,
            "first missing-packet wait should hold");
    require(queue.dequeue(packet, 3) == ParticipantOpusDequeueStatus::WaitingForGap,
            "second missing-packet wait should hold");
    require(queue.dequeue(packet, 3) == ParticipantOpusDequeueStatus::WaitingForGap,
            "third missing-packet wait should hold");
    require(queue.try_dequeue(packet, 3) && packet.loss_concealment &&
                packet.sequence == 2,
            "permanent gap should produce PLC after wait budget");
    require_dequeue(queue, 3, 3);
}

void test_burst_gap_waits_once_then_conceals_missing_run() {
    ParticipantOpusPacketQueue queue;

    require(queue.enqueue(make_packet(1)), "packet 1 should enqueue");
    require(queue.enqueue(make_packet(5)), "packet 5 should enqueue");

    require_dequeue(queue, 1, 2);

    OpusPacket packet{};
    require(queue.dequeue(packet, 2) == ParticipantOpusDequeueStatus::WaitingForGap,
            "burst gap should wait first callback");
    require(queue.dequeue(packet, 2) == ParticipantOpusDequeueStatus::WaitingForGap,
            "burst gap should wait second callback");
    require_loss_concealment(queue, 2, 2);
    require_loss_concealment(queue, 3, 2);
    require_dequeue_with_reset(queue, 5, 2);
}

void test_large_gap_caps_plc_and_resumes_real_packet() {
    ParticipantOpusPacketQueue queue;

    require(MAX_OPUS_CONSECUTIVE_GAP_PLC_PACKETS <= 2,
            "large gaps should not synthesize more than two PLC packets");

    require(queue.enqueue(make_packet(1)), "packet 1 should enqueue");
    require(queue.enqueue(make_packet(100)), "future packet should enqueue");

    require_dequeue(queue, 1, 0);
    for (size_t i = 0; i < MAX_OPUS_CONSECUTIVE_GAP_PLC_PACKETS; ++i) {
        require_loss_concealment(queue, static_cast<uint32_t>(2 + i), 0);
    }
    require_dequeue_with_reset(queue, 100, 0);
    require(queue.size_approx() == 0, "large gap cap should leave no buffered packet");
}

void test_gap_wait_resets_when_missing_packet_arrives() {
    ParticipantOpusPacketQueue queue;

    require(queue.enqueue(make_packet(1)), "packet 1 should enqueue");
    require(queue.enqueue(make_packet(3)), "packet 3 should enqueue");

    require_dequeue(queue, 1, 3);

    OpusPacket packet{};
    require(!queue.try_dequeue(packet, 3), "missing packet should wait");
    require(!queue.try_dequeue(packet, 3), "missing packet should keep waiting");

    require(queue.enqueue(make_packet(2)), "missing packet should enqueue");
    require_dequeue(queue, 2, 3);
    require_dequeue(queue, 3, 3);
}

void test_discards_stale_packet_after_skip() {
    ParticipantOpusPacketQueue queue;

    require(queue.enqueue(make_packet(1)), "packet 1 should enqueue");
    require(queue.enqueue(make_packet(3)), "packet 3 should enqueue");
    require(queue.enqueue(make_packet(4)), "packet 4 should enqueue");

    require_dequeue(queue, 1, 2);
    OpusPacket wait_packet{};
    require(queue.dequeue(wait_packet, 2) == ParticipantOpusDequeueStatus::WaitingForGap,
            "first stale-gap wait should hold");
    require(queue.dequeue(wait_packet, 2) == ParticipantOpusDequeueStatus::WaitingForGap,
            "second stale-gap wait should hold");
    require_loss_concealment(queue, 2, 2);
    require(queue.enqueue(make_packet(2)), "late skipped packet should enqueue into handoff");

    OpusPacket packet{};
    require(queue.try_dequeue(packet, 2) && !packet.loss_concealment &&
                packet.sequence == 3,
            "stale packet should be discarded before next playable packet");
    require_dequeue(queue, 4, 2);
    require(queue.size_approx() == 0, "stale discard should decrement queue depth");
}

void test_rejects_duplicate_packet() {
    ParticipantOpusPacketQueue queue;

    require(queue.enqueue(make_packet(7)), "packet 7 should enqueue");
    require(queue.enqueue(make_packet(7)), "producer handoff should accept duplicate packet");
    require_dequeue(queue, 7);

    OpusPacket packet{};
    require(!queue.try_dequeue(packet), "duplicate should not remain queued");
}

void test_discard_oldest_actual_packet_does_not_emit_loss_marker() {
    ParticipantOpusPacketQueue queue;

    require(queue.enqueue(make_packet(1)), "packet 1 should enqueue");
    require(queue.enqueue(make_packet(3)), "packet 3 should enqueue");
    require(queue.enqueue(make_packet(4)), "packet 4 should enqueue");

    require_dequeue(queue, 1, 2);
    require(queue.discard_oldest_actual_packet(), "discard should remove real packet 3");

    require_loss_concealment(queue, 2, 0);
    require_loss_concealment(queue, 3, 0);
    require_dequeue(queue, 4, 0);
    require(queue.size_approx() == 0, "discarded packet should not remain counted");
}

void test_bounded_enqueue_rejects_when_full() {
    ParticipantOpusPacketQueue queue;

    require(queue.enqueue_bounded(make_packet(20), 2), "packet 20 should enqueue");
    require(queue.enqueue_bounded(make_packet(21), 2), "packet 21 should enqueue");
    require(!queue.enqueue_bounded(make_packet(22), 2), "bounded enqueue should reject full queue");
    require(queue.size_approx() == 2, "bounded enqueue should preserve queue size");

    require_dequeue(queue, 20);
    require_dequeue(queue, 21);
}

void test_accepts_expected_late_packet_with_recovery_reserve() {
    ParticipantOpusPacketQueue queue;

    require(queue.enqueue_bounded(make_packet(1), 4), "packet 1 should enqueue");
    require(queue.enqueue_bounded(make_packet(3), 4), "packet 3 should enqueue");
    require(queue.enqueue_bounded(make_packet(4), 4), "packet 4 should enqueue");
    require(queue.enqueue_bounded(make_packet(5), 4), "packet 5 should enqueue");

    require_dequeue(queue, 1, 3);
    require(queue.enqueue_bounded(make_packet(6), 4), "future packet should refill queue");
    require(queue.enqueue_bounded(make_packet(2), 4),
            "expected late packet should use recovery reserve");

    require_dequeue(queue, 2, 3);
    require_dequeue(queue, 3, 3);
}

void test_rejects_non_expected_packet_when_full_after_playout_started() {
    ParticipantOpusPacketQueue queue;

    require(queue.enqueue_bounded(make_packet(1), 4), "packet 1 should enqueue");
    require(queue.enqueue_bounded(make_packet(3), 4), "packet 3 should enqueue");
    require(queue.enqueue_bounded(make_packet(4), 4), "packet 4 should enqueue");
    require(queue.enqueue_bounded(make_packet(5), 4), "packet 5 should enqueue");

    require_dequeue(queue, 1, 3);
    require(queue.enqueue_bounded(make_packet(6), 4), "future packet should refill queue");
    require(!queue.enqueue_bounded(make_packet(7), 4),
            "non-expected future packet should not use recovery reserve");
}

void test_enqueue_or_drop_uses_recovery_reserve_before_dropping_incoming() {
    ParticipantOpusPacketQueue queue;

    require(queue.enqueue_bounded(make_packet(1), 4), "packet 1 should enqueue");
    require(queue.enqueue_bounded(make_packet(3), 4), "packet 3 should enqueue");
    require(queue.enqueue_bounded(make_packet(4), 4), "packet 4 should enqueue");
    require(queue.enqueue_bounded(make_packet(5), 4), "packet 5 should enqueue");

    require_dequeue(queue, 1, 3);
    require(queue.enqueue_bounded(make_packet(6), 4), "future packet should refill incoming");
    const bool enqueued = queue.enqueue_bounded_or_reject_overflow(make_packet(2), 4);
    require(enqueued, "expected late packet should enqueue");

    require_dequeue(queue, 2, 3);
    require_dequeue(queue, 3, 3);
}

void test_enqueue_or_drop_rejects_non_expected_full_packet() {
    ParticipantOpusPacketQueue queue;

    require(queue.enqueue_bounded(make_packet(1), 4), "packet 1 should enqueue");
    require(queue.enqueue_bounded(make_packet(3), 4), "packet 3 should enqueue");
    require(queue.enqueue_bounded(make_packet(4), 4), "packet 4 should enqueue");
    require(queue.enqueue_bounded(make_packet(5), 4), "packet 5 should enqueue");

    require_dequeue(queue, 1, 3);
    require(queue.enqueue_bounded(make_packet(6), 4), "future packet should refill incoming");
    const bool enqueued = queue.enqueue_bounded_or_reject_overflow(make_packet(7), 4);
    require(!enqueued, "non-expected packet should be rejected at configured limit");
}

void test_future_overflow_does_not_drop_expected_late_packet() {
    ParticipantOpusPacketQueue queue;

    require(queue.enqueue_bounded(make_packet(1), 4), "packet 1 should enqueue");
    require(queue.enqueue_bounded(make_packet(3), 4), "packet 3 should enqueue");
    require(queue.enqueue_bounded(make_packet(4), 4), "packet 4 should enqueue");
    require(queue.enqueue_bounded(make_packet(5), 4), "packet 5 should enqueue");

    require_dequeue(queue, 1, 3);
    require(queue.enqueue_bounded(make_packet(6), 4), "future packet should refill incoming");
    require(queue.enqueue_bounded(make_packet(2), 4),
            "expected late packet should use recovery reserve");

    const bool enqueued = queue.enqueue_bounded_or_reject_overflow(make_packet(7), 4);
    require(!enqueued, "future overflow should be rejected");

    require_dequeue(queue, 2, 3);
    require_dequeue(queue, 3, 3);
}

void test_startup_reorder_does_not_drop_first_packet_when_queue_full() {
    ParticipantOpusPacketQueue queue;

    require(queue.enqueue_bounded(make_packet(1), 4), "packet 1 should enqueue");
    require(queue.enqueue_bounded(make_packet(3), 4), "packet 3 should enqueue");
    require(queue.enqueue_bounded(make_packet(4), 4), "packet 4 should enqueue");
    require(queue.enqueue_bounded(make_packet(5), 4), "packet 5 should enqueue");

    const bool enqueued = queue.enqueue_bounded_or_reject_overflow(make_packet(2), 4);
    require(enqueued, "startup late packet should enqueue");

    require_dequeue(queue, 1, 3);
    require_dequeue(queue, 2, 3);
    require_dequeue(queue, 3, 3);
}

void test_startup_future_packet_does_not_drop_first_packet_when_queue_full() {
    ParticipantOpusPacketQueue queue;

    require(queue.enqueue_bounded(make_packet(1), 4), "packet 1 should enqueue");
    require(queue.enqueue_bounded(make_packet(2), 4), "packet 2 should enqueue");
    require(queue.enqueue_bounded(make_packet(3), 4), "packet 3 should enqueue");
    require(queue.enqueue_bounded(make_packet(4), 4), "packet 4 should enqueue");

    const bool enqueued = queue.enqueue_bounded_or_reject_overflow(make_packet(5), 4);
    require(!enqueued, "startup future packet should be rejected when full");

    require_dequeue(queue, 1, 3);
    require_dequeue(queue, 2, 3);
    require_dequeue(queue, 3, 3);
    require_dequeue(queue, 4, 3);
}

void test_unsequenced_overflow_does_not_evict_sequenced_packet() {
    ParticipantOpusPacketQueue queue;

    require(queue.enqueue_bounded(make_packet(1), 1), "sequenced packet should enqueue");

    const bool enqueued =
        queue.enqueue_bounded_or_reject_overflow(make_unsequenced_packet(99), 1);
    require(!enqueued, "unsequenced overflow should be rejected");

    require_dequeue(queue, 1, 3);
    require(queue.size_approx() == 0, "queue should only contain the original packet");
}

void test_hard_cap_still_accepts_startup_recovery_packet() {
    ParticipantOpusPacketQueue queue;

    require(queue.enqueue_bounded(make_packet(1), MAX_OPUS_QUEUE_SIZE),
            "first packet should enqueue at hard cap");
    for (uint32_t sequence = 3; sequence <= 129; ++sequence) {
        require(queue.enqueue_bounded(make_packet(sequence), MAX_OPUS_QUEUE_SIZE),
                "future packet should fill queue to hard cap");
    }

    require(queue.enqueue_bounded(make_packet(2), MAX_OPUS_QUEUE_SIZE),
            "startup recovery packet should use hard-cap reserve");

    require_dequeue(queue, 1, 3);
    require_dequeue(queue, 2, 3);
    require_dequeue(queue, 3, 3);
}

void test_handles_sequence_wraparound() {
    ParticipantOpusPacketQueue queue;

    require(queue.enqueue(make_packet(UINT32_MAX - 1)), "pre-wrap packet should enqueue");
    require(queue.enqueue(make_packet(0)), "post-wrap packet should enqueue");
    require(queue.enqueue(make_packet(UINT32_MAX)), "wrap boundary packet should enqueue");

    require_dequeue(queue, UINT32_MAX - 1, 3);
    require_dequeue(queue, UINT32_MAX, 3);
    require_dequeue(queue, 0, 3);
}

}  // namespace

int main() {
    test_reorders_available_packets();
    test_waits_for_missing_packet();
    test_skips_permanent_gap_after_budget();
    test_skips_permanent_gap_after_wait_callbacks();
    test_burst_gap_waits_once_then_conceals_missing_run();
    test_large_gap_caps_plc_and_resumes_real_packet();
    test_gap_wait_resets_when_missing_packet_arrives();
    test_discards_stale_packet_after_skip();
    test_rejects_duplicate_packet();
    test_discard_oldest_actual_packet_does_not_emit_loss_marker();
    test_bounded_enqueue_rejects_when_full();
    test_accepts_expected_late_packet_with_recovery_reserve();
    test_rejects_non_expected_packet_when_full_after_playout_started();
    test_enqueue_or_drop_uses_recovery_reserve_before_dropping_incoming();
    test_enqueue_or_drop_rejects_non_expected_full_packet();
    test_future_overflow_does_not_drop_expected_late_packet();
    test_startup_reorder_does_not_drop_first_packet_when_queue_full();
    test_startup_future_packet_does_not_drop_first_packet_when_queue_full();
    test_unsequenced_overflow_does_not_evict_sequenced_packet();
    test_hard_cap_still_accepts_startup_recovery_packet();
    test_handles_sequence_wraparound();

    std::cout << "participant packet queue self-test passed\n";
    return 0;
}
