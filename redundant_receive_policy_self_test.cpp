#include "audio_packet.h"
#include "participant_info.h"
#include "sequence_tracker.h"

#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <vector>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}

std::shared_ptr<std::vector<unsigned char>> make_audio_packet(uint32_t sequence,
                                                              uint8_t marker) {
    const std::array<unsigned char, 3> payload{marker, static_cast<unsigned char>(marker + 1),
                                              static_cast<unsigned char>(marker + 2)};
    return audio_packet::create_audio_packet_v2(
        AudioCodec::Opus, sequence, opus_network_clock::SAMPLE_RATE,
        opus_network_clock::DEFAULT_FRAME_COUNT, 1, payload.data(),
        static_cast<uint16_t>(payload.size()));
}

std::shared_ptr<std::vector<unsigned char>> make_redundant_packet(
    const std::vector<std::shared_ptr<std::vector<unsigned char>>>& packets) {
    require(!packets.empty(), "redundant packet test input should not be empty");
    std::vector<const std::vector<unsigned char>*> children;
    children.reserve(packets.size());
    for (const auto& packet: packets) {
        require(packet != nullptr, "redundant packet test child should not be null");
        children.push_back(packet.get());
    }
    return audio_packet::create_redundant_audio_packet(children);
}

std::shared_ptr<std::vector<unsigned char>> make_redundant_packet(
    const std::shared_ptr<std::vector<unsigned char>>& current,
    const std::shared_ptr<std::vector<unsigned char>>& previous = nullptr) {
    if (previous == nullptr) {
        return make_redundant_packet(std::vector{current});
    }
    return make_redundant_packet(std::vector{current, previous});
}

class SimulatedRedundantReceiver {
public:
    void receive(const std::vector<unsigned char>& packet) {
        const uint32_t magic = read_magic(packet.data(), packet.size());
        if (magic == AUDIO_REDUNDANT_MAGIC) {
            audio_packet::for_each_redundant_audio_child_reverse(
                packet.data(), packet.size(),
                [this](const unsigned char* child, size_t child_len, uint8_t) {
                    receive_v2(child, child_len);
                });
            return;
        }
        receive_v2(packet.data(), packet.size());
    }

    size_t queued_packets() const {
        return queue_.size_approx();
    }

    void require_next(uint32_t expected_sequence) {
        OpusPacket packet{};
        require(queue_.try_dequeue(packet, 3), "expected queued packet");
        require(!packet.loss_concealment, "expected real packet");
        require(packet.sequence == expected_sequence, "unexpected dequeued sequence");
    }

private:
    static uint32_t read_magic(const unsigned char* data, size_t len) {
        require(len >= sizeof(MsgHdr), "packet too small for magic");
        uint32_t magic = 0;
        std::memcpy(&magic, data, sizeof(magic));
        return magic;
    }

    void receive_v2(const unsigned char* data, size_t len) {
        require(audio_packet::validate_audio_packet_v2_bytes(data, len),
                "test packet should be valid v2 audio");

        AudioHdrV2 hdr{};
        std::memcpy(&hdr, data, audio_packet::v2_header_size());
        const auto delta = sequence_tracker_.record(hdr.sequence);
        if (!sequence_arrival_should_enqueue(delta)) {
            return;
        }

        OpusPacket packet{};
        std::memcpy(packet.data.data(), packet_builder_payload(data), hdr.payload_bytes);
        packet.size = hdr.payload_bytes;
        packet.timestamp = std::chrono::steady_clock::now();
        packet.codec = hdr.codec;
        packet.sequence = hdr.sequence;
        packet.sequence_valid = true;
        packet.sample_rate = hdr.sample_rate;
        packet.frame_count = hdr.frame_count;
        packet.channels = hdr.channels;
        require(queue_.enqueue_bounded_or_reject_overflow(packet, MAX_OPUS_QUEUE_SIZE),
                "receiver policy should enqueue admissible packet");
    }

    static const unsigned char* packet_builder_payload(const unsigned char* data) {
        return data + audio_packet::v2_header_size();
    }

    SequenceArrivalTracker sequence_tracker_;
    ParticipantOpusPacketQueue queue_;
};

void test_single_dropped_datagram_recovers_from_next_redundant_packet() {
    auto packet0 = make_audio_packet(0, 10);
    auto packet1 = make_audio_packet(1, 20);
    auto packet2 = make_audio_packet(2, 30);

    auto datagram0 = make_redundant_packet(packet0);
    auto datagram2 = make_redundant_packet(packet2, packet1);

    SimulatedRedundantReceiver receiver;
    receiver.receive(*datagram0);
    // Datagram 1 is intentionally dropped. Datagram 2 carries packet 1 redundantly.
    receiver.receive(*datagram2);

    require(receiver.queued_packets() == 3,
            "redundant previous packet should recover the dropped datagram");
    receiver.require_next(0);
    receiver.require_next(1);
    receiver.require_next(2);
}

void test_two_dropped_datagrams_recover_from_deeper_redundant_packet() {
    auto packet0 = make_audio_packet(0, 10);
    auto packet1 = make_audio_packet(1, 20);
    auto packet2 = make_audio_packet(2, 30);
    auto packet3 = make_audio_packet(3, 40);

    auto datagram0 = make_redundant_packet(packet0);
    auto datagram3 = make_redundant_packet(std::vector{packet3, packet2, packet1});

    SimulatedRedundantReceiver receiver;
    receiver.receive(*datagram0);
    // Datagram 1 and datagram 2 are intentionally dropped. Datagram 3 carries both.
    receiver.receive(*datagram3);

    require(receiver.queued_packets() == 4,
            "deeper redundancy should recover two consecutive dropped datagrams");
    receiver.require_next(0);
    receiver.require_next(1);
    receiver.require_next(2);
    receiver.require_next(3);
}

void test_ten_dropped_datagrams_recover_from_bounded_redundant_packet() {
    std::vector<std::shared_ptr<std::vector<unsigned char>>> packets;
    packets.reserve(MAX_AUDIO_REDUNDANT_PACKETS);
    for (uint32_t sequence = 0; sequence < MAX_AUDIO_REDUNDANT_PACKETS; ++sequence) {
        packets.push_back(make_audio_packet(sequence, static_cast<uint8_t>(sequence + 10)));
    }

    auto datagram0 = make_redundant_packet(packets[0]);
    std::vector<std::shared_ptr<std::vector<unsigned char>>> datagram_children;
    datagram_children.reserve(MAX_AUDIO_REDUNDANT_PACKETS - 1);
    for (uint32_t sequence = MAX_AUDIO_REDUNDANT_PACKETS - 1; sequence >= 1; --sequence) {
        datagram_children.push_back(packets[sequence]);
        if (sequence == 1) {
            break;
        }
    }
    auto datagram11 = make_redundant_packet(datagram_children);

    SimulatedRedundantReceiver receiver;
    receiver.receive(*datagram0);
    // Datagrams 1 through 10 are intentionally dropped. Datagram 11 carries all of them.
    receiver.receive(*datagram11);

    require(receiver.queued_packets() == MAX_AUDIO_REDUNDANT_PACKETS,
            "bounded redundancy should recover a ten-datagram burst at 5 ms packet cadence");
    for (uint32_t sequence = 0; sequence < MAX_AUDIO_REDUNDANT_PACKETS; ++sequence) {
        receiver.require_next(sequence);
    }
}

void test_duplicate_redundant_datagram_does_not_inflate_queue() {
    auto packet0 = make_audio_packet(0, 40);
    auto packet1 = make_audio_packet(1, 50);
    auto datagram0 = make_redundant_packet(packet0);
    auto datagram1 = make_redundant_packet(packet1, packet0);

    SimulatedRedundantReceiver receiver;
    receiver.receive(*datagram0);
    receiver.receive(*datagram1);
    const size_t after_first_delivery = receiver.queued_packets();

    receiver.receive(*datagram1);
    require(receiver.queued_packets() == after_first_delivery,
            "duplicate redundant datagram should not add duplicate packets");
    receiver.require_next(0);
    receiver.require_next(1);
}

void test_plain_duplicate_v2_packet_is_rejected_before_queue() {
    auto packet0 = make_audio_packet(0, 60);

    SimulatedRedundantReceiver receiver;
    receiver.receive(*packet0);
    receiver.receive(*packet0);

    require(receiver.queued_packets() == 1,
            "plain duplicate v2 packet should not inflate receive queue");
    receiver.require_next(0);
}

}  // namespace

int main() {
    test_single_dropped_datagram_recovers_from_next_redundant_packet();
    test_two_dropped_datagrams_recover_from_deeper_redundant_packet();
    test_ten_dropped_datagrams_recover_from_bounded_redundant_packet();
    test_duplicate_redundant_datagram_does_not_inflate_queue();
    test_plain_duplicate_v2_packet_is_rejected_before_queue();

    std::cout << "redundant receive policy self-test passed\n";
    return 0;
}
