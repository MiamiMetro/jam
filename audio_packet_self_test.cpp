#include "audio_packet.h"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <vector>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}

bool validates(AudioCodec codec, uint32_t sample_rate, uint16_t frame_count,
               uint8_t channels, uint16_t payload_bytes, std::string* reason = nullptr) {
    std::vector<unsigned char> payload(std::max<size_t>(payload_bytes, 1), 0xA5);
    auto packet = audio_packet::create_audio_packet_v2(
        codec, 1, sample_rate, frame_count, channels, payload.data(), payload_bytes);
    return audio_packet::validate_audio_packet_v2_bytes(packet->data(), packet->size(),
                                                        reason);
}

void test_accepts_supported_opus_shapes() {
    require(validates(AudioCodec::Opus, 48000, 120, 1, 8),
            "120-frame opus packet should validate");
    require(validates(AudioCodec::Opus, 48000, 240, 1, 8),
            "240-frame opus packet should validate");
    require(validates(AudioCodec::Opus, 48000, 480, 1, 8),
            "480-frame opus packet should validate");
    require(validates(AudioCodec::Opus, 48000, 960, 1, 8),
            "960-frame opus packet should validate");
}

void test_rejects_unsupported_opus_shapes() {
    std::string reason;
    require(!validates(AudioCodec::Opus, 48000, 2880, 1, 8, &reason),
            "oversized opus frame count should be rejected");
    require(reason == "unsupported opus frame count",
            "oversized opus rejection reason should be precise");
    require(!validates(AudioCodec::Opus, 44100, 240, 1, 8),
            "unsupported opus sample rate should be rejected");
    require(!validates(AudioCodec::Opus, 48000, 240, 2, 8),
            "unsupported opus channel count should be rejected");
    require(!validates(AudioCodec::Opus, 48000, 240, 1, 0),
            "empty opus payload should be rejected");
}

void test_pcm_payload_must_match_shape() {
    require(validates(AudioCodec::PcmInt16, 48000, 128, 1, 256),
            "matching mono PCM payload should validate");
    require(!validates(AudioCodec::PcmInt16, 48000, 128, 1, 254),
            "short PCM payload should be rejected");
    require(!validates(AudioCodec::PcmInt16, 48000, 128, 2, 512),
            "unsupported PCM channel count should be rejected");
    require(!validates(AudioCodec::PcmInt16, 48000, 300, 1, 600),
            "oversized PCM payload should be rejected");
}

void test_length_mismatch_still_rejected() {
    auto packet = audio_packet::create_audio_packet_v2(
        AudioCodec::Opus, 1, 48000, 240, 1,
        reinterpret_cast<const unsigned char*>("payload"), 8);
    require(!audio_packet::validate_audio_packet_v2_bytes(packet->data(),
                                                          packet->size() - 1),
            "truncated packet should be rejected");
}

void test_redundant_audio_packet_validates_children() {
    std::vector<unsigned char> first_payload(8, 0x11);
    std::vector<unsigned char> second_payload(8, 0x22);
    auto first = audio_packet::create_audio_packet_v2(
        AudioCodec::Opus, 10, 48000, 240, 1, first_payload.data(),
        static_cast<uint16_t>(first_payload.size()));
    auto second = audio_packet::create_audio_packet_v2(
        AudioCodec::Opus, 9, 48000, 240, 1, second_payload.data(),
        static_cast<uint16_t>(second_payload.size()));

    auto redundant =
        audio_packet::create_redundant_audio_packet({first.get(), second.get()});
    require(redundant != nullptr, "valid v2 packets should build redundant audio packet");
    require(audio_packet::validate_redundant_audio_packet_bytes(redundant->data(),
                                                                redundant->size()),
            "valid redundant audio packet should validate");

    int child_count = 0;
    uint32_t sequences[2] = {};
    audio_packet::for_each_redundant_audio_child(
        redundant->data(), redundant->size(),
        [&](const unsigned char* child, size_t child_len, uint8_t index) {
            require(child_len == first->size(), "redundant child length should match v2 packet");
            AudioHdrV2 child_hdr{};
            std::memcpy(&child_hdr, child, audio_packet::v2_header_size());
            sequences[index] = child_hdr.sequence;
            ++child_count;
        });
    require(child_count == 2, "redundant packet should expose both children");
    require(sequences[0] == 10 && sequences[1] == 9,
            "redundant packet should keep current packet first");
}

void test_redundant_audio_packet_reverse_iteration_is_oldest_first() {
    std::vector<unsigned char> first_payload(8, 0x66);
    std::vector<unsigned char> second_payload(8, 0x77);
    auto current = audio_packet::create_audio_packet_v2(
        AudioCodec::Opus, 11, 48000, 240, 1, first_payload.data(),
        static_cast<uint16_t>(first_payload.size()));
    auto previous = audio_packet::create_audio_packet_v2(
        AudioCodec::Opus, 10, 48000, 240, 1, second_payload.data(),
        static_cast<uint16_t>(second_payload.size()));
    auto redundant =
        audio_packet::create_redundant_audio_packet({current.get(), previous.get()});

    int child_count = 0;
    uint32_t sequences[2] = {};
    uint8_t original_indexes[2] = {};
    audio_packet::for_each_redundant_audio_child_reverse(
        redundant->data(), redundant->size(),
        [&](const unsigned char* child, size_t, uint8_t index) {
            AudioHdrV2 child_hdr{};
            std::memcpy(&child_hdr, child, audio_packet::v2_header_size());
            sequences[child_count] = child_hdr.sequence;
            original_indexes[child_count] = index;
            ++child_count;
        });

    require(child_count == 2, "reverse redundant iterator should expose both children");
    require(sequences[0] == 10 && sequences[1] == 11,
            "reverse redundant iterator should process previous packet before current");
    require(original_indexes[0] == 1 && original_indexes[1] == 0,
            "reverse redundant iterator should preserve original child indexes");
}

void test_redundant_audio_packet_rejects_bad_children() {
    std::vector<unsigned char> payload(8, 0x33);
    auto packet = audio_packet::create_audio_packet_v2(
        AudioCodec::Opus, 1, 48000, 240, 1, payload.data(),
        static_cast<uint16_t>(payload.size()));
    auto redundant = audio_packet::create_redundant_audio_packet({packet.get()});
    require(redundant != nullptr, "single-child redundant packet should build");

    redundant->pop_back();
    std::string reason;
    require(!audio_packet::validate_redundant_audio_packet_bytes(
                redundant->data(), redundant->size(), &reason),
            "truncated redundant child should be rejected");
    require(reason == "truncated redundant child",
            "truncated redundant rejection reason should be precise");
}

void test_redundant_audio_sender_id_stamping() {
    std::vector<unsigned char> first_payload(8, 0x44);
    std::vector<unsigned char> second_payload(8, 0x55);
    auto first = audio_packet::create_audio_packet_v2(
        AudioCodec::Opus, 2, 48000, 240, 1, first_payload.data(),
        static_cast<uint16_t>(first_payload.size()));
    auto second = audio_packet::create_audio_packet_v2(
        AudioCodec::Opus, 1, 48000, 240, 1, second_payload.data(),
        static_cast<uint16_t>(second_payload.size()));
    auto redundant =
        audio_packet::create_redundant_audio_packet({first.get(), second.get()});

    require(audio_packet::embed_sender_id_in_redundant_audio_packet(
                redundant->data(), redundant->size(), 77),
            "sender id should stamp into redundant children");
    audio_packet::for_each_redundant_audio_child(
        redundant->data(), redundant->size(),
        [](const unsigned char* child, size_t, uint8_t) {
            uint32_t sender_id = 0;
            std::memcpy(&sender_id, child + sizeof(MsgHdr), sizeof(sender_id));
            require(sender_id == 77, "sender id should be set on every redundant child");
        });
}

}  // namespace

int main() {
    test_accepts_supported_opus_shapes();
    test_rejects_unsupported_opus_shapes();
    test_pcm_payload_must_match_shape();
    test_length_mismatch_still_rejected();
    test_redundant_audio_packet_validates_children();
    test_redundant_audio_packet_reverse_iteration_is_oldest_first();
    test_redundant_audio_packet_rejects_bad_children();
    test_redundant_audio_sender_id_stamping();

    std::cout << "audio packet self-test passed\n";
    return 0;
}
