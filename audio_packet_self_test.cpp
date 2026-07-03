#include "audio_packet.h"

#include <algorithm>
#include <array>
#include <cstring>
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

bool validates_v3(AudioCodec codec, uint32_t sample_rate, uint16_t frame_count,
                  uint8_t channels, uint16_t payload_bytes, int64_t capture_ns,
                  std::string* reason = nullptr) {
    std::vector<unsigned char> payload(std::max<size_t>(payload_bytes, 1), 0xB6);
    auto packet = audio_packet::create_audio_packet_v3(
        codec, 7, sample_rate, frame_count, channels, payload.data(), payload_bytes,
        capture_ns);
    return audio_packet::validate_audio_packet_bytes(packet->data(), packet->size(),
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
    std::vector<unsigned char> third_payload(8, 0x33);
    std::vector<unsigned char> fourth_payload(8, 0x44);
    auto first = audio_packet::create_audio_packet_v2(
        AudioCodec::Opus, 10, 48000, 240, 1, first_payload.data(),
        static_cast<uint16_t>(first_payload.size()));
    auto second = audio_packet::create_audio_packet_v2(
        AudioCodec::Opus, 9, 48000, 240, 1, second_payload.data(),
        static_cast<uint16_t>(second_payload.size()));
    auto third = audio_packet::create_audio_packet_v2(
        AudioCodec::Opus, 8, 48000, 240, 1, third_payload.data(),
        static_cast<uint16_t>(third_payload.size()));
    auto fourth = audio_packet::create_audio_packet_v2(
        AudioCodec::Opus, 7, 48000, 240, 1, fourth_payload.data(),
        static_cast<uint16_t>(fourth_payload.size()));

    auto redundant =
        audio_packet::create_redundant_audio_packet(
            {first.get(), second.get(), third.get(), fourth.get()});
    require(redundant != nullptr, "valid v2 packets should build redundant audio packet");
    require(audio_packet::validate_redundant_audio_packet_bytes(redundant->data(),
                                                                redundant->size()),
            "valid redundant audio packet should validate");

    int child_count = 0;
    uint32_t sequences[4] = {};
    audio_packet::for_each_redundant_audio_child(
        redundant->data(), redundant->size(),
        [&](const unsigned char* child, size_t child_len, uint8_t index) {
            require(child_len == first->size(), "redundant child length should match v2 packet");
            AudioHdrV2 child_hdr{};
            std::memcpy(&child_hdr, child, audio_packet::v2_header_size());
            sequences[index] = child_hdr.sequence;
            ++child_count;
        });
    require(child_count == 4, "redundant packet should expose all protected children");
    require(sequences[0] == 10 && sequences[1] == 9 && sequences[2] == 8 &&
                sequences[3] == 7,
            "redundant packet should keep current packet first");
}

void test_redundant_audio_packet_respects_target_size() {
    std::vector<unsigned char> payload(100, 0x55);
    auto current = audio_packet::create_audio_packet_v2(
        AudioCodec::Opus, 10, 48000, 240, 1, payload.data(),
        static_cast<uint16_t>(payload.size()));
    auto previous = audio_packet::create_audio_packet_v2(
        AudioCodec::Opus, 9, 48000, 240, 1, payload.data(),
        static_cast<uint16_t>(payload.size()));
    auto older = audio_packet::create_audio_packet_v2(
        AudioCodec::Opus, 8, 48000, 240, 1, payload.data(),
        static_cast<uint16_t>(payload.size()));

    const size_t target_size =
        audio_packet::redundant_header_size() + current->size() + previous->size();
    auto redundant = audio_packet::create_redundant_audio_packet(
        {current.get(), previous.get(), older.get()}, target_size);
    require(redundant != nullptr, "target-sized redundant packet should build");
    require(redundant->size() == target_size,
            "redundant packet should omit older children that exceed target size");

    int child_count = 0;
    audio_packet::for_each_redundant_audio_child(
        redundant->data(), redundant->size(),
        [&](const unsigned char*, size_t, uint8_t) {
            ++child_count;
        });
    require(child_count == 2, "target cap should keep only fitting children");
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

void test_v3_timestamp_packet_round_trip() {
    std::vector<unsigned char> payload{0x10, 0x20, 0x30, 0x40};
    auto packet = audio_packet::create_audio_packet_v3(
        AudioCodec::Opus, 42, 48000, 120, 1, payload.data(),
        static_cast<uint16_t>(payload.size()), 123456789LL);

    require(packet != nullptr, "v3 packet should build");
    require(packet->size() == audio_packet::v3_header_size() + payload.size(),
            "v3 packet size should be header plus payload");
    require(audio_packet::validate_audio_packet_bytes(packet->data(), packet->size()),
            "v3 packet should validate");

    const auto parsed = audio_packet::parse_audio_header(packet->data(), packet->size());
    require(parsed.valid, "v3 parsed header should be valid");
    require(parsed.magic == AUDIO_V3_MAGIC, "v3 parsed magic should match");
    require(parsed.capture_timestamp_valid, "v3 capture timestamp should be valid");
    require(parsed.capture_server_time_ns == 123456789LL,
            "v3 capture timestamp should round trip");
    require(parsed.sequence == 42, "v3 sequence should round trip");
    require(parsed.frame_count == 120, "v3 frame count should round trip");
    require(std::equal(payload.begin(), payload.end(),
                       audio_packet::audio_payload(packet->data(), packet->size())),
            "v3 payload pointer should skip timestamp header");
}

void test_v3_validation_reuses_v2_shape_rules() {
    std::string reason;
    require(validates_v3(AudioCodec::Opus, 48000, 120, 1, 8, 55),
            "valid v3 opus packet should validate");
    require(!validates_v3(AudioCodec::Opus, 44100, 120, 1, 8, 55, &reason),
            "v3 unsupported sample rate should fail");
    require(reason == "unsupported audio shape",
            "v3 unsupported sample rate reason should match v2 validation");
}

void test_v3_timestamp_packet_strips_to_v2() {
    std::vector<unsigned char> payload{0x21, 0x22, 0x23};
    auto v3 = audio_packet::create_audio_packet_v3(
        AudioCodec::Opus, 9, 48000, 120, 1, payload.data(),
        static_cast<uint16_t>(payload.size()), 777777LL);
    auto v2 = audio_packet::strip_audio_v3_timestamp(v3->data(), v3->size());

    require(v2 != nullptr, "v3 packet should strip to v2");
    require(audio_packet::validate_audio_packet_v2_bytes(v2->data(), v2->size()),
            "stripped packet should validate as v2");
    require(v2->size() == audio_packet::v2_header_size() + payload.size(),
            "stripped v2 packet should remove timestamp bytes");

    AudioHdrV2 hdr{};
    std::memcpy(&hdr, v2->data(), audio_packet::v2_header_size());
    require(hdr.magic == AUDIO_V2_MAGIC, "stripped packet should use v2 magic");
    require(hdr.sequence == 9, "stripped packet should preserve sequence");
    require(hdr.payload_bytes == payload.size(), "stripped packet should preserve payload size");
}

void test_redundant_audio_packet_accepts_v3_children() {
    std::vector<unsigned char> current_payload(8, 0x31);
    std::vector<unsigned char> previous_payload(8, 0x32);
    auto current = audio_packet::create_audio_packet_v3(
        AudioCodec::Opus, 20, 48000, 120, 1, current_payload.data(),
        static_cast<uint16_t>(current_payload.size()), 2000000LL);
    auto previous = audio_packet::create_audio_packet_v3(
        AudioCodec::Opus, 19, 48000, 120, 1, previous_payload.data(),
        static_cast<uint16_t>(previous_payload.size()), 1000000LL);

    auto redundant = audio_packet::create_redundant_audio_packet(
        {current.get(), previous.get()});
    require(redundant != nullptr, "redundant packet should build from v3 children");
    require(audio_packet::validate_redundant_audio_packet_bytes(redundant->data(),
                                                                redundant->size()),
            "redundant v3 packet should validate");

    int child_count = 0;
    audio_packet::for_each_redundant_audio_child(
        redundant->data(), redundant->size(),
        [&](const unsigned char* child, size_t child_len, uint8_t index) {
            const auto parsed = audio_packet::parse_audio_header(child, child_len);
            require(parsed.valid, "redundant v3 child should parse");
            require(parsed.magic == AUDIO_V3_MAGIC, "redundant child should keep v3 magic");
            require(parsed.capture_timestamp_valid, "redundant child should keep capture timestamp");
            require(parsed.sequence == (index == 0 ? 20U : 19U),
                    "redundant child sequence should preserve order");
            ++child_count;
        });
    require(child_count == 2, "redundant v3 packet should expose two children");
}

void test_write_audio_packet_v3_into_caller_buffer() {
    std::array<unsigned char, 128> out{};
    const std::array<unsigned char, 4> payload{0x10, 0x20, 0x30, 0x40};
    size_t bytes_written = 0;

    require(audio_packet::write_audio_packet_v3(
                AudioCodec::Opus, 42, 48000, 120, 1, payload.data(),
                static_cast<uint16_t>(payload.size()), 123456789LL,
                out.data(), out.size(), bytes_written),
            "write_audio_packet_v3 should fit in caller buffer");
    require(bytes_written == audio_packet::v3_header_size() + payload.size(),
            "V3 writer should report exact packet size");
    require(audio_packet::validate_audio_packet_bytes(out.data(), bytes_written),
            "V3 writer should produce a valid packet");

    const auto parsed = audio_packet::parse_audio_header(out.data(), bytes_written);
    require(parsed.valid, "V3 writer parsed header should be valid");
    require(parsed.magic == AUDIO_V3_MAGIC, "V3 writer should preserve magic");
    require(parsed.sequence == 42, "V3 writer should preserve sequence");
    require(parsed.capture_server_time_ns == 123456789LL,
            "V3 writer should preserve capture timestamp");
    require(std::memcmp(audio_packet::audio_payload(out.data(), bytes_written),
                        payload.data(), payload.size()) == 0,
            "V3 writer should copy payload bytes");
}

void test_write_audio_packet_capacity_failure() {
    std::array<unsigned char, 8> out{};
    const std::array<unsigned char, 4> payload{0xAA, 0xBB, 0xCC, 0xDD};
    size_t bytes_written = 99;

    require(!audio_packet::write_audio_packet_v2(
                AudioCodec::Opus, 7, 48000, 120, 1, payload.data(),
                static_cast<uint16_t>(payload.size()),
                out.data(), out.size(), bytes_written),
            "V2 writer should fail when output buffer is too small");
    require(bytes_written == 0, "failed writer should zero bytes_written");
}

void test_write_redundant_audio_packet_into_caller_buffer() {
    std::array<unsigned char, 128> current{};
    std::array<unsigned char, 128> previous{};
    std::array<unsigned char, 256> redundant{};
    const std::array<unsigned char, 3> payload{0x01, 0x02, 0x03};
    size_t current_bytes = 0;
    size_t previous_bytes = 0;
    size_t redundant_bytes = 0;

    require(audio_packet::write_audio_packet_v3(
                AudioCodec::Opus, 11, 48000, 120, 1, payload.data(),
                static_cast<uint16_t>(payload.size()), 1111,
                current.data(), current.size(), current_bytes),
            "current V3 should write");
    require(audio_packet::write_audio_packet_v3(
                AudioCodec::Opus, 10, 48000, 120, 1, payload.data(),
                static_cast<uint16_t>(payload.size()), 1010,
                previous.data(), previous.size(), previous_bytes),
            "previous V3 should write");

    const audio_packet::AudioPacketView views[] = {
        {current.data(), current_bytes},
        {previous.data(), previous_bytes},
    };
    require(audio_packet::write_redundant_audio_packet(
                views, 2, redundant.data(), redundant.size(),
                AUDIO_REDUNDANT_TARGET_BYTES, redundant_bytes),
            "redundant writer should fit in caller buffer");
    require(audio_packet::validate_redundant_audio_packet_bytes(
                redundant.data(), redundant_bytes),
            "redundant writer should produce a valid datagram");
}

}  // namespace

int main() {
    test_accepts_supported_opus_shapes();
    test_rejects_unsupported_opus_shapes();
    test_pcm_payload_must_match_shape();
    test_length_mismatch_still_rejected();
    test_redundant_audio_packet_validates_children();
    test_redundant_audio_packet_respects_target_size();
    test_redundant_audio_packet_reverse_iteration_is_oldest_first();
    test_redundant_audio_packet_rejects_bad_children();
    test_redundant_audio_sender_id_stamping();
    test_v3_timestamp_packet_round_trip();
    test_v3_validation_reuses_v2_shape_rules();
    test_v3_timestamp_packet_strips_to_v2();
    test_redundant_audio_packet_accepts_v3_children();
    test_write_audio_packet_v3_into_caller_buffer();
    test_write_audio_packet_capacity_failure();
    test_write_redundant_audio_packet_into_caller_buffer();

    std::cout << "audio packet self-test passed\n";
    return 0;
}
