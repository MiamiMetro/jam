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

}  // namespace

int main() {
    test_accepts_supported_opus_shapes();
    test_rejects_unsupported_opus_shapes();
    test_pcm_payload_must_match_shape();
    test_length_mismatch_still_rejected();

    std::cout << "audio packet self-test passed\n";
    return 0;
}
