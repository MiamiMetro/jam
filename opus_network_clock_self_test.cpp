#include "opus_network_clock.h"

#include <cstdlib>
#include <iostream>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}

}  // namespace

int main() {
    require(opus_network_clock::SAMPLE_RATE == 48000, "Opus network sample rate must be 48 kHz");
    require(opus_network_clock::LOW_LATENCY_FRAME_COUNT == 120,
            "Low-latency Opus network packet must be 120 frames");
    require(opus_network_clock::FAST_FRAME_COUNT == 240,
            "Fast Opus network packet must be 240 frames");
    require(opus_network_clock::BALANCED_FRAME_COUNT == 480,
            "Balanced Opus network packet must be 480 frames");
    require(opus_network_clock::STABLE_FRAME_COUNT == 960,
            "Stable Opus network packet must be 960 frames");
    require(opus_network_clock::DEFAULT_FRAME_COUNT == opus_network_clock::BALANCED_FRAME_COUNT,
            "Default Opus network packet must be balanced");
    require(opus_network_clock::is_supported_frame_count(opus_network_clock::SAMPLE_RATE, 120),
            "120-frame Opus network packets must be supported");
    require(opus_network_clock::is_supported_frame_count(opus_network_clock::SAMPLE_RATE, 240),
            "240-frame Opus network packets must be supported");
    require(opus_network_clock::is_supported_frame_count(opus_network_clock::SAMPLE_RATE, 480),
            "480-frame Opus network packets must be supported");
    require(opus_network_clock::is_supported_frame_count(opus_network_clock::SAMPLE_RATE, 960),
            "960-frame Opus network packets must be supported");
    require(opus_network_clock::normalize_frame_count(opus_network_clock::SAMPLE_RATE, 120) == 120,
            "120-frame Opus packet selection must be preserved");
    require(opus_network_clock::normalize_frame_count(opus_network_clock::SAMPLE_RATE, 240) == 240,
            "240-frame Opus packet selection must be preserved");
    require(opus_network_clock::normalize_frame_count(opus_network_clock::SAMPLE_RATE, 480) == 480,
            "480-frame Opus packet selection must be preserved");
    require(opus_network_clock::normalize_frame_count(opus_network_clock::SAMPLE_RATE, 960) == 960,
            "960-frame Opus packet selection must be preserved");
    require(opus_network_clock::normalize_frame_count(opus_network_clock::SAMPLE_RATE, 128) ==
                opus_network_clock::DEFAULT_FRAME_COUNT,
            "Unsupported Opus packet selections must normalize to the default");
    require(opus_network_clock::can_send_callback_direct(120, 0, 120),
            "120-frame callbacks may send directly when packet size is 120");
    require(opus_network_clock::can_send_callback_direct(240, 0, 240),
            "240-frame callbacks may send directly when packet size is 240");
    require(!opus_network_clock::can_send_callback_direct(480, 0, 120),
            "480-frame callbacks must split to network packets");
    require(!opus_network_clock::can_send_callback_direct(120, 0, 960),
            "120-frame callbacks must accumulate for 960-frame packets");
    require(!opus_network_clock::can_send_callback_direct(120, 60, 120),
            "partial accumulator must not use direct send");

    size_t buffered_frames = 0;
    size_t completed_packets = 0;
    for (int callback = 0; callback < 15; ++callback) {
        completed_packets += opus_network_clock::completed_packets_after_append(buffered_frames,
                                                                                128, 120);
        buffered_frames = opus_network_clock::remaining_frames_after_append(buffered_frames, 128,
                                                                           120);
    }

    require(completed_packets == 16,
            "fifteen 128-frame callbacks should produce sixteen 120-frame packets");
    require(buffered_frames == 0, "fifteen 128-frame callbacks should end packet-aligned");

    buffered_frames = 0;
    completed_packets = 0;
    for (int callback = 0; callback < 4; ++callback) {
        completed_packets += opus_network_clock::completed_packets_after_append(buffered_frames,
                                                                                480, 120);
        buffered_frames = opus_network_clock::remaining_frames_after_append(buffered_frames, 480,
                                                                           120);
    }

    require(completed_packets == 16,
            "four 480-frame callbacks should produce sixteen 120-frame packets");
    require(buffered_frames == 0, "four 480-frame callbacks should end packet-aligned");

    buffered_frames = 0;
    completed_packets = 0;
    for (int callback = 0; callback < 8; ++callback) {
        completed_packets += opus_network_clock::completed_packets_after_append(buffered_frames,
                                                                                120, 960);
        buffered_frames = opus_network_clock::remaining_frames_after_append(buffered_frames, 120,
                                                                           960);
    }

    require(completed_packets == 1,
            "eight 120-frame callbacks should produce one 960-frame packet");
    require(buffered_frames == 0, "eight 120-frame callbacks should end packet-aligned");

    std::cout << "opus network clock self-test passed\n";
    return 0;
}
