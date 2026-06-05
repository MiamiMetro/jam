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
    require(opus_network_clock::FRAME_COUNT == 240, "Opus network packet must be 240 frames");
    require(opus_network_clock::FRAME_COUNT_MS == 5, "Opus network packet must be 5 ms");
    require(opus_network_clock::is_legal_network_frame_count(),
            "Opus network frame count must be legal");
    require(opus_network_clock::can_send_callback_direct(240, 0),
            "240-frame callbacks may send directly");
    require(!opus_network_clock::can_send_callback_direct(120, 0),
            "120-frame callbacks must accumulate to network packets");
    require(!opus_network_clock::can_send_callback_direct(480, 0),
            "480-frame callbacks must split to network packets");
    require(!opus_network_clock::can_send_callback_direct(240, 120),
            "partial accumulator must not use direct send");

    size_t buffered_frames = 0;
    size_t completed_packets = 0;
    for (int callback = 0; callback < 15; ++callback) {
        completed_packets += opus_network_clock::completed_packets_after_append(buffered_frames,
                                                                                128);
        buffered_frames = opus_network_clock::remaining_frames_after_append(buffered_frames, 128);
    }

    require(completed_packets == 8, "fifteen 128-frame callbacks should produce eight packets");
    require(buffered_frames == 0, "fifteen 128-frame callbacks should end packet-aligned");

    buffered_frames = 0;
    completed_packets = 0;
    for (int callback = 0; callback < 4; ++callback) {
        completed_packets += opus_network_clock::completed_packets_after_append(buffered_frames,
                                                                                480);
        buffered_frames = opus_network_clock::remaining_frames_after_append(buffered_frames, 480);
    }

    require(completed_packets == 8, "four 480-frame callbacks should produce eight packets");
    require(buffered_frames == 0, "four 480-frame callbacks should end packet-aligned");

    std::cout << "opus network clock self-test passed\n";
    return 0;
}
