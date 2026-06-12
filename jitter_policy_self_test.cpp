#include "jitter_policy.h"

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

void test_configured_opus_jitter_applies_to_all_supported_frame_sizes() {
    for (const uint16_t frame_count:
         {opus_network_clock::LOW_LATENCY_FRAME_COUNT,
          opus_network_clock::FAST_FRAME_COUNT,
          opus_network_clock::BALANCED_FRAME_COUNT,
          opus_network_clock::STABLE_FRAME_COUNT}) {
        require(jitter_floor_packets_for_audio(AudioCodec::Opus, frame_count, 12) == 12,
                "configured Opus jitter should apply to every supported Opus frame size");
    }
}

void test_configured_opus_jitter_is_clamped() {
    require(jitter_floor_packets_for_audio(AudioCodec::Opus,
                                           opus_network_clock::FAST_FRAME_COUNT, 999) ==
                MAX_OPUS_JITTER_PACKETS,
            "configured Opus jitter should be clamped to the maximum");
}

void test_auto_start_jitter_uses_larger_startup_cushion() {
    require(DEFAULT_OPUS_AUTO_START_JITTER_PACKETS > DEFAULT_OPUS_JITTER_PACKETS,
            "auto-start cushion should be higher than the steady-state floor");
    require(opus_auto_start_jitter_packets(DEFAULT_OPUS_JITTER_PACKETS) ==
                DEFAULT_OPUS_AUTO_START_JITTER_PACKETS,
            "auto-start jitter should begin at the internet burst cushion");
}

void test_auto_start_jitter_respects_higher_configured_floor() {
    constexpr size_t higher_floor = DEFAULT_OPUS_AUTO_START_JITTER_PACKETS + 2;
    require(opus_auto_start_jitter_packets(higher_floor) == higher_floor,
            "auto-start jitter should not lower an explicitly higher floor");
    require(opus_auto_start_jitter_packets(999) == MAX_OPUS_JITTER_PACKETS,
            "auto-start jitter should still be clamped to the user-facing maximum");
}

void test_jitter_ms_converts_to_packets_for_supported_frame_sizes() {
    require(opus_jitter_packets_for_ms(DEFAULT_OPUS_JITTER_MS,
                                       opus_network_clock::SAMPLE_RATE,
                                       opus_network_clock::LOW_LATENCY_FRAME_COUNT) == 8,
            "20 ms jitter should be 8 packets at 2.5 ms");
    require(opus_jitter_packets_for_ms(DEFAULT_OPUS_JITTER_MS,
                                       opus_network_clock::SAMPLE_RATE,
                                       opus_network_clock::FAST_FRAME_COUNT) == 4,
            "20 ms jitter should be 4 packets at 5 ms");
    require(opus_jitter_packets_for_ms(DEFAULT_OPUS_JITTER_MS,
                                       opus_network_clock::SAMPLE_RATE,
                                       opus_network_clock::BALANCED_FRAME_COUNT) == 2,
            "20 ms jitter should be 2 packets at 10 ms");
    require(opus_jitter_packets_for_ms(DEFAULT_OPUS_JITTER_MS,
                                       opus_network_clock::SAMPLE_RATE,
                                       opus_network_clock::STABLE_FRAME_COUNT) == 1,
            "20 ms jitter should be 1 packet at 20 ms");
}

void test_jitter_age_limit_uses_floor_packet_count() {
    require(opus_jitter_packets_within_ms(85, opus_network_clock::SAMPLE_RATE,
                                          opus_network_clock::BALANCED_FRAME_COUNT) == 8,
            "85 ms age limit should allow only 8 complete 10 ms packets");
    require(opus_jitter_packets_within_ms(85, opus_network_clock::SAMPLE_RATE,
                                          opus_network_clock::STABLE_FRAME_COUNT) == 4,
            "85 ms age limit should allow only 4 complete 20 ms packets");
}

void test_auto_start_jitter_ms_converts_to_packets_for_stable_frames() {
    require(opus_auto_start_jitter_packets_for_audio(
                DEFAULT_OPUS_JITTER_PACKETS, opus_network_clock::SAMPLE_RATE,
                opus_network_clock::BALANCED_FRAME_COUNT) == 4,
            "40 ms auto-start should be 4 packets at 10 ms");
    require(opus_auto_start_jitter_packets_for_audio(
                1, opus_network_clock::SAMPLE_RATE,
                opus_network_clock::STABLE_FRAME_COUNT) == 2,
            "40 ms auto-start should be 2 packets at 20 ms");
}

void test_jitter_packet_count_round_trips_to_effective_ms() {
    require(opus_jitter_ms_for_packets(2, opus_network_clock::SAMPLE_RATE,
                                       opus_network_clock::BALANCED_FRAME_COUNT) == 20,
            "2 balanced packets should be 20 ms");
    require(opus_jitter_ms_for_packets(2, opus_network_clock::SAMPLE_RATE,
                                       opus_network_clock::STABLE_FRAME_COUNT) == 40,
            "2 stable packets should be 40 ms");
}

void test_auto_start_target_does_not_snap_to_floor_before_ready() {
    require(!jitter_target_should_snap_to_floor(
                AudioCodec::Opus, false, true, false,
                DEFAULT_OPUS_AUTO_START_JITTER_PACKETS, DEFAULT_OPUS_JITTER_PACKETS),
            "auto jitter should preserve the startup cushion before the buffer is ready");
}

void test_non_auto_target_snaps_to_floor_before_ready() {
    require(jitter_target_should_snap_to_floor(
                AudioCodec::Opus, false, false, false,
                DEFAULT_OPUS_AUTO_START_JITTER_PACKETS, DEFAULT_OPUS_JITTER_PACKETS),
            "non-auto jitter should snap a not-ready target back to the configured floor");
}

void test_target_raises_when_floor_increases() {
    require(jitter_target_should_snap_to_floor(
                AudioCodec::Opus, false, true, true,
                DEFAULT_OPUS_JITTER_PACKETS, DEFAULT_OPUS_AUTO_START_JITTER_PACKETS),
            "jitter target should rise when the configured floor rises above the target");
}

void test_manual_opus_target_is_owned_by_manual_override() {
    require(!jitter_target_should_snap_to_floor(
                AudioCodec::Opus, true, false, false,
                DEFAULT_OPUS_JITTER_PACKETS, DEFAULT_OPUS_AUTO_START_JITTER_PACKETS),
            "manual Opus jitter should not be overwritten by packet floor updates");
}

void test_low_latency_pcm_keeps_smaller_floor() {
    require(jitter_floor_packets_for_audio(AudioCodec::PcmInt16, 120,
                                           DEFAULT_OPUS_JITTER_PACKETS) == 2,
            "small PCM packets should keep the low latency PCM floor");
}

}  // namespace

int main() {
    test_configured_opus_jitter_applies_to_all_supported_frame_sizes();
    test_configured_opus_jitter_is_clamped();
    test_auto_start_jitter_uses_larger_startup_cushion();
    test_auto_start_jitter_respects_higher_configured_floor();
    test_jitter_ms_converts_to_packets_for_supported_frame_sizes();
    test_jitter_age_limit_uses_floor_packet_count();
    test_auto_start_jitter_ms_converts_to_packets_for_stable_frames();
    test_jitter_packet_count_round_trips_to_effective_ms();
    test_auto_start_target_does_not_snap_to_floor_before_ready();
    test_non_auto_target_snaps_to_floor_before_ready();
    test_target_raises_when_floor_increases();
    test_manual_opus_target_is_owned_by_manual_override();
    test_low_latency_pcm_keeps_smaller_floor();

    std::cout << "jitter policy self-test passed\n";
    return 0;
}
