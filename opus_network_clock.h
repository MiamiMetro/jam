#pragma once

#include <cstddef>
#include <cstdint>

namespace opus_network_clock {

inline constexpr uint32_t SAMPLE_RATE = 48000;
inline constexpr uint16_t LOW_LATENCY_FRAME_COUNT = 120;
inline constexpr uint16_t FAST_FRAME_COUNT = 240;
inline constexpr uint16_t BALANCED_FRAME_COUNT = 480;
inline constexpr uint16_t STABLE_FRAME_COUNT = 960;
inline constexpr uint16_t DEFAULT_FRAME_COUNT = BALANCED_FRAME_COUNT;

inline bool is_legal_frame_count(uint32_t sample_rate, uint16_t frame_count) {
    constexpr int durations_per_400_ms[] = {1, 2, 4, 8, 16, 24};
    for (int duration: durations_per_400_ms) {
        if ((sample_rate * static_cast<uint32_t>(duration)) / 400U == frame_count &&
            (sample_rate * static_cast<uint32_t>(duration)) % 400U == 0U) {
            return true;
        }
    }
    return false;
}

inline bool is_supported_frame_count(uint32_t sample_rate, uint16_t frame_count) {
    return sample_rate == SAMPLE_RATE &&
           (frame_count == LOW_LATENCY_FRAME_COUNT || frame_count == FAST_FRAME_COUNT ||
            frame_count == BALANCED_FRAME_COUNT || frame_count == STABLE_FRAME_COUNT) &&
           is_legal_frame_count(sample_rate, frame_count);
}

inline uint16_t normalize_frame_count(uint32_t sample_rate, int frame_count) {
    if (frame_count > 0 &&
        is_supported_frame_count(sample_rate, static_cast<uint16_t>(frame_count))) {
        return static_cast<uint16_t>(frame_count);
    }
    return DEFAULT_FRAME_COUNT;
}

inline size_t completed_packets_after_append(size_t buffered_frames, size_t appended_frames,
                                             uint16_t frame_count) {
    return (buffered_frames + appended_frames) / frame_count;
}

inline size_t remaining_frames_after_append(size_t buffered_frames, size_t appended_frames,
                                            uint16_t frame_count) {
    return (buffered_frames + appended_frames) % frame_count;
}

inline bool can_send_callback_direct(size_t callback_frames, size_t buffered_frames,
                                     uint16_t frame_count) {
    return buffered_frames == 0 && callback_frames == frame_count;
}

inline double frame_duration_ms(uint32_t sample_rate, uint16_t frame_count) {
    return (static_cast<double>(frame_count) * 1000.0) / static_cast<double>(sample_rate);
}

}  // namespace opus_network_clock
