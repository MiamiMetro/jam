#pragma once

#include <cstddef>
#include <cstdint>

namespace opus_network_clock {

inline constexpr uint32_t SAMPLE_RATE = 48000;
inline constexpr uint16_t FRAME_COUNT = 240;
inline constexpr uint16_t FRAME_COUNT_MS = 5;

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

inline bool is_legal_network_frame_count() {
    return is_legal_frame_count(SAMPLE_RATE, FRAME_COUNT);
}

inline size_t completed_packets_after_append(size_t buffered_frames, size_t appended_frames) {
    return (buffered_frames + appended_frames) / FRAME_COUNT;
}

inline size_t remaining_frames_after_append(size_t buffered_frames, size_t appended_frames) {
    return (buffered_frames + appended_frames) % FRAME_COUNT;
}

inline bool can_send_callback_direct(size_t callback_frames, size_t buffered_frames) {
    return buffered_frames == 0 && callback_frames == FRAME_COUNT;
}

}  // namespace opus_network_clock
