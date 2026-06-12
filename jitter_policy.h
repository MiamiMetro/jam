#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include "opus_network_clock.h"
#include "protocol.h"

inline size_t clamp_opus_jitter_packets(size_t packets) {
    return std::clamp(packets, MIN_OPUS_JITTER_PACKETS, MAX_OPUS_JITTER_PACKETS);
}

inline size_t opus_auto_start_jitter_packets(size_t configured_opus_jitter_floor_packets) {
    return clamp_opus_jitter_packets(
        std::max(configured_opus_jitter_floor_packets,
                 DEFAULT_OPUS_AUTO_START_JITTER_PACKETS));
}

inline size_t opus_jitter_packets_for_ms(int target_ms, uint32_t sample_rate,
                                         uint16_t frame_count) {
    if (target_ms <= 0 || sample_rate == 0 || frame_count == 0) {
        return MIN_OPUS_JITTER_PACKETS;
    }

    const uint64_t denominator =
        static_cast<uint64_t>(frame_count) * 1000ULL;
    const uint64_t numerator =
        static_cast<uint64_t>(target_ms) * static_cast<uint64_t>(sample_rate);
    const uint64_t packets = (numerator + denominator - 1ULL) / denominator;
    return clamp_opus_jitter_packets(static_cast<size_t>(packets));
}

inline size_t opus_jitter_packets_within_ms(int target_ms, uint32_t sample_rate,
                                            uint16_t frame_count) {
    if (target_ms <= 0 || sample_rate == 0 || frame_count == 0) {
        return MIN_OPUS_JITTER_PACKETS;
    }

    const uint64_t denominator =
        static_cast<uint64_t>(frame_count) * 1000ULL;
    const uint64_t numerator =
        static_cast<uint64_t>(target_ms) * static_cast<uint64_t>(sample_rate);
    const uint64_t packets = numerator / denominator;
    return clamp_opus_jitter_packets(static_cast<size_t>(packets));
}

inline int opus_jitter_ms_for_packets(size_t packets, uint32_t sample_rate,
                                      uint16_t frame_count) {
    if (packets == 0 || sample_rate == 0 || frame_count == 0) {
        return 0;
    }

    const uint64_t numerator =
        static_cast<uint64_t>(packets) * static_cast<uint64_t>(frame_count) *
        1000ULL;
    return static_cast<int>((numerator + (sample_rate / 2U)) / sample_rate);
}

inline size_t opus_auto_start_jitter_packets_for_audio(
    size_t configured_opus_jitter_floor_packets, uint32_t sample_rate,
    uint16_t frame_count) {
    const size_t auto_start_packets = opus_jitter_packets_for_ms(
        DEFAULT_OPUS_AUTO_START_JITTER_MS, sample_rate, frame_count);
    return clamp_opus_jitter_packets(
        std::max(configured_opus_jitter_floor_packets, auto_start_packets));
}

inline size_t jitter_floor_packets_for_audio(AudioCodec codec, uint16_t frame_count,
                                             size_t configured_opus_jitter_packets) {
    if (codec == AudioCodec::PcmInt16 && frame_count <= 120) {
        return 2;
    }
    if (codec == AudioCodec::Opus) {
        return clamp_opus_jitter_packets(configured_opus_jitter_packets);
    }
    return MIN_JITTER_BUFFER_PACKETS;
}

inline bool jitter_target_should_snap_to_floor(AudioCodec codec,
                                               bool opus_manual_override,
                                               bool opus_auto_enabled,
                                               bool buffer_ready,
                                               size_t current_target_packets,
                                               size_t floor_packets) {
    if (codec == AudioCodec::Opus && opus_manual_override) {
        return false;
    }
    if (current_target_packets < floor_packets) {
        return true;
    }
    if (codec == AudioCodec::Opus && opus_auto_enabled) {
        return false;
    }
    return !buffer_ready && current_target_packets > floor_packets;
}
