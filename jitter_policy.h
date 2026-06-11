#pragma once

#include <algorithm>
#include <cstddef>

#include "protocol.h"

inline size_t clamp_opus_jitter_packets(size_t packets) {
    return std::clamp(packets, MIN_OPUS_JITTER_PACKETS, MAX_OPUS_JITTER_PACKETS);
}

inline size_t clamp_opus_auto_jitter_max_packets(size_t configured_opus_jitter_floor_packets,
                                                 size_t configured_opus_jitter_max_packets) {
    return clamp_opus_jitter_packets(
        std::max(configured_opus_jitter_floor_packets,
                 configured_opus_jitter_max_packets));
}

inline size_t opus_auto_start_jitter_packets(
    size_t configured_opus_jitter_floor_packets,
    size_t configured_opus_jitter_max_packets = DEFAULT_OPUS_AUTO_MAX_JITTER_PACKETS) {
    const size_t floor = clamp_opus_jitter_packets(configured_opus_jitter_floor_packets);
    const size_t ceiling =
        clamp_opus_auto_jitter_max_packets(floor, configured_opus_jitter_max_packets);
    return clamp_opus_jitter_packets(
        std::min(ceiling, std::max(floor, DEFAULT_OPUS_AUTO_START_JITTER_PACKETS)));
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
