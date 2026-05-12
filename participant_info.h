#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <concurrentqueue.h>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include "opus_decoder.h"
#include "protocol.h"  // For AUDIO_BUF_SIZE

// Opus packet with metadata (for time-driven decode)
// Uses fixed buffer to avoid allocations in hot path
struct OpusPacket {
    uint16_t                              size = 0;  // Actual data size (<= AUDIO_BUF_SIZE)
    std::array<uint8_t, AUDIO_BUF_SIZE>   data;      // Fixed buffer (no allocations)
    std::chrono::steady_clock::time_point timestamp;
    AudioCodec                            codec = AudioCodec::Opus;
    uint32_t                              sequence = 0;
    uint32_t                              sample_rate = 48000;
    uint16_t                              frame_count = 0;
    uint8_t                               channels = 1;

    // Helper to get data pointer and size (compatible with old vector API)
    const uint8_t* get_data() const {
        return data.data();
    }
    size_t get_size() const {
        return size;
    }
};

// Per-participant audio data and state
struct ParticipantData {
    // Audio processing - store OPUS packets, decode in audio callback
    moodycamel::ConcurrentQueue<OpusPacket> opus_queue;
    std::unique_ptr<OpusDecoderWrapper>     decoder;
    std::array<float, 960>                  pcm_buffer;  // Preallocated decode buffer
    std::array<float, 1920>                 opus_pcm_buffer{};
    size_t                                  opus_pcm_buffered_frames = 0;
    std::atomic<size_t>                     opus_pcm_buffered_frames_observed{0};
    std::atomic<uint64_t>                   opus_packets_decoded_in_callback{0};
    std::atomic<uint64_t>                   opus_queue_limit_drops{0};
    std::atomic<uint64_t>                   opus_age_limit_drops{0};
    std::atomic<uint64_t>                   opus_decode_buffer_overflow_drops{0};
    std::atomic<uint64_t>                   opus_target_trim_drops{0};
    std::atomic<size_t>                     last_packet_frame_count{0};
    std::atomic<size_t>                     last_callback_frame_count{0};
    std::array<float, 960>                  last_pcm_buffer{};
    size_t                                  last_pcm_samples = 0;
    bool                                    last_pcm_valid = false;
    bool                                    pcm_concealment_used = false;
    std::atomic<uint64_t>                   pcm_drift_drops{0};

    // Participant state
    std::string                           profile_id;
    std::string                           display_name;
    bool                                  is_muted = false;
    float                                 gain     = 1.0F;
    float                                 pan      = 0.5F;  // 0.0 = full left, 0.5 = center, 1.0 = full right
    std::chrono::steady_clock::time_point last_packet_time;
    size_t                                jitter_buffer_floor_packets = MIN_JITTER_BUFFER_PACKETS;
    size_t                                jitter_buffer_min_packets = MIN_JITTER_BUFFER_PACKETS;
    size_t                                opus_queue_limit_packets = MAX_OPUS_QUEUE_SIZE;
    bool                                  opus_jitter_manual_override = false;
    bool                                  opus_jitter_auto_enabled = false;
    size_t                                opus_jitter_auto_floor_packets = DEFAULT_OPUS_JITTER_PACKETS;
    int                                   opus_jitter_auto_stable_callbacks = 0;
    int                                   opus_jitter_auto_instability_events = 0;
    std::atomic<uint64_t>                 opus_jitter_auto_increases{0};
    std::atomic<uint64_t>                 opus_jitter_auto_decreases{0};
    bool                                  buffer_ready              = false;
    int                                   opus_consecutive_empty_callbacks = 0;
    int                                   underrun_count            = 0;
    float                                 current_level             = 0.0F;  // RMS audio level
    bool                                  is_speaking = false;  // Voice activity detection

    // Adaptive jitter buffer tracking
    std::array<size_t, 8> queue_size_history = {};  // Rolling history for adaptive buffer
    size_t                history_index      = 0;   // Current index in history
    size_t                plc_count          = 0;   // PLC invocations (for diagnostics)
    AudioCodec            last_codec         = AudioCodec::Opus;
    std::atomic<int64_t>   packet_age_last_ns{0};
    std::atomic<int64_t>   packet_age_max_ns{0};
    std::atomic<int64_t>   packet_age_avg_ns{0};
    std::atomic<size_t>    queue_depth_max{0};
    std::atomic<size_t>    queue_depth_avg{0};
    std::atomic<int64_t>   queue_depth_drift_milli{0};
    bool                   sequence_initialized = false;
    uint32_t               next_expected_sequence = 0;
    std::atomic<uint64_t>   sequence_gaps{0};
    std::atomic<uint64_t>   sequence_late_or_reordered{0};
    std::atomic<uint64_t>   jitter_depth_drops{0};
    std::atomic<uint64_t>   jitter_age_drops{0};
    std::atomic<uint64_t>   pcm_concealment_frames{0};
    bool                    drift_reference_initialized = false;
    uint32_t                drift_reference_sequence = 0;
    uint32_t                drift_reference_sample_rate = 48000;
    uint16_t                drift_reference_frame_count = 0;
    std::chrono::steady_clock::time_point drift_reference_time{};
    std::atomic<int64_t>    receiver_drift_ppm_last_milli{0};
    std::atomic<int64_t>    receiver_drift_ppm_avg_milli{0};
    std::atomic<int64_t>    receiver_drift_ppm_abs_max_milli{0};
};

// Lightweight view for UI (snapshot of ParticipantData)
struct ParticipantInfo {
    uint32_t id;
    std::string profile_id;
    std::string display_name;
    bool     is_speaking;
    bool     is_muted;
    float    audio_level;
    float    gain;
    float    pan;  // 0.0 = full left, 0.5 = center, 1.0 = full right
    bool     buffer_ready;
    size_t   queue_size;
    size_t   queue_size_avg;
    size_t   queue_size_max;
    double   queue_drift_packets;
    size_t   jitter_buffer_min_packets;
    size_t   jitter_buffer_floor_packets;
    size_t   opus_queue_limit_packets;
    bool     opus_jitter_manual_override;
    bool     opus_jitter_auto_enabled;
    size_t   opus_jitter_auto_floor_packets;
    uint64_t opus_jitter_auto_increases;
    uint64_t opus_jitter_auto_decreases;
    size_t   opus_pcm_buffered_frames;
    uint64_t opus_packets_decoded_in_callback;
    uint64_t opus_queue_limit_drops;
    uint64_t opus_age_limit_drops;
    uint64_t opus_decode_buffer_overflow_drops;
    uint64_t opus_target_trim_drops;
    size_t   last_packet_frame_count;
    size_t   last_callback_frame_count;
    int      underrun_count;
    size_t   plc_count;  // PLC invocations for diagnostics
    double   packet_age_last_ms;
    double   packet_age_avg_ms;
    double   packet_age_max_ms;
    uint64_t sequence_gaps;
    uint64_t sequence_late_or_reordered;
    uint64_t jitter_depth_drops;
    uint64_t jitter_age_drops;
    uint64_t pcm_concealment_frames;
    uint64_t pcm_drift_drops;
    double   receiver_drift_ppm_last;
    double   receiver_drift_ppm_avg;
    double   receiver_drift_ppm_abs_max;
};
