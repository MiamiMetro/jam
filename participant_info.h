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
#include "pcm_clock_resampler.h"
#include "protocol.h"  // For AUDIO_BUF_SIZE

// Opus packet with metadata (for time-driven decode)
// Uses fixed buffer to avoid allocations in hot path
struct OpusPacket {
    uint16_t                              size = 0;  // Actual data size (<= AUDIO_BUF_SIZE)
    std::array<uint8_t, AUDIO_BUF_SIZE>   data;      // Fixed buffer (no allocations)
    std::chrono::steady_clock::time_point timestamp;
    AudioCodec                            codec = AudioCodec::Opus;
    uint32_t                              sequence = 0;
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
    std::array<float, 1920>                 pcm_playout_buffer{};
    size_t                                  pcm_playout_buffered_frames = 0;
    PcmClockResampler                       pcm_resampler;
    std::array<float, 960>                  last_pcm_buffer{};
    size_t                                  last_pcm_samples = 0;
    bool                                    last_pcm_valid = false;
    bool                                    pcm_concealment_used = false;
    std::atomic<uint64_t>                   pcm_drift_drops{0};
    std::atomic<uint64_t>                   pcm_drift_inserts{0};
    std::atomic<size_t>                     pcm_playout_depth_frames{0};
    std::atomic<size_t>                     pcm_target_buffer_frames{0};
    std::atomic<int64_t>                    pcm_resample_ratio_ppm{0};
    std::atomic<uint64_t>                   pcm_resampler_underruns{0};
    std::atomic<uint64_t>                   pcm_resampler_overruns{0};

    // Participant state
    std::string                           profile_id;
    std::string                           display_name;
    bool                                  is_muted = false;
    float                                 gain     = 1.0F;
    float                                 pan      = 0.5F;  // 0.0 = full left, 0.5 = center, 1.0 = full right
    std::chrono::steady_clock::time_point last_packet_time;
    size_t                                jitter_buffer_floor_packets = MIN_JITTER_BUFFER_PACKETS;
    size_t                                jitter_buffer_min_packets = MIN_JITTER_BUFFER_PACKETS;
    bool                                  buffer_ready              = false;
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
    uint64_t pcm_drift_inserts;
    size_t   pcm_playout_depth_frames;
    size_t   pcm_target_buffer_frames;
    int64_t  pcm_resample_ratio_ppm;
    uint64_t pcm_resampler_underruns;
    uint64_t pcm_resampler_overruns;
};
