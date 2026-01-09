#pragma once

#include <array>
#include <chrono>
#include <concurrentqueue.h>
#include <cstdint>
#include <memory>
#include <vector>
#include "opus_decoder.h"
#include "protocol.h"  // For AUDIO_BUF_SIZE

// Opus packet with metadata (for time-driven decode)
// Uses fixed buffer to avoid allocations in hot path
struct OpusPacket {
    uint16_t                              size = 0;  // Actual data size (<= AUDIO_BUF_SIZE)
    std::array<uint8_t, AUDIO_BUF_SIZE>   data;      // Fixed buffer (no allocations)
    std::chrono::steady_clock::time_point timestamp;

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

    // Participant state
    bool                                  is_muted = false;
    float                                 gain     = 1.0F;
    float                                 pan      = 0.5F;  // 0.0 = full left, 0.5 = center, 1.0 = full right
    std::chrono::steady_clock::time_point last_packet_time;
    size_t                                jitter_buffer_min_packets = MIN_JITTER_BUFFER_PACKETS;
    bool                                  buffer_ready              = false;
    int                                   underrun_count            = 0;
    float                                 current_level             = 0.0F;  // RMS audio level
    bool                                  is_speaking = false;  // Voice activity detection

    // Adaptive jitter buffer tracking
    std::array<size_t, 8> queue_size_history = {};  // Rolling history for adaptive buffer
    size_t                history_index      = 0;   // Current index in history
    size_t                plc_count          = 0;   // PLC invocations (for diagnostics)
};

// Lightweight view for UI (snapshot of ParticipantData)
struct ParticipantInfo {
    uint32_t id;
    bool     is_speaking;
    bool     is_muted;
    float    audio_level;
    float    gain;
    float    pan;  // 0.0 = full left, 0.5 = center, 1.0 = full right
    bool     buffer_ready;
    size_t   queue_size;
    int      underrun_count;
    size_t   plc_count;  // PLC invocations for diagnostics
};
