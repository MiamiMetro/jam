#pragma once

#include <chrono>
#include <concurrentqueue.h>
#include <cstdint>
#include <memory>
#include <vector>
#include "opus_decoder.h"

// Per-participant audio data and state
struct ParticipantData {
    // Audio processing
    moodycamel::ConcurrentQueue<std::vector<float>> audio_queue;
    std::unique_ptr<OpusDecoderWrapper>             decoder;

    // Participant state
    bool                                  is_muted = false;
    float                                 gain     = 1.0F;
    std::chrono::steady_clock::time_point last_packet_time;
    size_t                                jitter_buffer_min_packets = 2;
    bool                                  buffer_ready              = false;
    int                                   underrun_count            = 0;
    float                                 current_level             = 0.0F;  // RMS audio level
    bool                                  is_speaking = false;  // Voice activity detection
};

// Lightweight view for UI (snapshot of ParticipantData)
struct ParticipantInfo {
    uint32_t id;
    bool     is_speaking;
    bool     is_muted;
    float    audio_level;
    float    gain;
    bool     buffer_ready;
    size_t   queue_size;
    int      underrun_count;
};
