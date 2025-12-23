#pragma once

#include <chrono>
#include <cstdint>
#include <vector>

#include "opus_decoder.h"

// Per-client state and audio processing data
struct ClientInfo {
    std::chrono::steady_clock::time_point last_alive;
    uint32_t                              client_id;   // Unique ID for this client
    OpusDecoderWrapper                    decoder;     // Opus decoder for this client
    std::vector<int16_t>                  pcm_buffer;  // PCM buffer for mixing
};
