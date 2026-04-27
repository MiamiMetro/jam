#pragma once

#include <chrono>
#include <cstdint>

// Per-client state for SFU server
struct ClientInfo {
    std::chrono::steady_clock::time_point last_alive;
    uint32_t                              client_id;  // Unique ID for this client
};
