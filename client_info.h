#pragma once

#include <chrono>
#include <cstdint>
#include <string>

// Per-client state for SFU server
struct ClientInfo {
    std::chrono::steady_clock::time_point last_alive;
    uint32_t                              client_id;  // Unique ID for this client
    std::string                           room_id = "default";
    std::string                           room_handle;
    std::string                           user_id;
    std::string                           display_name;
    bool                                  has_join_token = false;
};
