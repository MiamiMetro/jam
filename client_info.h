#pragma once

#include <chrono>
#include <cstdint>
#include <string>

#include "protocol.h"
#include "session_crypto.h"

// Per-client state for SFU server
struct ClientInfo {
    std::chrono::steady_clock::time_point last_alive;
    std::chrono::steady_clock::time_point joined_at;
    uint32_t                              client_id = 0;  // Unique ID for this client
    std::string                           room_id;
    std::string                           profile_id;
    std::string                           display_name;
    uint32_t                              capabilities = 0;
    ClientRole                            role = ClientRole::Performer;
    bool                                  joined_with_metadata = false;
    bool                                  has_session_key = false;
    session_crypto::SessionKey            session_key{};
    std::string                           token_nonce_key;
    session_crypto::ReplayWindow          audio_replay_window;
    uint64_t                              secure_send_nonce = 1;
};
