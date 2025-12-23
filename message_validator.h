#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "protocol.h"

// Message validation utilities
namespace message_validator {

// Validate message has minimum header size
inline bool has_valid_header(size_t bytes) {
    return bytes >= sizeof(MsgHdr);
}

// Validate PING message size
inline bool is_valid_ping(size_t bytes) {
    return bytes >= sizeof(SyncHdr);
}

// Validate CTRL message size
inline bool is_valid_ctrl(size_t bytes) {
    return bytes >= sizeof(CtrlHdr);
}

// Validate audio packet size
inline bool is_valid_audio_packet(size_t bytes, size_t min_audio_packet_size) {
    return bytes >= min_audio_packet_size;
}

// Check if encoded_bytes is within reasonable limits
inline bool is_encoded_bytes_valid(uint16_t encoded_bytes, size_t max_audio_buf_size) {
    return encoded_bytes <= max_audio_buf_size;
}

// Validate audio packet has complete payload
inline bool has_complete_payload(size_t actual_bytes, size_t expected_bytes, size_t tolerance = 2) {
    if (actual_bytes < expected_bytes) {
        size_t missing = expected_bytes - actual_bytes;
        return missing <= tolerance;
    }
    return true;
}

}  // namespace message_validator
