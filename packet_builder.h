#pragma once

#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include "protocol.h"

// Helper utilities for building network packets
namespace packet_builder {

// Create a participant leave control packet
inline std::shared_ptr<std::vector<unsigned char>> create_participant_leave_packet(
    uint32_t participant_id) {
    CtrlHdr chdr{};
    chdr.magic          = CTRL_MAGIC;
    chdr.type           = CtrlHdr::Cmd::PARTICIPANT_LEAVE;
    chdr.participant_id = participant_id;

    auto buf = std::make_shared<std::vector<unsigned char>>(sizeof(CtrlHdr));
    std::memcpy(buf->data(), &chdr, sizeof(CtrlHdr));
    return buf;
}

// Embed sender ID into an audio packet
inline void embed_sender_id(unsigned char* packet_data, uint32_t sender_id) {
    std::memcpy(packet_data + sizeof(MsgHdr), &sender_id, sizeof(uint32_t));
}

// Extract sender ID from an audio packet
inline uint32_t extract_sender_id(const unsigned char* packet_data) {
    uint32_t sender_id;
    std::memcpy(&sender_id, packet_data + sizeof(MsgHdr), sizeof(uint32_t));
    return sender_id;
}

// Extract encoded bytes from audio packet
inline uint16_t extract_encoded_bytes(const unsigned char* packet_data) {
    uint16_t encoded_bytes;
    std::memcpy(&encoded_bytes, packet_data + sizeof(MsgHdr) + sizeof(uint32_t), sizeof(uint16_t));
    return encoded_bytes;
}

}  // namespace packet_builder
