#pragma once

#include <cstdint>
#include <cstring>
#include <algorithm>
#include <memory>
#include <string>
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

template <size_t N>
inline void write_fixed(Bytes<N>& target, const std::string& value) {
    const size_t copy_bytes = std::min(value.size(), target.size() - 1);
    std::memcpy(target.data(), value.data(), copy_bytes);
    target[copy_bytes] = '\0';
}

inline std::shared_ptr<std::vector<unsigned char>> create_participant_info_packet(
    uint32_t participant_id, const std::string& profile_id, const std::string& display_name) {
    ParticipantInfoHdr info{};
    info.magic          = CTRL_MAGIC;
    info.type           = CtrlHdr::Cmd::PARTICIPANT_INFO;
    info.participant_id = participant_id;
    write_fixed(info.profile_id, profile_id);
    write_fixed(info.display_name, display_name);

    auto buf = std::make_shared<std::vector<unsigned char>>(sizeof(ParticipantInfoHdr));
    std::memcpy(buf->data(), &info, sizeof(ParticipantInfoHdr));
    return buf;
}

inline uint16_t extract_v2_payload_bytes(const unsigned char* packet_data) {
    uint16_t payload_bytes;
    std::memcpy(&payload_bytes,
                packet_data + sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint32_t) +
                    sizeof(uint32_t) + sizeof(uint16_t),
                sizeof(uint16_t));
    return payload_bytes;
}

inline const unsigned char* audio_v1_payload(const unsigned char* packet_data) {
    return packet_data + sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t);
}

inline const unsigned char* audio_v2_payload(const unsigned char* packet_data) {
    return packet_data + sizeof(AudioHdrV2) - AUDIO_BUF_SIZE;
}

}  // namespace packet_builder
