#pragma once

#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>
#include "protocol.h"

// Audio packet construction utilities (extends packet_builder for client-specific needs)
namespace audio_packet {

// Create audio packet with encoded data
// Returns shared_ptr for async send safety
inline std::shared_ptr<std::vector<unsigned char>> create_audio_packet(
    const std::vector<unsigned char>& encoded_data) {
    uint16_t encoded_bytes = static_cast<uint16_t>(encoded_data.size());

    auto packet = std::make_shared<std::vector<unsigned char>>();
    packet->reserve(sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t) + encoded_bytes);

    // Write magic
    uint32_t magic = AUDIO_MAGIC;
    packet->insert(packet->end(), reinterpret_cast<const unsigned char*>(&magic),
                   reinterpret_cast<const unsigned char*>(&magic) + sizeof(uint32_t));

    // Write sender_id (0, server will overwrite)
    uint32_t sender_id = 0;
    packet->insert(packet->end(), reinterpret_cast<const unsigned char*>(&sender_id),
                   reinterpret_cast<const unsigned char*>(&sender_id) + sizeof(uint32_t));

    // Write encoded_bytes
    packet->insert(packet->end(), reinterpret_cast<const unsigned char*>(&encoded_bytes),
                   reinterpret_cast<const unsigned char*>(&encoded_bytes) + sizeof(uint16_t));

    // Write encoded audio data (if any)
    if (encoded_bytes > 0) {
        packet->insert(packet->end(), encoded_data.begin(), encoded_data.end());
    }

    return packet;
}

inline std::shared_ptr<std::vector<unsigned char>> create_audio_packet_v2(
    AudioCodec codec, uint32_t sequence, uint32_t sample_rate, uint16_t frame_count,
    uint8_t channels, const unsigned char* payload, uint16_t payload_bytes) {
    auto packet = std::make_shared<std::vector<unsigned char>>();
    packet->resize(sizeof(AudioHdrV2) - AUDIO_BUF_SIZE + payload_bytes);

    AudioHdrV2 hdr{};
    hdr.magic         = AUDIO_V2_MAGIC;
    hdr.sender_id     = 0;
    hdr.sequence      = sequence;
    hdr.sample_rate   = sample_rate;
    hdr.frame_count   = frame_count;
    hdr.payload_bytes = payload_bytes;
    hdr.channels      = channels;
    hdr.codec         = codec;

    std::memcpy(packet->data(), &hdr, sizeof(AudioHdrV2) - AUDIO_BUF_SIZE);
    if (payload_bytes > 0) {
        std::memcpy(packet->data() + sizeof(AudioHdrV2) - AUDIO_BUF_SIZE, payload, payload_bytes);
    }

    return packet;
}

}  // namespace audio_packet
