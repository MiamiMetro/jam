#pragma once

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>
#include "protocol.h"

// Audio packet construction utilities (extends packet_builder for client-specific needs)
namespace audio_packet {

inline constexpr size_t v2_header_size() {
    return sizeof(AudioHdrV2) - AUDIO_BUF_SIZE;
}

inline bool validate_audio_packet_v2_bytes(const unsigned char* data, size_t len,
                                           std::string* reason = nullptr) {
    if (data == nullptr) {
        if (reason != nullptr) {
            *reason = "null packet";
        }
        return false;
    }
    if (len < v2_header_size()) {
        if (reason != nullptr) {
            *reason = "short header";
        }
        return false;
    }

    AudioHdrV2 hdr{};
    std::memcpy(&hdr, data, v2_header_size());
    if (hdr.magic != AUDIO_V2_MAGIC) {
        if (reason != nullptr) {
            *reason = "wrong magic";
        }
        return false;
    }
    if (hdr.payload_bytes > AUDIO_BUF_SIZE) {
        if (reason != nullptr) {
            *reason = "payload too large";
        }
        return false;
    }

    const size_t expected = v2_header_size() + hdr.payload_bytes;
    if (len != expected) {
        if (reason != nullptr) {
            *reason = "length mismatch";
        }
        return false;
    }
    if (hdr.channels == 0 || hdr.frame_count == 0 || hdr.sample_rate == 0) {
        if (reason != nullptr) {
            *reason = "invalid audio shape";
        }
        return false;
    }
    if (hdr.codec != AudioCodec::Opus && hdr.codec != AudioCodec::PcmInt16) {
        if (reason != nullptr) {
            *reason = "invalid codec";
        }
        return false;
    }

    return true;
}

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
    packet->resize(v2_header_size() + payload_bytes);

    AudioHdrV2 hdr{};
    hdr.magic         = AUDIO_V2_MAGIC;
    hdr.sender_id     = 0;
    hdr.sequence      = sequence;
    hdr.sample_rate   = sample_rate;
    hdr.frame_count   = frame_count;
    hdr.payload_bytes = payload_bytes;
    hdr.channels      = channels;
    hdr.codec         = codec;

    std::memcpy(packet->data(), &hdr, v2_header_size());
    if (payload_bytes > 0) {
        std::memcpy(packet->data() + v2_header_size(), payload, payload_bytes);
    }

    return packet;
}

}  // namespace audio_packet
