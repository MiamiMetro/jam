#pragma once

#include <cstdint>

constexpr uint32_t JAM_BROADCAST_IPC_MAGIC = 0x4A424950;  // JBIP
constexpr uint16_t JAM_BROADCAST_IPC_VERSION = 1;

enum class JamBroadcastPcmFormat : uint16_t {
    Float32LE = 1,
};

#pragma pack(push, 1)
struct JamBroadcastIpcHeader {
    uint32_t magic = JAM_BROADCAST_IPC_MAGIC;
    uint16_t version = JAM_BROADCAST_IPC_VERSION;
    uint16_t header_bytes = sizeof(JamBroadcastIpcHeader);
    uint32_t sequence = 0;
    uint32_t sample_rate = 48000;
    uint16_t channels = 1;
    uint16_t frame_count = 0;
    uint16_t format = static_cast<uint16_t>(JamBroadcastPcmFormat::Float32LE);
    uint16_t payload_bytes = 0;
};
#pragma pack(pop)

