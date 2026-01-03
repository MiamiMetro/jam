#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

// Packet identification magic numbers
constexpr uint32_t PING_MAGIC  = 0x50494E47;  // 'PING'
constexpr uint32_t CTRL_MAGIC  = 0x4354524C;  // 'CTRL'
constexpr uint32_t AUDIO_MAGIC = 0x41554449;  // 'AUDI'

// Buffer sizes
constexpr size_t AUDIO_BUF_SIZE = 512;

// Jitter buffer configuration (CLIENT/LISTENER ONLY - server just relays packets)
constexpr size_t MAX_OPUS_QUEUE_SIZE       = 10;  // Maximum packets in queue (safety limit)
constexpr size_t TARGET_OPUS_QUEUE_SIZE    = 3;   // Target queue size for adaptive management
constexpr size_t MIN_JITTER_BUFFER_PACKETS = 3;   // Minimum packets before playback starts

// Type aliases
template <size_t N>
using Bytes = std::array<char, N>;

#pragma pack(push, 1)

struct MsgHdr {
    uint32_t magic;
};

struct SyncHdr : MsgHdr {
    uint32_t seq;
    int64_t  t1_client_send;
    int64_t  t2_server_recv;
    int64_t  t3_server_send;
};

struct CtrlHdr : MsgHdr {
    enum class Cmd : uint8_t {
        JOIN              = 1,
        LEAVE             = 2,
        ALIVE             = 3,
        PARTICIPANT_LEAVE = 4,  // Server broadcasts when participant leaves
    } type;
    uint32_t participant_id = 0;  // Used for PARTICIPANT_LEAVE to identify which participant left
};

struct AudioHdr : MsgHdr {
    uint32_t              sender_id;      // Unique sender identifier
    uint16_t              encoded_bytes;  // size of the encoded Opus data
    Bytes<AUDIO_BUF_SIZE> buf;
};

#pragma pack(pop)