#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

// Packet identification magic numbers
constexpr uint32_t PING_MAGIC  = 0x50494E47;  // 'PING'
constexpr uint32_t CTRL_MAGIC  = 0x4354524C;  // 'CTRL'
constexpr uint32_t AUDIO_MAGIC = 0x41554449;  // 'AUDI'
constexpr uint32_t AUDIO_V2_MAGIC = 0x41553249;  // 'AU2I'

// Buffer sizes
constexpr size_t AUDIO_BUF_SIZE = 512;

// Jitter buffer configuration (CLIENT/LISTENER ONLY - server just relays packets)
constexpr size_t MAX_OPUS_QUEUE_SIZE       = 64;  // Hard safety cap for Opus receive queue
constexpr size_t TARGET_OPUS_QUEUE_SIZE    = 3;   // Target queue size for adaptive management
constexpr size_t MIN_JITTER_BUFFER_PACKETS = 3;   // Minimum packets before playback starts
constexpr size_t MIN_OPUS_JITTER_PACKETS = 0;     // Manual testing can disable Opus prebuffer
constexpr size_t DEFAULT_OPUS_JITTER_PACKETS = 8; // Default Opus playout target
constexpr size_t DEFAULT_OPUS_QUEUE_LIMIT_PACKETS = 16; // Default Opus burst capacity
constexpr size_t MAX_OPUS_JITTER_PACKETS = 32;    // User-facing Opus jitter limit
constexpr size_t MIN_OPUS_QUEUE_LIMIT_PACKETS = 1;
constexpr size_t MAX_OPUS_QUEUE_LIMIT_PACKETS = 64; // User-facing Opus queue limit
constexpr int    DEFAULT_JITTER_PACKET_AGE_MS = 40;  // Default age limit at playout
constexpr int    MIN_JITTER_PACKET_AGE_MS = 0;        // Manual testing can disable age drops
constexpr int    MAX_JITTER_PACKET_AGE_MS = 250;      // User-facing age limit

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
        PARTICIPANT_INFO  = 6,  // Server broadcasts room-local participant metadata
    } type;
    uint32_t participant_id = 0;  // Used for PARTICIPANT_LEAVE to identify which participant left
};

struct JoinHdr : CtrlHdr {
    Bytes<64>  room_id;
    Bytes<64>  room_handle;
    Bytes<64>  profile_id;
    Bytes<64>  display_name;
    Bytes<512> join_token;
};

struct ParticipantInfoHdr : CtrlHdr {
    Bytes<64> profile_id;
    Bytes<64> display_name;
};

struct AudioHdr : MsgHdr {
    uint32_t              sender_id;      // Unique sender identifier
    uint16_t              encoded_bytes;  // size of the encoded Opus data
    Bytes<AUDIO_BUF_SIZE> buf;
};

enum class AudioCodec : uint8_t {
    Opus     = 1,
    PcmInt16 = 2,
};

struct AudioHdrV2 : MsgHdr {
    uint32_t              sender_id;      // Server-owned sender identifier
    uint32_t              sequence;       // Sender-local packet sequence
    uint32_t              sample_rate;    // Packet sample rate
    uint16_t              frame_count;    // Frames per packet
    uint16_t              payload_bytes;  // Audio payload bytes
    uint8_t               channels;       // Channel count in payload
    AudioCodec            codec;          // Payload codec
    Bytes<AUDIO_BUF_SIZE> buf;
};

#pragma pack(pop)
