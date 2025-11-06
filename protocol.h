#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

// Packet identification magic numbers
constexpr uint32_t PING_MAGIC  = 0x50494E47;  // 'PING'
constexpr uint32_t CTRL_MAGIC  = 0x4354524C;  // 'CTRL'
constexpr uint32_t ECHO_MAGIC  = 0x4543484F;  // 'ECHO'
constexpr uint32_t AUDIO_MAGIC = 0x41554449;  // 'AUDI'

// Buffer sizes
constexpr size_t ECHO_DATA_SIZE = 256;
constexpr size_t AUDIO_BUF_SIZE = 512;

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
        JOIN  = 1,
        LEAVE = 2,
        ALIVE = 3,
    } type;
};

struct EchoHdr : MsgHdr {
    Bytes<ECHO_DATA_SIZE> data;
};

struct AudioHdr : MsgHdr {
    uint16_t              encoded_bytes;  // size of the encoded Opus data
    Bytes<AUDIO_BUF_SIZE> buf;
};

#pragma pack(pop)