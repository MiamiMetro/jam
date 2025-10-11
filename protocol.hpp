#pragma once

#include <cstdint>

// Magic numbers for packet identification
constexpr uint32_t PING_MAGIC = 0x50494E47; // 'PING'
constexpr uint32_t CTRL_MAGIC = 0x4354524C; // 'CTRL'
constexpr uint32_t ECHO_MAGIC = 0x4543484F; // 'ECHO'
constexpr uint32_t AUDIO_MAGIC = 0x41554449; // 'AUDI'

#pragma pack(push, 1)

struct MsgHdr {
    uint32_t magic;
};

struct SyncHdr : MsgHdr {
    uint32_t seq;
    int64_t t1_client_send;
    int64_t t2_server_recv;
    int64_t t3_server_send;
};

struct CtrlHdr : MsgHdr {
    enum class Cmd : uint8_t {
        JOIN = 1,
        LEAVE = 2,
        ALIVE = 3,
    } type;
};

struct EchoHdr : MsgHdr {
    char data[256];
};

struct AudioHdr : MsgHdr {
    uint8_t encoded_bytes; // size of the encoded Opus data
    char buf[128];
};

#pragma pack(pop)