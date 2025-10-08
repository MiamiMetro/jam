#pragma once

#include <cstdint>

// Magic numbers for packet identification
constexpr uint32_t PING_MAGIC = 0x50494E47; // 'PING'
constexpr uint32_t CTRL_MAGIC = 0x4354524C; // 'CTRL'

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

#pragma pack(pop)