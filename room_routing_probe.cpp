#include <array>
#include <chrono>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

#include <asio.hpp>
#include <asio/ip/udp.hpp>

#include "audio_packet.h"
#include "performer_join_token.h"
#include "protocol.h"

using asio::ip::udp;
using namespace std::chrono_literals;

template <size_t N>
void write_fixed(Bytes<N>& target, const std::string& value) {
    const size_t copy_bytes = std::min(value.size(), target.size() - 1);
    std::copy_n(value.data(), copy_bytes, target.data());
    target[copy_bytes] = '\0';
}

std::string make_token(const std::string& secret, const std::string& server_id,
                       const std::string& room, const std::string& user, int64_t ttl_ms,
                       const std::string& room_override, const std::string& user_override,
                       bool malformed_token) {
    if (malformed_token) {
        return "not-a-valid-token";
    }
    if (secret.empty()) {
        return "";
    }
    performer_join_token::Claims claims;
    claims.expires_at_ms = performer_join_token::now_ms() + ttl_ms;
    claims.server_id     = server_id;
    claims.room_id       = room_override.empty() ? room : room_override;
    claims.profile_id    = user_override.empty() ? user : user_override;
    claims.role          = "performer";
    claims.nonce         = performer_join_token::random_nonce();
    return performer_join_token::create(claims, secret);
}

void send_join(udp::socket& socket, const udp::endpoint& server, const std::string& room,
                      const std::string& user, const std::string& token) {
    JoinHdr join{};
    join.magic = CTRL_MAGIC;
    join.type  = CtrlHdr::Cmd::JOIN;
    write_fixed(join.room_id, room);
    write_fixed(join.room_handle, room);
    write_fixed(join.profile_id, user);
    write_fixed(join.display_name, user);
    write_fixed(join.join_token, token);
    socket.send_to(asio::buffer(&join, sizeof(join)), server);
}

void send_leave(udp::socket& socket, const udp::endpoint& server) {
    CtrlHdr leave{};
    leave.magic = CTRL_MAGIC;
    leave.type  = CtrlHdr::Cmd::LEAVE;
    socket.send_to(asio::buffer(&leave, sizeof(leave)), server);
}

bool receive_any_audio(udp::socket& socket, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::array<unsigned char, 1024> buffer{};
    udp::endpoint sender;

    socket.non_blocking(true);
    while (std::chrono::steady_clock::now() < deadline) {
        std::error_code ec;
        const size_t bytes = socket.receive_from(asio::buffer(buffer), sender, 0, ec);
        if (!ec && bytes >= sizeof(MsgHdr)) {
            MsgHdr hdr{};
            std::memcpy(&hdr, buffer.data(), sizeof(hdr));
            if (hdr.magic == AUDIO_MAGIC || hdr.magic == AUDIO_V2_MAGIC) {
                return true;
            }
            continue;
        }
        if (!ec) {
            continue;
        }
        if (ec != asio::error::would_block && ec != asio::error::try_again) {
            std::cerr << "receive error: " << ec.message() << "\n";
            return false;
        }
        std::this_thread::sleep_for(5ms);
    }

    return false;
}

int main(int argc, char** argv) {
    std::string server_address = "127.0.0.1";
    short       server_port    = 9999;
    std::string server_id      = "local-dev";
    std::string secret;
    std::string token_room_override;
    std::string token_user_override;
    int64_t     ttl_ms = 120000;
    bool        malformed_token = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--server" && i + 1 < argc) {
            server_address = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            server_port = static_cast<short>(std::stoi(argv[++i]));
        } else if (arg == "--server-id" && i + 1 < argc) {
            server_id = argv[++i];
        } else if (arg == "--secret" && i + 1 < argc) {
            secret = argv[++i];
        } else if (arg == "--token-room" && i + 1 < argc) {
            token_room_override = argv[++i];
        } else if (arg == "--token-user" && i + 1 < argc) {
            token_user_override = argv[++i];
        } else if (arg == "--ttl-ms" && i + 1 < argc) {
            ttl_ms = std::stoll(argv[++i]);
        } else if (arg == "--malformed-token") {
            malformed_token = true;
        }
    }

    asio::io_context io;
    udp::resolver    resolver(io);
    const auto       server = *resolver.resolve(udp::v4(), server_address, std::to_string(server_port)).begin();

    udp::socket room_a_sender(io, udp::endpoint(udp::v4(), 0));
    udp::socket room_a_receiver(io, udp::endpoint(udp::v4(), 0));
    udp::socket room_b_receiver(io, udp::endpoint(udp::v4(), 0));

    send_join(room_a_sender, server, "room-a", "user-a1",
                     make_token(secret, server_id, "room-a", "user-a1", ttl_ms,
                                token_room_override, token_user_override, malformed_token));
    send_join(room_a_receiver, server, "room-a", "user-a2",
                     make_token(secret, server_id, "room-a", "user-a2", ttl_ms,
                                token_room_override, token_user_override, malformed_token));
    send_join(room_b_receiver, server, "room-b", "user-b1",
                     make_token(secret, server_id, "room-b", "user-b1", ttl_ms,
                                token_room_override, token_user_override, malformed_token));
    std::this_thread::sleep_for(50ms);

    std::array<unsigned char, 240> samples{};
    auto packet = audio_packet::create_audio_packet_v2(AudioCodec::PcmInt16, 1, 48000, 120, 1,
                                                       samples.data(), samples.size());
    room_a_sender.send_to(asio::buffer(packet->data(), packet->size()), server);

    const bool same_room_received      = receive_any_audio(room_a_receiver, 500ms);
    const bool different_room_received = receive_any_audio(room_b_receiver, 250ms);

    send_leave(room_a_sender, server);
    send_leave(room_a_receiver, server);
    send_leave(room_b_receiver, server);

    std::cout << "same_room_received=" << same_room_received << "\n";
    std::cout << "different_room_received=" << different_room_received << "\n";

    if (!same_room_received) {
        std::cerr << "same-room audio was not forwarded\n";
        return 2;
    }
    if (different_room_received) {
        std::cerr << "different-room audio leaked\n";
        return 3;
    }
    return 0;
}
