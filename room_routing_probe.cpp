#include <array>
#include <chrono>
#include <cstring>
#include <iostream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <asio.hpp>
#include <asio/ip/udp.hpp>

#include "audio_packet.h"
#include "performer_join_token.h"
#include "protocol.h"
#include "session_crypto.h"
#include "udp_port.h"

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
                       bool malformed_token, const std::string& role = "performer") {
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
    claims.role          = role;
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

bool receive_any_audio(udp::socket& socket, std::chrono::milliseconds timeout,
                       const std::optional<session_crypto::SessionKey>& key) {
    if (!key.has_value()) {
        return receive_any_audio(socket, timeout);
    }

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::array<unsigned char, 2048> buffer{};
    std::array<unsigned char, 2048> plaintext{};
    udp::endpoint sender;

    socket.non_blocking(true);
    while (std::chrono::steady_clock::now() < deadline) {
        std::error_code ec;
        const size_t bytes = socket.receive_from(asio::buffer(buffer), sender, 0, ec);
        if (!ec && bytes >= sizeof(MsgHdr)) {
            MsgHdr hdr{};
            std::memcpy(&hdr, buffer.data(), sizeof(hdr));
            if (hdr.magic == SECURE_AUDIO_MAGIC) {
                uint64_t nonce = 0;
                size_t plaintext_bytes = 0;
                if (session_crypto::open_audio_packet(
                        *key, buffer.data(), bytes, nonce, plaintext.data(),
                        plaintext.size(), plaintext_bytes) &&
                    plaintext_bytes >= sizeof(MsgHdr)) {
                    MsgHdr inner{};
                    std::memcpy(&inner, plaintext.data(), sizeof(inner));
                    if (inner.magic == AUDIO_MAGIC || inner.magic == AUDIO_V2_MAGIC ||
                        inner.magic == AUDIO_V3_MAGIC ||
                        inner.magic == AUDIO_REDUNDANT_MAGIC) {
                        return true;
                    }
                }
            } else if (hdr.magic == AUDIO_MAGIC || hdr.magic == AUDIO_V2_MAGIC ||
                       hdr.magic == AUDIO_V3_MAGIC || hdr.magic == AUDIO_REDUNDANT_MAGIC) {
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

void send_audio(udp::socket& socket, const udp::endpoint& server,
                const std::vector<unsigned char>& packet,
                const std::optional<session_crypto::SessionKey>& key,
                uint64_t& nonce) {
    if (!key.has_value()) {
        socket.send_to(asio::buffer(packet.data(), packet.size()), server);
        return;
    }

    std::vector<unsigned char> secure(
        SECURE_PACKET_HEADER_BYTES + packet.size() + SECURE_PACKET_TAG_BYTES);
    size_t secure_bytes = 0;
    if (!session_crypto::seal_audio_packet(*key, nonce++, packet.data(), packet.size(),
                                           secure.data(), secure.size(), secure_bytes)) {
        return;
    }
    secure.resize(secure_bytes);
    socket.send_to(asio::buffer(secure.data(), secure.size()), server);
}

void send_metronome_sync(udp::socket& socket, const udp::endpoint& server) {
    MetronomeSyncHdr sync{};
    sync.magic = CTRL_MAGIC;
    sync.type = CtrlHdr::Cmd::METRONOME_SYNC;
    sync.bpm_milli = 120000;
    sync.beat_number = 4;
    sync.flags = METRONOME_FLAG_RUNNING;
    socket.send_to(asio::buffer(&sync, sizeof(sync)), server);
}

bool receive_metronome_sync(udp::socket& socket, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::array<unsigned char, 1024> buffer{};
    udp::endpoint sender;

    socket.non_blocking(true);
    while (std::chrono::steady_clock::now() < deadline) {
        std::error_code ec;
        const size_t bytes = socket.receive_from(asio::buffer(buffer), sender, 0, ec);
        if (!ec && bytes >= sizeof(CtrlHdr)) {
            MsgHdr hdr{};
            std::memcpy(&hdr, buffer.data(), sizeof(hdr));
            if (hdr.magic != CTRL_MAGIC) {
                continue;
            }
            CtrlHdr ctrl{};
            std::memcpy(&ctrl, buffer.data(), sizeof(ctrl));
            if (ctrl.type == CtrlHdr::Cmd::METRONOME_SYNC) {
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

bool receive_participant_info_for_profile(udp::socket& socket, const std::string& profile_id,
                                          std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::array<unsigned char, 1024> buffer{};
    udp::endpoint sender;

    socket.non_blocking(true);
    while (std::chrono::steady_clock::now() < deadline) {
        std::error_code ec;
        const size_t bytes = socket.receive_from(asio::buffer(buffer), sender, 0, ec);
        if (!ec && bytes >= sizeof(ParticipantInfoHdr)) {
            ParticipantInfoHdr info{};
            std::memcpy(&info, buffer.data(), sizeof(info));
            if (info.magic == CTRL_MAGIC && info.type == CtrlHdr::Cmd::PARTICIPANT_INFO) {
                const auto end = std::find(info.profile_id.begin(), info.profile_id.end(), '\0');
                if (std::string(info.profile_id.begin(), end) == profile_id) {
                    return true;
                }
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
    uint16_t    server_port    = 9999;
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
            server_port = parse_udp_port(argv[++i], "--port");
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
    udp::socket room_a_rejoin_sender(io, udp::endpoint(udp::v4(), 0));
    udp::socket room_a_listener(io, udp::endpoint(udp::v4(), 0));

    const std::string room_a_sender_token =
        make_token(secret, server_id, "room-a", "user-a1", ttl_ms,
                   token_room_override, token_user_override, malformed_token);
    const std::string room_a_receiver_token =
        make_token(secret, server_id, "room-a", "user-a2", ttl_ms,
                   token_room_override, token_user_override, malformed_token);
    const std::string room_b_receiver_token =
        make_token(secret, server_id, "room-b", "user-b1", ttl_ms,
                   token_room_override, token_user_override, malformed_token);
    const std::string listener_token =
        make_token(secret, server_id, "room-a", "listener-a", ttl_ms,
                   token_room_override, token_user_override, malformed_token, "listener");
    const auto room_a_sender_key =
        session_crypto::derive_key_from_join_token_string(room_a_sender_token);
    const auto room_a_receiver_key =
        session_crypto::derive_key_from_join_token_string(room_a_receiver_token);
    const auto room_b_receiver_key =
        session_crypto::derive_key_from_join_token_string(room_b_receiver_token);
    const auto listener_key =
        session_crypto::derive_key_from_join_token_string(listener_token);
    uint64_t room_a_sender_nonce = 1;

    send_join(room_a_sender, server, "room-a", "user-a1", room_a_sender_token);
    send_join(room_a_receiver, server, "room-a", "user-a2", room_a_receiver_token);
    send_join(room_b_receiver, server, "room-b", "user-b1", room_b_receiver_token);
    JoinHdr listener_join{};
    listener_join.magic = CTRL_MAGIC;
    listener_join.type = CtrlHdr::Cmd::JOIN;
    listener_join.role = ClientRole::Listener;
    write_fixed(listener_join.room_id, "room-a");
    write_fixed(listener_join.room_handle, "room-a");
    write_fixed(listener_join.profile_id, "listener-a");
    write_fixed(listener_join.display_name, "listener-a");
    write_fixed(listener_join.join_token, listener_token);
    room_a_listener.send_to(asio::buffer(&listener_join, sizeof(listener_join)), server);
    std::this_thread::sleep_for(50ms);

    std::array<unsigned char, 240> samples{};
    auto packet = audio_packet::create_audio_packet_v2(AudioCodec::PcmInt16, 1, 48000, 120, 1,
                                                       samples.data(), samples.size());
    send_audio(room_a_sender, server, *packet, room_a_sender_key, room_a_sender_nonce);

    const bool same_room_received =
        receive_any_audio(room_a_receiver, 500ms, room_a_receiver_key);
    const bool different_room_received =
        receive_any_audio(room_b_receiver, 250ms, room_b_receiver_key);
    const bool listener_received =
        receive_any_audio(room_a_listener, 500ms, listener_key);
    const bool listener_announced =
        receive_participant_info_for_profile(room_a_receiver, "listener-a", 250ms);

    send_metronome_sync(room_a_sender, server);
    const bool same_room_metronome_received = receive_metronome_sync(room_a_receiver, 500ms);
    const bool different_room_metronome_received = receive_metronome_sync(room_b_receiver, 250ms);

    const std::string room_a_rejoin_token =
        make_token(secret, server_id, "room-a", "user-a1", ttl_ms,
                   token_room_override, token_user_override, malformed_token);
    const auto room_a_rejoin_key =
        session_crypto::derive_key_from_join_token_string(room_a_rejoin_token);
    uint64_t room_a_rejoin_nonce = 1;
    send_join(room_a_rejoin_sender, server, "room-a", "user-a1", room_a_rejoin_token);
    std::this_thread::sleep_for(50ms);

    send_audio(room_a_sender, server, *packet, room_a_sender_key, room_a_sender_nonce);
    const bool stale_duplicate_forwarded =
        receive_any_audio(room_a_receiver, 250ms, room_a_receiver_key);

    send_audio(room_a_rejoin_sender, server, *packet, room_a_rejoin_key,
               room_a_rejoin_nonce);
    const bool rejoined_sender_forwarded =
        receive_any_audio(room_a_receiver, 500ms, room_a_receiver_key);

    send_leave(room_a_sender, server);
    send_leave(room_a_rejoin_sender, server);
    send_leave(room_a_receiver, server);
    send_leave(room_b_receiver, server);
    send_leave(room_a_listener, server);

    std::cout << "same_room_received=" << same_room_received << "\n";
    std::cout << "different_room_received=" << different_room_received << "\n";
    std::cout << "listener_received=" << listener_received << "\n";
    std::cout << "listener_announced=" << listener_announced << "\n";
    std::cout << "same_room_metronome_received=" << same_room_metronome_received << "\n";
    std::cout << "different_room_metronome_received=" << different_room_metronome_received << "\n";
    std::cout << "stale_duplicate_forwarded=" << stale_duplicate_forwarded << "\n";
    std::cout << "rejoined_sender_forwarded=" << rejoined_sender_forwarded << "\n";

    if (!same_room_received) {
        std::cerr << "same-room audio was not forwarded\n";
        return 2;
    }
    if (different_room_received) {
        std::cerr << "different-room audio leaked\n";
        return 3;
    }
    if (!listener_received) {
        std::cerr << "listener did not receive same-room audio\n";
        return 8;
    }
    if (listener_announced) {
        std::cerr << "listener was announced as performer participant\n";
        return 9;
    }
    if (!same_room_metronome_received) {
        std::cerr << "same-room metronome sync was not forwarded\n";
        return 4;
    }
    if (different_room_metronome_received) {
        std::cerr << "different-room metronome sync leaked\n";
        return 5;
    }
    if (stale_duplicate_forwarded) {
        std::cerr << "stale duplicate sender was still forwarded\n";
        return 6;
    }
    if (!rejoined_sender_forwarded) {
        std::cerr << "rejoined sender was not forwarded\n";
        return 7;
    }
    return 0;
}
