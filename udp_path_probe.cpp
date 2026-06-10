#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include <asio.hpp>
#include <asio/ip/udp.hpp>

#include "packet_builder.h"
#include "performer_join_token.h"
#include "protocol.h"

using asio::ip::udp;
using clock_type = std::chrono::steady_clock;
using namespace std::chrono_literals;

namespace {

struct Args {
    std::string host = "127.0.0.1";
    unsigned short port = 9999;
    std::string server_id = "local-dev";
    std::string join_secret;
    std::string room = "udp-path-probe";
    std::string user = "udp-path-probe";
    int64_t join_token_ttl_ms = 120000;
    int seconds = 20;
    int rate_pps = 200;
    int payload_bytes = static_cast<int>(sizeof(SyncHdr));
    bool require_clean = false;
};

int64_t steady_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               clock_type::now().time_since_epoch())
        .count();
}

void configure_socket(udp::socket& socket) {
    std::error_code ec;
    socket.set_option(asio::socket_base::receive_buffer_size(UDP_SOCKET_BUFFER_BYTES), ec);
    socket.set_option(asio::socket_base::send_buffer_size(UDP_SOCKET_BUFFER_BYTES), ec);
}

std::string create_join_token(const Args& args) {
    if (args.join_secret.empty()) {
        return "";
    }

    performer_join_token::Claims claims;
    claims.expires_at_ms = performer_join_token::now_ms() + args.join_token_ttl_ms;
    claims.server_id = args.server_id;
    claims.room_id = args.room;
    claims.profile_id = args.user;
    claims.role = "performer";
    claims.nonce = performer_join_token::random_nonce();
    return performer_join_token::create(claims, args.join_secret);
}

void send_join(udp::socket& socket, const udp::endpoint& server, const Args& args) {
    JoinHdr hdr{};
    hdr.magic = CTRL_MAGIC;
    hdr.type = CtrlHdr::Cmd::JOIN;
    packet_builder::write_fixed(hdr.room_id, args.room);
    packet_builder::write_fixed(hdr.room_handle, args.room);
    packet_builder::write_fixed(hdr.profile_id, args.user);
    packet_builder::write_fixed(hdr.display_name, args.user);
    packet_builder::write_fixed(hdr.join_token, create_join_token(args));
    socket.send_to(asio::buffer(&hdr, sizeof(hdr)), server);
}

void send_leave(udp::socket& socket, const udp::endpoint& server) {
    CtrlHdr hdr{};
    hdr.magic = CTRL_MAGIC;
    hdr.type = CtrlHdr::Cmd::LEAVE;
    std::error_code ec;
    socket.send_to(asio::buffer(&hdr, sizeof(hdr)), server, 0, ec);
}

void send_alive(udp::socket& socket, const udp::endpoint& server) {
    CtrlHdr hdr{};
    hdr.magic = CTRL_MAGIC;
    hdr.type = CtrlHdr::Cmd::ALIVE;
    std::error_code ec;
    socket.send_to(asio::buffer(&hdr, sizeof(hdr)), server, 0, ec);
}

bool receive_join_ack(udp::socket& socket, uint32_t& client_id) {
    std::array<unsigned char, 2048> buffer{};
    udp::endpoint remote;

    while (true) {
        std::error_code ec;
        const size_t bytes = socket.receive_from(asio::buffer(buffer), remote, 0, ec);
        if (ec == asio::error::would_block || ec == asio::error::try_again) {
            return false;
        }
        if (ec) {
            return false;
        }
        if (bytes < sizeof(CtrlHdr)) {
            continue;
        }

        CtrlHdr hdr{};
        std::memcpy(&hdr, buffer.data(), sizeof(hdr));
        if (hdr.magic == CTRL_MAGIC && hdr.type == CtrlHdr::Cmd::JOIN_ACK) {
            client_id = hdr.participant_id;
            return true;
        }
    }
}

bool join_with_retry(udp::socket& socket, const udp::endpoint& server, const Args& args,
                     uint32_t& client_id, int& join_attempts) {
    const auto deadline = clock_type::now() + 5s;
    auto next_join = clock_type::now();

    while (clock_type::now() < deadline) {
        if (clock_type::now() >= next_join) {
            send_join(socket, server, args);
            ++join_attempts;
            next_join = clock_type::now() + 250ms;
        }
        if (receive_join_ack(socket, client_id)) {
            return true;
        }
        std::this_thread::sleep_for(5ms);
    }
    return receive_join_ack(socket, client_id);
}

void drain_replies(udp::socket& socket, std::vector<bool>& seen, uint32_t& replies,
                   uint32_t& duplicate_replies, uint32_t& unexpected_replies,
                   int64_t& rtt_sum_ns, int64_t& rtt_max_ns) {
    std::array<unsigned char, 2048> buffer{};
    udp::endpoint remote;

    while (true) {
        std::error_code ec;
        const size_t bytes = socket.receive_from(asio::buffer(buffer), remote, 0, ec);
        if (ec == asio::error::would_block || ec == asio::error::try_again) {
            return;
        }
        if (ec) {
            return;
        }
        if (bytes < sizeof(SyncHdr)) {
            continue;
        }

        SyncHdr hdr{};
        std::memcpy(&hdr, buffer.data(), sizeof(hdr));
        if (hdr.magic != PING_MAGIC) {
            continue;
        }

        if (hdr.seq >= seen.size()) {
            ++unexpected_replies;
            continue;
        }

        const int64_t now = steady_ns();
        const int64_t server_turnaround = hdr.t3_server_send - hdr.t2_server_recv;
        const int64_t rtt_ns = std::max<int64_t>(0, (now - hdr.t1_client_send) - server_turnaround);
        rtt_sum_ns += rtt_ns;
        rtt_max_ns = std::max(rtt_max_ns, rtt_ns);

        if (seen[hdr.seq]) {
            ++duplicate_replies;
        } else {
            seen[hdr.seq] = true;
            ++replies;
        }
    }
}

int run_probe(const Args& args) {
    asio::io_context io_context;
    udp::resolver resolver(io_context);
    udp::endpoint server =
        *resolver.resolve(udp::v4(), args.host, std::to_string(args.port)).begin();

    udp::socket socket(io_context, udp::endpoint(udp::v4(), 0));
    configure_socket(socket);
    socket.non_blocking(true);

    uint32_t client_id = 0;
    int join_attempts = 0;
    const bool joined = join_with_retry(socket, server, args, client_id, join_attempts);
    if (!joined) {
        std::cout << "udp_path_probe v1\n";
        std::cout << "server: " << args.host << ':' << args.port << "\n";
        std::cout << "local_port: " << socket.local_endpoint().port() << "\n";
        std::cout << "joined: 0\n";
        std::cout << "join_attempts: " << join_attempts << "\n";
        std::cout << "error: JOIN_ACK not received\n";
        return 1;
    }

    const int total_packets = std::max(1, args.seconds * args.rate_pps);
    const int payload_bytes =
        std::max<int>(static_cast<int>(sizeof(SyncHdr)), args.payload_bytes);
    std::vector<unsigned char> packet(static_cast<size_t>(payload_bytes), 0);
    std::vector<bool> seen(static_cast<size_t>(total_packets), false);

    uint32_t replies = 0;
    uint32_t duplicate_replies = 0;
    uint32_t unexpected_replies = 0;
    int64_t rtt_sum_ns = 0;
    int64_t rtt_max_ns = 0;

    const auto start = clock_type::now() + 100ms;
    const auto interval = std::chrono::duration_cast<clock_type::duration>(
        std::chrono::duration<double>(1.0 / static_cast<double>(std::max(1, args.rate_pps))));

    for (int i = 0; i < total_packets; ++i) {
        std::this_thread::sleep_until(start + interval * i);
        if (i % std::max(1, args.rate_pps) == 0) {
            send_alive(socket, server);
        }

        SyncHdr hdr{};
        hdr.magic = PING_MAGIC;
        hdr.seq = static_cast<uint32_t>(i);
        hdr.t1_client_send = steady_ns();
        std::memcpy(packet.data(), &hdr, sizeof(hdr));

        std::error_code ec;
        socket.send_to(asio::buffer(packet), server, 0, ec);
        drain_replies(socket, seen, replies, duplicate_replies, unexpected_replies,
                      rtt_sum_ns, rtt_max_ns);
    }

    const auto drain_deadline = clock_type::now() + 2s;
    while (clock_type::now() < drain_deadline) {
        drain_replies(socket, seen, replies, duplicate_replies, unexpected_replies,
                      rtt_sum_ns, rtt_max_ns);
        if (replies >= static_cast<uint32_t>(total_packets)) {
            break;
        }
        std::this_thread::sleep_for(5ms);
    }

    send_leave(socket, server);

    const int missing = total_packets - static_cast<int>(replies);
    const double reply_rate =
        100.0 * static_cast<double>(replies) / static_cast<double>(total_packets);
    const double avg_rtt_ms =
        replies > 0 ? static_cast<double>(rtt_sum_ns) / static_cast<double>(replies) / 1e6 : -1.0;
    const double max_rtt_ms = static_cast<double>(rtt_max_ns) / 1e6;

    std::cout << "udp_path_probe v1\n";
    std::cout << "server: " << args.host << ':' << args.port << "\n";
    std::cout << "local_port: " << socket.local_endpoint().port() << "\n";
    std::cout << "joined: 1\n";
    std::cout << "client_id: " << client_id << "\n";
    std::cout << "join_attempts: " << join_attempts << "\n";
    std::cout << "seconds: " << args.seconds << "\n";
    std::cout << "rate_pps: " << args.rate_pps << "\n";
    std::cout << "payload_bytes: " << payload_bytes << "\n";
    std::cout << "sent_packets: " << total_packets << "\n";
    std::cout << "reply_packets: " << replies << "\n";
    std::cout << "missing_replies: " << missing << "\n";
    std::cout << "reply_rate_percent: " << reply_rate << "\n";
    std::cout << "duplicate_replies: " << duplicate_replies << "\n";
    std::cout << "unexpected_replies: " << unexpected_replies << "\n";
    std::cout << "avg_rtt_ms: " << avg_rtt_ms << "\n";
    std::cout << "max_rtt_ms: " << max_rtt_ms << "\n";

    if (args.require_clean && missing != 0) {
        return 1;
    }
    return 0;
}

Args parse_args(int argc, char** argv) {
    Args args;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if ((arg == "--server" || arg == "--host") && i + 1 < argc) {
            args.host = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            args.port = static_cast<unsigned short>(std::stoi(argv[++i]));
        } else if (arg == "--server-id" && i + 1 < argc) {
            args.server_id = argv[++i];
        } else if (arg == "--join-secret" && i + 1 < argc) {
            args.join_secret = argv[++i];
        } else if (arg == "--room" && i + 1 < argc) {
            args.room = argv[++i];
        } else if (arg == "--user" && i + 1 < argc) {
            args.user = argv[++i];
        } else if (arg == "--seconds" && i + 1 < argc) {
            args.seconds = std::stoi(argv[++i]);
        } else if (arg == "--rate-pps" && i + 1 < argc) {
            args.rate_pps = std::stoi(argv[++i]);
        } else if (arg == "--payload-bytes" && i + 1 < argc) {
            args.payload_bytes = std::stoi(argv[++i]);
        } else if (arg == "--require-clean") {
            args.require_clean = true;
        }
    }
    return args;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        return run_probe(parse_args(argc, argv));
    } catch (const std::exception& e) {
        std::cerr << "udp_path_probe failed: " << e.what() << "\n";
        return 2;
    }
}
