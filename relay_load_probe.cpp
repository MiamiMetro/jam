#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <asio.hpp>
#include <asio/ip/udp.hpp>

#include "audio_packet.h"
#include "packet_builder.h"
#include "protocol.h"
#include "udp_port.h"

using asio::ip::udp;
using clock_type = std::chrono::steady_clock;
using namespace std::chrono_literals;

namespace {

constexpr int SAMPLE_RATE = 48000;
constexpr size_t RECV_BYTES = 2048;

struct Config {
    std::string host = "127.0.0.1";
    uint16_t port = 9999;
    int clients = 16;
    int senders = 8;
    int seconds = 30;
    int frames = 120;
    double min_delivery_ratio = 0.98;
    double max_recv_gap_ms = 250.0;
};

struct ClientSocket {
    explicit ClientSocket(asio::io_context& io_context)
        : socket(io_context, udp::endpoint(udp::v4(), 0)) {
        std::error_code ec;
        socket.set_option(asio::socket_base::receive_buffer_size(UDP_SOCKET_BUFFER_BYTES), ec);
        socket.set_option(asio::socket_base::send_buffer_size(UDP_SOCKET_BUFFER_BYTES), ec);
        socket.non_blocking(true, ec);
    }

    udp::socket socket;
    std::array<unsigned char, RECV_BYTES> buffer{};
    uint64_t received_forwards = 0;
};

Config parse_args(int argc, char** argv) {
    Config config;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if ((arg == "--server" || arg == "--host") && i + 1 < argc) {
            config.host = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            config.port = parse_udp_port(argv[++i], "--port");
        } else if (arg == "--clients" && i + 1 < argc) {
            config.clients = std::stoi(argv[++i]);
        } else if (arg == "--senders" && i + 1 < argc) {
            config.senders = std::stoi(argv[++i]);
        } else if (arg == "--seconds" && i + 1 < argc) {
            config.seconds = std::stoi(argv[++i]);
        } else if (arg == "--frames" && i + 1 < argc) {
            config.frames = std::stoi(argv[++i]);
        } else if (arg == "--min-delivery-ratio" && i + 1 < argc) {
            config.min_delivery_ratio = std::stod(argv[++i]);
        } else if (arg == "--max-recv-gap-ms" && i + 1 < argc) {
            config.max_recv_gap_ms = std::stod(argv[++i]);
        } else if (arg == "--help" || arg == "-h") {
            std::cout
                << "Usage: relay_load_probe --server <host> --port <port> "
                   "[--clients N] [--senders N] [--seconds N] [--frames N] "
                   "[--min-delivery-ratio R] [--max-recv-gap-ms MS]\n";
            std::exit(0);
        } else {
            throw std::runtime_error("unknown or incomplete argument: " + arg);
        }
    }

    config.clients = std::clamp(config.clients, 2, 64);
    config.senders = std::clamp(config.senders, 1, config.clients);
    config.seconds = std::max(1, config.seconds);
    config.frames = std::clamp(config.frames, 60, 1920);
    config.min_delivery_ratio = std::clamp(config.min_delivery_ratio, 0.0, 1.0);
    config.max_recv_gap_ms = std::max(1.0, config.max_recv_gap_ms);
    return config;
}

void send_join(ClientSocket& client, const udp::endpoint& server, int index) {
    JoinHdr hdr{};
    hdr.magic = CTRL_MAGIC;
    hdr.type = CtrlHdr::Cmd::JOIN;
    hdr.capabilities = AUDIO_SUPPORTED_CAPABILITIES;
    packet_builder::write_fixed(hdr.room_id, "phase5-load");
    packet_builder::write_fixed(hdr.room_handle, "phase5-load");
    const std::string user = "relay-load-" + std::to_string(index);
    packet_builder::write_fixed(hdr.profile_id, user);
    packet_builder::write_fixed(hdr.display_name, user);
    client.socket.send_to(asio::buffer(&hdr, sizeof(hdr)), server);
}

void send_alive(ClientSocket& client, const udp::endpoint& server) {
    CtrlHdr hdr{};
    hdr.magic = CTRL_MAGIC;
    hdr.type = CtrlHdr::Cmd::ALIVE;
    client.socket.send_to(asio::buffer(&hdr, sizeof(hdr)), server);
}

bool is_audio_datagram(const unsigned char* data, size_t bytes) {
    if (bytes < sizeof(MsgHdr)) {
        return false;
    }
    MsgHdr hdr{};
    std::memcpy(&hdr, data, sizeof(hdr));
    return hdr.magic == AUDIO_V2_MAGIC || hdr.magic == AUDIO_V3_MAGIC ||
           hdr.magic == AUDIO_REDUNDANT_MAGIC || hdr.magic == AUDIO_MAGIC;
}

bool send_audio(ClientSocket& client, const udp::endpoint& server, int sender_index,
                uint32_t sequence, int frames) {
    std::array<unsigned char, 12> payload{};
    payload[0] = static_cast<unsigned char>(sender_index & 0xFF);
    std::memcpy(payload.data() + 1, &sequence, sizeof(sequence));
    auto packet = audio_packet::create_audio_packet_v2(
        AudioCodec::Opus, sequence, SAMPLE_RATE, static_cast<uint16_t>(frames),
        1, payload.data(), static_cast<uint16_t>(payload.size()));
    if (packet == nullptr) {
        return false;
    }
    std::error_code ec;
    client.socket.send_to(asio::buffer(packet->data(), packet->size()), server, 0, ec);
    return !ec;
}

uint64_t drain_receives(std::vector<std::unique_ptr<ClientSocket>>& clients,
                        clock_type::time_point& last_receive,
                        double& max_receive_gap_ms) {
    uint64_t received = 0;
    for (auto& client: clients) {
        for (;;) {
            udp::endpoint sender;
            std::error_code ec;
            const size_t bytes =
                client->socket.receive_from(asio::buffer(client->buffer), sender, 0, ec);
            if (ec == asio::error::would_block || ec == asio::error::try_again) {
                break;
            }
            if (ec) {
                break;
            }
            if (!is_audio_datagram(client->buffer.data(), bytes)) {
                continue;
            }
            const auto now = clock_type::now();
            if (last_receive.time_since_epoch().count() != 0) {
                const double gap_ms =
                    static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(
                                            now - last_receive)
                                            .count()) /
                    1000.0;
                max_receive_gap_ms = std::max(max_receive_gap_ms, gap_ms);
            }
            last_receive = now;
            ++client->received_forwards;
            ++received;
        }
    }
    return received;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const Config config = parse_args(argc, argv);
        asio::io_context io_context;
        udp::resolver resolver(io_context);
        const udp::endpoint server =
            *resolver.resolve(udp::v4(), config.host, std::to_string(config.port)).begin();

        std::vector<std::unique_ptr<ClientSocket>> clients;
        clients.reserve(static_cast<size_t>(config.clients));
        for (int i = 0; i < config.clients; ++i) {
            clients.push_back(std::make_unique<ClientSocket>(io_context));
            send_join(*clients.back(), server, i);
        }
        std::this_thread::sleep_for(300ms);

        const auto frame_duration = std::chrono::duration_cast<clock_type::duration>(
            std::chrono::duration<double>(static_cast<double>(config.frames) /
                                          static_cast<double>(SAMPLE_RATE)));
        const int packets_per_sender =
            std::max(1, static_cast<int>((static_cast<int64_t>(config.seconds) * SAMPLE_RATE) /
                                         config.frames));
        const auto start = clock_type::now() + 100ms;
        const auto send_end = start + frame_duration * packets_per_sender;
        const auto drain_end = send_end + 1000ms;
        std::vector<int> next_sequence(static_cast<size_t>(config.senders), 0);
        uint64_t sent_packets = 0;
        uint64_t received_forwards = 0;
        auto next_alive = clock_type::now() + 1s;
        clock_type::time_point last_receive{};
        double max_receive_gap_ms = 0.0;

        while (clock_type::now() < drain_end) {
            const auto now = clock_type::now();
            if (now >= next_alive) {
                for (auto& client: clients) {
                    send_alive(*client, server);
                }
                next_alive += 1s;
            }

            if (now < send_end) {
                for (int sender = 0; sender < config.senders; ++sender) {
                    while (next_sequence[static_cast<size_t>(sender)] < packets_per_sender) {
                        const int seq = next_sequence[static_cast<size_t>(sender)];
                        if (start + frame_duration * seq > now) {
                            break;
                        }
                        if (send_audio(*clients[static_cast<size_t>(sender)], server, sender,
                                       static_cast<uint32_t>(seq), config.frames)) {
                            ++sent_packets;
                        }
                        ++next_sequence[static_cast<size_t>(sender)];
                    }
                }
            }

            received_forwards +=
                drain_receives(clients, last_receive, max_receive_gap_ms);
            std::this_thread::sleep_for(250us);
        }
        received_forwards += drain_receives(clients, last_receive, max_receive_gap_ms);

        const uint64_t expected_forwards =
            sent_packets * static_cast<uint64_t>(config.clients - 1);
        const double delivery_ratio =
            expected_forwards > 0
                ? static_cast<double>(received_forwards) /
                      static_cast<double>(expected_forwards)
                : 0.0;
        const double send_pps =
            static_cast<double>(sent_packets) / static_cast<double>(config.seconds);
        const double forward_pps =
            static_cast<double>(received_forwards) / static_cast<double>(config.seconds);
        const bool ok = delivery_ratio >= config.min_delivery_ratio &&
                        max_receive_gap_ms <= config.max_recv_gap_ms;

        std::cout << "relay_load_probe v1\n";
        std::cout << "clients: " << config.clients << "\n";
        std::cout << "senders: " << config.senders << "\n";
        std::cout << "frames: " << config.frames << "\n";
        std::cout << "seconds: " << config.seconds << "\n";
        std::cout << "sent_packets: " << sent_packets << "\n";
        std::cout << "expected_forwards: " << expected_forwards << "\n";
        std::cout << "received_forwards: " << received_forwards << "\n";
        std::cout << "delivery_ratio: " << delivery_ratio << "\n";
        std::cout << "send_packets_per_second: " << send_pps << "\n";
        std::cout << "forward_packets_per_second: " << forward_pps << "\n";
        std::cout << "max_receive_gap_ms: " << max_receive_gap_ms << "\n";
        std::cout << "status: " << (ok ? "ok" : "fail") << "\n";

        return ok ? 0 : 2;
    } catch (const std::exception& e) {
        std::cerr << "relay_load_probe failed: " << e.what() << "\n";
        return 1;
    }
}
