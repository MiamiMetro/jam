#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <exception>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include <asio.hpp>
#include <asio/ip/udp.hpp>
#include <opus_defines.h>

#include "audio_packet.h"
#include "opus_encoder.h"
#include "packet_builder.h"
#include "performer_join_token.h"
#include "protocol.h"

using asio::ip::udp;
using namespace std::chrono_literals;

namespace {

[[noreturn]] void usage(const std::string& reason) {
    throw std::runtime_error(
        reason +
        "\nUsage: listener_audio_sender_probe [--server host] [--port port] "
        "[--server-id id] [--secret secret] [--room room] [--profile profile] "
        "[--duration-ms ms] [--malformed-v2]\n");
}

std::string make_token(const std::string& secret, const std::string& server_id,
                       const std::string& room, const std::string& profile) {
    if (secret.empty()) {
        return "";
    }
    performer_join_token::Claims claims;
    claims.expires_at_ms = performer_join_token::now_ms() + 120000;
    claims.server_id = server_id;
    claims.room_id = room;
    claims.profile_id = profile;
    claims.role = "performer";
    claims.nonce = performer_join_token::random_nonce();
    return performer_join_token::create(claims, secret);
}

void send_join(udp::socket& socket, const udp::endpoint& server, const std::string& room,
               const std::string& profile, const std::string& token) {
    JoinHdr join{};
    join.magic = CTRL_MAGIC;
    join.type = CtrlHdr::Cmd::JOIN;
    join.role = ClientRole::Performer;
    packet_builder::write_fixed(join.room_id, room);
    packet_builder::write_fixed(join.room_handle, room);
    packet_builder::write_fixed(join.profile_id, profile);
    packet_builder::write_fixed(join.display_name, profile);
    packet_builder::write_fixed(join.join_token, token);
    socket.send_to(asio::buffer(&join, sizeof(join)), server);
}

void send_leave(udp::socket& socket, const udp::endpoint& server) {
    CtrlHdr leave{};
    leave.magic = CTRL_MAGIC;
    leave.type = CtrlHdr::Cmd::LEAVE;
    socket.send_to(asio::buffer(&leave, sizeof(leave)), server);
}

}  // namespace

int main(int argc, char** argv) {
    try {
        std::string server_address = "127.0.0.1";
        short       server_port = 9999;
        std::string server_id = "local-dev";
        std::string secret;
        std::string room = "room-a";
        std::string profile = "probe-performer";
        int         duration_ms = 1500;
        bool        malformed_v2 = false;

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            auto require_value = [&](const std::string& name) -> std::string {
                if (i + 1 >= argc) {
                    usage(name + " requires a value");
                }
                return argv[++i];
            };

            if (arg == "--server") {
                server_address = require_value(arg);
            } else if (arg == "--port") {
                server_port = static_cast<short>(std::stoi(require_value(arg)));
            } else if (arg == "--server-id") {
                server_id = require_value(arg);
            } else if (arg == "--secret") {
                secret = require_value(arg);
            } else if (arg == "--room") {
                room = require_value(arg);
            } else if (arg == "--profile") {
                profile = require_value(arg);
            } else if (arg == "--duration-ms") {
                duration_ms = std::stoi(require_value(arg));
            } else if (arg == "--malformed-v2") {
                malformed_v2 = true;
            } else {
                usage("Unknown argument: " + arg);
            }
        }

        asio::io_context io;
        udp::resolver    resolver(io);
        const auto server =
            *resolver.resolve(udp::v4(), server_address, std::to_string(server_port)).begin();
        udp::socket socket(io, udp::endpoint(udp::v4(), 0));

        send_join(socket, server, room, profile, make_token(secret, server_id, room, profile));
        std::this_thread::sleep_for(100ms);

        if (malformed_v2) {
            AudioHdrV2 hdr{};
            hdr.magic = AUDIO_V2_MAGIC;
            hdr.sender_id = 0;
            hdr.sequence = 1;
            hdr.sample_rate = 48000;
            hdr.frame_count = 240;
            hdr.payload_bytes = AUDIO_BUF_SIZE + 1;
            hdr.channels = 1;
            hdr.codec = AudioCodec::Opus;
            socket.send_to(asio::buffer(&hdr, sizeof(AudioHdrV2) - AUDIO_BUF_SIZE), server);
            std::this_thread::sleep_for(100ms);
            send_leave(socket, server);
            std::cout << "sent_malformed_v2=1\n";
            return 0;
        }

        OpusEncoderWrapper encoder;
        if (!encoder.create(48000, 1, OPUS_APPLICATION_RESTRICTED_LOWDELAY, 64000, 5)) {
            throw std::runtime_error("failed to create Opus encoder");
        }

        constexpr int frame_count = 240;
        constexpr float frequency_hz = 440.0F;
        constexpr float sample_rate = 48000.0F;
        std::array<float, frame_count> pcm{};
        std::vector<unsigned char>     encoded;
        uint32_t                       sequence = 1;
        int                            packets_sent = 0;
        float                          phase = 0.0F;
        const float phase_step = (2.0F * 3.14159265358979323846F * frequency_hz) / sample_rate;

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(duration_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            for (float& sample: pcm) {
                sample = std::sin(phase) * 0.10F;
                phase += phase_step;
                if (phase > 2.0F * 3.14159265358979323846F) {
                    phase -= 2.0F * 3.14159265358979323846F;
                }
            }
            if (!encoder.encode(pcm.data(), frame_count, encoded)) {
                throw std::runtime_error("Opus encode failed");
            }

            auto packet = audio_packet::create_audio_packet_v2(
                AudioCodec::Opus, sequence++, 48000, frame_count, 1, encoded.data(),
                static_cast<uint16_t>(encoded.size()));
            socket.send_to(asio::buffer(packet->data(), packet->size()), server);
            ++packets_sent;
            std::this_thread::sleep_for(5ms);
        }

        send_leave(socket, server);
        std::cout << "packets_sent=" << packets_sent << "\n";
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }

    return 0;
}
