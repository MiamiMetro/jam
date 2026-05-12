#include <array>
#include <chrono>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

#include <asio.hpp>
#include <asio/ip/udp.hpp>

#include "audio_packet.h"
#include "protocol.h"

using asio::ip::udp;
using namespace std::chrono_literals;

template <size_t N>
void write_fixed(Bytes<N>& target, const std::string& value) {
    const size_t copy_bytes = std::min(value.size(), target.size() - 1);
    std::copy_n(value.data(), copy_bytes, target.data());
    target[copy_bytes] = '\0';
}

void send_join(udp::socket& socket, const udp::endpoint& server, const std::string& room,
               const std::string& user) {
    JoinHdr join{};
    join.magic = CTRL_MAGIC;
    join.type = CtrlHdr::Cmd::JOIN;
    write_fixed(join.room_id, room);
    write_fixed(join.room_handle, room);
    write_fixed(join.profile_id, user);
    write_fixed(join.display_name, user);
    socket.send_to(asio::buffer(&join, sizeof(join)), server);
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
    short server_port = 9999;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--server" && i + 1 < argc) {
            server_address = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            server_port = static_cast<short>(std::stoi(argv[++i]));
        }
    }

    asio::io_context io;
    udp::resolver resolver(io);
    const auto server =
        *resolver.resolve(udp::v4(), server_address, std::to_string(server_port)).begin();

    udp::socket accepted_sender(io, udp::endpoint(udp::v4(), 0));
    udp::socket accepted_receiver(io, udp::endpoint(udp::v4(), 0));
    udp::socket rejected_sender(io, udp::endpoint(udp::v4(), 0));

    send_join(accepted_sender, server, "room-a", "user-a1");
    send_join(accepted_receiver, server, "room-a", "user-a2");
    send_join(rejected_sender, server, "room-a", "user-a3");
    std::this_thread::sleep_for(100ms);

    std::array<unsigned char, 240> samples{};
    auto packet = audio_packet::create_audio_packet_v2(AudioCodec::PcmInt16, 1, 48000, 120, 1,
                                                       samples.data(), samples.size());

    accepted_sender.send_to(asio::buffer(packet->data(), packet->size()), server);
    const bool accepted_forwarded = receive_any_audio(accepted_receiver, 500ms);

    rejected_sender.send_to(asio::buffer(packet->data(), packet->size()), server);
    const bool rejected_forwarded = receive_any_audio(accepted_receiver, 250ms);

    std::cout << "accepted_forwarded=" << accepted_forwarded << "\n";
    std::cout << "rejected_forwarded=" << rejected_forwarded << "\n";

    if (!accepted_forwarded) {
        std::cerr << "accepted performer audio was not forwarded\n";
        return 2;
    }
    if (rejected_forwarded) {
        std::cerr << "rejected performer audio was forwarded\n";
        return 3;
    }
    return 0;
}
