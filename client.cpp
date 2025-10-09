#include <array>
#include <asio.hpp>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <unordered_map>

#include "periodic_timer.hpp"
#include "protocol.hpp"

using asio::ip::udp;
using namespace std::chrono_literals;

class client {
  private:
    udp::socket _socket;
    udp::endpoint _server_endpoint;

    std::array<char, 1024> _recv_buf;
    std::array<unsigned char, 1024> _sync_tx_buf;
    std::array<unsigned char, 1024> _ctrl_tx_buf;

    periodic_timer _ping_timer;
    periodic_timer _alive_timer;

  public:
    client(asio::io_context &io, const std::string &server_ip, short server_port)
        : _socket(io, udp::endpoint(udp::v4(), 0)),
          _ping_timer(io, 100ms,
                      [this]() {
                          static uint32_t seq = 0;
                          SyncHdr shdr{};
                          shdr.magic = PING_MAGIC;
                          shdr.seq = seq++;
                          auto now = std::chrono::steady_clock::now();
                          shdr.t1_client_send =
                              std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
                          std::memcpy(_sync_tx_buf.data(), &shdr, sizeof(SyncHdr));
                          send(_sync_tx_buf.data(), sizeof(SyncHdr));
                      }),
          _alive_timer(io, 5s, [this]() {
              CtrlHdr chdr{};
              chdr.magic = CTRL_MAGIC;
              chdr.type = CtrlHdr::Cmd::ALIVE;
              std::memcpy(_ctrl_tx_buf.data(), &chdr, sizeof(CtrlHdr));
              send(_ctrl_tx_buf.data(), sizeof(CtrlHdr));
          }) {

        std::cout << "Client local port: " << _socket.local_endpoint().port() << "\n";
        _server_endpoint = udp::endpoint(asio::ip::make_address(server_ip), server_port);

        CtrlHdr chdr{};
        chdr.magic = CTRL_MAGIC;
        chdr.type = CtrlHdr::Cmd::JOIN;
        std::memcpy(_ctrl_tx_buf.data(), &chdr, sizeof(CtrlHdr));
        send(_ctrl_tx_buf.data(), sizeof(CtrlHdr));

        do_receive();
    }

    void on_receive(std::error_code ec, std::size_t bytes) {
        if (ec) {
            std::cerr << "receive error: " << ec.message() << "\n";
            do_receive(); // keep listening
            return;
        }

        if (bytes >= sizeof(MsgHdr)) {
            MsgHdr hdr{};
            std::memcpy(&hdr, _recv_buf.data(), sizeof(MsgHdr));

            if (hdr.magic == PING_MAGIC && bytes >= sizeof(SyncHdr)) {
                SyncHdr hdr{};
                std::memcpy(&hdr, _recv_buf.data(), sizeof(SyncHdr));

                auto now = std::chrono::steady_clock::now();
                auto t4 = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
                auto rtt = (t4 - hdr.t1_client_send) - (hdr.t3_server_send - hdr.t2_server_recv);
                auto offset = ((hdr.t2_server_recv - hdr.t1_client_send) + (hdr.t3_server_send - t4)) / 2;

                double rtt_ms = rtt / 1e6;
                double offset_ms = offset / 1e6;

                // print live stats
                std::cout << "seq " << hdr.seq << " RTT " << rtt_ms << " ms"
                          << " | offset " << offset_ms << " ms" << std::string(20, ' ') << "\r" << std::flush;
            } else {
                std::cout << "Unknown message: " << std::string(_recv_buf.data(), bytes) << "\n";
            }
        }

        do_receive(); // keep listening
    }

    void do_receive() {
        _socket.async_receive_from(asio::buffer(_recv_buf), _server_endpoint,
                                   [this](std::error_code ec, std::size_t bytes) { on_receive(ec, bytes); });
    }

    void send(void *data, std::size_t len) {
        _socket.async_send_to(asio::buffer(data, len), _server_endpoint, [](std::error_code ec, std::size_t) {
            if (ec)
                std::cerr << "send error: " << ec.message() << "\n";
        });
    }
};

int main() {
    try {
        asio::io_context io;
        client cl(io, "127.0.0.1", 9999);
        io.run();
    } catch (std::exception &e) {
        std::cerr << "ERR: " << e.what() << "\n";
    }
}