#include <array>
#include <asio.hpp>
#include <iostream>
#include <map>

#include "periodic_timer.hpp"
#include "protocol.hpp"

using asio::ip::udp;
using namespace std::chrono_literals;

class server {
  private:
    udp::socket _socket;

    struct client_info {
        std::chrono::steady_clock::time_point last_alive;
    };

    std::map<udp::endpoint, client_info> _clients;
    periodic_timer _alive_check_timer;

  public:
    server(asio::io_context &io, short port)
        : _socket(io, udp::endpoint(udp::v4(), port)), _alive_check_timer(io, 5s, [this]() {
              auto now = std::chrono::steady_clock::now();
              for (auto it = _clients.begin(); it != _clients.end();) {
                  if (now - it->second.last_alive > 15s) {
                      std::cout << "Client " << it->first.address().to_string() << ":" << it->first.port()
                                << " timed out\n";
                      it = _clients.erase(it);
                  } else {
                      ++it;
                  }
              }
          }) {}

    void do_receive() {
        auto buf = std::make_shared<std::array<char, 1024>>();
        auto remote = std::make_shared<udp::endpoint>();

        _socket.async_receive_from(
            asio::buffer(*buf), *remote,
            [buf, remote, this](std::error_code ec, std::size_t bytes) { on_receive(ec, bytes, buf, remote); });
    }

    void on_receive(std::error_code ec, std::size_t bytes, std::shared_ptr<std::array<char, 1024>> buf,
                    std::shared_ptr<udp::endpoint> remote) {
        if (ec) {
            std::cerr << "receive error: " << ec.message() << "\n";
            do_receive(); // keep listening
            return;
        }

        // std::cout << "Got " << bytes << " bytes from " << remote->address().to_string() << ":" << remote->port()
        //           << " -> " << std::string(buf->data(), bytes) << "\n";

        if (bytes >= sizeof(MsgHdr)) {
            MsgHdr hdr{};
            std::memcpy(&hdr, buf->data(), sizeof(MsgHdr));

            if (hdr.magic == PING_MAGIC && bytes >= sizeof(SyncHdr)) {
                SyncHdr shdr{};
                std::memcpy(&shdr, buf->data(), sizeof(SyncHdr));
                auto now = std::chrono::steady_clock::now();
                auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
                shdr.t2_server_recv = ns;
                shdr.t3_server_send = ns;
                std::memcpy(buf->data(), &shdr, sizeof(SyncHdr));

                _socket.async_send_to(asio::buffer(*buf, bytes), *remote,
                                      [buf, remote](std::error_code ec, std::size_t) {
                                          if (ec)
                                              std::cerr << "send error: " << ec.message() << "\n";
                                      });
            }

            if (hdr.magic == CTRL_MAGIC && bytes >= sizeof(CtrlHdr)) {
                std::cout << "CTRL msg from " << remote->address().to_string() << ":" << remote->port() << "\n";

                CtrlHdr chdr{};
                std::memcpy(&chdr, buf->data(), sizeof(CtrlHdr));

                auto now = std::chrono::steady_clock::now();

                switch (chdr.type) {
                case CtrlHdr::Cmd::JOIN:
                    std::cout << "  JOIN\n";
                    _clients[*remote].last_alive = now;
                    break;
                case CtrlHdr::Cmd::LEAVE:
                    std::cout << "  LEAVE\n";
                    _clients.erase(*remote);
                    break;
                case CtrlHdr::Cmd::ALIVE:
                    std::cout << "  ALIVE\n";
                    _clients[*remote].last_alive = now;
                    break;
                default:
                    std::cout << "  Unknown CTRL cmd: " << static_cast<int>(chdr.type) << "\n";
                    break;
                }
            }
        }

        do_receive(); // start next receive immediately
    }
};

int main() {
    try {
        asio::io_context io;
        server srv(io, 9999);

        std::cout << "Echo server listening on 127.0.0.1:9999\n";
        srv.do_receive();
        io.run();
    } catch (std::exception &e) {
        std::cerr << "ERR: " << e.what() << "\n";
    }
}
