#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
#include <string_view>
#include <system_error>
#include <unordered_map>

#include <asio.hpp>
#include <asio/buffer.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <spdlog/common.h>

#include "logger.h"
#include "periodic_timer.h"
#include "protocol.h"

using asio::ip::udp;
using namespace std::chrono_literals;

class Server {
public:
    static constexpr auto   ALIVE_CHECK_INTERVAL = 5s;
    static constexpr auto   CLIENT_TIMEOUT       = 15s;
    static constexpr size_t RECV_BUF_SIZE        = 1024;

    Server(asio::io_context& io_context, short port)
        : socket_(io_context, udp::endpoint(udp::v4(), port)),
          alive_check_timer_(io_context, ALIVE_CHECK_INTERVAL,
                             [this]() { alive_check_timer_callback(); }) {
        do_receive();
        Log::info("SFU server ready: forwarding audio between clients");
    }

    ~Server() {
        socket_.close();
    }

    void do_receive() {
        socket_.async_receive_from(asio::buffer(recv_buf_), remote_endpoint_,
                                   [this](std::error_code error_code, std::size_t bytes) {
                                       on_receive(error_code, bytes);
                                   });
    }

    void on_receive(std::error_code error_code, std::size_t bytes) {
        if (error_code) {
            handle_receive_error(error_code);
            return;
        }

        if (bytes < sizeof(MsgHdr)) {
            do_receive();
            return;
        }

        MsgHdr hdr{};
        std::memcpy(&hdr, recv_buf_.data(), sizeof(MsgHdr));

        if (hdr.magic == PING_MAGIC) {
            handle_ping_message(bytes);
        } else if (hdr.magic == CTRL_MAGIC) {
            handle_ctrl_message(bytes);
        } else if (hdr.magic == AUDIO_MAGIC) {
            handle_audio_message(bytes);
        }

        do_receive();  // start next receive immediately
    }

    void send(void* data, std::size_t len, const udp::endpoint& target) {
        socket_.async_send_to(asio::buffer(data, len), target,
                              [](std::error_code error_code, std::size_t) {
                                  if (error_code) {
                                      Log::error("send error: {}", error_code.message());
                                  }
                              });
    }

private:
    void handle_receive_error(std::error_code error_code) {
        Log::error("receive error: {}", error_code.message());
        clients_.erase(remote_endpoint_);
        Log::info("Client {}:{} removed due to receive error",
                  remote_endpoint_.address().to_string(), remote_endpoint_.port());
        do_receive();  // keep listening
    }

    void handle_ping_message(std::size_t bytes) {
        if (bytes < sizeof(SyncHdr) || !clients_.contains(remote_endpoint_)) {
            do_receive();
            return;
        }

        SyncHdr shdr{};
        std::memcpy(&shdr, recv_buf_.data(), sizeof(SyncHdr));
        auto now = std::chrono::steady_clock::now();
        auto nanoseconds =
            std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        shdr.t2_server_recv = nanoseconds;
        shdr.t3_server_send = nanoseconds;
        std::memcpy(recv_buf_.data(), &shdr, sizeof(SyncHdr));

        send(recv_buf_.data(), sizeof(SyncHdr), remote_endpoint_);
    }

    void handle_ctrl_message(std::size_t bytes) {
        if (bytes < sizeof(CtrlHdr)) {
            do_receive();
            return;
        }

        CtrlHdr chdr{};
        std::memcpy(&chdr, recv_buf_.data(), sizeof(CtrlHdr));

        auto now = std::chrono::steady_clock::now();

        switch (chdr.type) {
            case CtrlHdr::Cmd::JOIN:
                Log::info("Client JOIN: {}:{} (ID: {})", remote_endpoint_.address().to_string(),
                          remote_endpoint_.port(), next_client_id_);
                clients_[remote_endpoint_].last_alive = now;
                clients_[remote_endpoint_].client_id  = next_client_id_++;
                break;
            case CtrlHdr::Cmd::LEAVE:
                Log::info("Client LEAVE: {}:{}", remote_endpoint_.address().to_string(),
                          remote_endpoint_.port());
                clients_.erase(remote_endpoint_);
                break;
            case CtrlHdr::Cmd::ALIVE:
                clients_[remote_endpoint_].last_alive = now;
                break;
            default:
                Log::warn("Unknown CTRL cmd: {} from {}:{}", static_cast<int>(chdr.type),
                          remote_endpoint_.address().to_string(), remote_endpoint_.port());
                break;
        }
    }

    void handle_audio_message(std::size_t bytes) {
        if (bytes < sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t) ||
            !clients_.contains(remote_endpoint_)) {
            do_receive();
            return;
        }

        // Get sender's client ID
        uint32_t sender_id = clients_[remote_endpoint_].client_id;

        // Read encoded_bytes (after sender_id field)
        uint16_t encoded_bytes;
        std::memcpy(&encoded_bytes, recv_buf_.data() + sizeof(MsgHdr) + sizeof(uint32_t),
                    sizeof(uint16_t));

        // Verify we received all the data
        size_t expected_size = sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t) + encoded_bytes;
        if (bytes < expected_size) {
            Log::error("Incomplete audio packet: got {}, expected {} (encoded_bytes={})", bytes,
                       expected_size, encoded_bytes);
            do_receive();
            return;
        }

        // Additional safety check: ensure encoded_bytes is reasonable
        if (encoded_bytes > AUDIO_BUF_SIZE) {
            Log::error("Invalid audio packet: encoded_bytes {} exceeds max {}", encoded_bytes,
                       AUDIO_BUF_SIZE);
            do_receive();
            return;
        }

        // Embed sender_id in the packet (client may not have sent it, or we override it)
        std::memcpy(recv_buf_.data() + sizeof(MsgHdr), &sender_id, sizeof(uint32_t));

        // SFU: Forward audio packet to all other clients (not back to sender)
        forward_audio_to_others(remote_endpoint_, recv_buf_.data(), bytes);
    }

    void alive_check_timer_callback() {
        auto now = std::chrono::steady_clock::now();
        for (auto it = clients_.begin(); it != clients_.end();) {
            if (now - it->second.last_alive > CLIENT_TIMEOUT) {
                Log::info("Client {}:{} timed out", it->first.address().to_string(),
                          it->first.port());
                it = clients_.erase(it);
            } else {
                ++it;
            }
        }
    }

    void forward_audio_to_others(const udp::endpoint& sender, void* packet_data,
                                 std::size_t packet_size) {
        // Forward the audio packet to all clients except the sender
        for (const auto& [endpoint, client_info]: clients_) {
            if (endpoint != sender) {
                send(packet_data, packet_size, endpoint);
            }
        }
    }

    struct endpoint_hash {
        size_t operator()(const udp::endpoint& endpoint) const {
            // Avoid string allocations - hash IP bytes + port directly
            size_t address_hash = 0;
            if (endpoint.address().is_v4()) {
                address_hash = std::hash<uint32_t>{}(endpoint.address().to_v4().to_uint());
            } else {
                auto bytes   = endpoint.address().to_v6().to_bytes();
                address_hash = std::hash<std::string_view>{}(
                    std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
            }
            size_t port_hash = std::hash<unsigned short>{}(endpoint.port());
            return address_hash ^ (port_hash << 1);  // Combine hashes
        }
    };

    struct ClientInfo {
        std::chrono::steady_clock::time_point last_alive;
        uint32_t                               client_id;  // Unique ID for this client
    };

    udp::socket socket_;

    std::unordered_map<udp::endpoint, ClientInfo, endpoint_hash> clients_;
    uint32_t                                                     next_client_id_ = 1;  // Start from 1, 0 is invalid

    std::array<char, RECV_BUF_SIZE> recv_buf_;
    udp::endpoint                   remote_endpoint_;

    PeriodicTimer alive_check_timer_;
};

int main() {
    try {
        constexpr short SERVER_PORT = 9999;

        auto& log = Logger::instance();
        log.init(true, false, false, "", spdlog::level::debug);

        asio::io_context io_context;
        Server           srv(io_context, SERVER_PORT);

        log.info("SFU server listening on 127.0.0.1:{}", SERVER_PORT);
        log.info("Forwarding audio packets between clients");

        io_context.run();
    } catch (std::exception& e) {
        Log::error("ERR: {}", e.what());
    }
}
