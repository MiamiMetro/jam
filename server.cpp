#include <algorithm>
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
#include <vector>

#include <asio.hpp>
#include <asio/buffer.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <concurrentqueue.h>
#include <opus.h>
#include <spdlog/common.h>

#include "logger.h"
#include "periodic_timer.h"
#include "protocol.h"

using asio::ip::udp;
using namespace std::chrono_literals;

class Server {
public:
    Server(asio::io_context& io_context, short port)
        : socket_(io_context, udp::endpoint(udp::v4(), port)),
          alive_check_timer_(io_context, 5s, [this]() { alive_check_timer_callback(); }),
          broadcast_timer_(io_context, 5000us, [this]() { broadcast_timer_callback(); }) {
        do_receive();
        // Server encoder: sends stereo to clients (2 ch)
        // Complexity 2 matches Jamulus for lower CPU usage
        Log::info("Creating server encoder: 2ch (stereo), 48kHz, complexity=2");
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
        } else if (hdr.magic == ECHO_MAGIC) {
            handle_echo_message(bytes);
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
                Log::info("Client JOIN: {}:{}", remote_endpoint_.address().to_string(),
                          remote_endpoint_.port());
                clients_[remote_endpoint_].last_alive = now;
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

    void handle_echo_message(std::size_t bytes) {
        if (bytes < sizeof(EchoHdr) || !clients_.contains(remote_endpoint_)) {
            do_receive();
            return;
        }
        // Echo back the received message
        send(recv_buf_.data(), bytes, remote_endpoint_);
    }

    void handle_audio_message(std::size_t bytes) {
        if (bytes < sizeof(MsgHdr) + sizeof(uint16_t) || !clients_.contains(remote_endpoint_)) {
            do_receive();
            return;
        }

        // Read only the header fields we need
        uint16_t encoded_bytes;
        std::memcpy(&encoded_bytes, recv_buf_.data() + sizeof(MsgHdr), sizeof(uint16_t));

        // Verify we received all the data
        size_t expected_size = sizeof(MsgHdr) + sizeof(uint16_t) + encoded_bytes;
        if (bytes < expected_size) {
            Log::error("Incomplete audio packet: got {}, expected {}", bytes, expected_size);
            do_receive();
            return;
        }

        // Extract audio data (starts after magic + encoded_bytes field)
        const unsigned char* audio_data = reinterpret_cast<const unsigned char*>(
            recv_buf_.data() + sizeof(MsgHdr) + sizeof(uint16_t));

        std::vector<unsigned char> audio_data_vec(audio_data, audio_data + encoded_bytes);

        clients_[remote_endpoint_].push_audio_packet(audio_data_vec);
    }

    void alive_check_timer_callback() {
        auto now = std::chrono::steady_clock::now();
        for (auto it = clients_.begin(); it != clients_.end();) {
            if (now - it->second.last_alive > 15s) {
                Log::info("Client {}:{} timed out", it->first.address().to_string(),
                          it->first.port());
                it = clients_.erase(it);
            } else {
                ++it;
            }
        }
    }

    void send_audio_to_client(const udp::endpoint&              endpoint,
                              const std::vector<unsigned char>& encoded_audio) {
        if (encoded_audio.empty()) {
            return;
        }

        // Create audio packet header
        AudioHdr ahdr{};
        ahdr.magic         = AUDIO_MAGIC;
        ahdr.encoded_bytes = static_cast<uint16_t>(encoded_audio.size());

        // Copy encoded audio data to the header buffer
        size_t copy_size = std::min(encoded_audio.size(), sizeof(ahdr.buf));
        std::memcpy(ahdr.buf, encoded_audio.data(), copy_size);

        // Send the packet
        size_t packet_size = sizeof(MsgHdr) + sizeof(uint16_t) + ahdr.encoded_bytes;
        send(&ahdr, packet_size, endpoint);
    }

    void broadcast_timer_callback() {}

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
        std::chrono::steady_clock::time_point                   last_alive;
        moodycamel::ConcurrentQueue<std::vector<unsigned char>> audio_queue;

        void push_audio_packet(const std::vector<unsigned char>& packet) {
            if (audio_queue.size_approx() >= 16) {
                std::vector<unsigned char> discarded;
                audio_queue.try_dequeue(discarded);  // discard oldest
            }
            audio_queue.enqueue(packet);
        }
    };

    udp::socket socket_;

    std::unordered_map<udp::endpoint, ClientInfo, endpoint_hash> clients_;

    std::array<char, 1024> recv_buf_;
    udp::endpoint          remote_endpoint_;

    PeriodicTimer alive_check_timer_;
    PeriodicTimer broadcast_timer_;
};

int main() {
    try {
        auto& log = Logger::instance();
        log.init(true, false, false, "", spdlog::level::warn);

        asio::io_context io_context;
        Server           srv(io_context, 9999);

        log.info("Echo server listening on 127.0.0.1:9999");
        log.info("Broadcast timer running at 5ms intervals (48kHz, 240 frames)");

        // Just run the io_context - timers handle everything!
        io_context.run();
    } catch (std::exception& e) {
        Log::error("ERR: {}", e.what());
    }
}
