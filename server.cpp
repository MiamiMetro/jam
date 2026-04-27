#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

#include <asio.hpp>
#include <asio/buffer.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <spdlog/common.h>

#include "client_manager.h"
#include "logger.h"
#include "message_validator.h"
#include "packet_builder.h"
#include "periodic_timer.h"
#include "protocol.h"
#include "server_config.h"

using asio::ip::udp;
using namespace std::chrono_literals;
using namespace server_config;

class Server {
public:
    Server(asio::io_context& io_context, short port)
        : socket_(io_context, udp::endpoint(udp::v4(), port)),
          alive_check_timer_(io_context, server_config::ALIVE_CHECK_INTERVAL,
                             [this]() { alive_check_timer_callback(); }) {
        // Optimize UDP socket buffers for high-throughput packet forwarding
        try {
            socket_.set_option(asio::socket_base::receive_buffer_size(131072));  // 128KB
            socket_.set_option(asio::socket_base::send_buffer_size(131072));     // 128KB
            Log::info("UDP socket buffers optimized for packet forwarding");
        } catch (const std::exception& e) {
            Log::warn("Failed to set socket buffer sizes: {}", e.what());
        }

        Log::info("SFU server ready: forwarding audio between clients");
        do_receive();
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

        if (!message_validator::has_valid_header(bytes)) {
            do_receive();
            return;
        }

        MsgHdr hdr{};
        std::memcpy(&hdr, recv_buf_.data(), sizeof(MsgHdr));

        if (hdr.magic == PING_MAGIC) {
            handle_ping_message(bytes);
        } else if (hdr.magic == CTRL_MAGIC) {
            handle_ctrl_message(bytes);
        } else if (hdr.magic == AUDIO_MAGIC || hdr.magic == AUDIO_V2_MAGIC) {
            handle_audio_message(bytes);
        }

        do_receive();  // start next receive immediately
    }

    // Send with optional shared_ptr to keep data alive during async operation
    void send(void* data, std::size_t len, const udp::endpoint& target,
              const std::shared_ptr<std::vector<unsigned char>>& keep_alive = nullptr) {
        socket_.async_send_to(asio::buffer(data, len), target,
                              [keep_alive](std::error_code error_code, std::size_t) {
                                  if (error_code) {
                                      Log::error("send error: {}", error_code.message());
                                  }
                                  // keep_alive keeps the data alive until send completes
                              });
    }

private:
    static std::string fixed_string(const char* data, size_t capacity) {
        size_t len = 0;
        while (len < capacity && data[len] != '\0') {
            ++len;
        }
        return std::string(data, len);
    }

    void handle_receive_error(std::error_code error_code) {
        Log::error("receive error: {}", error_code.message());
        client_manager_.remove_client(remote_endpoint_);
        Log::info("Client {}:{} removed due to receive error",
                  remote_endpoint_.address().to_string(), remote_endpoint_.port());
        do_receive();  // keep listening
    }

    void handle_ping_message(std::size_t bytes) {
        if (!message_validator::is_valid_ping(bytes) || !client_manager_.exists(remote_endpoint_)) {
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
            case CtrlHdr::Cmd::JOIN: {
                std::string room_id = "default";
                std::string room_handle;
                std::string user_id;
                std::string display_name;
                bool        has_join_token = false;
                if (bytes >= sizeof(JoinCtrlHdr)) {
                    JoinCtrlHdr join_hdr{};
                    std::memcpy(&join_hdr, recv_buf_.data(), sizeof(JoinCtrlHdr));
                    room_id        = fixed_string(join_hdr.room_id, ROOM_ID_SIZE);
                    room_handle    = fixed_string(join_hdr.room_handle, ROOM_HANDLE_SIZE);
                    user_id        = fixed_string(join_hdr.user_id, USER_ID_SIZE);
                    display_name   = fixed_string(join_hdr.display_name, DISPLAY_NAME_SIZE);
                    has_join_token = fixed_string(join_hdr.join_token, JOIN_TOKEN_SIZE).size() > 0;
                }
                uint32_t client_id =
                    client_manager_.register_client(remote_endpoint_, now, room_id, room_handle,
                                                    user_id, display_name, has_join_token);
                Log::info("Client JOIN: {}:{} (ID: {}, room: {}, user: {}, token: {})",
                          remote_endpoint_.address().to_string(), remote_endpoint_.port(),
                          client_id, room_id.empty() ? "default" : room_id,
                          display_name.empty() ? user_id : display_name,
                          has_join_token ? "present" : "missing");
                break;
            }
            case CtrlHdr::Cmd::LEAVE: {
                Log::info("Client LEAVE: {}:{}", remote_endpoint_.address().to_string(),
                          remote_endpoint_.port());
                std::string room_id = client_manager_.get_room_id(remote_endpoint_);
                uint32_t leaving_client_id = client_manager_.remove_client(remote_endpoint_);
                if (leaving_client_id > 0) {
                    broadcast_participant_leave(leaving_client_id, room_id);
                }
                break;
            }
            case CtrlHdr::Cmd::ALIVE: {
                client_manager_.update_alive(remote_endpoint_, now);
                break;
            }
            case CtrlHdr::Cmd::PARTICIPANT_LEAVE:
                // Clients shouldn't send this, only server broadcasts it
                Log::warn("Client sent PARTICIPANT_LEAVE (should only come from server)");
                break;
            default:
                Log::warn("Unknown CTRL cmd: {} from {}:{}", static_cast<int>(chdr.type),
                          remote_endpoint_.address().to_string(), remote_endpoint_.port());
                break;
        }
    }

    void handle_audio_message(std::size_t bytes) {
        MsgHdr hdr{};
        std::memcpy(&hdr, recv_buf_.data(), sizeof(MsgHdr));

        const size_t min_audio_packet_size =
            hdr.magic == AUDIO_V2_MAGIC ? sizeof(AudioHdrV2) - AUDIO_BUF_SIZE
                                        : sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t);
        if (!message_validator::is_valid_audio_packet(bytes, min_audio_packet_size)) {
            Log::debug("Audio packet too small: {} bytes", bytes);
            do_receive();
            return;
        }

        // Auto-register client if not known
        if (!client_manager_.exists(remote_endpoint_)) {
            auto     now       = std::chrono::steady_clock::now();
            uint32_t client_id = client_manager_.register_client(remote_endpoint_, now);
            Log::info("Auto-registering client from audio packet: {}:{} (ID: {})",
                      remote_endpoint_.address().to_string(), remote_endpoint_.port(), client_id);
        }

        // Get sender's client ID
        uint32_t sender_id = client_manager_.get_client_id(remote_endpoint_);

        // Embed sender_id in the packet
        packet_builder::embed_sender_id(reinterpret_cast<unsigned char*>(recv_buf_.data()),
                                        sender_id);

        // SFU: Forward audio packet to all other clients (not back to sender)
        // Copy packet data before forwarding since recv_buf_ will be reused by do_receive()
        auto packet_copy = std::make_shared<std::vector<unsigned char>>(recv_buf_.data(),
                                                                        recv_buf_.data() + bytes);
        forward_audio_to_others(remote_endpoint_, packet_copy->data(), bytes, packet_copy);
    }

    void alive_check_timer_callback() {
        auto now = std::chrono::steady_clock::now();
        auto timed_out_clients =
            client_manager_.remove_timed_out_clients(now, server_config::CLIENT_TIMEOUT);

        for (const auto& timed_out: timed_out_clients) {
            Log::info("Client timed out (ID: {})", timed_out.client_id);
            broadcast_participant_leave(timed_out.client_id, timed_out.room_id);
        }
    }

    void broadcast_participant_leave(uint32_t participant_id, const std::string& room_id) {
        // Broadcast to all clients that a participant has left
        auto buf = packet_builder::create_participant_leave_packet(participant_id);

        // Get endpoints from manager (safe copy)
        auto endpoints = client_manager_.get_room_endpoints(room_id.empty() ? "default" : room_id);

        for (const auto& endpoint: endpoints) {
            send(buf->data(), sizeof(CtrlHdr), endpoint, buf);
        }
    }

    void forward_audio_to_others(
        const udp::endpoint& sender, void* packet_data, std::size_t packet_size,
        const std::shared_ptr<std::vector<unsigned char>>& keep_alive = nullptr) {
        // Forward the audio packet to all clients except the sender
        // keep_alive ensures packet data remains valid during async sends

        // Get endpoints from manager (safe copy, excluding sender)
        auto endpoints = client_manager_.get_room_endpoints_except(sender);

        for (const auto& endpoint: endpoints) {
            send(packet_data, packet_size, endpoint, keep_alive);
        }
    }

    udp::socket socket_;

    ClientManager client_manager_;

    std::array<char, server_config::RECV_BUF_SIZE> recv_buf_;
    udp::endpoint                                  remote_endpoint_;

    PeriodicTimer alive_check_timer_;
};

int main(int argc, char** argv) {
    try {
        asio::io_context io_context;
        short            server_port = 9999;
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if ((arg == "--port" || arg == "-p") && i + 1 < argc) {
                server_port = static_cast<short>(std::stoi(argv[++i]));
            } else if (arg.rfind("--port=", 0) == 0) {
                server_port = static_cast<short>(std::stoi(arg.substr(7)));
            }
        }

        auto& log = Logger::instance();
        log.init(true, false, false, "", spdlog::level::info);

        Log::info("Starting SFU server on 0.0.0.0:{}", server_port);
        Log::info("Forwarding audio packets between clients");

        Server server(io_context, server_port);

        io_context.run();
    } catch (std::exception& e) {
        Log::error("ERR: {}", e.what());
    }
}
