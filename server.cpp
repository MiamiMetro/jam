#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <vector>

#include <asio.hpp>
#include <asio/buffer.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <spdlog/common.h>
#include <srt.h>

#include "logger.h"
#include "opus_decoder.h"
#include "periodic_timer.h"
#include "protocol.h"
#include "srt_client.h"

#include "audio_constants.h"
#include "audio_processor.h"
#include "broadcast_manager.h"
#include "client_info.h"
#include "client_manager.h"
#include "message_validator.h"
#include "packet_builder.h"
#include "server_config.h"

using asio::ip::udp;
using namespace std::chrono_literals;
using namespace audio_constants;
using namespace server_config;

class Server {
public:
    Server(asio::io_context& io_context, short port, const std::string& srt_host = "127.0.0.1",
           int srt_port = 9000, bool broadcast_enabled = false)
        : socket_(io_context, udp::endpoint(udp::v4(), port)),
          alive_check_timer_(io_context, server_config::ALIVE_CHECK_INTERVAL,
                             [this]() { alive_check_timer_callback(); }),
          mix_timer_(io_context, server_config::MIX_INTERVAL,
                     [this]() { mix_and_send_timer_callback(); }),
          broadcast_manager_(io_context, srt_host, srt_port, broadcast_enabled) {
        if (broadcast_enabled) {
            // Try to enable broadcasting
            if (broadcast_manager_.enable()) {
                Log::info("SFU server ready: decoding, mixing, and broadcasting audio via SRT");
            }
        } else {
            Log::info("SFU server ready: forwarding audio between clients (broadcasting disabled)");
        }
        Log::info("Mix timer initialized ({}ms interval)",
                  std::chrono::duration_cast<std::chrono::milliseconds>(server_config::MIX_INTERVAL)
                      .count());
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
        } else if (hdr.magic == AUDIO_MAGIC) {
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
                uint32_t client_id = client_manager_.register_client(remote_endpoint_, now);
                Log::info("Client JOIN: {}:{} (ID: {})", remote_endpoint_.address().to_string(),
                          remote_endpoint_.port(), client_id);
                break;
            }
            case CtrlHdr::Cmd::LEAVE: {
                Log::info("Client LEAVE: {}:{}", remote_endpoint_.address().to_string(),
                          remote_endpoint_.port());
                uint32_t leaving_client_id = client_manager_.remove_client(remote_endpoint_);
                // Broadcast participant leave to all other clients
                if (leaving_client_id > 0) {
                    broadcast_participant_leave(leaving_client_id);
                }
                // Check if no participants left and disable broadcast
                if (client_manager_.empty() && broadcast_manager_.is_enabled()) {
                    Log::info("No participants left, disabling broadcast");
                    broadcast_manager_.disable();
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
            case CtrlHdr::Cmd::BROADCAST_ENABLE: {
                Log::info("Client {}:{} requested broadcast enable",
                          remote_endpoint_.address().to_string(), remote_endpoint_.port());
                broadcast_manager_.enable();
                break;
            }
            case CtrlHdr::Cmd::BROADCAST_DISABLE: {
                Log::info("Client {}:{} requested broadcast disable",
                          remote_endpoint_.address().to_string(), remote_endpoint_.port());
                broadcast_manager_.disable();
                break;
            }
            default:
                Log::warn("Unknown CTRL cmd: {} from {}:{}", static_cast<int>(chdr.type),
                          remote_endpoint_.address().to_string(), remote_endpoint_.port());
                break;
        }
    }

    void handle_audio_message(std::size_t bytes) {
        // Minimum size check first (magic + sender_id + encoded_bytes)
        constexpr size_t MIN_AUDIO_PACKET_SIZE =
            sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t);
        if (!message_validator::is_valid_audio_packet(bytes, MIN_AUDIO_PACKET_SIZE)) {
            // Too small to even read the header - silently drop
            Log::debug("Audio packet too small: {} bytes", bytes);
            do_receive();
            return;
        }

        // Auto-register client if not known (handles case where server starts after clients)
        if (!client_manager_.exists(remote_endpoint_)) {
            auto     now       = std::chrono::steady_clock::now();
            uint32_t client_id = client_manager_.register_client(remote_endpoint_, now);
            Log::info("Auto-registering client from audio packet: {}:{} (ID: {})",
                      remote_endpoint_.address().to_string(), remote_endpoint_.port(), client_id);
            // Initialize decoder for new client
            client_manager_.with_client(remote_endpoint_, [](ClientInfo& client) {
                if (!client.decoder.is_initialized()) {
                    if (!client.decoder.create(SAMPLE_RATE, CHANNELS)) {
                        Log::error("Failed to create decoder");
                    } else {
                        Log::info("Created decoder for new client");
                    }
                }
            });
        }

        // Read encoded_bytes (after sender_id field)
        uint16_t encoded_bytes;
        std::memcpy(&encoded_bytes, recv_buf_.data() + sizeof(MsgHdr) + sizeof(uint32_t),
                    sizeof(uint16_t));

        // Validate encoded_bytes is reasonable FIRST (before using it in calculations)
        if (!message_validator::is_encoded_bytes_valid(encoded_bytes, AUDIO_BUF_SIZE)) {
            // Silently drop - likely corrupted packet (encoded_bytes is garbage)
            do_receive();
            return;
        }

        // Calculate expected size and check for corruption
        size_t expected_size = MIN_AUDIO_PACKET_SIZE + encoded_bytes;
        if (!message_validator::has_complete_payload(bytes, expected_size)) {
            // Incomplete or corrupted packet - silently drop
            do_receive();
            return;
        }

        // Get sender's client ID
        uint32_t sender_id = client_manager_.get_client_id(remote_endpoint_);

        // Embed sender_id in the packet (client may not have sent it, or we override it)
        packet_builder::embed_sender_id(reinterpret_cast<unsigned char*>(recv_buf_.data()),
                                        sender_id);

        // SFU: Forward audio packet to all other clients (not back to sender)
        // Copy packet data before forwarding since recv_buf_ will be reused immediately
        // by do_receive() and async sends are still pending
        auto packet_copy = std::make_shared<std::vector<unsigned char>>(recv_buf_.data(),
                                                                        recv_buf_.data() + bytes);
        forward_audio_to_others(remote_endpoint_, packet_copy->data(), bytes, packet_copy);

        // Only decode and mix if broadcasting is enabled AND SRT is connected
        if (!broadcast_manager_.is_enabled()) {
            return;  // Skip decode/mix if broadcasting is disabled
        }

        if (!broadcast_manager_.is_connected()) {
            static int skip_count = 0;
            if (++skip_count % 1000 == 0) {
                Log::debug("SRT not connected, skipping audio decode/mix ({} packets skipped)",
                           skip_count);
            }
            return;  // Skip decode/mix if SRT is not connected
        }

        // Extract Opus encoded data
        const unsigned char* opus_data =
            reinterpret_cast<const unsigned char*>(recv_buf_.data() + MIN_AUDIO_PACKET_SIZE);

        // Decode and buffer via AudioProcessor
        if (!audio_processor_.process_opus_packet(remote_endpoint_, sender_id, opus_data,
                                                  encoded_bytes)) {
            do_receive();
            return;
        }

        // Debug: log occasionally
        static int decode_count = 0;
        if (++decode_count % 100 == 0 || decode_count <= 5) {
            Log::debug("Processed {} audio packets from client {}", decode_count, sender_id);
        }
    }

    void alive_check_timer_callback() {
        auto now = std::chrono::steady_clock::now();
        auto timed_out_ids =
            client_manager_.remove_timed_out_clients(now, server_config::CLIENT_TIMEOUT);

        for (uint32_t timed_out_id: timed_out_ids) {
            Log::info("Client timed out (ID: {})", timed_out_id);
            // Broadcast participant leave to all other clients
            broadcast_participant_leave(timed_out_id);
        }

        // Check if no participants left and disable broadcast
        if (!timed_out_ids.empty() && client_manager_.empty() && broadcast_manager_.is_enabled()) {
            Log::info("No participants left, disabling broadcast");
            broadcast_manager_.disable();
        }
    }

    void mix_and_send_timer_callback() {
        // Early exit if broadcasting is disabled or SRT is not connected
        if (!broadcast_manager_.is_enabled()) {
            return;  // Skip mixing if broadcasting is disabled
        }

        if (!broadcast_manager_.is_connected()) {
            // Wait for reconnect thread to finish attempts, then disable broadcasting
            static int consecutive_failures = 0;
            consecutive_failures++;

            // After configured timeout, disable if still not connected
            // This gives the reconnect thread time to complete its attempts with backoff
            if (consecutive_failures > server_config::SRT_RETRY_FAILURE_THRESHOLD &&
                broadcast_manager_.is_enabled()) {
                Log::warn("SRT connection failed after {} attempts. Disabling broadcasting.",
                          server_config::MAX_SRT_RETRY_ATTEMPTS);
                broadcast_manager_.disable();
                consecutive_failures = 0;
                return;
            }

            static int skip_count = 0;
            if (++skip_count % 1000 == 0) {
                Log::debug("SRT not connected, skipping mix/send ({} times)", skip_count);
            }
            return;  // Skip mixing if SRT is not connected
        }

        // Reset counter on successful connection (consecutive_failures is reset in the failure path
        // above)

        // Mix all client buffers
        constexpr size_t FRAME_SAMPLES =
            static_cast<size_t>(FRAME_SIZE) * static_cast<size_t>(CHANNELS);
        std::vector<int16_t> mixed_frame = audio_processor_.get_mixed_frame(FRAME_SAMPLES);

        // Check if frame is empty (all silence)
        bool has_audio = false;
        for (int16_t sample: mixed_frame) {
            if (sample != 0) {
                has_audio = true;
                break;
            }
        }
        if (!has_audio) {
            return;  // Skip sending silence
        }

        // Send mixed frame via SRT (connection already checked at start of function)
        int result = broadcast_manager_.send_audio_frame(mixed_frame.data(), FRAME_BYTES);
        if (result == SRT_ERROR) {
            // Error already logged by SrtClient, and reconnection started if needed
            // Congestion errors are expected with non-blocking send
        } else if (result > 0) {
            // Successfully sent - log occasionally for debugging
            static int send_count = 0;
            if (++send_count % 100 == 0 || send_count <= 10) {
                Log::debug("Sent {} SRT frames ({} bytes each)", send_count, result);
            }
        } else {
            // result == 0 shouldn't happen with non-blocking send, but log it
            static int zero_count = 0;
            if (++zero_count % 1000 == 0) {
                Log::debug("SRT send returned 0 (unexpected)");
            }
        }
    }

    void broadcast_participant_leave(uint32_t participant_id) {
        // Broadcast to all clients that a participant has left
        auto buf = packet_builder::create_participant_leave_packet(participant_id);

        // Get endpoints from manager (safe copy)
        auto endpoints = client_manager_.get_all_endpoints();

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
        auto endpoints = client_manager_.get_endpoints_except(sender);

        for (const auto& endpoint: endpoints) {
            send(packet_data, packet_size, endpoint, keep_alive);
        }
    }

private:
    udp::socket socket_;

    ClientManager  client_manager_;
    AudioProcessor audio_processor_{client_manager_};

    std::array<char, server_config::RECV_BUF_SIZE> recv_buf_;
    udp::endpoint                                  remote_endpoint_;

    PeriodicTimer alive_check_timer_;
    PeriodicTimer mix_timer_;

    // Broadcast management
    BroadcastManager broadcast_manager_;
};

int main() {
    try {
        constexpr short SERVER_PORT = 9999;

        auto& log = Logger::instance();
        log.init(true, false, false, "", spdlog::level::info);

        asio::io_context io_context;

        Server srv(io_context, SERVER_PORT);

        log.info("SFU server listening on 127.0.0.1:{}", SERVER_PORT);
        log.info("Forwarding audio packets between clients");

        io_context.run();
    } catch (std::exception& e) {
        Log::error("ERR: {}", e.what());
    }
}
