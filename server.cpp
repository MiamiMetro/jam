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
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <vector>

#include <asio.hpp>
#include <asio/buffer.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <spdlog/common.h>
#include <srt.h>


#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include "logger.h"
#include "opus_decoder.h"
#include "periodic_timer.h"
#include "protocol.h"

using asio::ip::udp;
using namespace std::chrono_literals;

// Audio format constants (matching broadcast_client.cpp)
constexpr int SAMPLE_RATE       = 48000;
constexpr int CHANNELS          = 1;    // mono
constexpr int FRAME_SIZE        = 480;  // 10ms at 48kHz
constexpr int CLIENT_FRAME_SIZE = 240;  // 5ms at 48kHz (client sends this)
constexpr int BYTES_PER_SAMPLE  = 2;    // int16
constexpr int FRAME_BYTES       = FRAME_SIZE * CHANNELS * BYTES_PER_SAMPLE;

// SRT configuration
constexpr const char* SRT_HOST = "127.0.0.1";
constexpr int         SRT_PORT = 9000;

class Server {
public:
    static constexpr auto   ALIVE_CHECK_INTERVAL = 5s;
    static constexpr auto   CLIENT_TIMEOUT       = 15s;
    static constexpr size_t RECV_BUF_SIZE        = 1024;

    Server(asio::io_context& io_context, short port)
        : socket_(io_context, udp::endpoint(udp::v4(), port)),
          alive_check_timer_(io_context, ALIVE_CHECK_INTERVAL,
                             [this]() { alive_check_timer_callback(); }),
          mix_timer_(io_context, 10ms, [this]() { mix_and_send_timer_callback(); }) {
#ifdef _WIN32
        // Initialize Winsock (required before any socket functions on Windows)
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            Log::error("WSAStartup failed");
            throw std::runtime_error("WSAStartup failed");
        }
#endif
        // Initialize SRT
        if (!init_srt()) {
            Log::error("SRT initialization failed");
            throw std::runtime_error("SRT initialization failed");
        }
        // Create and connect SRT socket
        srt_sock_ = create_srt_socket();
        if (srt_sock_ == SRT_INVALID_SOCK) {
            cleanup_srt();
            throw std::runtime_error("Failed to create SRT socket");
        }
        if (!connect_srt(srt_sock_)) {
            Log::warn("Initial SRT connection failed. Will retry in background...");
            // Start reconnection thread
            reconnect_thread_ = std::thread([this]() { reconnect_with_backoff(); });
        } else {
            Log::info("Connected to SRT endpoint {}:{}", SRT_HOST, SRT_PORT);
        }
        do_receive();
        Log::info("SFU server ready: decoding, mixing, and broadcasting audio via SRT");
        Log::info("Mix timer initialized (10ms interval)");
    }

    ~Server() {
        g_running_ = false;
        socket_.close();
        if (reconnect_thread_.joinable()) {
            reconnect_thread_.join();
        }
        if (srt_sock_ != SRT_INVALID_SOCK) {
            srt_close(srt_sock_);
        }
        cleanup_srt();
#ifdef _WIN32
        WSACleanup();
#endif
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
            case CtrlHdr::Cmd::LEAVE: {
                Log::info("Client LEAVE: {}:{}", remote_endpoint_.address().to_string(),
                          remote_endpoint_.port());
                uint32_t leaving_client_id = clients_[remote_endpoint_].client_id;
                clients_.erase(remote_endpoint_);
                // Broadcast participant leave to all other clients
                broadcast_participant_leave(leaving_client_id);
                break;
            }
            case CtrlHdr::Cmd::ALIVE:
                clients_[remote_endpoint_].last_alive = now;
                break;
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
        // Minimum size check first (magic + sender_id + encoded_bytes)
        constexpr size_t MIN_AUDIO_PACKET_SIZE =
            sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t);
        if (bytes < MIN_AUDIO_PACKET_SIZE) {
            // Too small to even read the header - silently drop
            Log::debug("Audio packet too small: {} bytes", bytes);
            do_receive();
            return;
        }

        // Auto-register client if not known (handles case where server starts after clients)
        if (!clients_.contains(remote_endpoint_)) {
            auto now = std::chrono::steady_clock::now();
            Log::info("Auto-registering client from audio packet: {}:{} (ID: {})",
                      remote_endpoint_.address().to_string(), remote_endpoint_.port(),
                      next_client_id_);
            clients_[remote_endpoint_].last_alive = now;
            clients_[remote_endpoint_].client_id  = next_client_id_++;
            // Create decoder for new client
            {
                std::lock_guard<std::mutex> lock(client_decoders_mutex_);
                auto&                       decoder = client_decoders_[remote_endpoint_];
                if (!decoder.is_initialized()) {
                    if (!decoder.create(SAMPLE_RATE, CHANNELS)) {
                        Log::error("Failed to create decoder for client {}:{}",
                                   remote_endpoint_.address().to_string(), remote_endpoint_.port());
                        do_receive();
                        return;
                    }
                    Log::info("Created decoder for client {}:{}",
                              remote_endpoint_.address().to_string(), remote_endpoint_.port());
                }
            }
            // Also initialize PCM buffer for this client
            {
                std::lock_guard<std::mutex> lock(client_buffers_mutex_);
                client_pcm_buffers_[remote_endpoint_];  // Initialize empty buffer
            }
        }

        // Read encoded_bytes (after sender_id field)
        uint16_t encoded_bytes;
        std::memcpy(&encoded_bytes, recv_buf_.data() + sizeof(MsgHdr) + sizeof(uint32_t),
                    sizeof(uint16_t));

        // Validate encoded_bytes is reasonable FIRST (before using it in calculations)
        if (encoded_bytes > AUDIO_BUF_SIZE) {
            // Silently drop - likely corrupted packet (encoded_bytes is garbage)
            do_receive();
            return;
        }

        // Calculate expected size and check for corruption
        size_t expected_size = MIN_AUDIO_PACKET_SIZE + encoded_bytes;
        if (bytes < expected_size) {
            size_t missing_bytes = expected_size - bytes;

            // If missing more than 2 bytes, it's likely a corrupted/incomplete packet
            // Silently drop to avoid log spam (UDP can have packet loss/fragmentation)
            if (missing_bytes > 2) {
                do_receive();
                return;
            }

            // Very minor mismatch (1-2 bytes) - might be edge case, still drop
            do_receive();
            return;
        }

        // Get sender's client ID
        uint32_t sender_id = clients_[remote_endpoint_].client_id;

        // Log first few audio packets
        static std::unordered_map<udp::endpoint, int, endpoint_hash> packet_counts;
        int& count = packet_counts[remote_endpoint_];
        if (++count <= 5 || count % 100 == 0) {
            Log::info("Received audio packet from client {} ({} bytes, {} encoded)", sender_id,
                      bytes, encoded_bytes);
        }

        // Extract Opus encoded data
        const unsigned char* opus_data =
            reinterpret_cast<const unsigned char*>(recv_buf_.data() + MIN_AUDIO_PACKET_SIZE);

        // Decode Opus to PCM float
        std::vector<float> decoded_pcm;
        {
            std::lock_guard<std::mutex> lock(client_decoders_mutex_);
            auto                        it = client_decoders_.find(remote_endpoint_);
            if (it == client_decoders_.end()) {
                // Decoder not found - this shouldn't happen if registration worked
                Log::error("Decoder not found in map for client {}:{} (ID: {}). Recreating...",
                           remote_endpoint_.address().to_string(), remote_endpoint_.port(),
                           sender_id);
                // Try to create it now
                auto& decoder = client_decoders_[remote_endpoint_];
                if (!decoder.create(SAMPLE_RATE, CHANNELS)) {
                    Log::error("Failed to create decoder on retry");
                    do_receive();
                    return;
                }
                it = client_decoders_.find(remote_endpoint_);
            }

            if (it != client_decoders_.end() && it->second.is_initialized()) {
                if (!it->second.decode(opus_data, encoded_bytes, CLIENT_FRAME_SIZE, decoded_pcm)) {
                    // Decode failed - use PLC (packet loss concealment)
                    Log::debug("Opus decode failed for client {}, using PLC", sender_id);
                    it->second.decode_plc(CLIENT_FRAME_SIZE, decoded_pcm);
                }
            } else {
                // Decoder exists but not initialized
                Log::error("Decoder exists but not initialized for client {}:{} (ID: {})",
                           remote_endpoint_.address().to_string(), remote_endpoint_.port(),
                           sender_id);
                do_receive();
                return;
            }
        }

        // Buffer decoded PCM for mixing
        {
            std::lock_guard<std::mutex> lock(client_buffers_mutex_);
            auto&                       buffer = client_pcm_buffers_[remote_endpoint_];
            // Convert float to int16 and append
            buffer.reserve(buffer.size() + decoded_pcm.size());
            for (float sample: decoded_pcm) {
                // Clamp to [-1.0, 1.0] and convert to int16
                sample             = std::max(-1.0F, std::min(1.0F, sample));
                int16_t int_sample = static_cast<int16_t>(sample * 32767.0F);
                buffer.push_back(int_sample);
            }
            // Debug: log occasionally
            static int decode_count = 0;
            if (++decode_count % 100 == 0 || decode_count <= 5) {
                Log::info("Decoded {} packets from client {}, buffer size: {} samples",
                          decode_count, sender_id, buffer.size());
            }
        }

        // Embed sender_id in the packet (client may not have sent it, or we override it)
        std::memcpy(recv_buf_.data() + sizeof(MsgHdr), &sender_id, sizeof(uint32_t));

        // SFU: Forward audio packet to all other clients (not back to sender)
        // Copy packet data before forwarding since recv_buf_ will be reused immediately
        // by do_receive() and async sends are still pending
        auto packet_copy = std::make_shared<std::vector<unsigned char>>(recv_buf_.data(),
                                                                        recv_buf_.data() + bytes);
        forward_audio_to_others(remote_endpoint_, packet_copy->data(), bytes, packet_copy);
    }

    void alive_check_timer_callback() {
        auto now = std::chrono::steady_clock::now();
        for (auto it = clients_.begin(); it != clients_.end();) {
            if (now - it->second.last_alive > CLIENT_TIMEOUT) {
                Log::info("Client {}:{} timed out (ID: {})", it->first.address().to_string(),
                          it->first.port(), it->second.client_id);
                uint32_t timed_out_id = it->second.client_id;
                // Clean up decoder and buffer
                {
                    std::lock_guard<std::mutex> lock_dec(client_decoders_mutex_);
                    client_decoders_.erase(it->first);
                }
                {
                    std::lock_guard<std::mutex> lock_buf(client_buffers_mutex_);
                    client_pcm_buffers_.erase(it->first);
                }
                it = clients_.erase(it);
                // Broadcast participant leave to all other clients
                broadcast_participant_leave(timed_out_id);
            } else {
                ++it;
            }
        }
    }

    void mix_and_send_timer_callback() {
        // Mix all client buffers and send via SRT
        constexpr size_t FRAME_SAMPLES =
            static_cast<size_t>(FRAME_SIZE) * static_cast<size_t>(CHANNELS);
        std::vector<int16_t> mixed_frame(FRAME_SAMPLES, 0);

        {
            std::lock_guard<std::mutex> lock(client_buffers_mutex_);

            // Check if we have any clients with data
            if (client_pcm_buffers_.empty()) {
                static int empty_count = 0;
                if (++empty_count % 1000 == 0) {
                    Log::debug("Mix timer: no clients registered");
                }
                return;  // No clients
            }

            // Mix all client buffers - take up to FRAME_SAMPLES from each
            int active_clients = 0;
            for (auto& [endpoint, buffer]: client_pcm_buffers_) {
                size_t samples_to_mix = std::min(buffer.size(), FRAME_SAMPLES);
                if (samples_to_mix > 0) {
                    // Mix this client's available samples
                    for (size_t i = 0; i < samples_to_mix; ++i) {
                        mixed_frame[i] = static_cast<int16_t>(static_cast<int32_t>(mixed_frame[i]) +
                                                              static_cast<int32_t>(buffer[i]));
                    }
                    // Remove mixed samples from buffer
                    buffer.erase(buffer.begin(),
                                 buffer.begin() + static_cast<ptrdiff_t>(samples_to_mix));
                    active_clients++;
                }
            }

            // Average the mixed samples to prevent clipping (only if we have active clients)
            if (active_clients > 0) {
                for (auto& sample: mixed_frame) {
                    int32_t mixed = static_cast<int32_t>(sample) / active_clients;
                    sample        = static_cast<int16_t>(std::max(-32768, std::min(32767, mixed)));
                }
                static int mix_count = 0;
                if (++mix_count % 100 == 0 || mix_count <= 5) {
                    Log::info("Mixed {} clients, sending frame", active_clients);
                }
            } else {
                // No active clients with data - send silence
                // mixed_frame is already zero-initialized
                static int silence_count = 0;
                if (++silence_count % 1000 == 0) {
                    Log::debug("Mix timer: no active clients with data, sending silence");
                }
            }
        }

        // Always send a frame (even if silence) to maintain timing
        if (srt_sock_ != SRT_INVALID_SOCK) {
            // Check socket state - only send if connected
            SRT_SOCKSTATUS status = srt_getsockstate(srt_sock_);
            if (status != SRTS_CONNECTED) {
                // Socket not connected - don't try to send
                static int skip_count = 0;
                if (++skip_count % 1000 == 0) {
                    Log::debug("SRT socket not connected (status: {}), skipping send",
                               static_cast<int>(status));
                }
                return;
            }

            int result =
                srt_send(srt_sock_, reinterpret_cast<const char*>(mixed_frame.data()), FRAME_BYTES);
            if (result == SRT_ERROR) {
                int err = srt_getlasterror(nullptr);
                if (err == SRT_EASYNCSND || err == SRT_ECONGEST) {
                    // Congestion - drop frame (this is expected with non-blocking send)
                } else {
                    // Connection broken - trigger reconnection
                    Log::warn("SRT send error: {} (status: {}), will reconnect",
                              srt_getlasterror_str(), static_cast<int>(status));
                    srt_close(srt_sock_);
                    srt_sock_ = SRT_INVALID_SOCK;
                    if (!reconnect_thread_.joinable()) {
                        reconnect_thread_ = std::thread([this]() { reconnect_with_backoff(); });
                    }
                }
            } else if (result > 0) {
                // Successfully sent - log occasionally for debugging
                static int send_count = 0;
                if (++send_count % 100 == 0 || send_count <= 10) {
                    Log::info("Sent {} SRT frames ({} bytes each)", send_count, result);
                }
            } else {
                // result == 0 shouldn't happen with non-blocking send, but log it
                static int zero_count = 0;
                if (++zero_count % 1000 == 0) {
                    Log::debug("SRT send returned 0 (unexpected)");
                }
            }
        }
    }

    void broadcast_participant_leave(uint32_t participant_id) {
        // Broadcast to all clients that a participant has left
        CtrlHdr chdr{};
        chdr.magic          = CTRL_MAGIC;
        chdr.type           = CtrlHdr::Cmd::PARTICIPANT_LEAVE;
        chdr.participant_id = participant_id;

        // Create shared_ptr to keep buffer alive during async sends
        auto buf = std::make_shared<std::vector<unsigned char>>(sizeof(CtrlHdr));
        std::memcpy(buf->data(), &chdr, sizeof(CtrlHdr));

        for (const auto& [endpoint, client_info]: clients_) {
            send(buf->data(), sizeof(CtrlHdr), endpoint, buf);
        }
    }

    void forward_audio_to_others(
        const udp::endpoint& sender, void* packet_data, std::size_t packet_size,
        const std::shared_ptr<std::vector<unsigned char>>& keep_alive = nullptr) {
        // Forward the audio packet to all clients except the sender
        // keep_alive ensures packet data remains valid during async sends
        for (const auto& [endpoint, client_info]: clients_) {
            if (endpoint != sender) {
                send(packet_data, packet_size, endpoint, keep_alive);
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
        uint32_t                              client_id;  // Unique ID for this client
    };

    // SRT functions
    static bool init_srt() {
        srt_startup();
        return true;
    }

    static void cleanup_srt() {
        srt_cleanup();
    }

    static SRTSOCKET create_srt_socket() {
        SRTSOCKET sock = srt_create_socket();
        if (sock == SRT_INVALID_SOCK) {
            Log::error("Failed to create SRT socket: {}", srt_getlasterror_str());
            return SRT_INVALID_SOCK;
        }

        // Set non-blocking send (SRTO_SNDSYN = 0)
        int sndsyn = 0;
        if (srt_setsockopt(sock, 0, SRTO_SNDSYN, &sndsyn, sizeof(sndsyn)) == SRT_ERROR) {
            Log::error("Failed to set SRTO_SNDSYN: {}", srt_getlasterror_str());
            srt_close(sock);
            return SRT_INVALID_SOCK;
        }

        // Set latency (200ms as per broadcast_client)
        int latency = 200;
        if (srt_setsockopt(sock, 0, SRTO_LATENCY, &latency, sizeof(latency)) == SRT_ERROR) {
            Log::error("Failed to set SRTO_LATENCY: {}", srt_getlasterror_str());
            srt_close(sock);
            return SRT_INVALID_SOCK;
        }

        return sock;
    }

    static bool connect_srt(SRTSOCKET sock) {
        sockaddr_in sa;
        std::memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port   = htons(SRT_PORT);

        if (inet_pton(AF_INET, SRT_HOST, &sa.sin_addr) != 1) {
            Log::error("Failed to parse address: {}", SRT_HOST);
            return false;
        }

        if (srt_connect(sock, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == SRT_ERROR) {
            Log::error("Failed to connect: {}", srt_getlasterror_str());
            return false;
        }

        return true;
    }

    void reconnect_with_backoff() {
        int       backoff_ms     = 100;
        const int max_backoff_ms = 5000;

        while (g_running_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms));

            if (srt_sock_ != SRT_INVALID_SOCK) {
                srt_close(srt_sock_);
                srt_sock_ = SRT_INVALID_SOCK;
            }

            srt_sock_ = create_srt_socket();
            if (srt_sock_ == SRT_INVALID_SOCK) {
                backoff_ms = (backoff_ms * 2 < max_backoff_ms) ? (backoff_ms * 2) : max_backoff_ms;
                continue;
            }

            if (connect_srt(srt_sock_)) {
                Log::info("Reconnected to SRT endpoint {}:{}", SRT_HOST, SRT_PORT);
                return;
            }

            srt_close(srt_sock_);
            srt_sock_  = SRT_INVALID_SOCK;
            backoff_ms = (backoff_ms * 2 < max_backoff_ms) ? (backoff_ms * 2) : max_backoff_ms;
        }
    }

    udp::socket socket_;

    std::unordered_map<udp::endpoint, ClientInfo, endpoint_hash> clients_;
    uint32_t next_client_id_ = 1;  // Start from 1, 0 is invalid

    std::array<char, RECV_BUF_SIZE> recv_buf_;
    udp::endpoint                   remote_endpoint_;

    PeriodicTimer alive_check_timer_;
    PeriodicTimer mix_timer_;

    // SRT socket
    SRTSOCKET         srt_sock_ = SRT_INVALID_SOCK;
    std::thread       reconnect_thread_;
    std::atomic<bool> g_running_{true};

    // Per-client decoders and PCM buffers
    std::mutex                                                           client_decoders_mutex_;
    std::unordered_map<udp::endpoint, OpusDecoderWrapper, endpoint_hash> client_decoders_;

    std::mutex                                                             client_buffers_mutex_;
    std::unordered_map<udp::endpoint, std::vector<int16_t>, endpoint_hash> client_pcm_buffers_;
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
