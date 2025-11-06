#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>
#include <opus.h>
#include <portaudio.h>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <asio.hpp>
#include <asio/buffer.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <concurrentqueue.h>
#include <ixwebsocket/IXConnectionState.h>
#include <ixwebsocket/IXWebSocket.h>
#include <ixwebsocket/IXWebSocketMessage.h>
#include <ixwebsocket/IXWebSocketMessageType.h>
#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>
#include <spdlog/common.h>

#include "audio_stream.h"
#include "logger.h"
#include "periodic_timer.h"
#include "protocol.h"
#include "websocket.h"

using asio::ip::udp;
using namespace std::chrono_literals;
using nlohmann::json;

class Client {
public:
    Client(asio::io_context& io_context, const std::string& server_address, short server_port)
        : io_context_(io_context),
          socket_(io_context, udp::endpoint(udp::v4(), 0)),
          is_connected_(false),
          echo_enabled_(false),
          jitter_buffer_ready_(false),
          jitter_buffer_min_packets_(2),
          jitter_buffer_target_packets_(4),
          jitter_buffer_max_packets_(16),
          ping_timer_(io_context, 500ms, [this]() { ping_timer_callback(); }),
          alive_timer_(io_context, 5s, [this]() { alive_timer_callback(); }) {
        Log::info("Client local port: {}", socket_.local_endpoint().port());

        // Start audio stream with configuration
        AudioStream::AudioConfig config;
        config.sample_rate       = 48000;
        config.bitrate           = 64000;
        config.complexity        = 2;
        config.frames_per_buffer = 240;
        config.input_gain        = 1.0F;
        config.output_gain       = 1.0F;

        auto wdm_ks_devices = AudioStream::get_devices_json("Windows WDM-KS");
        Log::info("Available Windows WDM-KS devices: {}", wdm_ks_devices.dump());

        start_audio_stream(17, 15, config);
        // start_audio_stream(38, 40, config);
        // Connect to server
        start_connection(server_address, server_port);
    }

    // Start connection to server (or switch to new server)
    void start_connection(const std::string& server_address, short server_port) {
        Log::info("Connecting to {}:{}...", server_address, server_port);

        // Resolve hostname or IP address
        udp::resolver               resolver(io_context_);
        udp::resolver::results_type endpoints =
            resolver.resolve(udp::v4(), server_address, std::to_string(server_port));
        server_endpoint_ = *endpoints.begin();

        Log::info("Resolved to: {}:{}", server_endpoint_.address().to_string(),
                  server_endpoint_.port());

        is_connected_.store(true, std::memory_order_relaxed);
        do_receive();

        Log::info("Connected and receiving!");

        // Send JOIN message
        CtrlHdr chdr{};
        chdr.magic = CTRL_MAGIC;
        chdr.type  = CtrlHdr::Cmd::JOIN;
        std::memcpy(ctrl_tx_buf_.data(), &chdr, sizeof(CtrlHdr));
        send(ctrl_tx_buf_.data(), sizeof(CtrlHdr));
    }

    // Stop connection (stops sending/receiving UDP packets)
    void stop_connection() {
        Log::info("Disconnecting from server...");

        is_connected_.store(false, std::memory_order_relaxed);

        // Cancel pending async operations
        socket_.cancel();

        // Clear audio receive queue
        std::vector<float> temp;
        while (audio_recv_queue_.try_dequeue(temp)) {
        }
        jitter_buffer_ready_ = false;

        Log::info("Disconnected (no longer sending/receiving)");
    }

    // Check if connected to server
    bool is_connected() const {
        return is_connected_.load(std::memory_order_relaxed);
    }

    bool start_audio_stream(PaDeviceIndex input_device, PaDeviceIndex output_device,
                            const AudioStream::AudioConfig& config = AudioStream::AudioConfig{}) {
        Log::info("Starting audio stream...");
        bool success =
            audio_.start_audio_stream(input_device, output_device, config, audio_callback, this);
        if (success) {
            audio_.print_latency_info();
        }
        return success;
    }

    void stop_audio_stream() {
        audio_.stop_audio_stream();
    }

    void enable_echo(bool enable) {
        echo_enabled_.store(enable, std::memory_order_relaxed);
    }

    bool is_echo_enabled() const {
        return echo_enabled_.load(std::memory_order_relaxed);
    }

    void on_receive(std::error_code error_code, std::size_t bytes) {
        if (error_code) {
            // std::cerr << "receive error: " << error_code.message() << "\n";
            do_receive();  // keep listening
            return;
        }

        if (bytes < sizeof(MsgHdr)) {
            do_receive();
            return;
        }

        MsgHdr hdr{};
        std::memcpy(&hdr, recv_buf_.data(), sizeof(MsgHdr));

        if (hdr.magic == PING_MAGIC && bytes >= sizeof(SyncHdr)) {
            handle_ping_message(bytes);
        } else if (hdr.magic == CTRL_MAGIC && bytes >= sizeof(CtrlHdr)) {
            handle_ctrl_message(bytes);
        } else if (hdr.magic == ECHO_MAGIC && bytes >= sizeof(EchoHdr)) {
            handle_echo_message(bytes);
        } else if (hdr.magic == AUDIO_MAGIC && bytes >= sizeof(MsgHdr) + sizeof(uint16_t)) {
            handle_audio_message(bytes);
        } else {
            // Log unknown message with hex dump for debugging
            std::string hex_dump;
            hex_dump.reserve(bytes * 3);
            for (size_t i = 0; i < std::min(bytes, size_t(32)); ++i) {
                char hex[4];
                std::snprintf(hex, sizeof(hex), "%02x ", static_cast<unsigned char>(recv_buf_[i]));
                hex_dump += hex;
            }
            Log::warn("Unknown message (magic=0x{:08x}, bytes={}, hex={}...)", hdr.magic, bytes,
                      hex_dump);
        }

        do_receive();  // keep listening
    }

    void do_receive() {
        // Only receive if connected
        if (!is_connected_.load(std::memory_order_relaxed)) {
            return;
        }

        socket_.async_receive_from(asio::buffer(recv_buf_), server_endpoint_,
                                   [this](std::error_code error_code, std::size_t bytes) {
                                       on_receive(error_code, bytes);
                                   });
    }

    void send(void* data, std::size_t len) {
        // Only send if connected
        if (!is_connected_.load(std::memory_order_relaxed)) {
            return;
        }

        socket_.async_send_to(asio::buffer(data, len), server_endpoint_,
                              [](std::error_code error_code, std::size_t) {
                                  if (error_code) {
                                      Log::error("send error: {}", error_code.message());
                                  }
                              });
    }

private:
    void ping_timer_callback() {
        static uint32_t seq = 0;
        SyncHdr         shdr{};
        shdr.magic = PING_MAGIC;
        shdr.seq   = seq++;
        auto now   = std::chrono::steady_clock::now();
        shdr.t1_client_send =
            std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        std::memcpy(sync_tx_buf_.data(), &shdr, sizeof(SyncHdr));
        send(sync_tx_buf_.data(), sizeof(SyncHdr));
    }

    void alive_timer_callback() {
        CtrlHdr chdr{};
        chdr.magic = CTRL_MAGIC;
        chdr.type  = CtrlHdr::Cmd::ALIVE;
        std::memcpy(ctrl_tx_buf_.data(), &chdr, sizeof(CtrlHdr));
        send(ctrl_tx_buf_.data(), sizeof(CtrlHdr));
    }

    void handle_ping_message(std::size_t /*bytes*/) {
        SyncHdr hdr{};
        std::memcpy(&hdr, recv_buf_.data(), sizeof(SyncHdr));

        auto now = std::chrono::steady_clock::now();
        auto current_time =
            std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        auto rtt = (current_time - hdr.t1_client_send) - (hdr.t3_server_send - hdr.t2_server_recv);
        auto offset =
            ((hdr.t2_server_recv - hdr.t1_client_send) + (hdr.t3_server_send - current_time)) / 2;

        double rtt_ms    = static_cast<double>(rtt) / 1e6;
        double offset_ms = static_cast<double>(offset) / 1e6;

        // print live stats
        Log::debug("seq {} RTT {:.5f} ms | offset {:.5f} ms", hdr.seq, rtt_ms, offset_ms);
    }

    void handle_ctrl_message(std::size_t /*bytes*/) {
        CtrlHdr chdr{};
        std::memcpy(&chdr, recv_buf_.data(), sizeof(CtrlHdr));
        // Client doesn't need to process CTRL messages from server
        // (server processes them, client just sends them)
    }

    void handle_echo_message(std::size_t /*bytes*/) {
        EchoHdr ehdr{};
        std::memcpy(&ehdr, recv_buf_.data(), sizeof(EchoHdr));
        static int echo_count = 0;
        Log::info("Echo {} from server: {}", ++echo_count, std::string(ehdr.data.data()));
    }

    void handle_audio_message(std::size_t bytes) {
        uint16_t encoded_bytes;
        std::memcpy(&encoded_bytes, recv_buf_.data() + sizeof(MsgHdr), sizeof(uint16_t));
        size_t expected_size = sizeof(MsgHdr) + sizeof(uint16_t) + encoded_bytes;

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

        const unsigned char* audio_data = reinterpret_cast<const unsigned char*>(
            recv_buf_.data() + sizeof(MsgHdr) + sizeof(uint16_t));

        std::vector<float> decoded_data;
        if (encoded_bytes > 0) {
            decode_audio_data(audio_data, encoded_bytes, decoded_data);
        }

        if (!decoded_data.empty()) {
            process_decoded_audio(std::move(decoded_data));
        }
    }

    void decode_audio_data(const unsigned char* audio_data, uint16_t encoded_bytes,
                           std::vector<float>& decoded_data) {
        // Decode the received Opus data
        audio_.decode_opus(audio_data, encoded_bytes, 240, decoded_data);

        // Diagnostic: Check decoded size periodically
        static int decode_count = 0;
        static int size_errors  = 0;
        if (++decode_count % 400 == 0) {
            Log::debug("Client decoded {} packets, {} samples (expected {}), {} size errors",
                       decode_count, decoded_data.size(), (240 * audio_.get_output_channel_count()),
                       size_errors);
        }
        if (decoded_data.size() != 240ULL * audio_.get_output_channel_count()) {
            size_errors++;
        }
    }

    void process_decoded_audio(std::vector<float> decoded_data) {
        // Add to jitter buffer queue
        size_t queue_size = audio_recv_queue_.size_approx();

        // Drop packet if queue is too full (prevent unbounded latency)
        if (queue_size < 16) {
            audio_recv_queue_.enqueue(std::move(decoded_data));

            // Mark buffer as ready once we have enough packets
            if (!jitter_buffer_ready_ && queue_size >= jitter_buffer_min_packets_) {
                jitter_buffer_ready_ = true;
                Log::info("Jitter buffer ready ({} packets buffered)", queue_size);
            }
        } else {
            // Buffer overflow - drop oldest packet
            std::vector<float> discarded;
            audio_recv_queue_.try_dequeue(discarded);
            audio_recv_queue_.enqueue(std::move(decoded_data));
        }
    }

    // Helper methods for audio callback to reduce cognitive complexity
    struct AudioCallbackState {
        std::vector<float>                    decoded_data;
        std::vector<unsigned char>            encoded_data;
        int                                   underrun_count          = 0;
        int                                   playback_count          = 0;
        int                                   consecutive_low_buffer  = 0;
        int                                   consecutive_high_buffer = 0;
        std::chrono::steady_clock::time_point last_adaptation = std::chrono::steady_clock::now();
    };

    static void handle_audio_playback(Client* client_ptr, float* output_buffer,
                                      unsigned long frame_count, size_t out_channels,
                                      size_t bytes_to_copy, AudioCallbackState& state) {
        size_t queue_size     = client_ptr->audio_recv_queue_.size_approx();
        size_t current_min    = client_ptr->jitter_buffer_min_packets_.load();
        size_t current_target = client_ptr->jitter_buffer_target_packets_.load();

        // Jitter buffer logic: only play if buffer is ready
        if (client_ptr->jitter_buffer_ready_ &&
            client_ptr->audio_recv_queue_.try_dequeue(state.decoded_data)) {
            // Validate decoded data size matches expected output
            size_t expected_samples = frame_count * out_channels;
            if (state.decoded_data.size() == expected_samples) {
                std::memcpy(output_buffer, state.decoded_data.data(), bytes_to_copy);
            } else {
                // Size mismatch - zero output and log warning
                std::memset(output_buffer, 0, bytes_to_copy);
                static int mismatch_count = 0;
                if (++mismatch_count % 100 == 0) {
                    Log::warn("Client: Decoded size mismatch: got {} samples, expected {}",
                              state.decoded_data.size(), expected_samples);
                }
            }
            state.playback_count++;

            // Adaptive buffer management
            adapt_jitter_buffer(client_ptr, queue_size, current_min, current_target, state);

            // Warn if buffer is critically low
            if (queue_size < current_min - 1) {
                state.underrun_count++;
                if (state.underrun_count % 200 == 0) {
                    Log::warn("Jitter buffer low ({}/{}) packets", queue_size, current_min);
                }
            } else {
                state.underrun_count = 0;
            }
        } else {
            // Buffer not ready or underrun - play silence
            std::memset(output_buffer, 0, bytes_to_copy);
            state.underrun_count++;

            // Print underrun stats periodically
            if (!client_ptr->jitter_buffer_ready_ && state.underrun_count % 100 == 0) {
                // logger::debug("Buffering... ({}/{}) packets", queue_size, current_min);
            }

            // Reset buffer ready flag if we've drained completely
            if (client_ptr->jitter_buffer_ready_ && queue_size == 0) {
                client_ptr->jitter_buffer_ready_ = false;
                Log::warn("Jitter buffer underrun! Rebuffering...");
                state.consecutive_low_buffer  = 0;
                state.consecutive_high_buffer = 0;
            }
        }
    }

    static void adapt_jitter_buffer(Client* client_ptr, size_t queue_size, size_t current_min,
                                    size_t current_target, AudioCallbackState& state) {
        auto now = std::chrono::steady_clock::now();
        auto time_since_adapt =
            std::chrono::duration_cast<std::chrono::milliseconds>(now - state.last_adaptation);

        // Only adapt every 1 second to avoid oscillation
        if (time_since_adapt.count() >= 1000) {
            // Track buffer health
            if (queue_size < current_min) {
                state.consecutive_low_buffer++;
                state.consecutive_high_buffer = 0;
            } else if (queue_size > current_target + 2) {
                state.consecutive_high_buffer++;
                state.consecutive_low_buffer = 0;
            } else {
                // Buffer in healthy range - decay counters slowly
                state.consecutive_low_buffer  = std::max(0, state.consecutive_low_buffer - 1);
                state.consecutive_high_buffer = std::max(0, state.consecutive_high_buffer - 1);
            }

            // Increase buffer if consistently low (network jitter detected)
            if (state.consecutive_low_buffer >= 3 &&
                current_min < client_ptr->jitter_buffer_max_packets_ - 2) {
                size_t new_min =
                    std::min(current_min + 2, client_ptr->jitter_buffer_max_packets_ - 2);
                size_t new_target =
                    std::min(current_target + 2, client_ptr->jitter_buffer_max_packets_);
                client_ptr->jitter_buffer_min_packets_.store(new_min);
                client_ptr->jitter_buffer_target_packets_.store(new_target);
                Log::info("Adaptive: Increasing buffer to min={}, target={} (high jitter detected)",
                          new_min, new_target);
                state.consecutive_low_buffer = 0;
                state.last_adaptation        = now;
            }
            // Decrease buffer if consistently high (stable network, reduce latency)
            else if (state.consecutive_high_buffer >= 5 && current_min > 2) {
                size_t new_min    = std::max(current_min - 1, size_t(2));
                size_t new_target = std::max(current_target - 1, size_t(3));
                client_ptr->jitter_buffer_min_packets_.store(new_min);
                client_ptr->jitter_buffer_target_packets_.store(new_target);
                Log::info("Adaptive: Decreasing buffer to min={}, target={} (stable network)",
                          new_min, new_target);
                state.consecutive_high_buffer = 0;
                state.last_adaptation         = now;
            }
        }
    }

    static void handle_echo_monitoring(const float* input_buffer, float* output_buffer,
                                       unsigned long frame_count, size_t out_channels,
                                       bool echo_enabled) {
        if (echo_enabled && (input_buffer != nullptr)) {
            float self_gain = 1.0F;  // Adjust to taste (0.0–1.0)
            for (size_t i = 0; i < frame_count; ++i) {
                float sample = input_buffer[i] * self_gain;
                output_buffer[(i * out_channels) + 0] += sample;  // Left
                output_buffer[(i * out_channels) + 1] += sample;  // Right
            }
        }
    }

    static void handle_audio_encoding(Client* client_ptr, const float* input_buffer,
                                      unsigned long frame_count, AudioCallbackState& state) {
        if (input_buffer == nullptr) {
            // No input - send silence packet periodically to keep connection alive
            static int no_input_count = 0;
            if (++no_input_count % 100 == 0) {
                Log::warn("No input audio (in == nullptr)");
            }
            return;
        }

        // Silence detection: Check if input has significant audio
        static constexpr float SILENCE_THRESHOLD = 0.001F;  // -60dB
        float                  max_sample        = 0.0F;
        for (unsigned long i = 0; i < frame_count; ++i) {
            float abs_sample = std::fabs(input_buffer[i]);
            max_sample       = std::max(abs_sample, max_sample);
        }

        // Only encode and send if there's actual audio (not silence) and stream is active
        if (max_sample > SILENCE_THRESHOLD && client_ptr->audio_.is_stream_active()) {
            client_ptr->audio_.encode_opus(input_buffer, frame_count, state.encoded_data);

            // Diagnostic: Check encoding success
            static int encode_count    = 0;
            static int encode_failures = 0;
            encode_count++;
            if (state.encoded_data.empty()) {
                encode_failures++;
            }
            if (encode_count % 400 == 0) {
                Log::debug(
                    "Client encoded {} packets, {} failures, last size: {} bytes, peak: {:.3f}",
                    encode_count, encode_failures, state.encoded_data.size(), max_sample);
            }

            if (!state.encoded_data.empty()) {
                AudioHdr ahdr{};
                ahdr.magic         = AUDIO_MAGIC;
                ahdr.encoded_bytes = static_cast<uint16_t>(state.encoded_data.size());
                std::memcpy(ahdr.buf.data(), state.encoded_data.data(),
                            std::min(state.encoded_data.size(), ahdr.buf.size()));
                size_t packetSize = sizeof(MsgHdr) + sizeof(uint16_t) + ahdr.encoded_bytes;
                client_ptr->send(&ahdr, packetSize);
            }
        } else {
            // Silence detected - don't send packet (save bandwidth and prevent glitches)
            static int silence_count = 0;
            if (++silence_count % 400 == 0) {
                Log::debug("Client: {} silent frames skipped", silence_count);
            }
        }
    }

    static int audio_callback(const void* input, void* output, unsigned long frame_count,
                              const PaStreamCallbackTimeInfo* /*unused*/,
                              PaStreamCallbackFlags /*unused*/, void* user_data) {
        const auto* input_buffer  = static_cast<const float*>(input);
        auto*       output_buffer = static_cast<float*>(output);
        if (output_buffer == nullptr) {
            return paContinue;
        }

        auto* client_ptr = static_cast<Client*>(user_data);

        // Use static state to avoid allocations (reused across calls)
        static AudioCallbackState state;

        size_t out_channels  = client_ptr->audio_.get_output_channel_count();  // 2
        size_t bytes_to_copy = frame_count * out_channels * sizeof(float);

        // 1. Play received audio from server (with adaptive jitter buffer)
        Client::handle_audio_playback(client_ptr, output_buffer, frame_count, out_channels,
                                      bytes_to_copy, state);

        // 2. Mix in your own live instrument (local monitor)
        Client::handle_echo_monitoring(input_buffer, output_buffer, frame_count, out_channels,
                                       client_ptr->is_echo_enabled());

        // 3. Encode and send to server
        Client::handle_audio_encoding(client_ptr, input_buffer, frame_count, state);

        return paContinue;
    }

    asio::io_context& io_context_;
    udp::socket       socket_;
    udp::endpoint     server_endpoint_;

    std::array<char, 1024>         recv_buf_;
    std::array<unsigned char, 128> sync_tx_buf_;
    std::array<unsigned char, 128> ctrl_tx_buf_;

    AudioStream                                     audio_;
    std::vector<float>                              stereo_buffer_;
    moodycamel::ConcurrentQueue<std::vector<float>> audio_recv_queue_;

    // Connection state (atomic for thread-safe access from audio callback)
    std::atomic<bool> is_connected_;

    std::atomic<bool> echo_enabled_;

    // Jitter buffer state
    std::atomic<bool>   jitter_buffer_ready_;
    std::atomic<size_t> jitter_buffer_min_packets_;     // Adaptive minimum (starts at 4)
    std::atomic<size_t> jitter_buffer_target_packets_;  // Adaptive target (starts at 6)
    const size_t        jitter_buffer_max_packets_;     // Hard max (12 packets = 30ms)

    PeriodicTimer ping_timer_;
    PeriodicTimer alive_timer_;
};

int main() {
    try {
        auto& log = Logger::instance();
        log.init(true, true, false, "", spdlog::level::info);

        asio::io_context io_context;
        Client           client_instance(io_context, "127.0.0.1", 9999);

        WebSocket ws_server(9969,
                            [](const std::shared_ptr<ix::ConnectionState>& /*connectionState*/,
                               ix::WebSocket& webSocket, const ix::WebSocketMessagePtr& message) {
                                if (message->type == ix::WebSocketMessageType::Message) {
                                    auto json_message = json::parse(message->str);
                                    if (json_message.contains("command")) {
                                        if (json_message["command"] == "get_devices") {
                                            if (json_message.contains("host_api")) {
                                                auto devices = AudioStream::get_devices_json(
                                                    json_message["host_api"].get<std::string>());
                                                webSocket.sendText(devices.dump());
                                            } else {
                                                auto devices = AudioStream::get_devices_json();
                                                webSocket.sendText(devices.dump());
                                            }
                                        }
                                    }
                                }
                            });
        ws_server.start();
        // PeriodicTimer timer(io_context, 1s, [&ws_server]() {
        //     ws_server.broadcast(json({{"type", "ping"}}).dump());
        // });

        io_context.run();
    } catch (std::exception& e) {
        Log::error("ERR: {}", e.what());
    }
}