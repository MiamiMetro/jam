#include <algorithm>
#include <array>
#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <concurrentqueue.h>
#include <cstdint>
#include <cstring>
#include <nlohmann/json.hpp>
#include <opus.h>
#include <portaudio.h>

#include "audio_stream.hpp"
#include "logger.hpp"
#include "periodic_timer.hpp"
#include "protocol.hpp"
#include "websocket.hpp"

using asio::ip::udp;
using namespace std::chrono_literals;
using nlohmann::json;

class client {
  public:
    client(asio::io_context &io_context, const std::string &server_address, short server_port)
        : _io_context(io_context), _socket(io_context, udp::endpoint(udp::v4(), 0)),
          _ping_timer(io_context, 500ms, [this]() { _ping_timer_callback(); }),
          _alive_timer(io_context, 5s, [this]() { _alive_timer_callback(); }), _jitter_buffer_ready(false),
          _jitter_buffer_min_packets(2), _jitter_buffer_target_packets(4), _jitter_buffer_max_packets(16),
          _is_connected(false), _echo_enabled(false) {

        Log::info("Client local port: {}", _socket.local_endpoint().port());

        // Start audio stream with configuration
        audio_stream::AudioConfig config;
        config.sample_rate = 48000;
        config.bitrate = 64000;
        config.complexity = 2;
        config.frames_per_buffer = 240;
        config.input_gain = 1.0F;
        config.output_gain = 1.0F;

        auto wdm_ks_devices = audio_stream::get_devices_json("Windows WDM-KS");
        Log::info("Available Windows WDM-KS devices: {}", wdm_ks_devices.dump());

        start_audio_stream(17, 15, config);
        // start_audio_stream(38, 40, config);
        // Connect to server
        start_connection(server_address, server_port);
    }

    // Start connection to server (or switch to new server)
    void start_connection(const std::string &server_address, short server_port) {
        Log::info("Connecting to {}:{}...", server_address, server_port);

        // Resolve hostname or IP address
        udp::resolver resolver(_io_context);
        udp::resolver::results_type endpoints =
            resolver.resolve(udp::v4(), server_address, std::to_string(server_port));
        _server_endpoint = *endpoints.begin();

        Log::info("Resolved to: {}:{}", _server_endpoint.address().to_string(), _server_endpoint.port());

        _is_connected.store(true, std::memory_order_relaxed);
        do_receive();

        Log::info("Connected and receiving!");

        // Send JOIN message
        CtrlHdr chdr{};
        chdr.magic = CTRL_MAGIC;
        chdr.type = CtrlHdr::Cmd::JOIN;
        std::memcpy(_ctrl_tx_buf.data(), &chdr, sizeof(CtrlHdr));
        send(_ctrl_tx_buf.data(), sizeof(CtrlHdr));
    }

    // Stop connection (stops sending/receiving UDP packets)
    void stop_connection() {
        Log::info("Disconnecting from server...");

        _is_connected.store(false, std::memory_order_relaxed);

        // Cancel pending async operations
        _socket.cancel();

        // Clear audio receive queue
        std::vector<float> temp;
        while (_audio_recv_queue.try_dequeue(temp)) {
        }
        _jitter_buffer_ready = false;

        Log::info("Disconnected (no longer sending/receiving)");
    }

    // Check if connected to server
    bool is_connected() const { return _is_connected.load(std::memory_order_relaxed); }

    bool start_audio_stream(PaDeviceIndex inputDevice, PaDeviceIndex outputDevice,
                            const audio_stream::AudioConfig &config = audio_stream::AudioConfig{}) {
        Log::info("Starting audio stream...");
        bool success = _audio.start_audio_stream(inputDevice, outputDevice, config, audio_callback, this);
        if (success) {
            _audio.print_latency_info();
        }
        return success;
    }

    void stop_audio_stream() { _audio.stop_audio_stream(); }

    void enable_echo(bool enable) { _echo_enabled.store(enable, std::memory_order_relaxed); }

    bool is_echo_enabled() const { return _echo_enabled.load(std::memory_order_relaxed); }

    void on_receive(std::error_code error_code, std::size_t bytes) {
        if (error_code) {
            // std::cerr << "receive error: " << error_code.message() << "\n";
            do_receive(); // keep listening
            return;
        }

        if (bytes < sizeof(MsgHdr)) {
            do_receive();
            return;
        }

        MsgHdr hdr{};
        std::memcpy(&hdr, _recv_buf.data(), sizeof(MsgHdr));

        if (hdr.magic == PING_MAGIC && bytes >= sizeof(SyncHdr)) {
            _handle_ping_message(bytes);
        } else if (hdr.magic == ECHO_MAGIC && bytes >= sizeof(EchoHdr)) {
            _handle_echo_message(bytes);
        } else if (hdr.magic == AUDIO_MAGIC && bytes >= sizeof(MsgHdr) + sizeof(uint16_t)) {
            _handle_audio_message(bytes);
        } else {
            Log::warn("Unknown message: {}", std::string(_recv_buf.data(), bytes));
        }

        do_receive(); // keep listening
    }

    void do_receive() {
        // Only receive if connected
        if (!_is_connected.load(std::memory_order_relaxed)) {
            return;
        }

        _socket.async_receive_from(
            asio::buffer(_recv_buf), _server_endpoint,
            [this](std::error_code error_code, std::size_t bytes) { on_receive(error_code, bytes); });
    }

    void send(void *data, std::size_t len) {
        // Only send if connected
        if (!_is_connected.load(std::memory_order_relaxed)) {
            return;
        }

        _socket.async_send_to(asio::buffer(data, len), _server_endpoint,
                              [this](std::error_code error_code, std::size_t) {
                                  if (error_code) {
                                      Log::error("send error: {}", error_code.message());
                                  }
                              });
    }

  private:
    asio::io_context &_io_context;
    udp::socket _socket;
    udp::endpoint _server_endpoint;

    std::array<char, 1024> _recv_buf;
    std::array<unsigned char, 128> _sync_tx_buf;
    std::array<unsigned char, 128> _ctrl_tx_buf;

    audio_stream _audio;
    std::vector<float> _stereo_buffer;
    moodycamel::ConcurrentQueue<std::vector<float>> _audio_recv_queue;

    // Connection state (atomic for thread-safe access from audio callback)
    std::atomic<bool> _is_connected;

    std::atomic<bool> _echo_enabled;

    // Jitter buffer state
    std::atomic<bool> _jitter_buffer_ready;
    std::atomic<size_t> _jitter_buffer_min_packets;    // Adaptive minimum (starts at 4)
    std::atomic<size_t> _jitter_buffer_target_packets; // Adaptive target (starts at 6)
    const size_t _jitter_buffer_max_packets;           // Hard max (12 packets = 30ms)

    periodic_timer _ping_timer;
    void _ping_timer_callback() {
        static uint32_t seq = 0;
        SyncHdr shdr{};
        shdr.magic = PING_MAGIC;
        shdr.seq = seq++;
        auto now = std::chrono::steady_clock::now();
        shdr.t1_client_send = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        std::memcpy(_sync_tx_buf.data(), &shdr, sizeof(SyncHdr));
        send(_sync_tx_buf.data(), sizeof(SyncHdr));
    }
    periodic_timer _alive_timer;
    void _alive_timer_callback() {
        CtrlHdr chdr{};
        chdr.magic = CTRL_MAGIC;
        chdr.type = CtrlHdr::Cmd::ALIVE;
        std::memcpy(_ctrl_tx_buf.data(), &chdr, sizeof(CtrlHdr));
        send(_ctrl_tx_buf.data(), sizeof(CtrlHdr));
    }

    void _handle_ping_message(std::size_t bytes) {
        SyncHdr hdr{};
        std::memcpy(&hdr, _recv_buf.data(), sizeof(SyncHdr));

        auto now = std::chrono::steady_clock::now();
        auto current_time = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        auto rtt = (current_time - hdr.t1_client_send) - (hdr.t3_server_send - hdr.t2_server_recv);
        auto offset = ((hdr.t2_server_recv - hdr.t1_client_send) + (hdr.t3_server_send - current_time)) / 2;

        double rtt_ms = rtt / 1e6;
        double offset_ms = offset / 1e6;

        // print live stats
        Log::debug("seq {} RTT {:.5f} ms | offset {:.5f} ms", hdr.seq, rtt_ms, offset_ms);
    }

    void _handle_echo_message(std::size_t bytes) {
        EchoHdr ehdr{};
        std::memcpy(&ehdr, _recv_buf.data(), sizeof(EchoHdr));
        static int echo_count = 0;
        Log::info("Echo {} from server: {}", ++echo_count, std::string(ehdr.data));
    }

    void _handle_audio_message(std::size_t bytes) {
        uint16_t encoded_bytes;
        std::memcpy(&encoded_bytes, _recv_buf.data() + sizeof(MsgHdr), sizeof(uint16_t));
        size_t expected_size = sizeof(MsgHdr) + sizeof(uint16_t) + encoded_bytes;

        if (bytes < expected_size) {
            Log::error("Incomplete audio packet: got {}, expected {}", bytes, expected_size);
            do_receive();
            return;
        }

        const unsigned char *audio_data =
            reinterpret_cast<const unsigned char *>(_recv_buf.data() + sizeof(MsgHdr) + sizeof(uint16_t));

        std::vector<float> decodedData;
        if (encoded_bytes > 0) {
            _decode_audio_data(audio_data, encoded_bytes, decodedData);
        }

        if (!decodedData.empty()) {
            _process_decoded_audio(std::move(decodedData));
        }
    }

    void _decode_audio_data(const unsigned char *audio_data, uint16_t encoded_bytes, std::vector<float> &decodedData) {
        // Decode the received Opus data
        _audio.decode_opus(audio_data, encoded_bytes, 240, _audio.get_output_channel_count(), decodedData);

        // Diagnostic: Check decoded size periodically
        static int decode_count = 0;
        static int size_errors = 0;
        if (++decode_count % 400 == 0) {
            Log::debug("Client decoded {} packets, {} samples (expected {}), {} size errors", decode_count,
                       decodedData.size(), (240 * _audio.get_output_channel_count()), size_errors);
        }
        if (decodedData.size() != 240 * _audio.get_output_channel_count()) {
            size_errors++;
        }
    }

    void _process_decoded_audio(std::vector<float> decodedData) {
        // Add to jitter buffer queue
        size_t queue_size = _audio_recv_queue.size_approx();

        // Drop packet if queue is too full (prevent unbounded latency)
        if (queue_size < 16) {
            _audio_recv_queue.enqueue(std::move(decodedData));

            // Mark buffer as ready once we have enough packets
            if (!_jitter_buffer_ready && queue_size >= _jitter_buffer_min_packets) {
                _jitter_buffer_ready = true;
                Log::info("Jitter buffer ready ({} packets buffered)", queue_size);
            }
        } else {
            // Buffer overflow - drop oldest packet
            std::vector<float> discarded;
            _audio_recv_queue.try_dequeue(discarded);
            _audio_recv_queue.enqueue(std::move(decodedData));
        }
    }

    // Helper methods for audio callback to reduce cognitive complexity
    struct AudioCallbackState {
        std::vector<float> decoded_data;
        std::vector<unsigned char> encoded_data;
        int underrun_count = 0;
        int playback_count = 0;
        int consecutive_low_buffer = 0;
        int consecutive_high_buffer = 0;
        std::chrono::steady_clock::time_point last_adaptation = std::chrono::steady_clock::now();
    };

    static void handle_audio_playback(client *client_ptr, float *output_buffer, unsigned long frame_count,
                                      size_t out_channels, size_t bytes_to_copy, AudioCallbackState &state) {
        size_t queue_size = client_ptr->_audio_recv_queue.size_approx();
        size_t current_min = client_ptr->_jitter_buffer_min_packets.load();
        size_t current_target = client_ptr->_jitter_buffer_target_packets.load();

        // Jitter buffer logic: only play if buffer is ready
        if (client_ptr->_jitter_buffer_ready && client_ptr->_audio_recv_queue.try_dequeue(state.decoded_data)) {
            // Validate decoded data size matches expected output
            size_t expected_samples = frame_count * out_channels;
            if (state.decoded_data.size() == expected_samples) {
                std::memcpy(output_buffer, state.decoded_data.data(), bytes_to_copy);
            } else {
                // Size mismatch - zero output and log warning
                std::memset(output_buffer, 0, bytes_to_copy);
                static int mismatch_count = 0;
                if (++mismatch_count % 100 == 0) {
                    Log::warn("Client: Decoded size mismatch: got {} samples, expected {}", state.decoded_data.size(),
                              expected_samples);
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
            if (!client_ptr->_jitter_buffer_ready && state.underrun_count % 100 == 0) {
                // logger::debug("Buffering... ({}/{}) packets", queue_size, current_min);
            }

            // Reset buffer ready flag if we've drained completely
            if (client_ptr->_jitter_buffer_ready && queue_size == 0) {
                client_ptr->_jitter_buffer_ready = false;
                Log::warn("Jitter buffer underrun! Rebuffering...");
                state.consecutive_low_buffer = 0;
                state.consecutive_high_buffer = 0;
            }
        }
    }

    static void adapt_jitter_buffer(client *client_ptr, size_t queue_size, size_t current_min, size_t current_target,
                                    AudioCallbackState &state) {
        auto now = std::chrono::steady_clock::now();
        auto time_since_adapt = std::chrono::duration_cast<std::chrono::milliseconds>(now - state.last_adaptation);

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
                state.consecutive_low_buffer = std::max(0, state.consecutive_low_buffer - 1);
                state.consecutive_high_buffer = std::max(0, state.consecutive_high_buffer - 1);
            }

            // Increase buffer if consistently low (network jitter detected)
            if (state.consecutive_low_buffer >= 3 && current_min < client_ptr->_jitter_buffer_max_packets - 2) {
                size_t new_min = std::min(current_min + 2, client_ptr->_jitter_buffer_max_packets - 2);
                size_t new_target = std::min(current_target + 2, client_ptr->_jitter_buffer_max_packets);
                client_ptr->_jitter_buffer_min_packets.store(new_min);
                client_ptr->_jitter_buffer_target_packets.store(new_target);
                Log::info("Adaptive: Increasing buffer to min={}, target={} (high jitter detected)", new_min,
                          new_target);
                state.consecutive_low_buffer = 0;
                state.last_adaptation = now;
            }
            // Decrease buffer if consistently high (stable network, reduce latency)
            else if (state.consecutive_high_buffer >= 5 && current_min > 2) {
                size_t new_min = std::max(current_min - 1, size_t(2));
                size_t new_target = std::max(current_target - 1, size_t(3));
                client_ptr->_jitter_buffer_min_packets.store(new_min);
                client_ptr->_jitter_buffer_target_packets.store(new_target);
                Log::info("Adaptive: Decreasing buffer to min={}, target={} (stable network)", new_min, new_target);
                state.consecutive_high_buffer = 0;
                state.last_adaptation = now;
            }
        }
    }

    static void handle_echo_monitoring(const float *input_buffer, float *output_buffer, unsigned long frame_count,
                                       size_t out_channels, bool echo_enabled) {
        if (echo_enabled && (input_buffer != nullptr)) {
            float self_gain = 1.0F; // Adjust to taste (0.0–1.0)
            for (size_t i = 0; i < frame_count; ++i) {
                float sample = input_buffer[i] * self_gain;
                output_buffer[(i * out_channels) + 0] += sample; // Left
                output_buffer[(i * out_channels) + 1] += sample; // Right
            }
        }
    }

    static void handle_audio_encoding(client *client_ptr, const float *input_buffer, unsigned long frame_count,
                                      AudioCallbackState &state) {
        if (input_buffer == nullptr) {
            // No input - send silence packet periodically to keep connection alive
            static int no_input_count = 0;
            if (++no_input_count % 100 == 0) {
                Log::warn("No input audio (in == nullptr)");
            }
            return;
        }

        // Silence detection: Check if input has significant audio
        static constexpr float SILENCE_THRESHOLD = 0.001F; // -60dB
        float max_sample = 0.0F;
        for (unsigned long i = 0; i < frame_count; ++i) {
            float abs_sample = std::fabs(input_buffer[i]);
            max_sample = std::max(abs_sample, max_sample);
        }

        // Only encode and send if there's actual audio (not silence) and stream is active
        if (max_sample > SILENCE_THRESHOLD && client_ptr->_audio.is_stream_active()) {
            client_ptr->_audio.encode_opus(input_buffer, frame_count, state.encoded_data);

            // Diagnostic: Check encoding success
            static int encode_count = 0;
            static int encode_failures = 0;
            encode_count++;
            if (state.encoded_data.empty()) {
                encode_failures++;
            }
            if (encode_count % 400 == 0) {
                Log::debug("Client encoded {} packets, {} failures, last size: {} bytes, peak: {:.3f}", encode_count,
                           encode_failures, state.encoded_data.size(), max_sample);
            }

            if (!state.encoded_data.empty()) {
                AudioHdr ahdr{};
                ahdr.magic = AUDIO_MAGIC;
                ahdr.encoded_bytes = static_cast<uint16_t>(state.encoded_data.size());
                std::memcpy(ahdr.buf, state.encoded_data.data(), std::min(state.encoded_data.size(), sizeof(ahdr.buf)));
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

    static int audio_callback(const void *input, void *output, unsigned long frame_count,
                              const PaStreamCallbackTimeInfo * /*unused*/, PaStreamCallbackFlags /*unused*/,
                              void *user_data) {
        const auto *input_buffer = static_cast<const float *>(input);
        auto *output_buffer = static_cast<float *>(output);
        if (output_buffer == nullptr) {
            return paContinue;
        }

        auto *client_ptr = static_cast<client *>(user_data);

        // Use static state to avoid allocations (reused across calls)
        static AudioCallbackState state;

        size_t out_channels = client_ptr->_audio.get_output_channel_count(); // 2
        size_t bytes_to_copy = frame_count * out_channels * sizeof(float);

        // 1. Play received audio from server (with adaptive jitter buffer)
        client::handle_audio_playback(client_ptr, output_buffer, frame_count, out_channels, bytes_to_copy, state);

        // 2. Mix in your own live instrument (local monitor)
        client::handle_echo_monitoring(input_buffer, output_buffer, frame_count, out_channels,
                                       client_ptr->is_echo_enabled());

        // 3. Encode and send to server
        client::handle_audio_encoding(client_ptr, input_buffer, frame_count, state);

        return paContinue;
    }
};

int main() {
    try {
        auto &log = logger::instance();
        log.init(true, true, false, "", spdlog::level::info);

        asio::io_context io_context;
        client client_instance(io_context, "127.0.0.1", 9999);

        websocket ws_server(9969, [&client_instance](const std::shared_ptr<ix::ConnectionState> &connectionState,
                                                     ix::WebSocket &webSocket, const ix::WebSocketMessagePtr &message) {
            if (message->type == ix::WebSocketMessageType::Message) {
                auto json_message = json::parse(message->str);
                if (json_message.contains("command")) {
                    if (json_message["command"] == "get_devices") {
                        auto devices = audio_stream::get_devices_json(json_message["host_api"].get<std::string>());
                        webSocket.sendText(devices.dump());
                    }
                }
            }
        });
        ws_server.start();
        periodic_timer timer(io_context, 1s, [&ws_server]() { ws_server.broadcast(json({{"type", "ping"}}).dump()); });

        io_context.run();
    } catch (std::exception &e) {
        Log::error("ERR: {}", e.what());
    }
}