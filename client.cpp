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
#include <mutex>
#include <string>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <asio.hpp>
#include <asio/buffer.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <concurrentqueue.h>
#include <imgui.h>
#include <opus.h>
#include <portaudio.h>
#include <spdlog/common.h>

#include "ImGuiApp.h"
#include "audio_stream.h"
#include "logger.h"
#include "opus_decoder.h"
#include "opus_defines.h"
#include "opus_encoder.h"
#include "periodic_timer.h"
#include "protocol.h"

using asio::ip::udp;
using namespace std::chrono_literals;

class Client {
public:
    Client(asio::io_context& io_context, const std::string& server_address, short server_port)
        : io_context_(io_context),
          socket_(io_context, udp::endpoint(udp::v4(), 0)),
          ping_timer_(io_context, 500ms, [this]() { ping_timer_callback(); }),
          alive_timer_(io_context, 5s, [this]() { alive_timer_callback(); }),
          cleanup_timer_(io_context, 10s, [this]() { cleanup_timer_callback(); }) {
        Log::info("Client local port: {}", socket_.local_endpoint().port());

        // Start audio stream with configuration
        AudioStream::AudioConfig config;
        config.sample_rate       = 48000;
        config.bitrate           = 64000;
        config.complexity        = 2;
        config.frames_per_buffer = 240;
        config.input_gain        = 1.0F;
        config.output_gain       = 1.0F;

        // Check audio stream initialization - fail gracefully if it fails
        if (!start_audio_stream(17, 15, config)) {
            Log::error("Failed to initialize audio stream - client will not function correctly");
            // Note: audio_config_ is now set even if validation fails, but the stream won't work
            // Remote audio decoding will fail gracefully with error messages
        }
        // start_audio_stream(38, 40, config);
        // Connect to server
        start_connection(server_address, server_port);
    }

    // Participant data structure (merged from ParticipantAudio and ParticipantInfo)
    struct ParticipantData {
        // Audio processing
        moodycamel::ConcurrentQueue<std::vector<float>> audio_queue;
        std::unique_ptr<OpusDecoderWrapper>             decoder;

        // Participant state
        bool                                  is_muted = false;
        float                                 gain     = 1.0F;
        std::chrono::steady_clock::time_point last_packet_time;
        size_t                                jitter_buffer_min_packets = 2;
        bool                                  buffer_ready              = false;
        int                                   underrun_count            = 0;
        float                                 current_level             = 0.0F;  // RMS audio level
        bool                                  is_speaking = false;  // Voice activity detection
    };

    // Lightweight view for UI (snapshot of ParticipantData)
    struct ParticipantInfo {
        uint32_t id;
        bool     is_speaking;
        bool     is_muted;
        float    audio_level;
        float    gain;
        bool     buffer_ready;
        size_t   queue_size;
        int      underrun_count;
    };

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

        // Send LEAVE message
        CtrlHdr chdr{};
        chdr.magic = CTRL_MAGIC;
        chdr.type  = CtrlHdr::Cmd::LEAVE;
        std::memcpy(ctrl_tx_buf_.data(), &chdr, sizeof(CtrlHdr));
        send(ctrl_tx_buf_.data(), sizeof(CtrlHdr));

        // Cancel pending async operations
        socket_.cancel();

        Log::info("Disconnected (no longer sending/receiving)");
    }

    bool start_audio_stream(PaDeviceIndex input_device, PaDeviceIndex output_device,
                            const AudioStream::AudioConfig& config = AudioStream::AudioConfig{}) {
        // Store config FIRST before any validation that could cause early return
        // This ensures audio_config_ is always set, even if validation fails
        audio_config_ = config;

        // Get input channel count from device info before creating encoder
        // (audio_.get_input_channel_count() returns 0 before stream starts)
        const auto* input_info = AudioStream::get_device_info(input_device);
        if (input_info == nullptr) {
            Log::error("Invalid input device");
            return false;
        }
        int input_channels = std::min(input_info->maxInputChannels, 1);  // Mono input

        // Initialize Opus encoder for sending own audio BEFORE starting stream
        // This prevents data race where callback might access encoder during initialization
        if (!audio_encoder_.create(config.sample_rate, input_channels, OPUS_APPLICATION_VOIP,
                                   config.bitrate, config.complexity)) {
            Log::error("Failed to create Opus encoder");
            return false;
        }

        Log::info("Starting audio stream...");
        bool success =
            audio_.start_audio_stream(input_device, output_device, config, audio_callback, this);
        if (success) {
            audio_.print_latency_info();
        } else {
            // Clean up encoder if stream start failed
            audio_encoder_.destroy();
        }
        return success;
    }

    void stop_audio_stream() {
        audio_.stop_audio_stream();
    }

    // Getters for UI access
    std::string get_server_address() const {
        return server_endpoint_.address().to_string();
    }

    unsigned short get_server_port() const {
        return server_endpoint_.port();
    }

    unsigned short get_local_port() const {
        return socket_.local_endpoint().port();
    }

    size_t get_participant_count() const {
        std::lock_guard<std::mutex> lock(participant_audio_mutex_);
        return participant_audio_.size();
    }

    bool is_audio_stream_active() const {
        return audio_.is_stream_active();
    }

    std::vector<ParticipantInfo> get_participant_info() const {
        std::lock_guard<std::mutex>  lock(participant_audio_mutex_);
        std::vector<ParticipantInfo> info;
        info.reserve(participant_audio_.size());

        for (const auto& [id, participant]: participant_audio_) {
            ParticipantInfo p_info{};
            p_info.id             = id;
            p_info.is_speaking    = participant.is_speaking;
            p_info.is_muted       = participant.is_muted;
            p_info.audio_level    = participant.current_level;
            p_info.gain           = participant.gain;
            p_info.buffer_ready   = participant.buffer_ready;
            p_info.queue_size     = participant.audio_queue.size_approx();
            p_info.underrun_count = participant.underrun_count;
            info.push_back(p_info);
        }

        return info;
    }

    // Get own audio level (for displaying user's own microphone level)
    float get_own_audio_level() const {
        return own_audio_level_.load();
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
        } else if (hdr.magic == AUDIO_MAGIC &&
                   bytes >= sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t)) {
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
        socket_.async_receive_from(asio::buffer(recv_buf_), server_endpoint_,
                                   [this](std::error_code error_code, std::size_t bytes) {
                                       on_receive(error_code, bytes);
                                   });
    }

    // Send with optional shared_ptr to keep data alive during async operation
    void send(void* data, std::size_t len,
              const std::shared_ptr<std::vector<unsigned char>>& keep_alive = nullptr) {
        socket_.async_send_to(asio::buffer(data, len), server_endpoint_,
                              [keep_alive](std::error_code error_code, std::size_t) {
                                  if (error_code) {
                                      Log::error("send error: {}", error_code.message());
                                  }
                                  // keep_alive keeps the data alive until send completes
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

    void handle_ctrl_message(std::size_t bytes) {
        if (bytes < sizeof(CtrlHdr)) {
            return;
        }

        CtrlHdr chdr{};
        std::memcpy(&chdr, recv_buf_.data(), sizeof(CtrlHdr));

        switch (chdr.type) {
            case CtrlHdr::Cmd::PARTICIPANT_LEAVE: {
                uint32_t participant_id = chdr.participant_id;
                remove_participant(participant_id);
                Log::info("Participant {} left (server notification)", participant_id);
                break;
            }
            default:
                // Other CTRL messages (JOIN, LEAVE, ALIVE) are not handled by clients
                break;
        }
    }

    void remove_participant(uint32_t participant_id) {
        std::lock_guard<std::mutex> lock(participant_audio_mutex_);
        auto                        it = participant_audio_.find(participant_id);
        if (it != participant_audio_.end()) {
            participant_audio_.erase(it);
            Log::debug("Removed participant {} from client", participant_id);
        }
    }

    void cleanup_timer_callback() {
        // Remove participants who haven't sent packets in a while (backup cleanup)
        auto           now                 = std::chrono::steady_clock::now();
        constexpr auto PARTICIPANT_TIMEOUT = 20s;  // Longer than server timeout (15s)

        std::lock_guard<std::mutex> lock(participant_audio_mutex_);
        for (auto it = participant_audio_.begin(); it != participant_audio_.end();) {
            if (now - it->second.last_packet_time > PARTICIPANT_TIMEOUT) {
                Log::info(
                    "Removing stale participant {} (no packets for {}s)", it->first,
                    std::chrono::duration_cast<std::chrono::seconds>(PARTICIPANT_TIMEOUT).count());
                it = participant_audio_.erase(it);
            } else {
                ++it;
            }
        }
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

    void handle_audio_message(std::size_t bytes) {
        if (bytes < sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t)) {
            do_receive();
            return;
        }

        // Extract sender_id and encoded_bytes
        uint32_t sender_id;
        std::memcpy(&sender_id, recv_buf_.data() + sizeof(MsgHdr), sizeof(uint32_t));

        uint16_t encoded_bytes;
        std::memcpy(&encoded_bytes, recv_buf_.data() + sizeof(MsgHdr) + sizeof(uint32_t),
                    sizeof(uint16_t));

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

        // Get or create participant audio buffer (thread-safe)
        std::lock_guard<std::mutex> lock(participant_audio_mutex_);
        if (!participant_audio_.contains(sender_id)) {
            // Validate audio_config_ before using it (protects against uninitialized config)
            if (audio_config_.sample_rate == 0 || audio_config_.frames_per_buffer == 0) {
                Log::error(
                    "Cannot create decoder for participant {}: audio config not initialized "
                    "(sample_rate={}, frames_per_buffer={})",
                    sender_id, audio_config_.sample_rate, audio_config_.frames_per_buffer);
                do_receive();
                return;
            }

            ParticipantData new_participant;
            new_participant.decoder = std::make_unique<OpusDecoderWrapper>();
            // Initialize decoder with same config as encoder (sample_rate, channels)
            // Use input channel count since participants send mono (1 channel)
            if (!new_participant.decoder->create(audio_config_.sample_rate,
                                                 audio_.get_input_channel_count())) {
                Log::error("Failed to create decoder for participant {} ({}Hz, {}ch)", sender_id,
                           audio_config_.sample_rate, audio_.get_input_channel_count());
                do_receive();
                return;
            }
            // Initialize last_packet_time to current time to prevent immediate cleanup
            new_participant.last_packet_time = std::chrono::steady_clock::now();
            participant_audio_[sender_id]    = std::move(new_participant);
            Log::info("New participant {} joined (decoder: {}Hz, {}ch)", sender_id,
                      audio_config_.sample_rate, audio_.get_input_channel_count());
        }

        auto& participant = participant_audio_[sender_id];

        // Decode audio
        const unsigned char* audio_data = reinterpret_cast<const unsigned char*>(
            recv_buf_.data() + sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t));

        std::vector<float> decoded_data;
        if (encoded_bytes > 0) {
            // Use configured frame size instead of hardcoded value to match audio callback
            // expectations
            // Validate frame_size before using it
            int frame_size = audio_config_.frames_per_buffer;
            if (frame_size == 0) {
                Log::error(
                    "Cannot decode audio from participant {}: invalid frame_size (audio "
                    "config not initialized)",
                    sender_id);
                do_receive();
                return;
            }
            if (!participant.decoder->decode(audio_data, encoded_bytes, frame_size, decoded_data)) {
                Log::warn("Failed to decode audio from participant {} (frame_size={})", sender_id,
                          frame_size);
                do_receive();
                return;
            }
        }

        // Queue decoded audio for this participant
        if (!decoded_data.empty()) {
            size_t queue_size = participant.audio_queue.size_approx();
            if (queue_size < 16) {
                participant.audio_queue.enqueue(std::move(decoded_data));
                participant.last_packet_time = std::chrono::steady_clock::now();

                // Mark buffer as ready once we have enough packets
                if (!participant.buffer_ready &&
                    queue_size >= participant.jitter_buffer_min_packets) {
                    participant.buffer_ready = true;
                    Log::info("Jitter buffer ready for participant {} ({} packets)", sender_id,
                              queue_size);
                }
            } else {
                // Buffer overflow - drop oldest packet
                std::vector<float> discarded;
                participant.audio_queue.try_dequeue(discarded);
                participant.audio_queue.enqueue(std::move(decoded_data));
                participant.last_packet_time = std::chrono::steady_clock::now();
            }
        }
    }

    static int audio_callback(const void* input, void* output, unsigned long frame_count,
                              const PaStreamCallbackTimeInfo* /*unused*/,
                              PaStreamCallbackFlags /*unused*/, void* user_data) {
        const auto* input_buffer  = static_cast<const float*>(input);
        auto*       output_buffer = static_cast<float*>(output);
        auto*       client        = static_cast<Client*>(user_data);

        if (output_buffer == nullptr) {
            return paContinue;
        }

        const size_t out_channels  = client->audio_.get_output_channel_count();
        const size_t bytes_to_copy = frame_count * out_channels * sizeof(float);

        // Initialize output buffer to silence
        std::memset(output_buffer, 0, bytes_to_copy);

        // Mix audio from all active participants (thread-safe iteration)
        std::lock_guard<std::mutex> lock(client->participant_audio_mutex_);
        for (auto& [participant_id, participant]: client->participant_audio_) {
            if (participant.is_muted || !participant.buffer_ready) {
                continue;
            }

            std::vector<float> audio_frame;

            if (participant.audio_queue.try_dequeue(audio_frame)) {
                // Calculate audio level (RMS - Root Mean Square) for voice activity detection
                float sum_squares = 0.0F;
                for (float sample: audio_frame) {
                    sum_squares += sample * sample;
                }
                float rms = std::sqrt(sum_squares / static_cast<float>(audio_frame.size()));
                participant.current_level = rms;

                // Voice Activity Detection (simple threshold-based)
                constexpr float SPEAKING_THRESHOLD = 0.01F;  // Adjust based on your audio levels
                bool            was_speaking       = participant.is_speaking;
                participant.is_speaking            = rms > SPEAKING_THRESHOLD;

                if (participant.is_speaking && !was_speaking) {
                    // Just started speaking
                    Log::debug("Participant {} started speaking (level: {:.4f})", participant_id,
                               rms);
                } else if (!participant.is_speaking && was_speaking) {
                    // Just stopped speaking
                    Log::debug("Participant {} stopped speaking", participant_id);
                }

                // Validate decoded data size
                size_t expected_samples = frame_count * out_channels;
                if (audio_frame.size() == expected_samples) {
                    // Mix into output with participant's gain
                    for (size_t i = 0; i < audio_frame.size(); ++i) {
                        output_buffer[i] += audio_frame[i] * participant.gain;
                    }
                } else if (audio_frame.size() == frame_count) {
                    // Mono input, stereo output - duplicate channel
                    for (size_t i = 0; i < frame_count; ++i) {
                        float sample = audio_frame[i] * participant.gain;
                        output_buffer[(i * out_channels) + 0] += sample;  // Left
                        if (out_channels > 1) {
                            output_buffer[(i * out_channels) + 1] += sample;  // Right
                        }
                    }
                } else {
                    // Size mismatch - log warning occasionally
                    static int mismatch_count = 0;
                    if (++mismatch_count % 100 == 0) {
                        Log::warn(
                            "Audio size mismatch: participant {}, got {} samples, expected {}",
                            participant_id, audio_frame.size(), expected_samples);
                    }
                }
            } else {
                // Underrun - failed to dequeue
                size_t current_queue_size = participant.audio_queue.size_approx();
                if (current_queue_size == 0 && participant.buffer_ready) {
                    participant.buffer_ready = false;
                    Log::warn(
                        "Jitter buffer underrun for participant {}! Rebuffering... (queue: {} "
                        "packets)",
                        participant_id, current_queue_size);
                } else if (participant.buffer_ready) {
                    // Log underrun with queue size info (use per-participant counter)
                    if (++participant.underrun_count % 20 == 0) {
                        Log::warn(
                            "Jitter buffer underrun for participant {} (queue: {} packets, min: "
                            "{})",
                            participant_id, current_queue_size,
                            participant.jitter_buffer_min_packets);
                    }
                }
            }
        }

        // Encode and send own audio (always send to maintain timing, even if silence)
        if (client->audio_encoder_.is_initialized() && client->audio_.is_stream_active()) {
            std::vector<unsigned char> encoded_data;
            bool                       encode_success = false;

            if (input_buffer != nullptr) {
                // Calculate RMS (Root Mean Square) for own audio level
                float sum_squares = 0.0F;
                for (unsigned long i = 0; i < frame_count; ++i) {
                    sum_squares += input_buffer[i] * input_buffer[i];
                }
                float rms = std::sqrt(sum_squares / static_cast<float>(frame_count));
                client->own_audio_level_.store(rms);

                // Silence detection: Check if input has significant audio
                static constexpr float SILENCE_THRESHOLD = 0.001F;  // -60dB
                float                  max_sample        = 0.0F;
                for (unsigned long i = 0; i < frame_count; ++i) {
                    float abs_sample = std::fabs(input_buffer[i]);
                    max_sample       = std::max(abs_sample, max_sample);
                }

                if (max_sample > SILENCE_THRESHOLD) {
                    // Encode actual audio
                    encode_success = client->audio_encoder_.encode(
                        input_buffer, static_cast<int>(frame_count), encoded_data);
                } else {
                    // Encode silence to maintain packet timing
                    std::vector<float> silence_frame(frame_count, 0.0F);
                    encode_success = client->audio_encoder_.encode(
                        silence_frame.data(), static_cast<int>(frame_count), encoded_data);
                }
            } else {
                // No input device - encode silence to maintain timing
                std::vector<float> silence_frame(frame_count, 0.0F);
                encode_success = client->audio_encoder_.encode(
                    silence_frame.data(), static_cast<int>(frame_count), encoded_data);
            }

            // Always send packets (even silence) to maintain timing and prevent buffer underruns
            // Note: Opus may return empty encoded_data for silence, but we should still send
            // a minimal packet to maintain timing. However, if encoding failed, skip sending.
            if (encode_success) {
                // Opus can encode silence as empty or very small packets - send them anyway
                // encoded_bytes = 0 is valid and indicates a silence packet
                uint16_t encoded_bytes = static_cast<uint16_t>(encoded_data.size());

                // Always send packet (even if encoded_bytes == 0 for silence) to maintain timing
                if (encoded_bytes <= AUDIO_BUF_SIZE) {
                    // Construct packet in a buffer: magic + sender_id + encoded_bytes + data
                    std::vector<unsigned char> packet;
                    packet.reserve(sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t) +
                                   encoded_bytes);

                    // Write magic
                    uint32_t magic = AUDIO_MAGIC;
                    packet.insert(packet.end(), reinterpret_cast<unsigned char*>(&magic),
                                  reinterpret_cast<unsigned char*>(&magic) + sizeof(uint32_t));

                    // Write sender_id (0, server will overwrite)
                    uint32_t sender_id = 0;
                    packet.insert(packet.end(), reinterpret_cast<unsigned char*>(&sender_id),
                                  reinterpret_cast<unsigned char*>(&sender_id) + sizeof(uint32_t));

                    // Write encoded_bytes (may be 0 for silence)
                    packet.insert(
                        packet.end(), reinterpret_cast<unsigned char*>(&encoded_bytes),
                        reinterpret_cast<unsigned char*>(&encoded_bytes) + sizeof(uint16_t));

                    // Write encoded audio data (if any - Opus may encode silence as empty)
                    if (encoded_bytes > 0) {
                        packet.insert(packet.end(), encoded_data.begin(), encoded_data.end());
                    }
                    // If encoded_bytes == 0, we still send the packet header to maintain timing

                    // Send the complete packet (header + optional data)
                    // Copy packet data to persistent storage before async send
                    // to avoid dangling pointer when callback returns
                    auto packet_copy =
                        std::make_shared<std::vector<unsigned char>>(std::move(packet));
                    client->send(packet_copy->data(), packet_copy->size(), packet_copy);
                }
            }
        }

        return paContinue;
    }

    asio::io_context& io_context_;
    udp::socket       socket_;
    udp::endpoint     server_endpoint_;

    std::array<char, 1024>         recv_buf_;
    std::array<unsigned char, 128> sync_tx_buf_;
    std::array<unsigned char, 128> ctrl_tx_buf_;

    AudioStream              audio_;
    OpusEncoderWrapper       audio_encoder_;
    AudioStream::AudioConfig audio_config_;  // Store config for decoder initialization

    // Thread-safe access to participant_audio_ map
    mutable std::mutex                            participant_audio_mutex_;
    std::unordered_map<uint32_t, ParticipantData> participant_audio_;

    // Own audio level tracking (thread-safe with atomic)
    std::atomic<float> own_audio_level_{0.0F};

    PeriodicTimer ping_timer_;
    PeriodicTimer alive_timer_;
    PeriodicTimer cleanup_timer_;
};

void DrawClientUI(Client& client) {
    // Show demo window (can be closed) - only call when open
    // Closed by default for better performance
    static bool demo_open = false;
    if (demo_open) {
        ImGui::ShowDemoWindow(&demo_open);
    }

    // Your custom windows here
    bool window_open = true;

    if (ImGui::Begin("Client Info", &window_open)) {
        ImGui::Text("Hello from GLFW + OpenGL3!");
        ImGui::Separator();
        ImGui::Text("FPS: %.1f", ImGui::GetIO().Framerate);
        ImGui::Text("Frame Time: %.3f ms", 1000.0F / ImGui::GetIO().Framerate);

        ImGui::Separator();
        ImGui::Text("Connection:");
        ImGui::Text("  Server: %s:%u", client.get_server_address().c_str(),
                    client.get_server_port());
        ImGui::Text("  Local Port: %u", client.get_local_port());
        ImGui::Text("  Participants: %zu", client.get_participant_count());
        ImGui::Text("  Audio Stream: %s", client.is_audio_stream_active() ? "Active" : "Inactive");

        ImGui::Separator();
        ImGui::Text("You:");
        float own_level = client.get_own_audio_level();
        ImGui::Text("  Audio Level: %.3f", own_level);
        if (own_level > 0.01F) {
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(0.0F, 1.0F, 0.0F, 1.0F), " [Speaking]");
        }

        ImGui::Separator();
        ImGui::Text("Participants:");

        auto participants = client.get_participant_info();
        if (participants.empty()) {
            ImGui::Text("  No other participants");
        } else {
            if (ImGui::BeginTable(
                    "Participants", 6,
                    ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
                ImGui::TableSetupColumn("ID", ImGuiTableColumnFlags_WidthFixed, 50.0F);
                ImGui::TableSetupColumn("Speaking", ImGuiTableColumnFlags_WidthFixed, 80.0F);
                ImGui::TableSetupColumn("Level", ImGuiTableColumnFlags_WidthFixed, 80.0F);
                ImGui::TableSetupColumn("Gain", ImGuiTableColumnFlags_WidthFixed, 60.0F);
                ImGui::TableSetupColumn("Queue", ImGuiTableColumnFlags_WidthFixed, 60.0F);
                ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();

                for (const auto& p: participants) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::Text("%u", p.id);

                    ImGui::TableNextColumn();
                    if (p.is_speaking) {
                        ImGui::TextColored(ImVec4(0.0F, 1.0F, 0.0F, 1.0F), "Yes");
                    } else {
                        ImGui::TextColored(ImVec4(0.5F, 0.5F, 0.5F, 1.0F), "No");
                    }

                    ImGui::TableNextColumn();
                    ImGui::Text("%.3f", p.audio_level);
                    // Visual level bar
                    ImGui::SameLine();
                    float bar_width = ImGui::GetContentRegionAvail().x;
                    ImGui::ProgressBar(p.audio_level, ImVec2(bar_width * 0.3F, 0.0F), "");

                    ImGui::TableNextColumn();
                    ImGui::Text("%.2f", p.gain);

                    ImGui::TableNextColumn();
                    ImGui::Text("%zu", p.queue_size);

                    ImGui::TableNextColumn();
                    std::string status;
                    if (p.is_muted) {
                        status += "[Muted] ";
                    }
                    if (!p.buffer_ready) {
                        status += "[Buffering] ";
                    }
                    if (p.underrun_count > 0) {
                        status += "[Underruns: " + std::to_string(p.underrun_count) + "] ";
                    }
                    if (status.empty()) {
                        status = "OK";
                    }
                    ImGui::Text("%s", status.c_str());
                }

                ImGui::EndTable();
            }
        }
    }
    ImGui::End();
}

int main() {
    try {
        auto& log = Logger::instance();
        log.init(true, true, false, "", spdlog::level::info);

        asio::io_context io_context;

        Client client_instance(io_context, "127.0.0.1", 9999);

        std::thread ui_thread([&io_context, &client_instance]() {
            // Enable VSync for efficient FPS limiting (hardware-accelerated)
            ImGuiApp app(640, 480, "Jam", true, 60);

            // Clean lambda - just delegates to separate function
            app.SetDrawCallback([&client_instance]() { DrawClientUI(client_instance); });

            app.SetCloseCallback([&io_context]() {
                // Stop io_context to exit the application
                io_context.stop();
            });
            app.Run();
        });

        // Run io_context until window closes
        io_context.run();

        // Clean up Client resources before exit
        client_instance.stop_audio_stream();
        client_instance.stop_connection();

        // Wait for UI thread to finish
        if (ui_thread.joinable()) {
            ui_thread.join();
        }
    } catch (std::exception& e) {
        Log::error("ERR: {}", e.what());
    }
}