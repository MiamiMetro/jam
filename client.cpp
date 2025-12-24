#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>
#include <string>
#include <system_error>
#include <thread>
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

#include "audio_analysis.h"
#include "audio_packet.h"
#include "audio_stream.h"
#include "imguiapp.h"
#include "logger.h"
#include "message_validator.h"
#include "opus_decoder.h"
#include "opus_defines.h"
#include "opus_encoder.h"
#include "packet_builder.h"
#include "participant_info.h"
#include "participant_manager.h"
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
        AudioStream::print_all_devices();
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

        // Get output device info
        const auto* output_info = AudioStream::get_device_info(output_device);
        if (output_info == nullptr) {
            Log::error("Invalid output device");
            return false;
        }

        // Store device info
        device_info_.input_device_name  = input_info->name;
        device_info_.input_api          = (Pa_GetHostApiInfo(input_info->hostApi) != nullptr)
                                              ? Pa_GetHostApiInfo(input_info->hostApi)->name
                                              : "Unknown";
        device_info_.input_channels     = input_channels;
        device_info_.input_sample_rate  = input_info->defaultSampleRate;
        device_info_.output_device_name = output_info->name;
        device_info_.output_api         = (Pa_GetHostApiInfo(output_info->hostApi) != nullptr)
                                              ? Pa_GetHostApiInfo(output_info->hostApi)->name
                                              : "Unknown";
        device_info_.output_channels    = std::min(output_info->maxOutputChannels, 1);
        device_info_.output_sample_rate = output_info->defaultSampleRate;

        // Initialize Opus encoder for sending own audio BEFORE starting stream
        // This prevents data race where callback might access encoder during initialization
        if (!audio_encoder_.create(config.sample_rate, input_channels, OPUS_APPLICATION_VOIP,
                                   config.bitrate, config.complexity)) {
            Log::error("Failed to create Opus encoder");
            return false;
        }

        // Store encoder info (get actual bitrate from encoder)
        encoder_info_.channels       = input_channels;
        encoder_info_.sample_rate    = config.sample_rate;
        encoder_info_.bitrate        = config.bitrate;
        encoder_info_.complexity     = config.complexity;
        encoder_info_.actual_bitrate = audio_encoder_.get_actual_bitrate();

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
        return participant_manager_.count();
    }

    bool is_audio_stream_active() const {
        return audio_.is_stream_active();
    }

    std::vector<ParticipantInfo> get_participant_info() const {
        return participant_manager_.get_all_info();
    }

    // Get own audio level (for displaying user's own microphone level)
    float get_own_audio_level() const {
        return own_audio_level_.load();
    }

    // Device and encoder info structure
    struct DeviceInfo {
        std::string input_device_name;
        std::string input_api;
        int         input_channels;
        double      input_sample_rate;
        std::string output_device_name;
        std::string output_api;
        int         output_channels;
        double      output_sample_rate;
    };

    struct EncoderInfo {
        int channels;
        int sample_rate;
        int bitrate;
        int actual_bitrate;
        int complexity;
    };

    DeviceInfo get_device_info() const {
        return device_info_;
    }

    EncoderInfo get_encoder_info() const {
        return encoder_info_;
    }

    AudioStream::LatencyInfo get_latency_info() const {
        return audio_.get_latency_info();
    }

    double get_rtt_ms() const {
        return rtt_ms_.load(std::memory_order_relaxed);
    }

    AudioStream::AudioConfig get_audio_config() const {
        return audio_config_;
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
        participant_manager_.remove_participant(participant_id);
    }

    void cleanup_timer_callback() {
        // Remove participants who haven't sent packets in a while (backup cleanup)
        auto           now                 = std::chrono::steady_clock::now();
        constexpr auto PARTICIPANT_TIMEOUT = 20s;  // Longer than server timeout (15s)

        auto removed_ids =
            participant_manager_.remove_timed_out_participants(now, PARTICIPANT_TIMEOUT);

        for (uint32_t id: removed_ids) {
            Log::info(
                "Removed stale participant {} (no packets for {}s)", id,
                std::chrono::duration_cast<std::chrono::seconds>(PARTICIPANT_TIMEOUT).count());
        }
    }

    void handle_ping_message(std::size_t /*bytes*/) {
        SyncHdr hdr{};
        std::memcpy(&hdr, recv_buf_.data(), sizeof(SyncHdr));

        auto now = std::chrono::steady_clock::now();
        auto current_time =
            std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        auto rtt = (current_time - hdr.t1_client_send) - (hdr.t3_server_send - hdr.t2_server_recv);
        // auto offset =
        //     ((hdr.t2_server_recv - hdr.t1_client_send) + (hdr.t3_server_send - current_time)) /
        //     2;

        double rtt_ms = static_cast<double>(rtt) / 1e6;
        // double offset_ms = static_cast<double>(offset) / 1e6;

        // Store RTT for GUI display (thread-safe atomic update)
        rtt_ms_.store(rtt_ms, std::memory_order_relaxed);

        // print live stats
        // Log::debug("seq {} RTT {:.5f} ms | offset {:.5f} ms", hdr.seq, rtt_ms, offset_ms);
    }

    void handle_audio_message(std::size_t bytes) {
        if (!message_validator::is_valid_audio_packet(
                bytes, sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t))) {
            return;
        }

        // Extract sender_id and encoded_bytes using packet_builder
        uint32_t sender_id = packet_builder::extract_sender_id(
            reinterpret_cast<const unsigned char*>(recv_buf_.data()));
        uint16_t encoded_bytes = packet_builder::extract_encoded_bytes(
            reinterpret_cast<const unsigned char*>(recv_buf_.data()));

        size_t expected_size = sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t) + encoded_bytes;
        if (!message_validator::has_complete_payload(bytes, expected_size)) {
            Log::error("Incomplete audio packet: got {}, expected {} (encoded_bytes={})", bytes,
                       expected_size, encoded_bytes);
            return;
        }

        // Additional safety check: ensure encoded_bytes is reasonable
        if (!message_validator::is_encoded_bytes_valid(encoded_bytes, AUDIO_BUF_SIZE)) {
            Log::error("Invalid audio packet: encoded_bytes {} exceeds max {}", encoded_bytes,
                       AUDIO_BUF_SIZE);
            return;
        }

        // Register participant if not known
        if (!participant_manager_.exists(sender_id)) {
            // Validate audio_config_ before using it
            if (audio_config_.sample_rate == 0 || audio_config_.frames_per_buffer == 0) {
                Log::error(
                    "Cannot create decoder for participant {}: audio config not initialized "
                    "(sample_rate={}, frames_per_buffer={})",
                    sender_id, audio_config_.sample_rate, audio_config_.frames_per_buffer);
                return;
            }

            if (!participant_manager_.register_participant(sender_id, audio_config_.sample_rate,
                                                           audio_.get_input_channel_count())) {
                return;
            }
        }

        // Get opus data pointer
        const unsigned char* audio_data = reinterpret_cast<const unsigned char*>(
            recv_buf_.data() + sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t));

        // CRITICAL: Enqueue Opus packet, DON'T decode here
        // Decoding happens in time-driven audio_callback
        participant_manager_.with_participant(sender_id, [&](ParticipantData& participant) {
            OpusPacket packet;
            // Use memcpy for zero-allocation copy (fixed buffer)
            if (encoded_bytes <= AUDIO_BUF_SIZE) {
                std::memcpy(packet.data.data(), audio_data, encoded_bytes);
                packet.size      = encoded_bytes;
                packet.timestamp = std::chrono::steady_clock::now();
            } else {
                Log::error("Packet too large: {} bytes (max {})", encoded_bytes, AUDIO_BUF_SIZE);
                return;
            }

            size_t queue_size = participant.opus_queue.size_approx();
            if (queue_size < 16) {
                participant.opus_queue.enqueue(packet);  // OpusPacket is trivially copyable
                participant.last_packet_time = packet.timestamp;

                // Mark buffer as ready once we have enough packets
                if (!participant.buffer_ready &&
                    queue_size >= participant.jitter_buffer_min_packets) {
                    participant.buffer_ready = true;
                    Log::info("Jitter buffer ready for participant {} ({} packets)", sender_id,
                              queue_size);
                }
            } else {
                // Buffer overflow - drop oldest packet
                OpusPacket discarded;
                participant.opus_queue.try_dequeue(discarded);
                participant.opus_queue.enqueue(packet);  // OpusPacket is trivially copyable
                participant.last_packet_time = packet.timestamp;
            }
        });
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
        int active_count = 0;
        client->participant_manager_.for_each([&](uint32_t         participant_id,
                                                  ParticipantData& participant) {
            if (participant.is_muted || !participant.buffer_ready) {
                return;
            }

            OpusPacket opus_packet;

            if (participant.opus_queue.try_dequeue(opus_packet)) {
                // Decode into preallocated buffer (zero allocations)
                int decoded_samples = participant.decoder->decode_into(
                    opus_packet.get_data(), static_cast<int>(opus_packet.get_size()),
                    participant.pcm_buffer.data(), static_cast<int>(frame_count));

                if (decoded_samples <= 0) {
                    // Decode failed - use silence
                    static int decode_fail_count = 0;
                    if (++decode_fail_count % 100 == 0) {
                        Log::warn("Decode failed for participant {} ({} times)", participant_id,
                                  decode_fail_count);
                    }
                    return;
                }

                // Calculate audio level (RMS) for voice activity detection
                float rms =
                    audio_analysis::calculate_rms(participant.pcm_buffer.data(), decoded_samples);
                participant.current_level = rms;

                // Voice Activity Detection (simple threshold-based)
                bool was_speaking       = participant.is_speaking;
                participant.is_speaking = audio_analysis::detect_voice_activity(rms);

                if (participant.is_speaking && !was_speaking) {
                    Log::debug("Participant {} started speaking (level: {:.4f})", participant_id,
                               rms);
                } else if (!participant.is_speaking && was_speaking) {
                    Log::debug("Participant {} stopped speaking", participant_id);
                }

                // Mix into output with participant's gain
                size_t expected_samples = frame_count * out_channels;
                if (static_cast<size_t>(decoded_samples) == expected_samples) {
                    audio_analysis::mix_with_gain(output_buffer, participant.pcm_buffer.data(),
                                                  decoded_samples, participant.gain);
                    active_count++;
                } else if (static_cast<size_t>(decoded_samples) == frame_count) {
                    // Mono input, stereo output - duplicate channel
                    audio_analysis::mix_mono_to_stereo(output_buffer, participant.pcm_buffer.data(),
                                                       frame_count, out_channels, participant.gain);
                    active_count++;
                } else {
                    // Size mismatch - log warning occasionally
                    static int mismatch_count = 0;
                    if (++mismatch_count % 100 == 0) {
                        Log::warn(
                            "Audio size mismatch: participant {}, got {} samples, expected {}",
                            participant_id, decoded_samples, expected_samples);
                    }
                }
            } else {
                // Underrun - failed to dequeue
                size_t current_queue_size = participant.opus_queue.size_approx();
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
        });

        // Apply normalization if multiple participants to prevent clipping
        if (active_count > 1) {
            constexpr float HEADROOM = 0.5F;  // VoIP can use more headroom than broadcast
            float           gain     = HEADROOM / static_cast<float>(active_count);

            for (unsigned long i = 0; i < frame_count * out_channels; ++i) {
                output_buffer[i] *= gain;

                // Soft clip (safety limiter)
                output_buffer[i] = std::min(output_buffer[i], 1.0F);
                output_buffer[i] = std::max(output_buffer[i], -1.0F);
            }
        }

        // Encode and send own audio (always send to maintain timing, even if silence)
        if (client->audio_encoder_.is_initialized() && client->audio_.is_stream_active()) {
            std::vector<unsigned char> encoded_data;
            bool                       encode_success = false;

            if (input_buffer != nullptr) {
                // Calculate RMS for own audio level
                float rms = audio_analysis::calculate_rms(input_buffer, frame_count);
                client->own_audio_level_.store(rms);

                // Check if input is silence
                if (audio_analysis::is_silence(input_buffer, frame_count)) {
                    // Encode silence to maintain packet timing
                    std::vector<float> silence_frame(frame_count, 0.0F);
                    encode_success = client->audio_encoder_.encode(
                        silence_frame.data(), static_cast<int>(frame_count), encoded_data);
                } else {
                    // Encode actual audio
                    encode_success = client->audio_encoder_.encode(
                        input_buffer, static_cast<int>(frame_count), encoded_data);
                }
            } else {
                // No input device - encode silence to maintain timing
                std::vector<float> silence_frame(frame_count, 0.0F);
                encode_success = client->audio_encoder_.encode(
                    silence_frame.data(), static_cast<int>(frame_count), encoded_data);
            }

            // Send packet if encoding succeeded
            if (encode_success && static_cast<uint16_t>(encoded_data.size()) <= AUDIO_BUF_SIZE) {
                auto packet = audio_packet::create_audio_packet(encoded_data);
                client->send(packet->data(), packet->size(), packet);
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

    ParticipantManager participant_manager_;

    // Own audio level tracking (thread-safe with atomic)
    std::atomic<float> own_audio_level_{0.0F};

    // RTT tracking (thread-safe with atomic)
    std::atomic<double> rtt_ms_{0.0};

    // Device and encoder info storage
    DeviceInfo  device_info_;
    EncoderInfo encoder_info_;

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

    // Cache static device/config info (only updates if devices change, which is rare)
    static Client::DeviceInfo       cached_device_info;
    static Client::EncoderInfo      cached_encoder_info;
    static AudioStream::AudioConfig cached_audio_config;
    static AudioStream::LatencyInfo cached_latency_info;
    static std::string              cached_server_address;
    static unsigned short           cached_server_port = 0;
    static unsigned short           cached_local_port  = 0;
    static bool                     info_cached        = false;

    // Cache participant info and update every ~4 frames (60 FPS / 4 = ~15 updates/sec)
    static std::vector<ParticipantInfo> cached_participants;
    static size_t                       cached_participant_count    = 0;
    static int                          frame_counter               = 0;
    static constexpr int                PARTICIPANT_UPDATE_INTERVAL = 4;  // Update every 4 frames

    // Update cached info periodically (only when needed)
    if (!info_cached || frame_counter % 60 == 0) {  // Check every second for device changes
        cached_device_info    = client.get_device_info();
        cached_encoder_info   = client.get_encoder_info();
        cached_audio_config   = client.get_audio_config();
        cached_latency_info   = client.get_latency_info();
        cached_server_address = client.get_server_address();
        cached_server_port    = client.get_server_port();
        cached_local_port     = client.get_local_port();
        info_cached           = true;
    }

    // Update participant info more frequently (every few frames)
    if (frame_counter % PARTICIPANT_UPDATE_INTERVAL == 0) {
        cached_participants      = client.get_participant_info();
        cached_participant_count = client.get_participant_count();
    }
    frame_counter++;

    // Static strings to avoid allocations
    static const ImVec4 speaking_color(0.0F, 1.0F, 0.0F, 1.0F);
    static const ImVec4 not_speaking_color(0.5F, 0.5F, 0.5F, 1.0F);
    static const char*  active_text      = "Active";
    static const char*  inactive_text    = "Inactive";
    static const char*  ok_text          = "OK";
    static const char*  muted_text       = "[Muted] ";
    static const char*  buffering_text   = "[Buffering] ";
    static const char*  underruns_prefix = "[Underruns: ";

    if (ImGui::Begin("Client Info")) {
        ImGui::Text("Hello from GLFW + OpenGL3!");
        ImGui::Separator();

        // FPS and Frame Time side by side
        const float fps = ImGui::GetIO().Framerate;
        ImGui::Text("FPS: %.1f", fps);
        ImGui::SameLine(150.0F);
        ImGui::Text("Frame Time: %.3f ms", 1000.0F / fps);

        ImGui::Separator();
        ImGui::Text("Connection:");
        if (ImGui::BeginTable("Connection", 2, ImGuiTableFlags_BordersInnerV)) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::Text("Server: %s:%u", cached_server_address.c_str(), cached_server_port);
            ImGui::TableNextColumn();
            ImGui::Text("Local Port: %u", cached_local_port);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::Text("Participants: %zu", cached_participant_count);
            ImGui::TableNextColumn();
            const bool audio_active = client.is_audio_stream_active();
            ImGui::Text("Audio Stream: %s", audio_active ? active_text : inactive_text);
            ImGui::EndTable();
        }

        ImGui::Separator();
        ImGui::Text("Audio Devices:");
        if (ImGui::BeginTable("AudioDevices", 2, ImGuiTableFlags_BordersInnerV)) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::Text("Input: %s", cached_device_info.input_device_name.c_str());
            ImGui::Text("  API: %s", cached_device_info.input_api.c_str());
            ImGui::Text("  Channels: %d", cached_device_info.input_channels);
            ImGui::Text("  Sample Rate: %.0f Hz", cached_device_info.input_sample_rate);
            ImGui::TableNextColumn();
            ImGui::Text("Output: %s", cached_device_info.output_device_name.c_str());
            ImGui::Text("  API: %s", cached_device_info.output_api.c_str());
            ImGui::Text("  Channels: %d", cached_device_info.output_channels);
            ImGui::Text("  Sample Rate: %.0f Hz", cached_device_info.output_sample_rate);
            ImGui::EndTable();
        }

        ImGui::Separator();
        ImGui::Text("Audio Config:");
        if (ImGui::BeginTable("AudioConfig", 3, ImGuiTableFlags_BordersInnerV)) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::Text("Stream Config");
            ImGui::Text("  Frames/buffer: %d", cached_audio_config.frames_per_buffer);
            ImGui::Text("  Sample rate: %d Hz", cached_encoder_info.sample_rate);
            ImGui::Text("  Bitrate: %d bps", cached_encoder_info.bitrate);
            ImGui::Text("  Channels: %d in, %d out", cached_device_info.input_channels,
                        cached_device_info.output_channels);
            ImGui::TableNextColumn();
            ImGui::Text("Latency");
            ImGui::Text("  Input: %.3f ms", cached_latency_info.input_latency_ms);
            ImGui::Text("  Output: %.3f ms", cached_latency_info.output_latency_ms);
            ImGui::Text("  Sample rate: %.1f Hz", cached_latency_info.sample_rate);
            ImGui::TableNextColumn();
            ImGui::Text("Opus Encoder");
            ImGui::Text("  %dch, %dHz", cached_encoder_info.channels,
                        cached_encoder_info.sample_rate);
            ImGui::Text("  Target: %d bps", cached_encoder_info.bitrate);
            ImGui::Text("  Actual: %d bps", cached_encoder_info.actual_bitrate);
            ImGui::Text("  Complexity: %d", cached_encoder_info.complexity);
            ImGui::EndTable();
        }

        ImGui::Separator();
        if (ImGui::BeginTable("NetworkYou", 2, ImGuiTableFlags_BordersInnerV)) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::Text("Network:");
            const double rtt = client.get_rtt_ms();
            if (rtt > 0.0) {
                ImGui::Text("  RTT: %.3f ms", rtt);
            } else {
                ImGui::Text("  RTT: -- ms (no ping)");
            }
            ImGui::TableNextColumn();
            ImGui::Text("You:");
            const float own_level = client.get_own_audio_level();
            ImGui::Text("  Audio Level: %.3f", own_level);
            if (own_level > 0.01F) {
                ImGui::SameLine();
                ImGui::TextColored(speaking_color, " [Speaking]");
            }
            ImGui::EndTable();
        }

        ImGui::Separator();
        ImGui::Text("Participants:");

        if (cached_participants.empty()) {
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

                // Pre-allocate status string to avoid reallocations
                static thread_local std::string status_buffer;
                status_buffer.clear();
                status_buffer.reserve(64);  // Pre-allocate reasonable size

                for (const auto& p: cached_participants) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::Text("%u", p.id);

                    ImGui::TableNextColumn();
                    if (p.is_speaking) {
                        ImGui::TextColored(speaking_color, "Yes");
                    } else {
                        ImGui::TextColored(not_speaking_color, "No");
                    }

                    ImGui::TableNextColumn();
                    ImGui::Text("%.3f", p.audio_level);
                    // Visual level bar
                    ImGui::SameLine();
                    const float bar_width = ImGui::GetContentRegionAvail().x;
                    ImGui::ProgressBar(p.audio_level, ImVec2(bar_width * 0.3F, 0.0F), "");

                    ImGui::TableNextColumn();
                    ImGui::Text("%.2f", p.gain);

                    ImGui::TableNextColumn();
                    ImGui::Text("%zu", p.queue_size);

                    ImGui::TableNextColumn();
                    // Build status string efficiently
                    status_buffer.clear();
                    if (p.is_muted) {
                        status_buffer += muted_text;
                    }
                    if (!p.buffer_ready) {
                        status_buffer += buffering_text;
                    }
                    if (p.underrun_count > 0) {
                        status_buffer += underruns_prefix;
                        status_buffer += std::to_string(p.underrun_count);
                        status_buffer += "] ";
                    }
                    if (status_buffer.empty()) {
                        ImGui::TextUnformatted(ok_text);
                    } else {
                        ImGui::TextUnformatted(status_buffer.c_str());
                    }
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

        // Run io_context in background thread (GLFW must be on main thread on macOS)
        std::thread io_thread([&io_context]() { io_context.run(); });

        // Run UI on main thread (required for GLFW on macOS)
        {
            ImGuiApp app(900, 500, "Jam", false, 60);

            // Clean lambda - just delegates to separate function
            app.SetDrawCallback([&client_instance]() { DrawClientUI(client_instance); });

            app.SetCloseCallback([&io_context]() {
                // Stop io_context to exit the application
                io_context.stop();
            });
            app.Run();
        }

        // Clean up Client resources before exit
        client_instance.stop_audio_stream();
        client_instance.stop_connection();

        // Stop io_context and wait for network thread to finish
        io_context.stop();
        if (io_thread.joinable()) {
            io_thread.join();
        }
    } catch (std::exception& e) {
        Log::error("ERR: {}", e.what());
    }
}