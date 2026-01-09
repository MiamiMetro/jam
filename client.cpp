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
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX  // Prevent Windows from defining min/max macros
#endif
#include <winsock2.h>  // Must come before windows.h
#include <windows.h>   // For SetThreadPriority
#endif

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
#include "gui.h"
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
#include "wav_file_playback.h"

using asio::ip::udp;
using namespace std::chrono_literals;

class Client {
public:
    Client(asio::io_context& io_context, const std::string& server_address, short server_port)
        : io_context_(io_context),
          socket_(io_context, udp::endpoint(udp::v4(), 0)),
          selected_input_device_(paNoDevice),
          selected_output_device_(paNoDevice),
          ping_timer_(io_context, 500ms, [this]() { ping_timer_callback(); }),
          alive_timer_(io_context, 5s, [this]() { alive_timer_callback(); }),
          cleanup_timer_(io_context, 10s, [this]() { cleanup_timer_callback(); }) {
        Log::info("Client local port: {}", socket_.local_endpoint().port());

        // Optimize UDP socket buffers for low-latency audio streaming
        try {
            socket_.set_option(asio::socket_base::receive_buffer_size(65536));
            socket_.set_option(asio::socket_base::send_buffer_size(65536));
            Log::info("UDP socket buffers optimized for low latency");
        } catch (const std::exception& e) {
            Log::warn("Failed to set socket buffer sizes: {}", e.what());
        }

        // Initialize audio config with defaults (but don't start stream yet)
        audio_config_.sample_rate       = 48000;
        audio_config_.bitrate           = 64000;
        audio_config_.complexity        = 2;
        audio_config_.frames_per_buffer = 240;  // 5ms (optimal for stability)
        audio_config_.input_gain        = 1.0F;
        audio_config_.output_gain       = 1.0F;

        // Set default devices
        selected_input_device_  = AudioStream::get_default_input_device();
        selected_output_device_ = AudioStream::get_default_output_device();

        // Initialize device info with default devices
        if (selected_input_device_ != paNoDevice) {
            set_input_device(selected_input_device_);
        }
        if (selected_output_device_ != paNoDevice) {
            set_output_device(selected_output_device_);
        }

        AudioStream::print_all_devices();
        // Connect to server (audio stream will be started manually via UI)
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

    // Microphone mute control
    void set_mic_muted(bool muted) {
        mic_muted_.store(muted, std::memory_order_release);
    }

    bool get_mic_muted() const {
        return mic_muted_.load(std::memory_order_acquire);
    }

    // Master input gain control (0.0 - 2.0, 1.0 = unity)
    void set_input_gain(float gain) {
        input_gain_.store(std::clamp(gain, 0.0F, 2.0F), std::memory_order_release);
    }

    float get_input_gain() const {
        return input_gain_.load(std::memory_order_acquire);
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

    uint64_t get_total_bytes_rx() const {
        return total_bytes_rx_.load(std::memory_order_relaxed);
    }

    uint64_t get_total_bytes_tx() const {
        return total_bytes_tx_.load(std::memory_order_relaxed);
    }

    AudioStream::AudioConfig get_audio_config() const {
        return audio_config_;
    }

    // WAV file playback methods
    bool load_wav_file(const std::string& path) {
        return wav_playback_.load_file(path);
    }

    void wav_play() {
        wav_playback_.play();
    }

    void wav_pause() {
        wav_playback_.pause();
    }

    void wav_seek(int64_t frame_position) {
        wav_playback_.seek(frame_position);
    }

    struct WavState {
        bool    is_loaded;
        bool    is_playing;
        int64_t position;
        int64_t total_frames;
        int     sample_rate;
        int     channels;
        float   gain;
        bool    muted_local;  // Muted locally (still sends over network)
    };

    void set_wav_gain(float gain) {
        wav_gain_.store(std::max(0.0F, std::min(2.0F, gain)), std::memory_order_release);
    }

    float get_wav_gain() const {
        return wav_gain_.load(std::memory_order_acquire);
    }

    void set_wav_muted_local(bool muted) {
        wav_muted_local_.store(muted, std::memory_order_release);
    }

    bool get_wav_muted_local() const {
        return wav_muted_local_.load(std::memory_order_acquire);
    }

    WavState get_wav_state() const {
        WavState state{};
        state.is_loaded    = wav_playback_.is_loaded();
        state.is_playing   = wav_playback_.is_playing();
        state.position     = wav_playback_.get_position();
        state.total_frames = wav_playback_.get_total_frames();
        state.sample_rate  = wav_playback_.get_sample_rate();
        state.channels     = wav_playback_.get_channels();
        state.gain         = wav_gain_.load(std::memory_order_acquire);
        state.muted_local  = wav_muted_local_.load(std::memory_order_acquire);
        return state;
    }

    // Device selection methods (removed - use AudioStream static methods directly)

    PaDeviceIndex get_selected_input_device() const {
        return selected_input_device_;
    }

    PaDeviceIndex get_selected_output_device() const {
        return selected_output_device_;
    }

    bool set_input_device(PaDeviceIndex device_index) {
        if (!AudioStream::is_device_valid(device_index)) {
            Log::error("Invalid input device index: {}", device_index);
            return false;
        }
        selected_input_device_ = device_index;

        // Update device info for UI display
        const auto* input_info = AudioStream::get_device_info(device_index);
        if (input_info != nullptr) {
            device_info_.input_device_name = input_info->name;
            device_info_.input_api         = (Pa_GetHostApiInfo(input_info->hostApi) != nullptr)
                                                 ? Pa_GetHostApiInfo(input_info->hostApi)->name
                                                 : "Unknown";
            device_info_.input_channels    = std::min(input_info->maxInputChannels, 1);
            device_info_.input_sample_rate = input_info->defaultSampleRate;
        }
        return true;
    }

    bool set_output_device(PaDeviceIndex device_index) {
        if (!AudioStream::is_device_valid(device_index)) {
            Log::error("Invalid output device index: {}", device_index);
            return false;
        }
        selected_output_device_ = device_index;

        // Update device info for UI display
        const auto* output_info = AudioStream::get_device_info(device_index);
        if (output_info != nullptr) {
            device_info_.output_device_name = output_info->name;
            device_info_.output_api         = (Pa_GetHostApiInfo(output_info->hostApi) != nullptr)
                                                  ? Pa_GetHostApiInfo(output_info->hostApi)->name
                                                  : "Unknown";
            device_info_.output_channels    = std::min(output_info->maxOutputChannels, 1);
            device_info_.output_sample_rate = output_info->defaultSampleRate;
        }
        return true;
    }

    // Hot-swap audio devices (stops current stream and starts new one)
    bool swap_audio_devices(PaDeviceIndex input_device, PaDeviceIndex output_device) {
        bool was_active = audio_.is_stream_active();

        // Stop current stream if active
        if (was_active) {
            stop_audio_stream();
        }

        // Update selected devices
        selected_input_device_  = input_device;
        selected_output_device_ = output_device;

        // Start new stream if it was active before
        if (was_active) {
            return start_audio_stream(input_device, output_device, audio_config_);
        }

        return true;
    }

    // =========================================================================
    // Participant control methods (mute, gain, pan)
    // =========================================================================

    // Set participant mute state
    void set_participant_muted(uint32_t id, bool muted) {
        participant_manager_.with_participant(id,
                                              [muted](ParticipantData& p) { p.is_muted = muted; });
    }

    // Get participant mute state
    bool get_participant_muted(uint32_t id) {
        bool muted = false;
        participant_manager_.with_participant(id,
                                              [&muted](ParticipantData& p) { muted = p.is_muted; });
        return muted;
    }

    // Set participant gain (0.0 - 2.0, 1.0 = unity)
    void set_participant_gain(uint32_t id, float gain) {
        participant_manager_.with_participant(
            id, [gain](ParticipantData& p) { p.gain = std::clamp(gain, 0.0F, 2.0F); });
    }

    // Get participant gain
    float get_participant_gain(uint32_t id) {
        float gain = 1.0F;
        participant_manager_.with_participant(id, [&gain](ParticipantData& p) { gain = p.gain; });
        return gain;
    }

    // Set participant pan (0.0 = full left, 0.5 = center, 1.0 = full right)
    void set_participant_pan(uint32_t id, float pan) {
        participant_manager_.with_participant(
            id, [pan](ParticipantData& p) { p.pan = std::clamp(pan, 0.0F, 1.0F); });
    }

    // Get participant pan
    float get_participant_pan(uint32_t id) {
        float pan = 0.5F;
        participant_manager_.with_participant(id, [&pan](ParticipantData& p) { pan = p.pan; });
        return pan;
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
        // Add to total bytes sent
        total_bytes_tx_.fetch_add(len, std::memory_order_relaxed);
        
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
        // Add to total bytes received
        total_bytes_rx_.fetch_add(bytes, std::memory_order_relaxed);

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

    void handle_ping_message(std::size_t bytes) {
        // Add to total bytes received
        total_bytes_rx_.fetch_add(bytes, std::memory_order_relaxed);

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

            // Get channel count - use 1 (mono) as default if stream isn't active
            int channel_count = audio_.get_input_channel_count();
            if (channel_count == 0) {
                channel_count = 1;  // Default to mono for VoIP
            }

            if (!participant_manager_.register_participant(sender_id, audio_config_.sample_rate,
                                                           channel_count)) {
                return;
            }
        }

        // Add to total bytes received
        total_bytes_rx_.fetch_add(bytes, std::memory_order_relaxed);

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

            // Adaptive queue management: drop old packets if queue is too large
            // This keeps latency bounded to TARGET_OPUS_QUEUE_SIZE + 2 packets
            while (queue_size > TARGET_OPUS_QUEUE_SIZE + 2) {
                OpusPacket discarded;
                if (participant.opus_queue.try_dequeue(discarded)) {
                    queue_size--;
                } else {
                    break;
                }
            }

            if (queue_size < MAX_OPUS_QUEUE_SIZE) {
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
                // Buffer overflow - drop oldest packet (safety limit)
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

#ifdef _WIN32
        // Boost thread priority on Windows for minimal audio latency
        static bool priority_set = false;
        if (!priority_set) {
            SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
            priority_set = true;
        }
#endif

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

                // Adaptive jitter buffer: track queue size history and adjust minimum
                size_t current_queue_size = participant.opus_queue.size_approx();
                participant.queue_size_history[participant.history_index] = current_queue_size;
                participant.history_index =
                    (participant.history_index + 1) % participant.queue_size_history.size();

                // Calculate average queue size over history window
                size_t total = 0;
                for (size_t qs: participant.queue_size_history) {
                    total += qs;
                }
                size_t avg_queue_size = total / participant.queue_size_history.size();

                // Adaptive adjustment: increase buffer if queue is often low (jittery network)
                // Decrease buffer if queue is consistently high (stable network, reduce latency)
                constexpr size_t MAX_JITTER_BUFFER_PACKETS = 5;  // Upper limit for adaptation
                if (avg_queue_size < 2 &&
                    participant.jitter_buffer_min_packets < MAX_JITTER_BUFFER_PACKETS) {
                    participant.jitter_buffer_min_packets++;
                    Log::debug("Participant {} jitter buffer increased to {} (avg queue: {})",
                               participant_id, participant.jitter_buffer_min_packets,
                               avg_queue_size);
                } else if (avg_queue_size > 4 &&
                           participant.jitter_buffer_min_packets > MIN_JITTER_BUFFER_PACKETS) {
                    participant.jitter_buffer_min_packets--;
                    Log::debug("Participant {} jitter buffer decreased to {} (avg queue: {})",
                               participant_id, participant.jitter_buffer_min_packets,
                               avg_queue_size);
                }
            } else {
                // Underrun - use PLC instead of silence for smoother audio
                size_t current_queue_size = participant.opus_queue.size_approx();

                // Use Opus PLC to generate concealment audio
                int plc_samples = participant.decoder->decode_plc(participant.pcm_buffer.data(),
                                                                  static_cast<int>(frame_count));

                if (plc_samples > 0) {
                    // Mix PLC output (same as normal decode path)
                    size_t expected_samples = frame_count * out_channels;
                    if (static_cast<size_t>(plc_samples) == expected_samples) {
                        audio_analysis::mix_with_gain(output_buffer, participant.pcm_buffer.data(),
                                                      plc_samples, participant.gain);
                    } else if (static_cast<size_t>(plc_samples) == frame_count) {
                        // Mono PLC, stereo output - duplicate channel
                        audio_analysis::mix_mono_to_stereo(
                            output_buffer, participant.pcm_buffer.data(), frame_count, out_channels,
                            participant.gain);
                    }
                    participant.plc_count++;
                }

                // Handle rebuffering state (reduced logging - PLC handles gaps silently)
                if (current_queue_size == 0 && participant.buffer_ready) {
                    participant.buffer_ready = false;
                    participant.underrun_count++;
                    // Only log first rebuffer or every 10th to reduce noise
                    if (participant.underrun_count == 1 || participant.underrun_count % 10 == 0) {
                        Log::info("Participant {} rebuffering (underruns: {}, PLC: {})",
                                  participant_id, participant.underrun_count,
                                  participant.plc_count);
                    }
                } else if (participant.buffer_ready) {
                    participant.underrun_count++;
                }
            }
        });

        // Mix WAV file audio for local output (if loaded and playing)
        // WAV and mic are completely independent - WAV can work without mic, mic can work without
        // WAV
        std::array<float, 480>
             wav_buffer{};  // Buffer for WAV audio (sized for max possible frame_count)
        int  wav_frames_read = 0;
        bool wav_active      = false;

        if (client->wav_playback_.is_loaded() && client->wav_playback_.is_playing()) {
            wav_frames_read =
                client->wav_playback_.read(wav_buffer.data(), static_cast<int>(frame_count),
                                           client->audio_config_.sample_rate);
            if (wav_frames_read > 0) {
                wav_active = true;  // Only set active if we actually read frames (handles EOF case)

                // Mix WAV into local output buffer only if not muted locally
                if (!client->wav_muted_local_.load(std::memory_order_acquire)) {
                    float wav_gain = client->wav_gain_.load(std::memory_order_acquire);
                    if (out_channels == 1) {
                        audio_analysis::mix_with_gain(output_buffer, wav_buffer.data(),
                                                      wav_frames_read, wav_gain);
                    } else {
                        // Stereo output - duplicate mono WAV to both channels
                        audio_analysis::mix_mono_to_stereo(output_buffer, wav_buffer.data(),
                                                           wav_frames_read, out_channels, wav_gain);
                    }
                    active_count++;
                }
                // Note: WAV is still sent over network even if muted locally (handled in encoding
                // section)
            }
        }

        // Apply normalization if multiple sources to prevent clipping
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
        // Mix WAV with microphone input before encoding
        if (client->audio_encoder_.is_initialized() && client->audio_.is_stream_active()) {
            std::vector<unsigned char> encoded_data;
            bool                       encode_success = false;

            // Prepare mixed input buffer (WAV + mic)
            std::array<float, 480>
                mixed_input{};  // Buffer for mixed audio (sized for max possible frame_count)

            if (wav_active && wav_frames_read > 0) {
                // Copy WAV data first and apply gain
                // mixed_input is already zero-initialized, so any remaining frames are silence
                float wav_gain = client->wav_gain_.load(std::memory_order_acquire);
                for (int i = 0; i < wav_frames_read; ++i) {
                    mixed_input[i] = wav_buffer[i] * wav_gain;
                }
                // Note: If wav_frames_read < frame_count, remaining frames stay as 0.0F (silence)

                // Mix microphone input if available and not muted
                if (input_buffer != nullptr &&
                    !client->mic_muted_.load(std::memory_order_acquire)) {
                    // Apply input gain to mic and mix with WAV (average mixing to prevent clipping)
                    float input_gain = client->input_gain_.load(std::memory_order_acquire);
                    for (unsigned long i = 0; i < frame_count; ++i) {
                        mixed_input[i] = (mixed_input[i] + input_buffer[i] * input_gain) * 0.5F;
                    }
                    // Calculate RMS for own audio level (from mixed signal)
                    float rms = audio_analysis::calculate_rms(mixed_input.data(),
                                                              static_cast<int>(frame_count));
                    client->own_audio_level_.store(rms);
                } else {
                    // No mic or mic muted - apply same scaling to WAV for consistent volume
                    // When mixing with mic we use 0.5F, so apply 0.5F here too to keep WAV volume
                    // consistent
                    constexpr float MIX_SCALE = 0.5F;
                    for (unsigned long i = 0; i < frame_count; ++i) {
                        mixed_input[i] *= MIX_SCALE;
                    }
                    // Calculate RMS for own audio level (from WAV signal)
                    float rms = audio_analysis::calculate_rms(mixed_input.data(),
                                                              static_cast<int>(frame_count));
                    client->own_audio_level_.store(rms);
                }

                // Encode mixed audio (WAV + optional mic, or just WAV)
                encode_success = client->audio_encoder_.encode(
                    mixed_input.data(), static_cast<int>(frame_count), encoded_data);
            } else {
                // No WAV active - use original behavior (mic only or silence)
                // This branch preserves exact backward compatibility when WAV is not in use
                if (input_buffer != nullptr &&
                    !client->mic_muted_.load(std::memory_order_acquire)) {
                    // Apply input gain to mic
                    float input_gain = client->input_gain_.load(std::memory_order_acquire);
                    std::array<float, 960> gained_input{};  // Max frame size
                    for (unsigned long i = 0; i < frame_count; ++i) {
                        gained_input[i] = input_buffer[i] * input_gain;
                    }

                    // Calculate RMS for own audio level (after gain)
                    float rms = audio_analysis::calculate_rms(gained_input.data(), frame_count);
                    client->own_audio_level_.store(rms);

                    // Check if input is silence
                    if (audio_analysis::is_silence(gained_input.data(), frame_count)) {
                        // Encode silence to maintain packet timing
                        std::vector<float> silence_frame(frame_count, 0.0F);
                        encode_success = client->audio_encoder_.encode(
                            silence_frame.data(), static_cast<int>(frame_count), encoded_data);
                    } else {
                        // Encode actual audio with gain applied
                        encode_success = client->audio_encoder_.encode(
                            gained_input.data(), static_cast<int>(frame_count), encoded_data);
                    }
                } else {
                    // Mic muted or no input device - encode silence to maintain timing
                    std::vector<float> silence_frame(frame_count, 0.0F);
                    encode_success = client->audio_encoder_.encode(
                        silence_frame.data(), static_cast<int>(frame_count), encoded_data);
                }
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
    WavFilePlayback    wav_playback_;

    // WAV playback volume/gain (thread-safe with atomic)
    std::atomic<float> wav_gain_{1.0F};          // Default to 100% volume
    std::atomic<bool>  wav_muted_local_{false};  // Mute locally (still sends over network)

    // Microphone mute (thread-safe with atomic)
    std::atomic<bool> mic_muted_{false};  // Mute mic (doesn't send to server)

    // Master input gain (thread-safe with atomic) - 1.0 = unity
    std::atomic<float> input_gain_{1.0F};

    // Own audio level tracking (thread-safe with atomic)
    std::atomic<float> own_audio_level_{0.0F};

    // RTT tracking (thread-safe with atomic)
    std::atomic<double> rtt_ms_{0.0};

    // Total bytes sent/received (cumulative counters)
    std::atomic<uint64_t> total_bytes_rx_{0};
    std::atomic<uint64_t> total_bytes_tx_{0};

    // Device and encoder info storage
    DeviceInfo  device_info_;
    EncoderInfo encoder_info_;

    // Selected devices (for UI)
    PaDeviceIndex selected_input_device_;
    PaDeviceIndex selected_output_device_;

    PeriodicTimer ping_timer_;
    PeriodicTimer alive_timer_;
    PeriodicTimer cleanup_timer_;
};

// =============================================================================
// Zynlab-Style Jam Client UI
// =============================================================================

// Layout constants
static constexpr float TRACK_WIDTH = 140.0F;  // Wider strips
// FADER_HEIGHT removed - now dynamically calculated based on window size
static constexpr float METER_WIDTH  = 20.0F;
static constexpr float KNOB_SIZE    = 50.0F;
static constexpr float MASTER_WIDTH = 160.0F;  // Wider master

// Draw the master (your own audio) channel strip with WAV controls
static void draw_master_strip(Client& client, float available_height) {
    ImGuiStyle& style       = ImGui::GetStyle();
    float       strip_width = MASTER_WIDTH;
    float       line_height = ImGui::GetTextLineHeightWithSpacing();

    // Dynamic fader height - scale with available space, min 200, max based on window
    float fader_height = std::max(200.0F, available_height - 350.0F);

    // Padding constant
    constexpr float PADDING = 8.0F;

    ImGui::BeginChild("MasterStrip", ImVec2(strip_width, 0), ImGuiChildFlags_None);
    {
        float width = ImGui::GetContentRegionAvail().x - PADDING;
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (PADDING / 2.0F));

        // Title
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2F, 0.4F, 0.6F, 1.0F));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.25F, 0.5F, 0.7F, 1.0F));
        ImGui::Button("YOU", ImVec2(width, 0));
        ImGui::PopStyleColor(2);

        ImGui::Spacing();
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (PADDING / 2.0F));

        // Mute button - explicit MUTE/UNMUTE text
        bool mic_muted = client.get_mic_muted();
        ImGui::PushStyleColor(ImGuiCol_Button, mic_muted ? ImVec4(0.8F, 0.2F, 0.2F, 1.0F)
                                                         : ImVec4(0.2F, 0.5F, 0.3F, 1.0F));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, mic_muted ? ImVec4(0.9F, 0.3F, 0.3F, 1.0F)
                                                                : ImVec4(0.3F, 0.6F, 0.4F, 1.0F));
        if (ImGui::Button(mic_muted ? "UNMUTE" : "MUTE", ImVec2(width, 0))) {
            client.set_mic_muted(!mic_muted);
        }
        JamGui::ShowTooltipOnHover("Click to toggle microphone mute");
        ImGui::PopStyleColor(2);

        ImGui::Spacing();

        // Level meter and fader section
        float own_level = client.get_own_audio_level();
        int   meter_val = static_cast<int>(own_level * fader_height);

        // Center the meter + fader
        float total_control_width = METER_WIDTH + style.ItemSpacing.x + METER_WIDTH;
        float offset              = (strip_width - total_control_width) / 2.0F;

        ImGui::SetCursorPosX(offset);
        JamGui::UvMeter("##MasterMeter", ImVec2(METER_WIDTH, fader_height), &meter_val, 0,
                        static_cast<int>(fader_height));
        ImGui::SameLine();

        // Master volume fader (0-200, 100 = unity gain)
        static int master_vol = 100;
        // Sync from client when not dragging
        if (!ImGui::IsItemActive()) {
            master_vol = static_cast<int>(client.get_input_gain() * 100.0F);
        }
        if (JamGui::Fader("##MasterFader", ImVec2(METER_WIDTH, fader_height), &master_vol, 0, 200,
                          "%d%%", 1.0F)) {
            client.set_input_gain(static_cast<float>(master_vol) / 100.0F);
        }

        ImGui::Spacing();

        // Label
        JamGui::TextCentered(ImVec2(strip_width, line_height), "master");

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // ========== LATENCY INFO (with padding) ==========
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        AudioStream::LatencyInfo latency = client.get_latency_info();
        ImGui::Text("Latency:");
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        ImGui::Text("In: %.1fms", latency.input_latency_ms);
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        ImGui::Text("Out: %.1fms", latency.output_latency_ms);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // ========== WAV SECTION (with padding) ==========
        Client::WavState wav_state = client.get_wav_state();

        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        ImGui::Text("WAV File:");

        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (PADDING / 2.0F));
        static char wav_file_path[512] = "";
        ImGui::PushItemWidth(width);
        ImGui::InputText("##WavPath", wav_file_path, sizeof(wav_file_path));
        ImGui::PopItemWidth();

        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (PADDING / 2.0F));
        if (ImGui::Button("Load", ImVec2(width, 0))) {
            if (strlen(wav_file_path) > 0) {
                client.load_wav_file(wav_file_path);
            }
        }

        if (wav_state.is_loaded) {
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (PADDING / 2.0F));
            // Play/Pause button
            if (wav_state.is_playing) {
                if (ImGui::Button("Pause", ImVec2(width, 0))) {
                    client.wav_pause();
                }
            } else {
                if (ImGui::Button("Play", ImVec2(width, 0))) {
                    client.wav_play();
                }
            }

            // Progress/Seek
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (PADDING / 2.0F));
            float seek_pos = static_cast<float>(wav_state.position);
            float max_pos  = static_cast<float>(wav_state.total_frames);
            ImGui::PushItemWidth(width);
            if (wav_state.is_playing) {
                float progress = (max_pos > 0) ? seek_pos / max_pos : 0.0F;
                ImGui::ProgressBar(progress, ImVec2(width, 0), "");
            } else {
                if (ImGui::SliderFloat("##Seek", &seek_pos, 0.0F, max_pos, "%.0f")) {
                    client.wav_seek(static_cast<int64_t>(seek_pos));
                }
            }
            ImGui::PopItemWidth();

            // Volume
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            ImGui::Text("Volume:");
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (PADDING / 2.0F));
            float wav_gain = wav_state.gain;
            ImGui::PushItemWidth(width);
            if (ImGui::SliderFloat("##WavVol", &wav_gain, 0.0F, 2.0F, "%.2f")) {
                client.set_wav_gain(wav_gain);
            }
            ImGui::PopItemWidth();

            // Mute local
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (PADDING / 2.0F));
            bool muted_local = wav_state.muted_local;
            if (ImGui::Checkbox("Mute Local##wav", &muted_local)) {
                client.set_wav_muted_local(muted_local);
            }
            JamGui::ShowTooltipOnHover("Mute locally but still send to others");
        }
    }
    ImGui::EndChild();
}

// Draw a participant channel strip
static void draw_participant_strip(Client& client, const ParticipantInfo& p, int index,
                                   float available_height) {
    ImGuiStyle& style       = ImGui::GetStyle();
    float       strip_width = TRACK_WIDTH;
    float       line_height = ImGui::GetTextLineHeightWithSpacing();

    // Dynamic fader height - scale with available space
    // Reserve more space for: title, mute btn, pan knob, label, separator, stats section (expanded)
    float fader_height = std::max(200.0F, available_height - 330.0F);

    // Padding constant
    constexpr float PADDING = 8.0F;

    // Get track color based on index
    ImVec4 track_color         = JamGui::GetTrackColor(index, 0.6F, 0.6F);
    ImVec4 track_color_hovered = JamGui::GetTrackColor(index, 0.7F, 0.7F);
    ImVec4 track_color_active  = JamGui::GetTrackColor(index, 0.8F, 0.8F);

    // Background tint for highlighted/selected
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(1, 1, 1, 0.02F));

    ImGui::PushID(static_cast<int>(p.id));
    ImGui::BeginChild("ParticipantStrip", ImVec2(strip_width, 0), ImGuiChildFlags_None);
    {
        float width = ImGui::GetContentRegionAvail().x - PADDING;
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (PADDING / 2.0F));

        // Push track-specific colors for title
        ImGui::PushStyleColor(ImGuiCol_Button, track_color);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, track_color_hovered);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, track_color_active);

        // Participant name button (title)
        char name_buf[32];
        std::snprintf(name_buf, sizeof(name_buf), "User #%u", p.id);
        ImGui::Button(name_buf, ImVec2(width, 0));
        ImGui::PopStyleColor(3);

        ImGui::Spacing();
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (PADDING / 2.0F));

        // Mute button - explicit MUTE/UNMUTE text
        bool muted = p.is_muted;
        ImGui::PushStyleColor(ImGuiCol_Button, muted ? ImVec4(0.8F, 0.2F, 0.2F, 1.0F)
                                                     : ImVec4(0.2F, 0.5F, 0.3F, 1.0F));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, muted ? ImVec4(0.9F, 0.3F, 0.3F, 1.0F)
                                                            : ImVec4(0.3F, 0.6F, 0.4F, 1.0F));
        char mute_label[32];
        std::snprintf(mute_label, sizeof(mute_label), muted ? "UNMUTE##%u" : "MUTE##%u", p.id);
        if (ImGui::Button(mute_label, ImVec2(width, 0))) {
            client.set_participant_muted(p.id, !muted);
        }
        JamGui::ShowTooltipOnHover(muted ? "Click to unmute" : "Click to mute");
        ImGui::PopStyleColor(2);

        ImGui::Spacing();

        // Pan knob at TOP - use local cache to prevent jitter during drag
        static std::unordered_map<uint32_t, float> pan_cache;
        if (!pan_cache.contains(p.id)) {
            pan_cache[p.id] = p.pan * 127.0F;
        }
        bool  knob_active = false;
        float pan_val     = pan_cache[p.id];

        float knob_offset = (strip_width - KNOB_SIZE) / 2.0F;
        ImGui::SetCursorPosX(knob_offset);
        if (JamGui::Knob("pan", &pan_val, 0.0F, 127.0F, ImVec2(KNOB_SIZE, KNOB_SIZE), "Pan")) {
            pan_cache[p.id] = pan_val;
            client.set_participant_pan(p.id, pan_val / 127.0F);
            knob_active = true;
        }
        // Update cache from server when not dragging
        if (!knob_active && !ImGui::IsItemActive()) {
            pan_cache[p.id] = p.pan * 127.0F;
        }

        ImGui::Spacing();

        // Level meter and volume fader
        int meter_val = static_cast<int>(p.audio_level * fader_height);

        // Center the meter + fader
        float total_control_width = METER_WIDTH + style.ItemSpacing.x + METER_WIDTH;
        float offset              = (strip_width - total_control_width) / 2.0F;

        ImGui::SetCursorPosX(offset);
        JamGui::UvMeter("##meter", ImVec2(METER_WIDTH, fader_height), &meter_val, 0,
                        static_cast<int>(fader_height));
        ImGui::SameLine();

        // Volume fader - 0-200 range, 100 = unity gain (use local cache to prevent jitter)
        static std::unordered_map<uint32_t, int> vol_cache;
        if (!vol_cache.contains(p.id) || !ImGui::IsItemActive()) {
            vol_cache[p.id] = static_cast<int>(p.gain * 100.0F);
        }
        int vol = vol_cache[p.id];
        vol     = std::clamp(vol, 0, 200);
        if (JamGui::Fader("##vol", ImVec2(METER_WIDTH, fader_height), &vol, 0, 200, "%d%%", 1.0F)) {
            vol_cache[p.id] = vol;
            client.set_participant_gain(p.id, static_cast<float>(vol) / 100.0F);
        }

        ImGui::Spacing();

        // Participant label (lowercase to avoid ID conflict with title button)
        char label_buf[32];
        std::snprintf(label_buf, sizeof(label_buf), "user %u", p.id);
        JamGui::TextCentered(ImVec2(strip_width, line_height), label_buf);

        ImGui::Spacing();
        ImGui::Separator();

        // Connection stats section at bottom (open by default, with padding)
        char stats_label[32];
        std::snprintf(stats_label, sizeof(stats_label), "Stats##%u", p.id);
        if (ImGui::CollapsingHeader(stats_label, ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            ImGui::Text("Queue: %zu", p.queue_size);
            if (p.underrun_count > 0) {
                ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
                ImGui::TextColored(ImVec4(1.0F, 0.6F, 0.2F, 1.0F), "Underruns: %d",
                                   p.underrun_count);
            }
            if (p.plc_count > 0) {
                ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
                ImGui::Text("PLC: %zu", p.plc_count);
            }
            if (!p.buffer_ready) {
                ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
                ImGui::TextColored(ImVec4(1.0F, 0.8F, 0.2F, 1.0F), "Buffering...");
            }
        }
    }
    ImGui::EndChild();
    ImGui::PopID();

    ImGui::PopStyleColor();  // ChildBg
}

// Draw bottom device selector bar (horizontal)
static void draw_bottom_bar(Client& client) {
    static std::vector<AudioStream::DeviceInfo> input_devices;
    static std::vector<AudioStream::DeviceInfo> output_devices;
    static std::vector<AudioStream::ApiInfo>    available_apis;
    static int                                  selected_api        = -1;
    static int                                  refresh_counter     = 0;
    static PaDeviceIndex                        pending_input       = paNoDevice;
    static PaDeviceIndex                        pending_output      = paNoDevice;
    static bool                                 devices_initialized = false;

    if (!devices_initialized) {
        pending_input       = client.get_selected_input_device();
        pending_output      = client.get_selected_output_device();
        devices_initialized = true;
    }

    if (refresh_counter++ % 60 == 0) {
        input_devices  = AudioStream::get_input_devices();
        output_devices = AudioStream::get_output_devices();
        available_apis = AudioStream::get_apis();
    }

    // API selector
    ImGui::AlignTextToFramePadding();
    ImGui::Text("API:");
    ImGui::SameLine();
    ImGui::PushItemWidth(100);
    const char* api_preview = (selected_api < 0) ? "All" : nullptr;
    for (const auto& api: available_apis) {
        if (api.index == selected_api) {
            api_preview = api.name.c_str();
            break;
        }
    }
    if (api_preview == nullptr) {
        api_preview = "All";
    }
    if (ImGui::BeginCombo("##ApiSelect", api_preview)) {
        if (ImGui::Selectable("All APIs", selected_api < 0)) {
            selected_api = -1;
        }
        for (const auto& api: available_apis) {
            char api_label[128];
            std::snprintf(api_label, sizeof(api_label), "%s##api_%d", api.name.c_str(), api.index);
            if (ImGui::Selectable(api_label, api.index == selected_api)) {
                selected_api = api.index;
            }
        }
        ImGui::EndCombo();
    }
    ImGui::PopItemWidth();

    ImGui::SameLine();
    ImGui::AlignTextToFramePadding();
    ImGui::Text("Input:");
    ImGui::SameLine();
    ImGui::PushItemWidth(250);
    std::string input_preview = "Select...";
    for (const auto& dev: input_devices) {
        if (dev.index == pending_input) {
            input_preview = dev.name;
            break;
        }
    }
    if (ImGui::BeginCombo("##InputDev", input_preview.c_str())) {
        for (const auto& dev: input_devices) {
            if (selected_api >= 0 && dev.api_name != available_apis[selected_api].name) {
                continue;
            }
            char dev_label[256];
            std::snprintf(dev_label, sizeof(dev_label), "%s (%s)##dev_%d", dev.name.c_str(),
                          dev.api_name.c_str(), dev.index);
            if (ImGui::Selectable(dev_label, dev.index == pending_input)) {
                pending_input = dev.index;
            }
        }
        ImGui::EndCombo();
    }
    ImGui::PopItemWidth();

    ImGui::SameLine();
    ImGui::AlignTextToFramePadding();
    ImGui::Text("Output:");
    ImGui::SameLine();
    ImGui::PushItemWidth(250);
    std::string output_preview = "Select...";
    for (const auto& dev: output_devices) {
        if (dev.index == pending_output) {
            output_preview = dev.name;
            break;
        }
    }
    if (ImGui::BeginCombo("##OutputDev", output_preview.c_str())) {
        for (const auto& dev: output_devices) {
            if (selected_api >= 0 && dev.api_name != available_apis[selected_api].name) {
                continue;
            }
            char dev_label[256];
            std::snprintf(dev_label, sizeof(dev_label), "%s (%s)##dev_%d", dev.name.c_str(),
                          dev.api_name.c_str(), dev.index);
            if (ImGui::Selectable(dev_label, dev.index == pending_output)) {
                pending_output = dev.index;
            }
        }
        ImGui::EndCombo();
    }
    ImGui::PopItemWidth();

    ImGui::SameLine();

    // Check if devices changed
    PaDeviceIndex active_input  = client.get_selected_input_device();
    PaDeviceIndex active_output = client.get_selected_output_device();
    bool devices_changed = (pending_input != active_input) || (pending_output != active_output);

    if (devices_changed) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8F, 0.6F, 0.2F, 1.0F));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.9F, 0.7F, 0.3F, 1.0F));
        if (ImGui::Button("APPLY")) {
            client.set_input_device(pending_input);
            client.set_output_device(pending_output);
            if (client.is_audio_stream_active()) {
                client.swap_audio_devices(pending_input, pending_output);
            }
        }
        ImGui::PopStyleColor(2);
    } else {
        bool is_active = client.is_audio_stream_active();
        if (is_active) {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.7F, 0.2F, 0.2F, 1.0F));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.8F, 0.3F, 0.3F, 1.0F));
            if (ImGui::Button("STOP")) {
                client.stop_audio_stream();
            }
            ImGui::PopStyleColor(2);
        } else {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2F, 0.6F, 0.3F, 1.0F));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.3F, 0.7F, 0.4F, 1.0F));
            if (ImGui::Button("START")) {
                if (pending_input != paNoDevice && pending_output != paNoDevice) {
                    client.set_input_device(pending_input);
                    client.set_output_device(pending_output);
                    AudioStream::AudioConfig config = client.get_audio_config();
                    client.start_audio_stream(pending_input, pending_output, config);
                }
            }
            ImGui::PopStyleColor(2);
        }
    }

    // Show error message if any
    const std::string& last_error = AudioStream::get_last_error();
    if (!last_error.empty()) {
        ImGui::TextColored(ImVec4(1.0F, 0.3F, 0.3F, 1.0F), "Error: %s", last_error.c_str());
    }
}

void draw_client_ui(Client& client) {
    // Apply zynlab theme on first frame
    static bool theme_applied = false;
    if (!theme_applied) {
        JamGui::ApplyZynlabTheme();
        theme_applied = true;
    }

    // Cache participant info
    static std::vector<ParticipantInfo> cached_participants;
    static int                          frame_counter = 0;
    if (frame_counter++ % 4 == 0) {
        cached_participants = client.get_participant_info();
    }

    // Main mixer window
    ImGui::SetNextWindowSize(ImVec2(900, 600), ImGuiCond_FirstUseEver);
    if (ImGui::Begin("Jam Client", nullptr, ImGuiWindowFlags_MenuBar)) {
        // Menu bar with connection info
        if (ImGui::BeginMenuBar()) {
            // Connection status
            std::string server_info =
                client.get_server_address() + ":" + std::to_string(client.get_server_port());
            ImGui::Text("Server: %s", server_info.c_str());

            ImGui::Separator();

            // RTT
            double rtt = client.get_rtt_ms();
            if (rtt > 0) {
                ImGui::Text("RTT: %.1f ms", rtt);
            } else {
                ImGui::Text("RTT: --");
            }

            ImGui::Separator();

            // Participants count
            ImGui::Text("Users: %zu", cached_participants.size());

            ImGui::Separator();

            // Total bytes sent/received (throttled updates to reduce CPU usage)
            static std::string cached_rx_str = "0 B";
            static std::string cached_tx_str = "0 B";
            static auto last_update = std::chrono::steady_clock::now();
            
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_update).count() >= 1000) {
                uint64_t total_rx = client.get_total_bytes_rx();
                uint64_t total_tx = client.get_total_bytes_tx();
                
                // Format as KB or MB
                auto format_bytes = [](uint64_t bytes) -> std::string {
                    if (bytes < 1024) {
                        return std::to_string(bytes) + " B";
                    } else if (bytes < 1024 * 1024) {
                        return std::to_string(bytes / 1024) + " KB";
                    } else {
                        char buf[32];
                        std::snprintf(buf, sizeof(buf), "%.2f MB", bytes / (1024.0 * 1024.0));
                        return std::string(buf);
                    }
                };
                
                cached_rx_str = format_bytes(total_rx);
                cached_tx_str = format_bytes(total_tx);
                last_update = now;
            }
            
            ImGui::Text("RX: %s", cached_rx_str.c_str());
            ImGui::SameLine();
            ImGui::Text("TX: %s", cached_tx_str.c_str());
            JamGui::ShowTooltipOnHover("Total bytes received / transmitted");

            ImGui::Separator();

            // Audio status
            bool is_active = client.is_audio_stream_active();
            if (is_active) {
                ImGui::TextColored(ImVec4(0.3F, 0.9F, 0.3F, 1.0F), "CONNECTED");
            } else {
                ImGui::TextColored(ImVec4(0.9F, 0.5F, 0.2F, 1.0F), "DISCONNECTED");
            }

            ImGui::Separator();

            // FPS
            ImGui::Text("%.0f FPS", ImGui::GetIO().Framerate);

            ImGui::EndMenuBar();
        }

        // Get available height for channel strips
        float available_height =
            ImGui::GetContentRegionAvail().y - 65;  // Reserve space for device bar + error

        // Horizontal scrolling mixer area
        ImGui::BeginChild("Mixer", ImVec2(0, available_height), ImGuiChildFlags_None,
                          ImGuiWindowFlags_HorizontalScrollbar);
        {
            ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(5, 10));

            // Draw master strip
            draw_master_strip(client, available_height);
            ImGui::SameLine();

            // Space between master and participants
            // ImGui::Dummy(ImVec2(1, 0));
            // ImGui::SameLine();

            // Draw participant strips
            int index = 0;
            for (const auto& p: cached_participants) {
                draw_participant_strip(client, p, index++, available_height);
                ImGui::SameLine();
            }

            // Empty space at the end for scrolling
            ImGui::Dummy(ImVec2(20, 0));

            ImGui::PopStyleVar();
        }
        ImGui::EndChild();

        ImGui::Separator();

        // WAV playback controls at bottom
        draw_bottom_bar(client);
    }
    ImGui::End();
}

int main() {
    try {
        auto& log = Logger::instance();
        log.init(true, true, false, "", spdlog::level::info);

        asio::io_context io_context;

        Client client_instance(io_context, "127.0.0.1", 9999);

        // Auto-start audio stream with default devices
        {
            PaDeviceIndex input_dev  = client_instance.get_selected_input_device();
            PaDeviceIndex output_dev = client_instance.get_selected_output_device();
            if (input_dev != paNoDevice && output_dev != paNoDevice) {
                AudioStream::AudioConfig config = client_instance.get_audio_config();
                if (client_instance.start_audio_stream(input_dev, output_dev, config)) {
                    Log::info("Auto-started audio stream with default devices");
                } else {
                    Log::warn("Failed to auto-start audio stream");
                }
            }
        }

        // Run io_context in background thread (GLFW must be on main thread on macOS)
        std::thread io_thread([&io_context]() { io_context.run(); });

        // Run UI on main thread (required for GLFW on macOS)
        {
            Gui app(810, 555, "Jam", false, 60);

            // Clean lambda - just delegates to separate function
            app.set_draw_callback([&client_instance]() { draw_client_ui(client_instance); });

            app.set_close_callback([&io_context]() {
                // Stop io_context to exit the application
                io_context.stop();
            });
            app.run();
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