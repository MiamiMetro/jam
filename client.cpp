#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cctype>
#include <exception>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX  // Prevent Windows from defining min/max macros
#endif
#include <windows.h>
#include <winsock2.h>
#endif

#include <asio.hpp>
#include <asio/buffer.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <asio/socket_base.hpp>
#include <concurrentqueue.h>
#include <imgui.h>
#include <opus.h>
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

static int normalized_buffer_frames_for_codec(AudioCodec codec, int frames_per_buffer) {
#ifdef __APPLE__
    if (codec == AudioCodec::Opus && frames_per_buffer != 128 && frames_per_buffer != 240) {
        return 128;
    }
#endif
    return frames_per_buffer;
}

static int normalize_buffer_frames_for_codec(AudioCodec codec, int frames_per_buffer) {
    const int normalized = normalized_buffer_frames_for_codec(codec, frames_per_buffer);
    if (normalized != frames_per_buffer) {
        Log::info("Normalizing buffer from {} to {} frames for macOS Opus/CoreAudio pacing",
                  frames_per_buffer, normalized);
    }
    return normalized;
}

struct PerformerJoinOptions {
    std::string room_id;
    std::string room_handle;
    std::string user_id;
    std::string display_name;
    std::string join_token;
};

class Client {
public:
    Client(asio::io_context& io_context, const std::string& server_address, short server_port,
           PerformerJoinOptions performer_join_options = {})
        : io_context_(io_context),
          socket_(io_context, udp::endpoint(udp::v4(), 0)),
          performer_join_options_(std::move(performer_join_options)),
          selected_input_device_(AudioStream::NO_DEVICE),
          selected_output_device_(AudioStream::NO_DEVICE),
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
        audio_config_.bitrate           = AudioStream::AudioConfig::DEFAULT_BITRATE;
        audio_config_.complexity        = AudioStream::AudioConfig::DEFAULT_COMPLEXITY;
        audio_config_.frames_per_buffer = 120;  // 2.5ms validated low-latency default
        audio_config_.input_gain        = 1.0F;
        audio_config_.output_gain       = 1.0F;

        // Set default devices
        selected_input_device_  = AudioStream::get_default_input_device();
        selected_output_device_ = AudioStream::get_default_output_device();

        // Initialize device info with default devices
        if (selected_input_device_ != AudioStream::NO_DEVICE) {
            set_input_device(selected_input_device_);
        }
        if (selected_output_device_ != AudioStream::NO_DEVICE) {
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

        send_join();
    }

    void send_join() {
        JoinHdr join{};
        join.magic = CTRL_MAGIC;
        join.type  = CtrlHdr::Cmd::JOIN;
        write_fixed(join.room_id, performer_join_options_.room_id);
        write_fixed(join.room_handle, performer_join_options_.room_handle);
        write_fixed(join.profile_id, performer_join_options_.user_id);
        write_fixed(join.display_name, performer_join_options_.display_name);
        write_fixed(join.join_token, performer_join_options_.join_token);
        auto buf = std::make_shared<std::vector<unsigned char>>(sizeof(JoinHdr));
        std::memcpy(buf->data(), &join, sizeof(JoinHdr));
        send(buf->data(), buf->size(), buf);
        Log::info("Sent JOIN for room '{}' user '{}' token {}", performer_join_options_.room_id,
                  performer_join_options_.user_id,
                  performer_join_options_.join_token.empty() ? "missing" : "present");
    }

    // Stop connection (stops sending/receiving UDP packets)
    void stop_connection() {
        Log::info("Disconnecting from server...");

        // Send LEAVE message
        CtrlHdr chdr{};
        chdr.magic = CTRL_MAGIC;
        chdr.type  = CtrlHdr::Cmd::LEAVE;
        auto buf = std::make_shared<std::vector<unsigned char>>(sizeof(CtrlHdr));
        std::memcpy(buf->data(), &chdr, sizeof(CtrlHdr));
        send(buf->data(), buf->size(), buf);

        // Cancel pending async operations
        socket_.cancel();

        Log::info("Disconnected (no longer sending/receiving)");
    }

    bool start_audio_stream(AudioStream::DeviceIndex input_device,
                            AudioStream::DeviceIndex output_device,
                            const AudioStream::AudioConfig& config = AudioStream::AudioConfig{}) {
        stop_pcm_sender_thread();

        // Store config FIRST before any validation that could cause early return
        // This ensures audio_config_ is always set, even if validation fails
        audio_config_ = config;

        // Get input channel count from device info before creating encoder
        // (audio_.get_input_channel_count() returns 0 before stream starts)
        const auto* input_info_ptr = AudioStream::get_device_info(input_device);
        if (input_info_ptr == nullptr) {
            Log::error("Invalid input device");
            return false;
        }
        auto input_info = *input_info_ptr;
        int input_channels = std::min(input_info.max_input_channels, 1);  // Mono input

        // Get output device info
        const auto* output_info_ptr = AudioStream::get_device_info(output_device);
        if (output_info_ptr == nullptr) {
            Log::error("Invalid output device");
            return false;
        }
        auto output_info = *output_info_ptr;

        // Store device info
        device_info_.input_device_name  = input_info.name;
        device_info_.input_api          = input_info.api_name;
        device_info_.input_channels     = input_channels;
        device_info_.input_sample_rate  = input_info.default_sample_rate;
        device_info_.output_device_name = output_info.name;
        device_info_.output_api         = output_info.api_name;
        device_info_.output_channels    = output_info.max_output_channels >= 2 ? 2 : 1;
        device_info_.output_sample_rate = output_info.default_sample_rate;

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
            start_pcm_sender_thread();
            audio_.print_latency_info();
        } else {
            // Clean up encoder if stream start failed
            audio_encoder_.destroy();
        }
        return success;
    }

    void stop_audio_stream() {
        audio_.stop_audio_stream();
        stop_pcm_sender_thread();
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

    struct CallbackTimingInfo {
        double last_ms;
        double max_ms;
        double avg_ms;
        double deadline_ms;
        uint64_t callback_count;
        uint64_t over_deadline_count;
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

    void set_requested_frames_per_buffer(int frames_per_buffer) {
        audio_config_.frames_per_buffer =
            normalize_buffer_frames_for_codec(get_audio_codec(), frames_per_buffer);
    }

    CallbackTimingInfo get_callback_timing_info() const {
        CallbackTimingInfo info{};
        info.last_ms = callback_last_ns_.load(std::memory_order_relaxed) / 1e6;
        info.max_ms = callback_max_ns_.load(std::memory_order_relaxed) / 1e6;
        info.avg_ms = callback_avg_ns_.load(std::memory_order_relaxed) / 1e6;
        info.deadline_ms = callback_deadline_ns_.load(std::memory_order_relaxed) / 1e6;
        info.callback_count = callback_count_.load(std::memory_order_relaxed);
        info.over_deadline_count = callback_over_deadline_count_.load(std::memory_order_relaxed);
        return info;
    }

    AudioCodec get_audio_codec() const {
        return audio_codec_.load(std::memory_order_acquire);
    }

    void set_audio_codec(AudioCodec codec) {
        audio_codec_.store(codec, std::memory_order_release);
        audio_config_.frames_per_buffer =
            normalize_buffer_frames_for_codec(codec, audio_config_.frames_per_buffer);
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

    AudioStream::DeviceIndex get_selected_input_device() const {
        return selected_input_device_;
    }

    AudioStream::DeviceIndex get_selected_output_device() const {
        return selected_output_device_;
    }

    bool set_input_device(AudioStream::DeviceIndex device_index) {
        if (!AudioStream::is_device_valid(device_index)) {
            Log::error("Invalid input device index: {}", device_index);
            return false;
        }
        selected_input_device_ = device_index;

        // Update device info for UI display
        const auto* input_info = AudioStream::get_device_info(device_index);
        if (input_info != nullptr) {
            device_info_.input_device_name = input_info->name;
            device_info_.input_api         = input_info->api_name;
            device_info_.input_channels    = std::min(input_info->max_input_channels, 1);
            device_info_.input_sample_rate = input_info->default_sample_rate;
        }
        return true;
    }

    bool set_output_device(AudioStream::DeviceIndex device_index) {
        if (!AudioStream::is_device_valid(device_index)) {
            Log::error("Invalid output device index: {}", device_index);
            return false;
        }
        selected_output_device_ = device_index;

        // Update device info for UI display
        const auto* output_info = AudioStream::get_device_info(device_index);
        if (output_info != nullptr) {
            device_info_.output_device_name = output_info->name;
            device_info_.output_api         = output_info->api_name;
            device_info_.output_channels    = output_info->max_output_channels >= 2 ? 2 : 1;
            device_info_.output_sample_rate = output_info->default_sample_rate;
        }
        return true;
    }

    // Hot-swap audio devices (stops current stream and starts new one)
    bool swap_audio_devices(AudioStream::DeviceIndex input_device,
                            AudioStream::DeviceIndex output_device) {
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
        } else if ((hdr.magic == AUDIO_MAGIC &&
                    bytes >= sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t)) ||
                   (hdr.magic == AUDIO_V2_MAGIC && bytes >= sizeof(AudioHdrV2) - AUDIO_BUF_SIZE)) {
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

        asio::post(io_context_, [this, data, len, keep_alive]() {
            socket_.async_send_to(asio::buffer(data, len), server_endpoint_,
                                  [keep_alive](std::error_code error_code, std::size_t) {
                                      if (error_code) {
                                          Log::error("send error: {}", error_code.message());
                                      }
                                      // keep_alive keeps the data alive until send completes
                                  });
        });
    }

private:
    template <size_t N>
    static void write_fixed(Bytes<N>& target, const std::string& value) {
        const size_t copy_bytes = std::min(value.size(), target.size() - 1);
        std::copy_n(value.data(), copy_bytes, target.data());
        target[copy_bytes] = '\0';
    }

    template <size_t N>
    static std::string fixed_string(const Bytes<N>& bytes) {
        const auto end = std::find(bytes.begin(), bytes.end(), '\0');
        return std::string(bytes.begin(), end);
    }

    struct PcmSendFrame {
        std::array<unsigned char, AUDIO_BUF_SIZE> payload{};
        uint16_t payload_bytes = 0;
        uint16_t frame_count = 0;
        uint32_t sample_rate = 48000;
        std::chrono::steady_clock::time_point capture_time;
    };

    struct OpusSendFrame {
        std::array<float, 960> samples{};
        uint16_t frame_count = 0;
        uint32_t sample_rate = 48000;
    };

    void start_pcm_sender_thread() {
        if (pcm_sender_running_.exchange(true, std::memory_order_acq_rel)) {
            return;
        }

        pcm_sender_thread_ = std::thread([this]() { pcm_sender_loop(); });
    }

    void stop_pcm_sender_thread() {
        pcm_sender_running_.store(false, std::memory_order_release);
        pcm_sender_wake_.store(true, std::memory_order_release);
        pcm_sender_cv_.notify_one();
        if (pcm_sender_thread_.joinable()) {
            pcm_sender_thread_.join();
        }

        PcmSendFrame discarded;
        while (pcm_send_queue_.try_dequeue(discarded)) {
        }
        OpusSendFrame discarded_opus;
        while (opus_send_queue_.try_dequeue(discarded_opus)) {
        }
        pcm_tx_accumulated_frames_ = 0;
        opus_tx_accumulated_frames_ = 0;
    }

    void pcm_sender_loop() {
        while (pcm_sender_running_.load(std::memory_order_acquire)) {
            PcmSendFrame frame;
            if (pcm_send_queue_.try_dequeue(frame)) {
                observe_pcm_send_queue_age(frame.capture_time);
                uint32_t seq = audio_tx_sequence_.fetch_add(1, std::memory_order_relaxed);
                auto packet = audio_packet::create_audio_packet_v2(
                    AudioCodec::PcmInt16, seq, frame.sample_rate, frame.frame_count, 1,
                    frame.payload.data(), frame.payload_bytes);
                send(packet->data(), packet->size(), packet);
                continue;
            }

            OpusSendFrame opus_frame;
            if (opus_send_queue_.try_dequeue(opus_frame)) {
                std::vector<unsigned char> encoded_data;
                if (audio_encoder_.encode(opus_frame.samples.data(), opus_frame.frame_count,
                                          encoded_data) &&
                    encoded_data.size() <= AUDIO_BUF_SIZE) {
                    uint32_t seq = audio_tx_sequence_.fetch_add(1, std::memory_order_relaxed);
                    auto packet = audio_packet::create_audio_packet_v2(
                        AudioCodec::Opus, seq, opus_frame.sample_rate, opus_frame.frame_count, 1,
                        encoded_data.data(), static_cast<uint16_t>(encoded_data.size()));
                    send(packet->data(), packet->size(), packet);
                }
                continue;
            }

            std::unique_lock<std::mutex> lock(pcm_sender_wait_mutex_);
            pcm_sender_cv_.wait_for(lock, 1ms, [this]() {
                return !pcm_sender_running_.load(std::memory_order_acquire) ||
                       pcm_sender_wake_.exchange(false, std::memory_order_acq_rel);
            });
        }
    }

    static size_t max_send_queue_frames(uint16_t frame_count) {
        if (frame_count <= 128) {
            return 8;
        }
        return 3;
    }

    void enqueue_pcm_send_frame(const unsigned char* payload, uint16_t payload_bytes,
                                uint16_t frame_count, uint32_t sample_rate) {
        if (payload == nullptr || frame_count == 0 || payload_bytes == 0 ||
            payload_bytes > AUDIO_BUF_SIZE) {
            pcm_send_drops_.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        const size_t max_queue_frames = max_send_queue_frames(frame_count);
        while (pcm_send_queue_.size_approx() >= max_queue_frames) {
            PcmSendFrame discarded;
            if (!pcm_send_queue_.try_dequeue(discarded)) {
                break;
            }
            pcm_send_drops_.fetch_add(1, std::memory_order_relaxed);
        }

        PcmSendFrame frame;
        std::memcpy(frame.payload.data(), payload, payload_bytes);
        frame.payload_bytes = payload_bytes;
        frame.frame_count = frame_count;
        frame.sample_rate = sample_rate;
        frame.capture_time = std::chrono::steady_clock::now();
        pcm_send_queue_.enqueue(frame);
        pcm_tx_packet_frame_count_.store(frame_count, std::memory_order_relaxed);
        wake_pcm_sender_thread();
    }

    static bool is_valid_pcm_tx_frame_count(uint16_t frame_count) {
        return frame_count > 0 &&
               static_cast<size_t>(frame_count) * sizeof(int16_t) <= AUDIO_BUF_SIZE;
    }

    static uint16_t preferred_pcm_tx_frame_count(uint16_t requested_frame_count) {
        if (is_valid_pcm_tx_frame_count(requested_frame_count)) {
            return requested_frame_count;
        }
        return is_valid_pcm_tx_frame_count(120) ? 120 : 0;
    }

    void enqueue_pcm_send_samples(const float* samples, unsigned long frame_count,
                                  uint32_t sample_rate) {
        if (frame_count == 0 || samples == nullptr) {
            return;
        }
        if (sample_rate != 48000) {
            pcm_send_drops_.fetch_add(1, std::memory_order_relaxed);
            pcm_tx_accumulated_frames_ = 0;
            return;
        }

        const uint16_t target_frame_count = preferred_pcm_tx_frame_count(
            static_cast<uint16_t>(audio_config_.frames_per_buffer));
        if (target_frame_count == 0 || target_frame_count > pcm_tx_accumulator_.size()) {
            pcm_send_drops_.fetch_add(1, std::memory_order_relaxed);
            pcm_tx_accumulated_frames_ = 0;
            return;
        }

        size_t offset = 0;
        while (offset < frame_count) {
            const size_t room =
                static_cast<size_t>(target_frame_count) - pcm_tx_accumulated_frames_;
            const size_t samples_to_copy =
                std::min(room, static_cast<size_t>(frame_count) - offset);
            auto accumulator_out = pcm_tx_accumulator_.begin() +
                                   static_cast<std::ptrdiff_t>(pcm_tx_accumulated_frames_);
            std::copy_n(samples + offset, samples_to_copy, accumulator_out);

            pcm_tx_accumulated_frames_ += samples_to_copy;
            offset += samples_to_copy;

            if (pcm_tx_accumulated_frames_ == target_frame_count) {
                std::array<unsigned char, AUDIO_BUF_SIZE> pcm_payload{};
                for (size_t i = 0; i < target_frame_count; ++i) {
                    const float clamped =
                        std::clamp(pcm_tx_accumulator_[i], -1.0F, 1.0F);
                    const auto sample =
                        static_cast<int16_t>(std::lrint(clamped * 32767.0F));
                    std::memcpy(pcm_payload.data() + i * sizeof(sample), &sample,
                                sizeof(sample));
                }
                enqueue_pcm_send_frame(pcm_payload.data(),
                                       static_cast<uint16_t>(target_frame_count *
                                                             sizeof(int16_t)),
                                       target_frame_count, sample_rate);
                pcm_tx_accumulated_frames_ = 0;
            }
        }
    }

    void enqueue_opus_send_frame(const float* samples, uint16_t frame_count, uint32_t sample_rate) {
        if (!OpusEncoderWrapper::is_legal_frame_size(static_cast<int>(sample_rate), frame_count)) {
            opus_send_drops_.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        const size_t max_queue_frames = max_send_queue_frames(frame_count);
        while (opus_send_queue_.size_approx() >= max_queue_frames) {
            OpusSendFrame discarded;
            if (!opus_send_queue_.try_dequeue(discarded)) {
                break;
            }
            opus_send_drops_.fetch_add(1, std::memory_order_relaxed);
        }

        OpusSendFrame frame;
        std::copy_n(samples, frame_count, frame.samples.begin());
        frame.frame_count = frame_count;
        frame.sample_rate = sample_rate;
        opus_send_queue_.enqueue(frame);
        wake_pcm_sender_thread();
    }

    static uint16_t preferred_opus_tx_frame_count(uint32_t sample_rate,
                                                  uint16_t requested_frame_count) {
        if (OpusEncoderWrapper::is_legal_frame_size(static_cast<int>(sample_rate),
                                                    requested_frame_count)) {
            return requested_frame_count;
        }

        const int low_latency_frame_count = static_cast<int>(sample_rate) / 400;
        if (OpusEncoderWrapper::is_legal_frame_size(static_cast<int>(sample_rate),
                                                    low_latency_frame_count)) {
            return static_cast<uint16_t>(low_latency_frame_count);
        }

        return 0;
    }

    void enqueue_opus_send_samples(const float* samples, unsigned long frame_count,
                                   uint32_t sample_rate) {
        if (frame_count == 0 || samples == nullptr) {
            return;
        }

        if (frame_count <= opus_tx_accumulator_.size() &&
            OpusEncoderWrapper::is_legal_frame_size(static_cast<int>(sample_rate),
                                                    static_cast<int>(frame_count)) &&
            opus_tx_accumulated_frames_ == 0) {
            enqueue_opus_send_frame(samples, static_cast<uint16_t>(frame_count), sample_rate);
            return;
        }

        const uint16_t target_frame_count = preferred_opus_tx_frame_count(
            sample_rate, static_cast<uint16_t>(audio_config_.frames_per_buffer));
        if (target_frame_count == 0 || target_frame_count > opus_tx_accumulator_.size()) {
            opus_send_drops_.fetch_add(1, std::memory_order_relaxed);
            opus_tx_accumulated_frames_ = 0;
            return;
        }

        size_t offset = 0;
        while (offset < frame_count) {
            const size_t room =
                static_cast<size_t>(target_frame_count) - opus_tx_accumulated_frames_;
            const size_t samples_to_copy =
                std::min(room, static_cast<size_t>(frame_count) - offset);
            auto accumulator_out = opus_tx_accumulator_.begin() +
                                   static_cast<std::ptrdiff_t>(opus_tx_accumulated_frames_);
            std::copy_n(samples + offset, samples_to_copy, accumulator_out);

            opus_tx_accumulated_frames_ += samples_to_copy;
            offset += samples_to_copy;

            if (opus_tx_accumulated_frames_ == target_frame_count) {
                enqueue_opus_send_frame(opus_tx_accumulator_.data(), target_frame_count,
                                        sample_rate);
                opus_tx_accumulated_frames_ = 0;
            }
        }
    }

    void wake_pcm_sender_thread() {
        pcm_sender_wake_.store(true, std::memory_order_release);
        pcm_sender_cv_.notify_one();
    }

    static void consume_opus_pcm_buffer(ParticipantData& participant, size_t frame_count) {
        if (participant.opus_pcm_buffered_frames <= frame_count) {
            participant.opus_pcm_buffered_frames = 0;
            return;
        }

        const size_t remaining = participant.opus_pcm_buffered_frames - frame_count;
        std::move(participant.opus_pcm_buffer.begin() + static_cast<std::ptrdiff_t>(frame_count),
                  participant.opus_pcm_buffer.begin() +
                      static_cast<std::ptrdiff_t>(participant.opus_pcm_buffered_frames),
                  participant.opus_pcm_buffer.begin());
        participant.opus_pcm_buffered_frames = remaining;
    }

    static size_t pcm_target_packets_for_frame_count(uint16_t frame_count) {
        return frame_count <= 128 ? 2 : 3;
    }

    static size_t pcm_remote_frame_count_or(const ParticipantData& participant,
                                            size_t fallback_frame_count) {
        const uint16_t remote_frame_count =
            participant.pcm_remote_frame_count.load(std::memory_order_relaxed);
        return remote_frame_count > 0 ? remote_frame_count : fallback_frame_count;
    }

    static size_t pcm_target_buffer_frames(const ParticipantData& participant,
                                           size_t fallback_frame_count) {
        const size_t remote_frame_count =
            pcm_remote_frame_count_or(participant, fallback_frame_count);
        return remote_frame_count *
               pcm_target_packets_for_frame_count(static_cast<uint16_t>(remote_frame_count));
    }

    static void update_pcm_fifo_depth(ParticipantData& participant) {
        participant.pcm_fifo_depth.store(participant.pcm_fifo_buffered_frames,
                                         std::memory_order_relaxed);
    }

    static void drop_pcm_fifo_frames(ParticipantData& participant, size_t frames_to_drop) {
        const size_t dropped = std::min(frames_to_drop, participant.pcm_fifo_buffered_frames);
        participant.pcm_fifo_read_index =
            (participant.pcm_fifo_read_index + dropped) %
            ParticipantData::PCM_FIFO_CAPACITY_FRAMES;
        participant.pcm_fifo_buffered_frames -= dropped;
        update_pcm_fifo_depth(participant);
    }

    static void trim_pcm_fifo_to_latency_target(ParticipantData& participant,
                                                size_t local_frame_count) {
        const size_t target_frames = pcm_target_buffer_frames(participant, local_frame_count);
        const size_t remote_frame_count =
            pcm_remote_frame_count_or(participant, local_frame_count);
        const size_t high_watermark =
            target_frames + (std::max(remote_frame_count, local_frame_count) * 2);

        if (participant.pcm_fifo_buffered_frames > high_watermark) {
            const size_t frames_to_drop = participant.pcm_fifo_buffered_frames - target_frames;
            drop_pcm_fifo_frames(participant, frames_to_drop);
            participant.pcm_drift_drops.fetch_add(1, std::memory_order_relaxed);
            participant.jitter_depth_drops.fetch_add(1, std::memory_order_relaxed);
        }
    }

    static bool append_pcm_packet_to_fifo(ParticipantData& participant,
                                          const OpusPacket& packet,
                                          size_t local_frame_count) {
        if (packet.sample_rate != 48000 || packet.channels != 1 || packet.frame_count == 0) {
            participant.pcm_format_drops.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        const size_t packet_frames = packet.frame_count;
        const size_t expected_bytes = packet_frames * sizeof(int16_t);
        if (packet.get_size() != expected_bytes) {
            participant.pcm_size_mismatches.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        if (packet_frames > ParticipantData::PCM_FIFO_CAPACITY_FRAMES) {
            participant.pcm_format_drops.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        participant.pcm_remote_frame_count.store(packet.frame_count, std::memory_order_relaxed);
        if (participant.pcm_fifo_buffered_frames + packet_frames >
            ParticipantData::PCM_FIFO_CAPACITY_FRAMES) {
            const size_t overflow =
                participant.pcm_fifo_buffered_frames + packet_frames -
                ParticipantData::PCM_FIFO_CAPACITY_FRAMES;
            drop_pcm_fifo_frames(participant, overflow);
            participant.pcm_fifo_overflows.fetch_add(1, std::memory_order_relaxed);
            participant.jitter_depth_drops.fetch_add(1, std::memory_order_relaxed);
        }

        for (size_t i = 0; i < packet_frames; ++i) {
            int16_t sample = 0;
            std::memcpy(&sample, packet.get_data() + i * sizeof(sample), sizeof(sample));
            const size_t write_index =
                (participant.pcm_fifo_read_index + participant.pcm_fifo_buffered_frames) %
                ParticipantData::PCM_FIFO_CAPACITY_FRAMES;
            participant.pcm_fifo[write_index] = static_cast<float>(sample) / 32767.0F;
            participant.pcm_fifo_buffered_frames++;
        }

        update_pcm_fifo_depth(participant);
        trim_pcm_fifo_to_latency_target(participant, local_frame_count);
        return true;
    }

    static size_t read_pcm_fifo(ParticipantData& participant, float* output,
                                size_t frame_count) {
        const size_t frames_to_read = std::min(frame_count, participant.pcm_fifo_buffered_frames);
        for (size_t i = 0; i < frames_to_read; ++i) {
            output[i] = participant.pcm_fifo[participant.pcm_fifo_read_index];
            participant.pcm_fifo_read_index =
                (participant.pcm_fifo_read_index + 1) %
                ParticipantData::PCM_FIFO_CAPACITY_FRAMES;
        }
        participant.pcm_fifo_buffered_frames -= frames_to_read;
        update_pcm_fifo_depth(participant);
        return frames_to_read;
    }

    static void drain_pcm_packets_until(ParticipantData& participant, size_t target_frames,
                                        size_t local_frame_count) {
        while (participant.pcm_fifo_buffered_frames < target_frames) {
            OpusPacket next_packet;
            if (!participant.opus_queue.try_dequeue(next_packet)) {
                break;
            }
            if (next_packet.codec != AudioCodec::PcmInt16) {
                participant.jitter_depth_drops.fetch_add(1, std::memory_order_relaxed);
                break;
            }
            append_pcm_packet_to_fifo(participant, next_packet, local_frame_count);
        }
    }

    static size_t pcm_drain_target_frames(const ParticipantData& participant,
                                          size_t local_frame_count) {
        return std::max(local_frame_count,
                        pcm_target_buffer_frames(participant, local_frame_count));
    }

    static bool mix_pcm_fifo_to_output(ParticipantData& participant, float* output_buffer,
                                       size_t frame_count, size_t out_channels) {
        if (frame_count == 0 || frame_count > participant.pcm_buffer.size()) {
            return false;
        }

        const size_t frames_read =
            read_pcm_fifo(participant, participant.pcm_buffer.data(), frame_count);
        const bool had_fallback_source =
            participant.last_pcm_valid && !participant.pcm_concealment_used &&
            participant.last_pcm_samples > 0;
        const bool rendered_any_audio = frames_read > 0 || had_fallback_source;
        if (frames_read < frame_count) {
            const float fade_start =
                frames_read > 0
                    ? participant.pcm_buffer[frames_read - 1]
                    : (had_fallback_source
                           ? participant.last_pcm_buffer[participant.last_pcm_samples - 1]
                           : 0.0F);
            constexpr size_t FADE_SAMPLES = 16;
            for (size_t i = frames_read; i < frame_count; ++i) {
                const size_t tail_index = i - frames_read;
                if (tail_index < FADE_SAMPLES) {
                    const float fade =
                        1.0F -
                        (static_cast<float>(tail_index + 1) /
                         static_cast<float>(FADE_SAMPLES + 1));
                    participant.pcm_buffer[i] = fade_start * fade;
                } else {
                    participant.pcm_buffer[i] = 0.0F;
                }
            }
            participant.pcm_fifo_underflows.fetch_add(1, std::memory_order_relaxed);
            participant.pcm_concealment_frames.fetch_add(1, std::memory_order_relaxed);
            participant.underrun_count++;
            participant.pcm_concealment_used = true;
        } else {
            participant.pcm_concealment_used = false;
        }

        if (!rendered_any_audio) {
            return false;
        }

        std::copy_n(participant.pcm_buffer.begin(), frame_count,
                    participant.last_pcm_buffer.begin());
        participant.last_pcm_samples = frame_count;
        participant.last_pcm_valid = true;

        float rms = audio_analysis::calculate_rms(participant.pcm_buffer.data(), frame_count);
        participant.current_level = rms;

        bool was_speaking       = participant.is_speaking;
        participant.is_speaking = audio_analysis::detect_voice_activity(rms);
        (void)was_speaking;

        if (out_channels == 1) {
            audio_analysis::mix_with_gain(output_buffer, participant.pcm_buffer.data(),
                                          frame_count, participant.gain);
        } else {
            audio_analysis::mix_mono_to_stereo(output_buffer, participant.pcm_buffer.data(),
                                               frame_count, out_channels, participant.gain);
        }

        trim_pcm_fifo_to_latency_target(participant, frame_count);
        return true;
    }

    static void observe_participant_queue_depth(ParticipantData& participant, size_t depth) {
        size_t previous_max = participant.queue_depth_max.load(std::memory_order_relaxed);
        while (depth > previous_max &&
               !participant.queue_depth_max.compare_exchange_weak(
                   previous_max, depth, std::memory_order_relaxed)) {
        }

        size_t previous_avg = participant.queue_depth_avg.load(std::memory_order_relaxed);
        size_t next_avg = previous_avg == 0 ? depth : ((previous_avg * 31) + depth) / 32;
        participant.queue_depth_avg.store(next_avg, std::memory_order_relaxed);

        const auto drift_milli =
            (static_cast<int64_t>(depth) - static_cast<int64_t>(TARGET_OPUS_QUEUE_SIZE)) * 1000;
        const auto previous_drift =
            participant.queue_depth_drift_milli.load(std::memory_order_relaxed);
        const auto next_drift =
            previous_drift == 0 ? drift_milli : ((previous_drift * 31) + drift_milli) / 32;
        participant.queue_depth_drift_milli.store(next_drift, std::memory_order_relaxed);
    }

    static size_t max_receive_queue_packets(uint16_t frame_count) {
        if (frame_count == 0) {
            return TARGET_OPUS_QUEUE_SIZE + 1;
        }

        constexpr size_t MAX_QUEUE_BUDGET_MS = 36;
        const size_t frames_per_packet = frame_count;
        const size_t queue_budget_frames = (48000 * MAX_QUEUE_BUDGET_MS) / 1000;
        const size_t packets_for_budget =
            (queue_budget_frames + frames_per_packet - 1) / frames_per_packet;
        const size_t burst_slack_packets = 2;
        return std::clamp(packets_for_budget + burst_slack_packets,
                          static_cast<size_t>(8), static_cast<size_t>(128));
    }

    static size_t jitter_floor_for_packet(const OpusPacket& packet) {
        if (packet.codec == AudioCodec::PcmInt16 && packet.frame_count <= 128) {
            return 2;
        }
        if (packet.codec == AudioCodec::Opus && packet.frame_count <= 120) {
            return 5;
        }
        return MIN_JITTER_BUFFER_PACKETS;
    }

    static void update_jitter_floor(ParticipantData& participant, const OpusPacket& packet) {
        const size_t floor_packets = jitter_floor_for_packet(packet);
        participant.jitter_buffer_floor_packets = floor_packets;
        if (participant.jitter_buffer_min_packets < floor_packets ||
            (!participant.buffer_ready && participant.jitter_buffer_min_packets > floor_packets)) {
            participant.jitter_buffer_min_packets = floor_packets;
        }
    }

    void observe_pcm_send_queue_age(std::chrono::steady_clock::time_point capture_time) {
        if (capture_time.time_since_epoch().count() == 0) {
            return;
        }

        const auto age_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                std::chrono::steady_clock::now() - capture_time)
                                .count();
        pcm_send_queue_age_last_ns_.store(age_ns, std::memory_order_relaxed);

        int64_t previous_max = pcm_send_queue_age_max_ns_.load(std::memory_order_relaxed);
        while (age_ns > previous_max &&
               !pcm_send_queue_age_max_ns_.compare_exchange_weak(
                   previous_max, age_ns, std::memory_order_relaxed)) {
        }

        const int64_t previous_avg = pcm_send_queue_age_avg_ns_.load(std::memory_order_relaxed);
        const int64_t next_avg =
            previous_avg == 0 ? age_ns : ((previous_avg * 31) + age_ns) / 32;
        pcm_send_queue_age_avg_ns_.store(next_avg, std::memory_order_relaxed);
    }

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
        auto buf = std::make_shared<std::vector<unsigned char>>(sizeof(CtrlHdr));
        std::memcpy(buf->data(), &chdr, sizeof(CtrlHdr));
        send(buf->data(), buf->size(), buf);
        log_audio_diagnostics();
    }

    void log_audio_diagnostics() {
        struct DropRate {
            double pcm_send_per_sec;
            double opus_send_per_sec;
            double jitter_depth_per_sec;
            double jitter_age_per_sec;
            double pcm_hold_per_sec;
            double pcm_drift_drop_per_sec;
            double pcm_format_drop_per_sec;
            double pcm_size_mismatch_per_sec;
            double pcm_fifo_underflow_per_sec;
            double pcm_fifo_overflow_per_sec;
        };

        auto calculate_rate = [](uint64_t current, uint64_t previous, double elapsed_sec) {
            if (elapsed_sec <= 0.0 || current < previous) {
                return 0.0;
            }
            return static_cast<double>(current - previous) / elapsed_sec;
        };

        const auto now = std::chrono::steady_clock::now();
        double elapsed_sec = 0.0;
        if (last_audio_health_log_time_.time_since_epoch().count() != 0) {
            elapsed_sec = std::chrono::duration<double>(now - last_audio_health_log_time_).count();
        }
        last_audio_health_log_time_ = now;

        const uint64_t pcm_send_drops = pcm_send_drops_.load(std::memory_order_relaxed);
        const uint64_t opus_send_drops = opus_send_drops_.load(std::memory_order_relaxed);
        const double pcm_send_drop_rate =
            calculate_rate(pcm_send_drops, last_pcm_send_drops_, elapsed_sec);
        const double opus_send_drop_rate =
            calculate_rate(opus_send_drops, last_opus_send_drops_, elapsed_sec);
        last_pcm_send_drops_ = pcm_send_drops;
        last_opus_send_drops_ = opus_send_drops;

        const auto participants = participant_manager_.get_all_info();
        const auto ns_to_ms = [](int64_t ns) {
            return static_cast<double>(ns) / 1'000'000.0;
        };

        Log::info(
            "Audio diag: frames cfg/cb/tx={}/{}/{} tx_packets={} tx_drops pcm/opus={}/{} "
            "sendq_age_ms last/avg/max={:.2f}/{:.2f}/{:.2f} rx_bytes={} tx_bytes={}",
                  audio_config_.frames_per_buffer,
                  audio_callback_frame_count_last_.load(std::memory_order_relaxed),
                  pcm_tx_packet_frame_count_.load(std::memory_order_relaxed),
                  audio_tx_sequence_.load(std::memory_order_relaxed),
                  pcm_send_drops,
                  opus_send_drops,
                  ns_to_ms(pcm_send_queue_age_last_ns_.load(std::memory_order_relaxed)),
                  ns_to_ms(pcm_send_queue_age_avg_ns_.load(std::memory_order_relaxed)),
                  ns_to_ms(pcm_send_queue_age_max_ns_.load(std::memory_order_relaxed)),
                  total_bytes_rx_.load(std::memory_order_relaxed),
                  total_bytes_tx_.load(std::memory_order_relaxed));

        for (const auto& p: participants) {
            auto& previous = participant_drop_snapshots_[p.id];
            DropRate drop_rate{
                pcm_send_drop_rate,
                opus_send_drop_rate,
                calculate_rate(p.jitter_depth_drops, previous.jitter_depth_drops, elapsed_sec),
                calculate_rate(p.jitter_age_drops, previous.jitter_age_drops, elapsed_sec),
                calculate_rate(p.pcm_concealment_frames, previous.pcm_concealment_frames,
                               elapsed_sec),
                calculate_rate(p.pcm_drift_drops, previous.pcm_drift_drops, elapsed_sec),
                calculate_rate(p.pcm_format_drops, previous.pcm_format_drops, elapsed_sec),
                calculate_rate(p.pcm_size_mismatches, previous.pcm_size_mismatches, elapsed_sec),
                calculate_rate(p.pcm_fifo_underflows, previous.pcm_fifo_underflows, elapsed_sec),
                calculate_rate(p.pcm_fifo_overflows, previous.pcm_fifo_overflows, elapsed_sec),
            };
            previous.jitter_depth_drops = p.jitter_depth_drops;
            previous.jitter_age_drops = p.jitter_age_drops;
            previous.pcm_concealment_frames = p.pcm_concealment_frames;
            previous.pcm_drift_drops = p.pcm_drift_drops;
            previous.pcm_format_drops = p.pcm_format_drops;
            previous.pcm_size_mismatches = p.pcm_size_mismatches;
            previous.pcm_fifo_underflows = p.pcm_fifo_underflows;
            previous.pcm_fifo_overflows = p.pcm_fifo_overflows;

            Log::info(
                "Participant diag {}: ready={} q={} q_avg={} q_max={} q_drift={:.2f} "
                "age_avg_ms={:.1f} underruns={} pcm_hold/drop={}/{} drops q/age={}/{} seq gap/late={}/{} "
                "pcm_fifo frame/depth={}/{} bad fmt/size={}/{} fifo under/over={}/{} "
                "drop_rate pcm/q/hold/drift/bad/under={:.1f}/{:.1f}/{:.1f}/{:.1f}/{:.1f}/{:.1f}/s",
                p.id, p.buffer_ready, p.queue_size, p.queue_size_avg, p.queue_size_max,
                p.queue_drift_packets, p.packet_age_avg_ms, p.underrun_count,
                p.pcm_concealment_frames, p.pcm_drift_drops,
                p.jitter_depth_drops, p.jitter_age_drops, p.sequence_gaps,
                p.sequence_late_or_reordered, p.pcm_remote_frame_count, p.pcm_fifo_depth,
                p.pcm_format_drops, p.pcm_size_mismatches, p.pcm_fifo_underflows,
                p.pcm_fifo_overflows, drop_rate.pcm_send_per_sec,
                drop_rate.jitter_depth_per_sec, drop_rate.pcm_hold_per_sec,
                drop_rate.pcm_drift_drop_per_sec,
                drop_rate.pcm_format_drop_per_sec + drop_rate.pcm_size_mismatch_per_sec,
                drop_rate.pcm_fifo_underflow_per_sec);

            if (elapsed_sec > 0.0 &&
                (drop_rate.pcm_send_per_sec > 5.0 ||
                 drop_rate.jitter_depth_per_sec > 100.0 ||
                 drop_rate.jitter_age_per_sec > 5.0 ||
                 drop_rate.pcm_hold_per_sec > 5.0 ||
                 drop_rate.pcm_drift_drop_per_sec > 5.0 ||
                 drop_rate.pcm_format_drop_per_sec > 0.0 ||
                 drop_rate.pcm_size_mismatch_per_sec > 0.0 ||
                 drop_rate.pcm_fifo_underflow_per_sec > 5.0 ||
                 drop_rate.pcm_fifo_overflow_per_sec > 0.0)) {
                Log::warn(
                    "Audio health warning for participant {}: likely corrupt/robotic risk "
                    "(pcm_drop_rate={:.1f}/s opus_drop_rate={:.1f}/s "
                    "queue_drop_rate={:.1f}/s age_drop_rate={:.1f}/s "
                    "pcm_hold_rate={:.1f}/s pcm_drift_drop_rate={:.1f}/s "
                    "pcm_bad_rate={:.1f}/s pcm_fifo_under_rate={:.1f}/s)",
                    p.id, drop_rate.pcm_send_per_sec, drop_rate.opus_send_per_sec,
                    drop_rate.jitter_depth_per_sec, drop_rate.jitter_age_per_sec,
                    drop_rate.pcm_hold_per_sec, drop_rate.pcm_drift_drop_per_sec,
                    drop_rate.pcm_format_drop_per_sec + drop_rate.pcm_size_mismatch_per_sec,
                    drop_rate.pcm_fifo_underflow_per_sec);
            }
        }
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
            case CtrlHdr::Cmd::PARTICIPANT_INFO: {
                if (bytes < sizeof(ParticipantInfoHdr)) {
                    break;
                }
                ParticipantInfoHdr info{};
                std::memcpy(&info, recv_buf_.data(), sizeof(ParticipantInfoHdr));
                const auto profile_id = fixed_string(info.profile_id);
                const auto display_name = fixed_string(info.display_name);
                participant_manager_.set_participant_metadata(info.participant_id, profile_id,
                                                              display_name);
                Log::info("Participant {} metadata: user='{}' display='{}'", info.participant_id,
                          profile_id, display_name);
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
        MsgHdr msg_hdr{};
        std::memcpy(&msg_hdr, recv_buf_.data(), sizeof(MsgHdr));
        const bool is_v2 = msg_hdr.magic == AUDIO_V2_MAGIC;
        const size_t min_packet_size =
            is_v2 ? sizeof(AudioHdrV2) - AUDIO_BUF_SIZE
                  : sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t);

        if (!message_validator::is_valid_audio_packet(bytes, min_packet_size)) {
            return;
        }

        const auto* packet_bytes = reinterpret_cast<const unsigned char*>(recv_buf_.data());
        uint32_t sender_id = packet_builder::extract_sender_id(packet_bytes);
        uint16_t payload_bytes =
            is_v2 ? packet_builder::extract_v2_payload_bytes(packet_bytes)
                  : packet_builder::extract_encoded_bytes(packet_bytes);

        size_t expected_size = min_packet_size + payload_bytes;
        if (!message_validator::has_complete_payload(bytes, expected_size)) {
            Log::error("Incomplete audio packet: got {}, expected {} (payload_bytes={})", bytes,
                       expected_size, payload_bytes);
            return;
        }

        // Additional safety check: ensure encoded_bytes is reasonable
        if (!message_validator::is_encoded_bytes_valid(payload_bytes, AUDIO_BUF_SIZE)) {
            Log::error("Invalid audio packet: payload_bytes {} exceeds max {}", payload_bytes,
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

        const unsigned char* audio_data =
            is_v2 ? packet_builder::audio_v2_payload(packet_bytes)
                  : packet_builder::audio_v1_payload(packet_bytes);

        // CRITICAL: Enqueue audio packet, DON'T decode here
        // Decoding happens in time-driven audio_callback
        participant_manager_.with_participant(sender_id, [&](ParticipantData& participant) {
            OpusPacket packet;
            // Use memcpy for zero-allocation copy (fixed buffer)
            if (payload_bytes <= AUDIO_BUF_SIZE) {
                std::memcpy(packet.data.data(), audio_data, payload_bytes);
                packet.size      = payload_bytes;
                packet.timestamp = std::chrono::steady_clock::now();
                if (is_v2) {
                    AudioHdrV2 audio_hdr{};
                    std::memcpy(&audio_hdr, recv_buf_.data(), sizeof(AudioHdrV2) - AUDIO_BUF_SIZE);
                    packet.codec       = audio_hdr.codec;
                    packet.sequence    = audio_hdr.sequence;
                    packet.sample_rate = audio_hdr.sample_rate;
                    packet.frame_count = audio_hdr.frame_count;
                    packet.channels    = audio_hdr.channels;
                    if (packet.codec == AudioCodec::PcmInt16) {
                        const bool valid_format =
                            packet.sample_rate == 48000 && packet.channels == 1 &&
                            packet.frame_count > 0;
                        const size_t expected_pcm_bytes =
                            static_cast<size_t>(packet.frame_count) * sizeof(int16_t);
                        if (!valid_format) {
                            participant.pcm_format_drops.fetch_add(1, std::memory_order_relaxed);
                            return;
                        }
                        if (payload_bytes != expected_pcm_bytes) {
                            participant.pcm_size_mismatches.fetch_add(1,
                                                                      std::memory_order_relaxed);
                            return;
                        }
                    }
                    if (!participant.sequence_initialized) {
                        participant.sequence_initialized = true;
                        participant.next_expected_sequence = packet.sequence + 1;
                    } else if (packet.sequence == participant.next_expected_sequence) {
                        participant.next_expected_sequence++;
                    } else if (packet.sequence > participant.next_expected_sequence) {
                        participant.sequence_gaps.fetch_add(
                            packet.sequence - participant.next_expected_sequence,
                            std::memory_order_relaxed);
                        participant.next_expected_sequence = packet.sequence + 1;
                    } else {
                        participant.sequence_late_or_reordered.fetch_add(
                            1, std::memory_order_relaxed);
                    }
                } else {
                    packet.codec       = AudioCodec::Opus;
                    packet.sample_rate = static_cast<uint32_t>(audio_config_.sample_rate);
                    packet.frame_count = static_cast<uint16_t>(audio_config_.frames_per_buffer);
                    packet.channels    = 1;
                }
            } else {
                Log::error("Packet too large: {} bytes (max {})", payload_bytes, AUDIO_BUF_SIZE);
                return;
            }

            size_t queue_size = participant.opus_queue.size_approx();
            observe_participant_queue_depth(participant, queue_size);
            update_jitter_floor(participant, packet);

            // Bounded jitter management: drop old packets if queue is too large.
            const size_t max_queue_packets = max_receive_queue_packets(packet.frame_count);
            while (queue_size + 1 > max_queue_packets) {
                OpusPacket discarded;
                if (participant.opus_queue.try_dequeue(discarded)) {
                    queue_size--;
                    participant.jitter_depth_drops.fetch_add(1, std::memory_order_relaxed);
                } else {
                    break;
                }
            }

            if (queue_size < MAX_OPUS_QUEUE_SIZE) {
                participant.opus_queue.enqueue(packet);  // OpusPacket is trivially copyable
                size_t queue_after_enqueue = queue_size + 1;
                observe_participant_queue_depth(participant, queue_after_enqueue);
                participant.last_packet_time = packet.timestamp;

                // Mark buffer as ready once we have enough packets
                if (!participant.buffer_ready &&
                    queue_after_enqueue >= participant.jitter_buffer_min_packets) {
                    participant.buffer_ready = true;
                    Log::info("Jitter buffer ready for participant {} ({} packets)", sender_id,
                              queue_after_enqueue);
                }
            } else {
                // Buffer overflow - drop oldest packet (safety limit)
                OpusPacket discarded;
                participant.opus_queue.try_dequeue(discarded);
                participant.opus_queue.enqueue(packet);  // OpusPacket is trivially copyable
                observe_participant_queue_depth(participant, participant.opus_queue.size_approx());
                participant.last_packet_time = packet.timestamp;
            }
        });
    }

    static int audio_callback(const void* input, void* output, unsigned long frame_count,
                              void* user_data) {
        const auto* input_buffer  = static_cast<const float*>(input);
        auto*       output_buffer = static_cast<float*>(output);
        auto*       client        = static_cast<Client*>(user_data);
        const auto callback_start = std::chrono::steady_clock::now();
        struct TimingScope {
            Client* client;
            std::chrono::steady_clock::time_point start;
            unsigned long frame_count;

            ~TimingScope() {
                auto elapsed = std::chrono::steady_clock::now() - start;
                auto elapsed_ns =
                    std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count();
                auto deadline_ns = static_cast<int64_t>(
                    (static_cast<double>(frame_count) * 1e9) /
                    static_cast<double>(client->audio_config_.sample_rate));

                client->callback_last_ns_.store(elapsed_ns, std::memory_order_relaxed);
                client->callback_deadline_ns_.store(deadline_ns, std::memory_order_relaxed);
                client->callback_count_.fetch_add(1, std::memory_order_relaxed);

                int64_t previous_max = client->callback_max_ns_.load(std::memory_order_relaxed);
                while (elapsed_ns > previous_max &&
                       !client->callback_max_ns_.compare_exchange_weak(
                           previous_max, elapsed_ns, std::memory_order_relaxed)) {
                }

                int64_t previous_avg = client->callback_avg_ns_.load(std::memory_order_relaxed);
                int64_t next_avg = previous_avg == 0 ? elapsed_ns : ((previous_avg * 31) + elapsed_ns) / 32;
                client->callback_avg_ns_.store(next_avg, std::memory_order_relaxed);

                if (elapsed_ns > deadline_ns) {
                    client->callback_over_deadline_count_.fetch_add(1, std::memory_order_relaxed);
                }
            }
        } timing_scope{client, callback_start, frame_count};

        client->audio_callback_frame_count_last_.store(static_cast<uint32_t>(frame_count),
                                                       std::memory_order_relaxed);

#ifdef _WIN32
        // Boost thread priority on Windows for minimal audio latency
        static bool priority_set = false;
        if (!priority_set) {
            SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
            priority_set = true;
        }
#endif

        if (output_buffer == nullptr) {
            return 0;
        }

        const size_t out_channels  = client->audio_.get_output_channel_count();
        const size_t bytes_to_copy = frame_count * out_channels * sizeof(float);

        // Initialize output buffer to silence
        std::memset(output_buffer, 0, bytes_to_copy);

        // Mix audio from all active participants (thread-safe iteration)
        int active_count = 0;
        client->participant_manager_.for_each([&](uint32_t         participant_id,
                                                  ParticipantData& participant) {
            if (participant.is_muted) {
                return;
            }

            if (!participant.buffer_ready) {
                const size_t queue_size = participant.opus_queue.size_approx();
                observe_participant_queue_depth(participant, queue_size);
                if (queue_size >= participant.jitter_buffer_min_packets) {
                    participant.buffer_ready = true;
                    Log::info("Jitter buffer ready for participant {} ({} packets)",
                              participant_id, queue_size);
                } else {
                    return;
                }
            }

            if (participant.last_codec == AudioCodec::Opus &&
                participant.opus_pcm_buffered_frames >= frame_count) {
                if (out_channels == 1) {
                    audio_analysis::mix_with_gain(output_buffer,
                                                  participant.opus_pcm_buffer.data(), frame_count,
                                                  participant.gain);
                } else {
                    audio_analysis::mix_mono_to_stereo(output_buffer,
                                                       participant.opus_pcm_buffer.data(),
                                                       frame_count, out_channels,
                                                       participant.gain);
                }
                consume_opus_pcm_buffer(participant, frame_count);
                active_count++;
                observe_participant_queue_depth(participant, participant.opus_queue.size_approx());
                return;
            }

            if (participant.last_codec == AudioCodec::PcmInt16) {
                drain_pcm_packets_until(participant,
                                        pcm_drain_target_frames(participant, frame_count),
                                        frame_count);
                if (participant.pcm_fifo_buffered_frames > 0 ||
                    (participant.last_pcm_valid && !participant.pcm_concealment_used)) {
                    if (mix_pcm_fifo_to_output(participant, output_buffer, frame_count,
                                               out_channels)) {
                        active_count++;
                    }
                    observe_participant_queue_depth(participant,
                                                    participant.opus_queue.size_approx());
                    return;
                }
            }

            OpusPacket opus_packet;

            if (participant.opus_queue.try_dequeue(opus_packet)) {
                auto now = std::chrono::steady_clock::now();
                auto packet_age = now - opus_packet.timestamp;
                auto packet_age_ns =
                    std::chrono::duration_cast<std::chrono::nanoseconds>(packet_age).count();
                const auto max_packet_age_ns =
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        std::chrono::milliseconds(MAX_JITTER_PACKET_AGE_MS))
                        .count();

                while (packet_age_ns > max_packet_age_ns) {
                    participant.jitter_age_drops.fetch_add(1, std::memory_order_relaxed);
                    if (!participant.opus_queue.try_dequeue(opus_packet)) {
                        participant.underrun_count++;
                        return;
                    }
                    now = std::chrono::steady_clock::now();
                    packet_age = now - opus_packet.timestamp;
                    packet_age_ns =
                        std::chrono::duration_cast<std::chrono::nanoseconds>(packet_age).count();
                }

                participant.packet_age_last_ns.store(packet_age_ns, std::memory_order_relaxed);
                int64_t previous_age_max =
                    participant.packet_age_max_ns.load(std::memory_order_relaxed);
                while (packet_age_ns > previous_age_max &&
                       !participant.packet_age_max_ns.compare_exchange_weak(
                           previous_age_max, packet_age_ns, std::memory_order_relaxed)) {
                }
                int64_t previous_age_avg =
                    participant.packet_age_avg_ns.load(std::memory_order_relaxed);
                int64_t next_age_avg =
                    previous_age_avg == 0 ? packet_age_ns : ((previous_age_avg * 31) + packet_age_ns) / 32;
                participant.packet_age_avg_ns.store(next_age_avg, std::memory_order_relaxed);

                participant.last_codec = opus_packet.codec;
                int decoded_samples = 0;
                if (opus_packet.codec == AudioCodec::PcmInt16) {
                    if (!append_pcm_packet_to_fifo(participant, opus_packet, frame_count)) {
                        observe_participant_queue_depth(participant,
                                                        participant.opus_queue.size_approx());
                        return;
                    }
                    drain_pcm_packets_until(participant,
                                            pcm_drain_target_frames(participant, frame_count),
                                            frame_count);
                    if (mix_pcm_fifo_to_output(participant, output_buffer, frame_count,
                                               out_channels)) {
                        active_count++;
                    }
                    observe_participant_queue_depth(participant,
                                                    participant.opus_queue.size_approx());
                    return;
                } else {
                    const int decode_frame_count =
                        opus_packet.frame_count > 0 ? static_cast<int>(opus_packet.frame_count)
                                                    : static_cast<int>(frame_count);
                    // Decode into preallocated buffer (zero allocations)
                    decoded_samples = participant.decoder->decode_into(
                        opus_packet.get_data(), static_cast<int>(opus_packet.get_size()),
                        participant.pcm_buffer.data(), decode_frame_count);
                }

                if (decoded_samples <= 0) {
                    // Decode failed - use silence
                    static int decode_fail_count = 0;
                    if (++decode_fail_count % 100 == 0) {
                        Log::warn("Decode failed for participant {} ({} times)", participant_id,
                                  decode_fail_count);
                    }
                    return;
                }

                if (opus_packet.codec == AudioCodec::Opus) {
                    const size_t decoded_frames = static_cast<size_t>(decoded_samples);
                    if (participant.opus_pcm_buffered_frames + decoded_frames <=
                        participant.opus_pcm_buffer.size()) {
                        std::copy_n(participant.pcm_buffer.begin(), decoded_frames,
                                    participant.opus_pcm_buffer.begin() +
                                        static_cast<std::ptrdiff_t>(
                                            participant.opus_pcm_buffered_frames));
                        participant.opus_pcm_buffered_frames += decoded_frames;
                    } else {
                        participant.opus_pcm_buffered_frames = 0;
                        participant.jitter_depth_drops.fetch_add(1, std::memory_order_relaxed);
                    }

                    while (participant.opus_pcm_buffered_frames < frame_count) {
                        OpusPacket next_packet;
                        if (!participant.opus_queue.try_dequeue(next_packet) ||
                            next_packet.codec != AudioCodec::Opus) {
                            break;
                        }

                        const int next_decode_frame_count =
                            next_packet.frame_count > 0
                                ? static_cast<int>(next_packet.frame_count)
                                : static_cast<int>(frame_count);
                        int next_decoded_samples = participant.decoder->decode_into(
                            next_packet.get_data(), static_cast<int>(next_packet.get_size()),
                            participant.pcm_buffer.data(), next_decode_frame_count);
                        if (next_decoded_samples <= 0) {
                            break;
                        }

                        const size_t next_decoded_frames =
                            static_cast<size_t>(next_decoded_samples);
                        if (participant.opus_pcm_buffered_frames + next_decoded_frames >
                            participant.opus_pcm_buffer.size()) {
                            participant.opus_pcm_buffered_frames = 0;
                            participant.jitter_depth_drops.fetch_add(1, std::memory_order_relaxed);
                            break;
                        }

                        std::copy_n(participant.pcm_buffer.begin(), next_decoded_frames,
                                    participant.opus_pcm_buffer.begin() +
                                        static_cast<std::ptrdiff_t>(
                                            participant.opus_pcm_buffered_frames));
                        participant.opus_pcm_buffered_frames += next_decoded_frames;
                    }

                    float rms = audio_analysis::calculate_rms(participant.pcm_buffer.data(),
                                                              decoded_samples);
                    participant.current_level = rms;

                    bool was_speaking       = participant.is_speaking;
                    participant.is_speaking = audio_analysis::detect_voice_activity(rms);

                    if (participant.opus_pcm_buffered_frames >= frame_count) {
                        if (out_channels == 1) {
                            audio_analysis::mix_with_gain(output_buffer,
                                                          participant.opus_pcm_buffer.data(),
                                                          frame_count, participant.gain);
                        } else {
                            audio_analysis::mix_mono_to_stereo(
                                output_buffer, participant.opus_pcm_buffer.data(), frame_count,
                                out_channels, participant.gain);
                        }
                        consume_opus_pcm_buffer(participant, frame_count);
                        active_count++;
                    }

                    if (participant.is_speaking && !was_speaking) {
                        Log::debug("Participant {} started speaking (level: {:.4f})",
                                   participant_id, rms);
                    } else if (!participant.is_speaking && was_speaking) {
                        Log::debug("Participant {} stopped speaking", participant_id);
                    }

                    observe_participant_queue_depth(participant,
                                                    participant.opus_queue.size_approx());
                    return;
                }

                participant.pcm_format_drops.fetch_add(1, std::memory_order_relaxed);
            } else {
                // Underrun - use PLC instead of silence for smoother audio
                size_t current_queue_size = participant.opus_queue.size_approx();
                observe_participant_queue_depth(participant, current_queue_size);

                int plc_samples = 0;
                if (participant.last_codec == AudioCodec::Opus) {
                    plc_samples = participant.decoder->decode_plc(participant.pcm_buffer.data(),
                                                                  static_cast<int>(frame_count));
                }

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

                // PCM has no PLC fallback. A transient empty queue should produce one silent
                // callback, then keep trying next callback instead of permanently disabling
                // playback while packets keep arriving.
                if (participant.last_codec == AudioCodec::PcmInt16) {
                    if (participant.last_pcm_valid && !participant.pcm_concealment_used &&
                        participant.last_pcm_samples == frame_count) {
                        constexpr float concealment_gain = 0.5F;
                        if (out_channels == 1) {
                            audio_analysis::mix_with_gain(
                                output_buffer, participant.last_pcm_buffer.data(), frame_count,
                                participant.gain * concealment_gain);
                        } else {
                            audio_analysis::mix_mono_to_stereo(
                                output_buffer, participant.last_pcm_buffer.data(), frame_count,
                                out_channels, participant.gain * concealment_gain);
                        }
                        participant.pcm_concealment_used = true;
                        participant.pcm_concealment_frames.fetch_add(
                            1, std::memory_order_relaxed);
                        participant.underrun_count++;
                    }
                    return;
                }

                // Handle Opus rebuffering state (PLC handles short gaps above)
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
        std::array<float, 960>
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
        if (client->audio_.is_stream_active()) {
            if (client->audio_codec_.load(std::memory_order_acquire) == AudioCodec::PcmInt16) {
                client->opus_tx_accumulated_frames_ = 0;

                std::array<float, 960> pcm_input{};
                if (wav_active && wav_frames_read > 0) {
                    float wav_gain = client->wav_gain_.load(std::memory_order_acquire);
                    for (int i = 0; i < wav_frames_read; ++i) {
                        pcm_input[static_cast<size_t>(i)] = wav_buffer[static_cast<size_t>(i)] * wav_gain;
                    }
                }
                if (input_buffer != nullptr && !client->mic_muted_.load(std::memory_order_acquire)) {
                    float input_gain = client->input_gain_.load(std::memory_order_acquire);
                    for (unsigned long i = 0; i < frame_count; ++i) {
                        float mic_sample = input_buffer[i] * input_gain;
                        pcm_input[i] = wav_active ? (pcm_input[i] + mic_sample) * 0.5F : mic_sample;
                    }
                } else if (wav_active) {
                    for (unsigned long i = 0; i < frame_count; ++i) {
                        pcm_input[i] *= 0.5F;
                    }
                }

                float rms = audio_analysis::calculate_rms(pcm_input.data(), frame_count);
                client->own_audio_level_.store(rms);

                client->enqueue_pcm_send_samples(
                    pcm_input.data(), frame_count,
                    static_cast<uint32_t>(client->audio_config_.sample_rate));
                return 0;
            }

            client->pcm_tx_accumulated_frames_ = 0;
            if (!client->audio_encoder_.is_initialized()) {
                return 0;
            }

            std::array<float, 960> opus_input{};
            if (wav_active && wav_frames_read > 0) {
                float wav_gain = client->wav_gain_.load(std::memory_order_acquire);
                for (int i = 0; i < wav_frames_read; ++i) {
                    opus_input[static_cast<size_t>(i)] = wav_buffer[static_cast<size_t>(i)] * wav_gain;
                }
            }

            if (input_buffer != nullptr && !client->mic_muted_.load(std::memory_order_acquire)) {
                float input_gain = client->input_gain_.load(std::memory_order_acquire);
                for (unsigned long i = 0; i < frame_count; ++i) {
                    float mic_sample = input_buffer[i] * input_gain;
                    opus_input[i] = wav_active ? (opus_input[i] + mic_sample) * 0.5F : mic_sample;
                }
            } else if (wav_active) {
                for (unsigned long i = 0; i < frame_count; ++i) {
                    opus_input[i] *= 0.5F;
                }
            }

            float rms = audio_analysis::calculate_rms(opus_input.data(), frame_count);
            client->own_audio_level_.store(rms);
            client->enqueue_opus_send_samples(
                opus_input.data(), frame_count,
                static_cast<uint32_t>(client->audio_config_.sample_rate));
        }

        return 0;
    }

    asio::io_context& io_context_;
    udp::socket       socket_;
    udp::endpoint     server_endpoint_;
    PerformerJoinOptions performer_join_options_;

    std::array<char, 1024>         recv_buf_;
    std::array<unsigned char, 128> sync_tx_buf_;

    AudioStream              audio_;
    OpusEncoderWrapper       audio_encoder_;
    AudioStream::AudioConfig audio_config_;  // Store config for decoder initialization
    std::atomic<AudioCodec>  audio_codec_{AudioCodec::PcmInt16};
    std::atomic<uint32_t>    audio_tx_sequence_{0};
    moodycamel::ConcurrentQueue<PcmSendFrame> pcm_send_queue_;
    moodycamel::ConcurrentQueue<OpusSendFrame> opus_send_queue_;
    std::array<float, 960>                     pcm_tx_accumulator_{};
    size_t                                     pcm_tx_accumulated_frames_ = 0;
    std::array<float, 960>                     opus_tx_accumulator_{};
    size_t                                     opus_tx_accumulated_frames_ = 0;
    std::atomic<bool>                         pcm_sender_running_{false};
    std::thread                               pcm_sender_thread_;
    std::condition_variable                   pcm_sender_cv_;
    std::mutex                                pcm_sender_wait_mutex_;
    std::atomic<bool>                         pcm_sender_wake_{false};
    std::atomic<uint64_t>                     pcm_send_drops_{0};
    std::atomic<uint64_t>                     opus_send_drops_{0};
    std::atomic<int64_t>                      pcm_send_queue_age_last_ns_{0};
    std::atomic<int64_t>                      pcm_send_queue_age_avg_ns_{0};
    std::atomic<int64_t>                      pcm_send_queue_age_max_ns_{0};
    std::atomic<uint32_t>                     audio_callback_frame_count_last_{0};
    std::atomic<uint16_t>                     pcm_tx_packet_frame_count_{0};

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

    // Audio callback timing diagnostics
    std::atomic<int64_t>  callback_last_ns_{0};
    std::atomic<int64_t>  callback_max_ns_{0};
    std::atomic<int64_t>  callback_avg_ns_{0};
    std::atomic<int64_t>  callback_deadline_ns_{0};
    std::atomic<uint64_t> callback_count_{0};
    std::atomic<uint64_t> callback_over_deadline_count_{0};

    struct ParticipantDropSnapshot {
        uint64_t jitter_depth_drops = 0;
        uint64_t jitter_age_drops   = 0;
        uint64_t pcm_concealment_frames = 0;
        uint64_t pcm_drift_drops = 0;
        uint64_t pcm_format_drops = 0;
        uint64_t pcm_size_mismatches = 0;
        uint64_t pcm_fifo_underflows = 0;
        uint64_t pcm_fifo_overflows = 0;
    };
    std::chrono::steady_clock::time_point                  last_audio_health_log_time_{};
    uint64_t                                               last_pcm_send_drops_  = 0;
    uint64_t                                               last_opus_send_drops_ = 0;
    std::unordered_map<uint32_t, ParticipantDropSnapshot>  participant_drop_snapshots_;

    // Device and encoder info storage
    DeviceInfo  device_info_;
    EncoderInfo encoder_info_;

    // Selected devices (for UI)
    AudioStream::DeviceIndex selected_input_device_;
    AudioStream::DeviceIndex selected_output_device_;

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
    // Reserved space: title, mute btn, fader/meter, label, separator, latency section (4 lines),
    // separator, WAV section
    float fader_height = std::max(200.0F, available_height - 370.0F);

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

        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        ImGui::Text("Codec:");
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        AudioCodec current_codec = client.get_audio_codec();
        int codec_choice = current_codec == AudioCodec::PcmInt16 ? 0 : 1;
        if (ImGui::RadioButton("PCM##codec", codec_choice == 0)) {
            client.set_audio_codec(AudioCodec::PcmInt16);
        }
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        if (ImGui::RadioButton("Opus##codec", codec_choice == 1)) {
            const int previous_buffer_frames = client.get_audio_config().frames_per_buffer;
            client.set_audio_codec(AudioCodec::Opus);
            if (client.is_audio_stream_active() &&
                client.get_audio_config().frames_per_buffer != previous_buffer_frames) {
                client.swap_audio_devices(client.get_selected_input_device(),
                                          client.get_selected_output_device());
            }
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // ========== LATENCY INFO (with padding) ==========
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        Client::DeviceInfo       device_info  = client.get_device_info();
        AudioStream::LatencyInfo latency      = client.get_latency_info();
        AudioStream::AudioConfig audio_config = client.get_audio_config();
        Client::CallbackTimingInfo callback_timing = client.get_callback_timing_info();
        ImGui::Text("%s", device_info.output_api.c_str());
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        ImGui::Text("In: %.1f ms", latency.input_latency_ms);
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        ImGui::Text("Out: %.1f ms", latency.output_latency_ms);
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        ImGui::Text("SR: %d kHz", audio_config.sample_rate / 1000);
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        ImGui::Text("Buf: %d/%d", latency.actual_buffer_frames, latency.requested_buffer_frames);
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        ImGui::Text("Buf ms: %.2f", latency.buffer_duration_ms);
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        ImGui::Text("Cb: %.2f/%.2f ms", callback_timing.avg_ms, callback_timing.deadline_ms);
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        ImGui::Text("Max: %.2f ms", callback_timing.max_ms);
        if (device_info.output_api == "WASAPI" && !latency.backend_latency_available) {
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            ImGui::TextColored(ImVec4(1.0F, 0.6F, 0.2F, 1.0F), "Backend latency unknown");
        }
        if (callback_timing.over_deadline_count > 0) {
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            ImGui::TextColored(ImVec4(1.0F, 0.6F, 0.2F, 1.0F), "Late: %llu",
                               static_cast<unsigned long long>(
                                   callback_timing.over_deadline_count));
        }

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
        char fallback_name_buf[32];
        std::snprintf(fallback_name_buf, sizeof(fallback_name_buf), "User #%u", p.id);
        const std::string participant_name =
            p.display_name.empty() ? std::string(fallback_name_buf) : p.display_name;
        ImGui::Button(participant_name.c_str(), ImVec2(width, 0));
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
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            ImGui::Text("Q avg/max: %zu/%zu", p.queue_size_avg, p.queue_size_max);
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            ImGui::Text("Q drift: %.2f", p.queue_drift_packets);
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            ImGui::Text("Age: %.1f ms", p.packet_age_avg_ms);
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            ImGui::Text("Max age: %.1f ms", p.packet_age_max_ms);
            if (p.sequence_gaps > 0 || p.sequence_late_or_reordered > 0) {
                ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
                ImGui::TextColored(ImVec4(1.0F, 0.6F, 0.2F, 1.0F), "Seq gap/late: %llu/%llu",
                                   static_cast<unsigned long long>(p.sequence_gaps),
                                   static_cast<unsigned long long>(
                                       p.sequence_late_or_reordered));
            }
            if (p.jitter_depth_drops > 0 || p.jitter_age_drops > 0) {
                ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
                ImGui::TextColored(ImVec4(1.0F, 0.6F, 0.2F, 1.0F), "Drop q/age: %llu/%llu",
                                   static_cast<unsigned long long>(p.jitter_depth_drops),
                                   static_cast<unsigned long long>(p.jitter_age_drops));
            }
            if (p.underrun_count > 0) {
                ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
                ImGui::TextColored(ImVec4(1.0F, 0.6F, 0.2F, 1.0F), "Underruns: %d",
                                   p.underrun_count);
            }
            if (p.plc_count > 0) {
                ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
                ImGui::Text("PLC: %zu", p.plc_count);
            }
            if (p.pcm_concealment_frames > 0) {
                ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
                ImGui::Text("PCM hold: %llu",
                            static_cast<unsigned long long>(p.pcm_concealment_frames));
            }
            if (p.pcm_drift_drops > 0) {
                ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
                ImGui::Text("PCM drift drop: %llu",
                            static_cast<unsigned long long>(p.pcm_drift_drops));
            }
            if (p.pcm_remote_frame_count > 0 || p.pcm_fifo_depth > 0) {
                ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
                ImGui::Text("PCM pkt/fifo: %u/%zu", p.pcm_remote_frame_count,
                            p.pcm_fifo_depth);
            }
            if (p.pcm_format_drops > 0 || p.pcm_size_mismatches > 0) {
                ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
                ImGui::TextColored(ImVec4(1.0F, 0.6F, 0.2F, 1.0F),
                                   "PCM bad f/s: %llu/%llu",
                                   static_cast<unsigned long long>(p.pcm_format_drops),
                                   static_cast<unsigned long long>(p.pcm_size_mismatches));
            }
            if (p.pcm_fifo_underflows > 0 || p.pcm_fifo_overflows > 0) {
                ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
                ImGui::TextColored(ImVec4(1.0F, 0.6F, 0.2F, 1.0F),
                                   "PCM fifo u/o: %llu/%llu",
                                   static_cast<unsigned long long>(p.pcm_fifo_underflows),
                                   static_cast<unsigned long long>(p.pcm_fifo_overflows));
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
    static AudioStream::DeviceIndex             pending_input       = AudioStream::NO_DEVICE;
    static AudioStream::DeviceIndex             pending_output      = AudioStream::NO_DEVICE;
    static int                                  pending_buffer_frames = 0;
    static bool                                 devices_initialized = false;

    if (!devices_initialized) {
        pending_input         = client.get_selected_input_device();
        pending_output        = client.get_selected_output_device();
        pending_buffer_frames = client.get_audio_config().frames_per_buffer;
        devices_initialized   = true;
    }
    pending_buffer_frames =
        normalize_buffer_frames_for_codec(client.get_audio_codec(), pending_buffer_frames);

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
            bool is_selected = (api.index == selected_api);
            if (ImGui::Selectable(api_label, is_selected)) {
                int old_api  = selected_api;
                selected_api = api.index;

                // Auto-switch: when user selects an API, automatically switch to first devices with
                // that API
                if (old_api != selected_api && selected_api >= 0) {
                    // Find first available input device with this API
                    AudioStream::DeviceIndex new_input = AudioStream::NO_DEVICE;
                    for (const auto& dev: input_devices) {
                        if (dev.api_name == api.name) {
                            new_input = dev.index;
                            break;
                        }
                    }

                    // Find first available output device with this API
                    AudioStream::DeviceIndex new_output = AudioStream::NO_DEVICE;
                    for (const auto& dev: output_devices) {
                        if (dev.api_name == api.name) {
                            new_output = dev.index;
                            break;
                        }
                    }

                    // Switch if we found both devices (preferred)
                    if (new_input != AudioStream::NO_DEVICE &&
                        new_output != AudioStream::NO_DEVICE) {
                        pending_input  = new_input;
                        pending_output = new_output;
                    } else if (new_input != AudioStream::NO_DEVICE) {
                        // Found input but not output - switch input only
                        pending_input = new_input;
                    } else if (new_output != AudioStream::NO_DEVICE) {
                        // Found output but not input - switch output only
                        pending_output = new_output;
                    }
                    // If neither found, just keep filter active (user can manually select)
                }
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

    ImGui::AlignTextToFramePadding();
    ImGui::Text("Buffer:");
    ImGui::SameLine();
    ImGui::PushItemWidth(90);
    const int buffer_options[] = {96, 120, 128, 240, 256};
    char buffer_preview[32];
    std::snprintf(buffer_preview, sizeof(buffer_preview), "%d", pending_buffer_frames);
    if (ImGui::BeginCombo("##BufferFrames", buffer_preview)) {
        for (int frames: buffer_options) {
            if (normalized_buffer_frames_for_codec(client.get_audio_codec(), frames) != frames) {
                continue;
            }
            char label[48];
            if (frames == 96) {
                std::snprintf(label, sizeof(label), "%d Ultra##buffer_%d", frames, frames);
            } else if (frames == 120) {
                std::snprintf(label, sizeof(label), "%d Low##buffer_%d", frames, frames);
            } else if (frames == 240) {
                std::snprintf(label, sizeof(label), "%d Safe##buffer_%d", frames, frames);
            } else {
                std::snprintf(label, sizeof(label), "%d##buffer_%d", frames, frames);
            }
            if (ImGui::Selectable(label, frames == pending_buffer_frames)) {
                pending_buffer_frames = frames;
            }
        }
        ImGui::EndCombo();
    }
    ImGui::PopItemWidth();

    ImGui::SameLine();

    // Check if devices changed
    AudioStream::DeviceIndex active_input  = client.get_selected_input_device();
    AudioStream::DeviceIndex active_output = client.get_selected_output_device();
    bool devices_changed = (pending_input != active_input) || (pending_output != active_output) ||
                           (pending_buffer_frames != client.get_audio_config().frames_per_buffer);

    if (devices_changed) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8F, 0.6F, 0.2F, 1.0F));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.9F, 0.7F, 0.3F, 1.0F));
        if (ImGui::Button("APPLY")) {
            client.set_input_device(pending_input);
            client.set_output_device(pending_output);
            client.set_requested_frames_per_buffer(pending_buffer_frames);
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
                if (pending_input != AudioStream::NO_DEVICE &&
                    pending_output != AudioStream::NO_DEVICE) {
                    client.set_input_device(pending_input);
                    client.set_output_device(pending_output);
                    client.set_requested_frames_per_buffer(pending_buffer_frames);
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
            static auto        last_update   = std::chrono::steady_clock::now();

            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_update).count() >=
                1000) {
                uint64_t total_rx = client.get_total_bytes_rx();
                uint64_t total_tx = client.get_total_bytes_tx();

                // Format as KB or MB
                auto format_bytes = [](uint64_t bytes) -> std::string {
                    if (bytes < 1024) {
                        return std::to_string(bytes) + " B";
                    }
                    if (bytes < static_cast<uint64_t>(1024 * 1024)) {
                        return std::to_string(bytes / 1024) + " KB";
                    }
                    char buf[32];
                    std::snprintf(buf, sizeof(buf), "%.2f MB",
                                  static_cast<double>(bytes) / (1024.0 * 1024.0));
                    return std::string(buf);
                };

                cached_rx_str = format_bytes(total_rx);
                cached_tx_str = format_bytes(total_tx);
                last_update   = now;
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

struct ClientStartupOptions {
    std::string server_address = "127.0.0.1";
    short server_port = 9999;
    int requested_frames = 0;
    bool list_audio_devices = false;
    bool audio_open_smoke = false;
    bool low_latency_check = false;
    std::optional<AudioCodec> startup_codec;
    std::string required_audio_api;
    PerformerJoinOptions performer_join;
};

int run_audio_open_smoke(const ClientStartupOptions& startup_options);

ClientStartupOptions parse_startup_options(int argc, char** argv) {
    ClientStartupOptions options;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--server" && i + 1 < argc) {
            options.server_address = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            options.server_port = static_cast<short>(std::stoi(argv[++i]));
        } else if (arg == "--room" && i + 1 < argc) {
            options.performer_join.room_id = argv[++i];
        } else if (arg == "--room-handle" && i + 1 < argc) {
            options.performer_join.room_handle = argv[++i];
        } else if (arg == "--user-id" && i + 1 < argc) {
            options.performer_join.user_id = argv[++i];
        } else if (arg == "--display-name" && i + 1 < argc) {
            options.performer_join.display_name = argv[++i];
        } else if (arg == "--join-token" && i + 1 < argc) {
            options.performer_join.join_token = argv[++i];
        } else if ((arg == "--frames" || arg == "--buffer-frames") && i + 1 < argc) {
            options.requested_frames = std::stoi(argv[++i]);
        } else if (arg == "--list-audio-devices" || arg == "--audio-devices") {
            options.list_audio_devices = true;
        } else if (arg == "--audio-open-smoke") {
            options.audio_open_smoke = true;
        } else if (arg == "--low-latency-check" || arg == "--backend-check") {
            options.low_latency_check = true;
        } else if (arg == "--codec" && i + 1 < argc) {
            std::string codec = argv[++i];
            std::transform(codec.begin(), codec.end(), codec.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (codec == "opus") {
                options.startup_codec = AudioCodec::Opus;
            } else if (codec == "pcm" || codec == "raw" || codec == "pcm_int16") {
                options.startup_codec = AudioCodec::PcmInt16;
            }
        } else if ((arg == "--require-api" || arg == "--api") && i + 1 < argc) {
            options.required_audio_api = argv[++i];
        }
    }
    return options;
}

void print_audio_backend_inventory() {
    Log::info("Compiled/available RtAudio APIs:");
    for (const auto& api: AudioStream::get_apis()) {
        Log::info("API {}: {} | default input {} | default output {}", api.index, api.name,
                  api.default_input_device, api.default_output_device);
    }

    AudioStream::print_all_devices();
}

AudioStream::DeviceIndex find_device_for_api(const std::string& api_name, bool input) {
    const auto devices = input ? AudioStream::get_input_devices() : AudioStream::get_output_devices();
    auto it = std::find_if(devices.begin(), devices.end(), [&](const AudioStream::DeviceInfo& device) {
        return device.api_name == api_name;
    });
    return it != devices.end() ? it->index : AudioStream::NO_DEVICE;
}

bool required_api_has_duplex_devices(const std::string& api_name) {
    return find_device_for_api(api_name, true) != AudioStream::NO_DEVICE &&
           find_device_for_api(api_name, false) != AudioStream::NO_DEVICE;
}

int run_low_latency_backend_check(const ClientStartupOptions& startup_options) {
    const std::string api_name =
        startup_options.required_audio_api.empty() ? "ASIO" : startup_options.required_audio_api;
    const int frames = startup_options.requested_frames > 0 ? startup_options.requested_frames : 96;

    Log::info("Low-latency backend check: API={} frames={}", api_name, frames);
    if (!required_api_has_duplex_devices(api_name)) {
        Log::error("Low-latency backend '{}' is not ready: missing input or output device",
                   api_name);
        print_audio_backend_inventory();
        return 2;
    }

    ClientStartupOptions smoke_options = startup_options;
    smoke_options.required_audio_api = api_name;
    smoke_options.requested_frames = frames;
    const int smoke_result = run_audio_open_smoke(smoke_options);
    if (smoke_result != 0) {
        return smoke_result;
    }

    Log::info("Low-latency backend '{}' is ready for validation", api_name);
    return 0;
}

int smoke_audio_callback(const void*, void* output, unsigned long frame_count, void* user_data) {
    auto* stream = static_cast<AudioStream*>(user_data);
    if (output == nullptr || stream == nullptr) {
        return 0;
    }

    const size_t channels = static_cast<size_t>(stream->get_output_channel_count());
    std::memset(output, 0, frame_count * channels * sizeof(float));
    return 0;
}

int run_audio_open_smoke(const ClientStartupOptions& startup_options) {
    AudioStream::DeviceIndex input_dev = AudioStream::get_default_input_device();
    AudioStream::DeviceIndex output_dev = AudioStream::get_default_output_device();
    if (!startup_options.required_audio_api.empty()) {
        input_dev = find_device_for_api(startup_options.required_audio_api, true);
        output_dev = find_device_for_api(startup_options.required_audio_api, false);
    }

    if (input_dev == AudioStream::NO_DEVICE || output_dev == AudioStream::NO_DEVICE) {
        Log::error("Audio open smoke has no valid input/output device");
        print_audio_backend_inventory();
        return 2;
    }

    AudioStream stream;
    AudioStream::AudioConfig config;
    config.frames_per_buffer =
        startup_options.requested_frames > 0 ? startup_options.requested_frames : 120;

    if (!stream.start_audio_stream(input_dev, output_dev, config, smoke_audio_callback, &stream)) {
        Log::error("Audio open smoke failed: {}", AudioStream::get_last_error());
        return 3;
    }

    stream.print_latency_info();
    stream.stop_audio_stream();
    Log::info("Audio open smoke succeeded");
    return 0;
}

int main(int argc, char** argv) {
    try {
        auto& log = Logger::instance();
        log.init(true, true, false, "", spdlog::level::info);
        auto startup_options = parse_startup_options(argc, argv);

        if (startup_options.list_audio_devices) {
            print_audio_backend_inventory();
            return 0;
        }
        if (startup_options.low_latency_check) {
            return run_low_latency_backend_check(startup_options);
        }
        if (!startup_options.required_audio_api.empty() &&
            !required_api_has_duplex_devices(startup_options.required_audio_api)) {
            Log::error("Required audio API '{}' does not have both input and output devices",
                       startup_options.required_audio_api);
            print_audio_backend_inventory();
            return 2;
        }
        if (startup_options.audio_open_smoke) {
            return run_audio_open_smoke(startup_options);
        }

        asio::io_context io_context;

        Client client_instance(io_context, startup_options.server_address,
                               startup_options.server_port, startup_options.performer_join);
        if (!startup_options.required_audio_api.empty()) {
            const auto input_dev =
                find_device_for_api(startup_options.required_audio_api, true);
            const auto output_dev =
                find_device_for_api(startup_options.required_audio_api, false);
            client_instance.set_input_device(input_dev);
            client_instance.set_output_device(output_dev);
            Log::info("Startup required audio API: {}", startup_options.required_audio_api);
        }
        if (startup_options.requested_frames > 0) {
            client_instance.set_requested_frames_per_buffer(startup_options.requested_frames);
            Log::info("Startup requested buffer override: {} frames",
                      startup_options.requested_frames);
        }
        if (startup_options.startup_codec.has_value()) {
            client_instance.set_audio_codec(*startup_options.startup_codec);
            Log::info("Startup codec override: {}",
                      *startup_options.startup_codec == AudioCodec::Opus ? "Opus" : "PCM");
        }

        // Auto-start audio stream with default devices
        {
            AudioStream::DeviceIndex input_dev  = client_instance.get_selected_input_device();
            AudioStream::DeviceIndex output_dev = client_instance.get_selected_output_device();
            if (input_dev != AudioStream::NO_DEVICE && output_dev != AudioStream::NO_DEVICE) {
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
