#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
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
#include "jam_broadcast_ipc.h"
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
#include "recording_writer.h"
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

static const char* runtime_platform_name() {
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "macos";
#elif defined(__linux__)
    return "linux";
#else
    return "unknown";
#endif
}

static const char* runtime_arch_name() {
#if defined(_M_X64) || defined(__x86_64__)
    return "x64";
#elif defined(_M_ARM64) || defined(__aarch64__)
    return "arm64";
#elif defined(_M_IX86) || defined(__i386__)
    return "x86";
#else
    return "unknown";
#endif
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
        std::error_code leave_error;
        socket_.send_to(asio::buffer(&chdr, sizeof(CtrlHdr)), server_endpoint_, 0, leave_error);
        if (leave_error) {
            Log::warn("LEAVE send failed: {}", leave_error.message());
        }

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
        disable_broadcast_ipc();
        stop_recording();
    }

    bool enable_broadcast_ipc(uint16_t port) {
        if (port == 0) {
            return false;
        }
        if (broadcast_ipc_running_.load(std::memory_order_acquire)) {
            return true;
        }
        broadcast_ipc_port_.store(port, std::memory_order_release);
        broadcast_ipc_running_.store(true, std::memory_order_release);
        broadcast_ipc_thread_ = std::thread([this]() { broadcast_ipc_sender_loop(); });
        Log::info("Broadcast IPC enabled on localhost UDP port {}", port);
        return true;
    }

    void disable_broadcast_ipc() {
        if (!broadcast_ipc_running_.exchange(false, std::memory_order_acq_rel)) {
            return;
        }
        if (broadcast_ipc_thread_.joinable()) {
            broadcast_ipc_thread_.join();
        }
        Log::info("Broadcast IPC stopped: produced={} sent={} drops enqueue/send={}/{}",
                  broadcast_frames_produced_.load(std::memory_order_relaxed),
                  broadcast_frames_sent_.load(std::memory_order_relaxed),
                  broadcast_enqueue_drops_.load(std::memory_order_relaxed),
                  broadcast_send_drops_.load(std::memory_order_relaxed));
    }

    // Getters for UI access
    std::string get_server_address() const {
        return server_endpoint_.address().to_string();
    }

    unsigned short get_server_port() const {
        return server_endpoint_.port();
    }

    std::string get_room_id() const {
        return performer_join_options_.room_id;
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

    size_t get_opus_jitter_buffer_packets() const {
        return opus_jitter_buffer_packets_.load(std::memory_order_acquire);
    }

    size_t get_opus_queue_limit_packets() const {
        return opus_queue_limit_packets_.load(std::memory_order_acquire);
    }

    int get_jitter_packet_age_limit_ms() const {
        return jitter_packet_age_limit_ms_.load(std::memory_order_acquire);
    }

    void set_opus_jitter_buffer_packets(size_t packets) {
        const size_t clamped =
            std::clamp(packets, MIN_OPUS_JITTER_PACKETS, MAX_OPUS_JITTER_PACKETS);
        opus_jitter_buffer_packets_.store(clamped, std::memory_order_release);

        participant_manager_.for_each([clamped](uint32_t, ParticipantData& participant) {
            if (participant.opus_jitter_manual_override) {
                return;
            }
            if (participant.last_codec == AudioCodec::Opus ||
                participant.jitter_buffer_floor_packets >= DEFAULT_OPUS_JITTER_PACKETS) {
                participant.jitter_buffer_floor_packets = clamped;
                participant.jitter_buffer_min_packets = clamped;
                if (participant.opus_queue.size_approx() < std::max<size_t>(1, clamped)) {
                    participant.buffer_ready = false;
                }
                participant.opus_consecutive_empty_callbacks = 0;
            }
        });
    }

    void set_opus_queue_limit_packets(size_t packets) {
        const size_t min_limit =
            std::max(MIN_OPUS_QUEUE_LIMIT_PACKETS, get_opus_jitter_buffer_packets());
        const size_t clamped = std::clamp(packets, min_limit, MAX_OPUS_QUEUE_LIMIT_PACKETS);
        opus_queue_limit_packets_.store(clamped, std::memory_order_release);

        participant_manager_.for_each([clamped](uint32_t, ParticipantData& participant) {
            participant.opus_queue_limit_packets = clamped;
        });
    }

    void set_jitter_packet_age_limit_ms(int age_ms) {
        jitter_packet_age_limit_ms_.store(
            std::clamp(age_ms, MIN_JITTER_PACKET_AGE_MS, MAX_JITTER_PACKET_AGE_MS),
            std::memory_order_release);
    }

    void set_opus_auto_jitter_default(bool enabled) {
        opus_auto_jitter_default_.store(enabled, std::memory_order_release);
        const size_t global_default = get_opus_jitter_buffer_packets();
        participant_manager_.for_each([enabled, global_default](uint32_t, ParticipantData& participant) {
            if (participant.opus_jitter_manual_override) {
                return;
            }
            participant.opus_jitter_auto_enabled = enabled;
            participant.opus_jitter_auto_floor_packets = global_default;
            participant.opus_jitter_auto_stable_callbacks = 0;
            participant.opus_jitter_auto_instability_events = 0;
        });
    }

    bool get_opus_auto_jitter_default() const {
        return opus_auto_jitter_default_.load(std::memory_order_acquire);
    }

    void set_participant_opus_jitter_buffer_packets(uint32_t id, size_t packets) {
        const size_t clamped =
            std::clamp(packets, MIN_OPUS_JITTER_PACKETS, MAX_OPUS_JITTER_PACKETS);
        participant_manager_.with_participant(id, [clamped](ParticipantData& participant) {
            participant.opus_jitter_manual_override = true;
            participant.opus_jitter_auto_enabled = false;
            participant.jitter_buffer_floor_packets = clamped;
            participant.jitter_buffer_min_packets = clamped;
            participant.opus_queue_limit_packets =
                std::max(participant.opus_queue_limit_packets, clamped);
            if (participant.opus_queue.size_approx() < std::max<size_t>(1, clamped)) {
                participant.buffer_ready = false;
            }
            participant.opus_consecutive_empty_callbacks = 0;
        });
    }

    void reset_participant_opus_jitter_buffer_packets(uint32_t id) {
        const size_t global_default = get_opus_jitter_buffer_packets();
        participant_manager_.with_participant(id, [global_default](ParticipantData& participant) {
            participant.opus_jitter_manual_override = false;
            participant.opus_jitter_auto_enabled = false;
            participant.jitter_buffer_floor_packets = global_default;
            participant.jitter_buffer_min_packets = global_default;
            participant.opus_queue_limit_packets =
                std::max(participant.opus_queue_limit_packets, global_default);
            if (participant.opus_queue.size_approx() < std::max<size_t>(1, global_default)) {
                participant.buffer_ready = false;
            }
            participant.opus_consecutive_empty_callbacks = 0;
        });
    }

    void set_participant_opus_auto_jitter(uint32_t id, bool enabled) {
        const size_t global_default = get_opus_jitter_buffer_packets();
        participant_manager_.with_participant(id, [enabled, global_default](ParticipantData& participant) {
            participant.opus_jitter_auto_enabled = enabled;
            participant.opus_jitter_manual_override = false;
            participant.opus_jitter_auto_floor_packets = global_default;
            participant.opus_jitter_auto_stable_callbacks = 0;
            participant.opus_jitter_auto_instability_events = 0;
            if (enabled && participant.jitter_buffer_min_packets < global_default) {
                participant.jitter_buffer_min_packets = global_default;
                participant.jitter_buffer_floor_packets = global_default;
            }
            participant.opus_consecutive_empty_callbacks = 0;
        });
    }

    void apply_default_opus_jitter_policy(ParticipantData& participant) {
        if (participant.opus_jitter_manual_override) {
            return;
        }
        participant.opus_jitter_auto_enabled =
            opus_auto_jitter_default_.load(std::memory_order_acquire);
        participant.opus_jitter_auto_floor_packets = get_opus_jitter_buffer_packets();
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

    struct MetronomeState {
        float    bpm;
        bool     running;
        uint32_t beat_number;
        uint64_t sync_sent;
        uint64_t sync_received;
        bool     clock_ready;
        double   clock_offset_ms;
    };

    MetronomeState get_metronome_state() const {
        return MetronomeState{
            static_cast<float>(metronome_bpm_milli_.load(std::memory_order_acquire)) / 1000.0F,
            metronome_running_.load(std::memory_order_acquire),
            metronome_beat_number_.load(std::memory_order_acquire),
            metronome_sync_sent_.load(std::memory_order_relaxed),
            metronome_sync_received_.load(std::memory_order_relaxed),
            server_clock_ready_.load(std::memory_order_acquire),
            static_cast<double>(server_clock_offset_ns_.load(std::memory_order_relaxed)) / 1e6,
        };
    }

    void set_metronome_bpm(float bpm, bool send_sync = true) {
        const int bpm_milli = std::clamp(static_cast<int>(std::lrint(bpm * 1000.0F)), 30000,
                                         240000);
        if (send_sync) {
            commit_metronome_bpm_milli(bpm_milli);
        } else {
            metronome_bpm_milli_.store(bpm_milli, std::memory_order_release);
        }
    }

    void commit_metronome_bpm(float bpm) {
        const int bpm_milli = std::clamp(static_cast<int>(std::lrint(bpm * 1000.0F)), 30000,
                                         240000);
        commit_metronome_bpm_milli(bpm_milli);
    }

    void start_metronome() {
        send_metronome_sync(metronome_bpm_milli_.load(std::memory_order_acquire), true, 0);
    }

    void stop_metronome() {
        send_metronome_sync(metronome_bpm_milli_.load(std::memory_order_acquire), false,
                            metronome_beat_number_.load(std::memory_order_acquire));
    }

    void tap_metronome_tempo() {
        const auto now = std::chrono::steady_clock::now();
        if (tap_count_ > 0 && now - tap_times_[(tap_index_ + tap_times_.size() - 1) %
                                               tap_times_.size()] > 2s) {
            tap_count_ = 0;
            tap_index_ = 0;
        }

        tap_times_[tap_index_] = now;
        tap_index_ = (tap_index_ + 1) % tap_times_.size();
        tap_count_ = std::min(tap_count_ + 1, tap_times_.size());

        if (tap_count_ < 3) {
            return;
        }

        double total_interval_ms = 0.0;
        size_t interval_count = 0;
        for (size_t i = 1; i < tap_count_; ++i) {
            const size_t newer = (tap_index_ + tap_times_.size() - i) % tap_times_.size();
            const size_t older = (tap_index_ + tap_times_.size() - i - 1) % tap_times_.size();
            const auto interval = tap_times_[newer] - tap_times_[older];
            total_interval_ms +=
                std::chrono::duration<double, std::milli>(interval).count();
            ++interval_count;
        }

        if (interval_count == 0 || total_interval_ms <= 0.0) {
            return;
        }

        const double avg_interval_ms = total_interval_ms / static_cast<double>(interval_count);
        commit_metronome_bpm(static_cast<float>(60000.0 / avg_interval_ms));
    }

    struct RecordingState {
        bool        active;
        std::string folder;
        size_t      queued_blocks;
        uint64_t    dropped_blocks;
    };

    RecordingState get_recording_state() const {
        return RecordingState{
            recording_writer_.is_active(),
            recording_writer_.folder(),
            recording_writer_.queued_blocks(),
            recording_writer_.dropped_blocks(),
        };
    }

    bool start_recording() {
        const bool started =
            recording_writer_.start(static_cast<uint32_t>(audio_config_.sample_rate));
        if (started) {
            Log::info("Recording started: {}", recording_writer_.folder());
        } else {
            Log::error("Recording failed to start");
        }
        return started;
    }

    void stop_recording() {
        const bool was_active = recording_writer_.is_active();
        const std::string folder = recording_writer_.folder();
        recording_writer_.stop();
        if (was_active && !folder.empty()) {
            Log::info("Recording stopped: {}", folder);
        }
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
        std::chrono::steady_clock::time_point capture_time;
    };

    static int64_t steady_now_ns() {
        const auto now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch())
            .count();
    }

    uint32_t next_metronome_boundary_beat() const {
        return metronome_beat_number_.load(std::memory_order_acquire) + 1;
    }

    void send_metronome_sync(int bpm_milli, bool running, uint32_t beat_number) {
        MetronomeSyncHdr sync{};
        sync.magic = CTRL_MAGIC;
        sync.type = CtrlHdr::Cmd::METRONOME_SYNC;
        sync.bpm_milli = static_cast<uint32_t>(std::max(1, bpm_milli));
        sync.beat_number = beat_number;
        sync.flags = running ? METRONOME_FLAG_RUNNING : 0;
        sync.sender_time_ns = steady_now_ns();

        auto buf = std::make_shared<std::vector<unsigned char>>(sizeof(MetronomeSyncHdr));
        std::memcpy(buf->data(), &sync, sizeof(MetronomeSyncHdr));
        send(buf->data(), buf->size(), buf);
        metronome_sync_sent_.fetch_add(1, std::memory_order_relaxed);
    }

    void commit_metronome_bpm_milli(int bpm_milli) {
        const int current_bpm_milli = metronome_bpm_milli_.load(std::memory_order_acquire);
        const int pending_bpm_milli =
            metronome_pending_bpm_milli_.load(std::memory_order_acquire);
        const uint32_t pending_sequence =
            metronome_pending_sequence_.load(std::memory_order_acquire);
        if (bpm_milli == current_bpm_milli &&
            (pending_sequence == 0 || pending_bpm_milli == bpm_milli)) {
            return;
        }
        send_metronome_sync(bpm_milli,
                            metronome_running_.load(std::memory_order_acquire),
                            next_metronome_boundary_beat());
    }

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
                observe_audio_packet_send_pacing();
                send(packet->data(), packet->size(), packet);
                continue;
            }

            OpusSendFrame opus_frame;
            if (opus_send_queue_.try_dequeue(opus_frame)) {
                observe_opus_send_queue_age(opus_frame.capture_time);
                std::vector<unsigned char> encoded_data;
                const auto encode_start = std::chrono::steady_clock::now();
                if (audio_encoder_.encode(opus_frame.samples.data(), opus_frame.frame_count,
                                          encoded_data) &&
                    encoded_data.size() <= AUDIO_BUF_SIZE) {
                    observe_tx_encode_time(std::chrono::steady_clock::now() - encode_start);
                    uint32_t seq = audio_tx_sequence_.fetch_add(1, std::memory_order_relaxed);
                    auto packet = audio_packet::create_audio_packet_v2(
                        AudioCodec::Opus, seq, opus_frame.sample_rate, opus_frame.frame_count, 1,
                        encoded_data.data(), static_cast<uint16_t>(encoded_data.size()));
                    observe_audio_packet_send_pacing();
                    send(packet->data(), packet->size(), packet);
                } else {
                    observe_tx_encode_time(std::chrono::steady_clock::now() - encode_start);
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
                                uint16_t frame_count, uint32_t sample_rate,
                                std::chrono::steady_clock::time_point capture_time) {
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
        frame.capture_time = capture_time;
        pcm_send_queue_.enqueue(frame);
        wake_pcm_sender_thread();
    }

    void enqueue_opus_send_frame(const float* samples, uint16_t frame_count, uint32_t sample_rate,
                                 std::chrono::steady_clock::time_point capture_time) {
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
        frame.capture_time = capture_time;
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
                                   uint32_t sample_rate,
                                   std::chrono::steady_clock::time_point capture_time) {
        if (frame_count == 0 || samples == nullptr) {
            return;
        }

        if (frame_count <= opus_tx_accumulator_.size() &&
            OpusEncoderWrapper::is_legal_frame_size(static_cast<int>(sample_rate),
                                                    static_cast<int>(frame_count)) &&
            opus_tx_accumulated_frames_ == 0) {
            enqueue_opus_send_frame(samples, static_cast<uint16_t>(frame_count), sample_rate,
                                    capture_time);
            return;
        }

        const uint16_t target_frame_count = preferred_opus_tx_frame_count(
            sample_rate, static_cast<uint16_t>(audio_config_.frames_per_buffer));
        if (target_frame_count == 0 || target_frame_count > opus_tx_accumulator_.size()) {
            opus_send_drops_.fetch_add(1, std::memory_order_relaxed);
            opus_tx_accumulated_frames_ = 0;
            opus_tx_accumulator_capture_time_ = {};
            return;
        }

        size_t offset = 0;
        while (offset < frame_count) {
            if (opus_tx_accumulated_frames_ == 0) {
                opus_tx_accumulator_capture_time_ = capture_time;
            }
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
                                        sample_rate, opus_tx_accumulator_capture_time_);
                opus_tx_accumulated_frames_ = 0;
                opus_tx_accumulator_capture_time_ = {};
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
            participant.opus_resample_phase = 0.0;
            return;
        }

        const size_t remaining = participant.opus_pcm_buffered_frames - frame_count;
        std::move(participant.opus_pcm_buffer.begin() + static_cast<std::ptrdiff_t>(frame_count),
                  participant.opus_pcm_buffer.begin() +
                      static_cast<std::ptrdiff_t>(participant.opus_pcm_buffered_frames),
                  participant.opus_pcm_buffer.begin());
        participant.opus_pcm_buffered_frames = remaining;
    }

    static double opus_playout_rate_ratio(ParticipantData& participant) {
        const size_t packet_frames =
            participant.last_packet_frame_count.load(std::memory_order_relaxed);
        const double decoded_packets =
            packet_frames > 0 ? static_cast<double>(participant.opus_pcm_buffered_frames) /
                                    static_cast<double>(packet_frames)
                              : 0.0;
        const double queued_packets =
            static_cast<double>(participant.opus_queue.size_approx()) + decoded_packets;
        const double target_packets =
            static_cast<double>(opus_playout_target_queue_packets(participant));
        const double queue_error = queued_packets - target_packets;
        const double gain = queue_error < 0.0 ? 0.01 : 0.005;
        double ratio = std::clamp(1.0 + (queue_error * gain), 0.95, 1.04);

        const uint64_t queue_limit_drops =
            participant.opus_queue_limit_drops.load(std::memory_order_relaxed);
        if (queue_limit_drops > participant.opus_rate_last_queue_limit_drops) {
            participant.opus_rate_last_queue_limit_drops = queue_limit_drops;
            participant.opus_rate_correction_callbacks = 400;
        }
        if (participant.opus_rate_correction_callbacks > 0) {
            participant.opus_rate_correction_callbacks--;
            if (queued_packets >= target_packets * 0.5) {
                ratio = std::max(ratio, 1.04);
            }
        }

        participant.opus_playout_rate_ratio_micros.store(
            static_cast<int64_t>(ratio * 1'000'000.0), std::memory_order_relaxed);
        participant.opus_rate_correction_callbacks_observed.store(
            participant.opus_rate_correction_callbacks, std::memory_order_relaxed);
        return ratio;
    }

    static size_t opus_resample_required_input_frames(const ParticipantData& participant,
                                                      unsigned long output_frames,
                                                      double ratio) {
        if (output_frames == 0) {
            return 0;
        }
        const double last_source =
            participant.opus_resample_phase +
            (static_cast<double>(output_frames - 1) * ratio);
        return static_cast<size_t>(std::floor(last_source)) + 1;
    }

    static void mix_resampled_opus_pcm(ParticipantData& participant, float* output_buffer,
                                       unsigned long output_frames, size_t output_channels,
                                       float gain, double ratio) {
        if (output_frames == 0 || output_buffer == nullptr) {
            return;
        }

        const double start_phase = participant.opus_resample_phase;
        for (unsigned long i = 0; i < output_frames; ++i) {
            const double source_pos = start_phase + (static_cast<double>(i) * ratio);
            const auto index = static_cast<size_t>(std::floor(source_pos));
            const float frac = static_cast<float>(source_pos - static_cast<double>(index));
            const float a = participant.opus_pcm_buffer[index];
            const float b =
                index + 1 < participant.opus_pcm_buffered_frames
                    ? participant.opus_pcm_buffer[index + 1]
                    : a;
            const float sample = (a + ((b - a) * frac)) * gain;

            if (output_channels == 1) {
                output_buffer[i] += sample;
            } else {
                const size_t base = static_cast<size_t>(i) * output_channels;
                output_buffer[base] += sample;
                output_buffer[base + 1] += sample;
            }
        }

        const double consumed_exact =
            start_phase + (static_cast<double>(output_frames) * ratio);
        const auto consumed_frames = static_cast<size_t>(std::floor(consumed_exact));
        participant.opus_resample_phase =
            consumed_exact - static_cast<double>(consumed_frames);
        consume_opus_pcm_buffer(participant, consumed_frames);
    }

    static void mix_available_opus_pcm_with_tail(ParticipantData& participant,
                                                 float* output_buffer,
                                                 unsigned long output_frames,
                                                 size_t output_channels, float gain,
                                                 double ratio) {
        if (output_frames == 0 || output_buffer == nullptr ||
            participant.opus_pcm_buffered_frames == 0) {
            return;
        }

        const double start_phase = participant.opus_resample_phase;
        const size_t last_index = participant.opus_pcm_buffered_frames - 1;
        for (unsigned long i = 0; i < output_frames; ++i) {
            const double source_pos = start_phase + (static_cast<double>(i) * ratio);
            const auto requested_index = static_cast<size_t>(std::floor(source_pos));
            const size_t index = std::min(requested_index, last_index);
            const float frac = requested_index < last_index
                                   ? static_cast<float>(source_pos -
                                                        static_cast<double>(requested_index))
                                   : 0.0F;
            const float a = participant.opus_pcm_buffer[index];
            const float b = index + 1 < participant.opus_pcm_buffered_frames
                                ? participant.opus_pcm_buffer[index + 1]
                                : a;
            const float sample = (a + ((b - a) * frac)) * gain;

            if (output_channels == 1) {
                output_buffer[i] += sample;
            } else {
                const size_t base = static_cast<size_t>(i) * output_channels;
                output_buffer[base] += sample;
                output_buffer[base + 1] += sample;
            }
        }

        const double consumed_exact =
            start_phase + (static_cast<double>(output_frames) * ratio);
        const auto consumed_frames = std::min(
            static_cast<size_t>(std::floor(consumed_exact)),
            participant.opus_pcm_buffered_frames);
        consume_opus_pcm_buffer(participant, consumed_frames);
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

        const auto target_depth = std::max<size_t>(1, participant.jitter_buffer_min_packets);
        const auto drift_milli =
            (static_cast<int64_t>(depth) - static_cast<int64_t>(target_depth)) * 1000;
        const auto previous_drift =
            participant.queue_depth_drift_milli.load(std::memory_order_relaxed);
        const auto next_drift =
            previous_drift == 0 ? drift_milli : ((previous_drift * 31) + drift_milli) / 32;
        participant.queue_depth_drift_milli.store(next_drift, std::memory_order_relaxed);
    }

    static void observe_receiver_clock_drift(ParticipantData& participant,
                                             const OpusPacket& packet) {
        if (packet.frame_count == 0 || packet.sample_rate == 0) {
            return;
        }

        if (!participant.drift_reference_initialized ||
            packet.sequence <= participant.drift_reference_sequence ||
            packet.frame_count != participant.drift_reference_frame_count ||
            packet.sample_rate != participant.drift_reference_sample_rate) {
            participant.drift_reference_initialized = true;
            participant.drift_reference_sequence = packet.sequence;
            participant.drift_reference_frame_count = packet.frame_count;
            participant.drift_reference_sample_rate = packet.sample_rate;
            participant.drift_reference_time = packet.timestamp;
            return;
        }

        const uint32_t elapsed_packets = packet.sequence - participant.drift_reference_sequence;
        // Arrival timestamps include OS/network scheduling jitter; use a longer
        // window so the diagnostic reflects clock drift instead of one callback hiccup.
        constexpr uint32_t DRIFT_MIN_OBSERVATION_PACKETS = 12'000;
        if (elapsed_packets < DRIFT_MIN_OBSERVATION_PACKETS) {
            return;
        }

        const auto arrival_elapsed_ns =
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                packet.timestamp - participant.drift_reference_time)
                .count();
        const double expected_elapsed_ns =
            static_cast<double>(elapsed_packets) *
            static_cast<double>(packet.frame_count) * 1'000'000'000.0 /
            static_cast<double>(packet.sample_rate);
        if (expected_elapsed_ns <= 0.0) {
            return;
        }

        const auto drift_ppm_milli = static_cast<int64_t>(
            ((static_cast<double>(arrival_elapsed_ns) - expected_elapsed_ns) /
             expected_elapsed_ns) *
            1'000'000'000.0);
        constexpr int64_t DRIFT_ARRIVAL_OUTLIER_PPM_MILLI = 1'000'000;
        const int64_t abs_sample_drift =
            drift_ppm_milli < 0 ? -drift_ppm_milli : drift_ppm_milli;
        if (abs_sample_drift > DRIFT_ARRIVAL_OUTLIER_PPM_MILLI) {
            participant.drift_reference_sequence = packet.sequence;
            participant.drift_reference_time = packet.timestamp;
            return;
        }
        participant.receiver_drift_ppm_last_milli.store(drift_ppm_milli,
                                                        std::memory_order_relaxed);

        const int64_t previous_avg =
            participant.receiver_drift_ppm_avg_milli.load(std::memory_order_relaxed);
        const int64_t next_avg =
            previous_avg == 0 ? drift_ppm_milli : ((previous_avg * 63) + drift_ppm_milli) / 64;
        participant.receiver_drift_ppm_avg_milli.store(next_avg, std::memory_order_relaxed);

        constexpr uint64_t DRIFT_MAX_WARMUP_OBSERVATIONS = 16;
        const uint64_t observations =
            participant.receiver_drift_observations.fetch_add(1, std::memory_order_relaxed) + 1;
        if (observations > DRIFT_MAX_WARMUP_OBSERVATIONS) {
            int64_t previous_abs_max =
                participant.receiver_drift_ppm_abs_max_milli.load(std::memory_order_relaxed);
            while (abs_sample_drift > previous_abs_max &&
                   !participant.receiver_drift_ppm_abs_max_milli.compare_exchange_weak(
                       previous_abs_max, abs_sample_drift, std::memory_order_relaxed)) {
            }
        }

        participant.drift_reference_sequence = packet.sequence;
        participant.drift_reference_time = packet.timestamp;
    }

    static void observe_opus_pcm_depth(ParticipantData& participant) {
        participant.opus_pcm_buffered_frames_observed.store(
            participant.opus_pcm_buffered_frames, std::memory_order_relaxed);
    }

    static size_t opus_playout_target_queue_packets(const ParticipantData& participant) {
        const size_t jitter_floor = std::max<size_t>(1, participant.jitter_buffer_min_packets);
        const size_t queue_midpoint =
            std::max<size_t>(1, participant.opus_queue_limit_packets / 2);
        return std::max(jitter_floor,
                        std::min<size_t>(MAX_OPUS_JITTER_PACKETS, queue_midpoint));
    }

    static size_t ready_threshold_packets(const ParticipantData& participant) {
        if (participant.last_codec == AudioCodec::Opus) {
            return std::max<size_t>(1, participant.jitter_buffer_min_packets);
        }
        return participant.jitter_buffer_min_packets;
    }

    static size_t opus_rebuffer_empty_callback_threshold(const ParticipantData& participant) {
        const size_t packet_frames =
            participant.last_packet_frame_count.load(std::memory_order_relaxed);
        const size_t callback_frames =
            participant.last_callback_frame_count.load(std::memory_order_relaxed);
        const size_t target_packets = opus_playout_target_queue_packets(participant);
        if (packet_frames > 0 && callback_frames > 0 && callback_frames < packet_frames) {
            const size_t callbacks_per_packet =
                (packet_frames + callback_frames - 1) / callback_frames;
            return std::max<size_t>(3, target_packets * callbacks_per_packet);
        }
        return std::max<size_t>(3, target_packets);
    }

    static void observe_auto_jitter_instability(ParticipantData& participant) {
        if (!participant.opus_jitter_auto_enabled ||
            participant.opus_jitter_manual_override) {
            return;
        }

        participant.opus_jitter_auto_stable_callbacks = 0;
        participant.opus_jitter_auto_instability_events++;
        if (participant.jitter_buffer_min_packets < MAX_OPUS_JITTER_PACKETS) {
            const size_t next_target =
                std::min(MAX_OPUS_JITTER_PACKETS,
                         std::max<size_t>(3, participant.jitter_buffer_min_packets + 1));
            if (next_target > participant.jitter_buffer_min_packets) {
                participant.jitter_buffer_min_packets = next_target;
                participant.jitter_buffer_floor_packets = next_target;
                participant.opus_queue_limit_packets =
                    std::max(participant.opus_queue_limit_packets, next_target + 3);
                participant.buffer_ready = false;
                participant.opus_consecutive_empty_callbacks = 0;
                participant.opus_jitter_auto_increases.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }

    static void observe_auto_jitter_stable(ParticipantData& participant) {
        if (!participant.opus_jitter_auto_enabled ||
            participant.opus_jitter_manual_override) {
            return;
        }

        participant.opus_jitter_auto_instability_events = 0;
        participant.opus_jitter_auto_stable_callbacks++;
        constexpr int STABLE_CALLBACKS_BEFORE_DECREASE = 2000;
        if (participant.opus_jitter_auto_stable_callbacks <
            STABLE_CALLBACKS_BEFORE_DECREASE) {
            return;
        }

        participant.opus_jitter_auto_stable_callbacks = 0;
        const size_t floor_packets =
            std::clamp(participant.opus_jitter_auto_floor_packets,
                       MIN_OPUS_JITTER_PACKETS, MAX_OPUS_JITTER_PACKETS);
        if (participant.jitter_buffer_min_packets > floor_packets) {
            participant.jitter_buffer_min_packets--;
            participant.jitter_buffer_floor_packets = participant.jitter_buffer_min_packets;
            participant.opus_jitter_auto_decreases.fetch_add(1, std::memory_order_relaxed);
        }
    }

    static size_t max_receive_queue_packets(const OpusPacket& packet, size_t opus_queue_limit) {
        size_t base_limit = TARGET_OPUS_QUEUE_SIZE + 1;
        if (packet.frame_count <= 128) {
            base_limit = 8;
        }
        if (packet.codec == AudioCodec::Opus) {
            base_limit = std::max(base_limit, opus_queue_limit);
        }
        return std::min(base_limit, MAX_OPUS_QUEUE_SIZE);
    }

    size_t jitter_floor_for_packet(const OpusPacket& packet) const {
        if (packet.codec == AudioCodec::PcmInt16 && packet.frame_count <= 120) {
            return 2;
        }
        if (packet.codec == AudioCodec::Opus && packet.frame_count <= 120) {
            return get_opus_jitter_buffer_packets();
        }
        return MIN_JITTER_BUFFER_PACKETS;
    }

    static size_t pcm_drift_drop_threshold(const ParticipantData& participant) {
        return participant.jitter_buffer_min_packets + 3;
    }

    void update_jitter_floor(ParticipantData& participant, const OpusPacket& packet) {
        const size_t floor_packets = jitter_floor_for_packet(packet);
        if (packet.codec == AudioCodec::Opus && participant.opus_jitter_manual_override) {
            participant.jitter_buffer_floor_packets = participant.jitter_buffer_min_packets;
            return;
        }
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
        observe_latency_sample(pcm_send_queue_age_last_ns_, pcm_send_queue_age_avg_ns_,
                               pcm_send_queue_age_max_ns_, age_ns);
    }

    void observe_opus_send_queue_age(std::chrono::steady_clock::time_point capture_time) {
        if (capture_time.time_since_epoch().count() == 0) {
            return;
        }

        const auto age_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                std::chrono::steady_clock::now() - capture_time)
                                .count();
        observe_latency_sample(opus_send_queue_age_last_ns_, opus_send_queue_age_avg_ns_,
                               opus_send_queue_age_max_ns_, age_ns);
    }

    void observe_tx_encode_time(std::chrono::steady_clock::duration elapsed) {
        observe_latency_sample(
            tx_encode_last_ns_, tx_encode_avg_ns_, tx_encode_max_ns_,
            std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
    }

    void observe_rx_decode_time(std::chrono::steady_clock::duration elapsed) {
        observe_latency_sample(
            rx_decode_last_ns_, rx_decode_avg_ns_, rx_decode_max_ns_,
            std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
    }

    void observe_rx_playout_time(std::chrono::steady_clock::duration elapsed) {
        observe_latency_sample(
            rx_playout_last_ns_, rx_playout_avg_ns_, rx_playout_max_ns_,
            std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
    }

    void observe_audio_packet_send_pacing() {
        const auto now = std::chrono::steady_clock::now();
        if (last_audio_packet_send_time_.time_since_epoch().count() != 0) {
            observe_latency_sample(
                tx_send_pace_last_ns_, tx_send_pace_avg_ns_, tx_send_pace_max_ns_,
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    now - last_audio_packet_send_time_)
                    .count());
        }
        last_audio_packet_send_time_ = now;
    }

    static void observe_latency_sample(std::atomic<int64_t>& last_ns,
                                       std::atomic<int64_t>& avg_ns,
                                       std::atomic<int64_t>& max_ns,
                                       int64_t sample_ns) {
        last_ns.store(sample_ns, std::memory_order_relaxed);

        int64_t previous_max = max_ns.load(std::memory_order_relaxed);
        while (sample_ns > previous_max &&
               !max_ns.compare_exchange_weak(previous_max, sample_ns,
                                             std::memory_order_relaxed)) {
        }

        const int64_t previous_avg = avg_ns.load(std::memory_order_relaxed);
        const int64_t next_avg =
            previous_avg == 0 ? sample_ns : ((previous_avg * 31) + sample_ns) / 32;
        avg_ns.store(next_avg, std::memory_order_relaxed);
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
            "Audio diag: frames={} tx_packets={} tx_drops pcm/opus={}/{} "
            "sendq_age_ms last/avg/max={:.2f}/{:.2f}/{:.2f} rx_bytes={} tx_bytes={}",
                  audio_config_.frames_per_buffer,
                  audio_tx_sequence_.load(std::memory_order_relaxed),
                  pcm_send_drops,
                  opus_send_drops,
                  ns_to_ms(pcm_send_queue_age_last_ns_.load(std::memory_order_relaxed)),
                  ns_to_ms(pcm_send_queue_age_avg_ns_.load(std::memory_order_relaxed)),
                  ns_to_ms(pcm_send_queue_age_max_ns_.load(std::memory_order_relaxed)),
                  total_bytes_rx_.load(std::memory_order_relaxed),
                  total_bytes_tx_.load(std::memory_order_relaxed));

        Log::info(
            "Latency diag: callback_ms last/avg/max/deadline={:.3f}/{:.3f}/{:.3f}/{:.3f} "
            "over={} txq_ms pcm={:.3f}/{:.3f}/{:.3f} opus={:.3f}/{:.3f}/{:.3f} "
            "encode_ms={:.3f}/{:.3f}/{:.3f} send_pace_ms={:.3f}/{:.3f}/{:.3f} "
            "rx_decode_ms={:.3f}/{:.3f}/{:.3f} rx_playout_ms={:.3f}/{:.3f}/{:.3f}",
            ns_to_ms(callback_last_ns_.load(std::memory_order_relaxed)),
            ns_to_ms(callback_avg_ns_.load(std::memory_order_relaxed)),
            ns_to_ms(callback_max_ns_.load(std::memory_order_relaxed)),
            ns_to_ms(callback_deadline_ns_.load(std::memory_order_relaxed)),
            callback_over_deadline_count_.load(std::memory_order_relaxed),
            ns_to_ms(pcm_send_queue_age_last_ns_.load(std::memory_order_relaxed)),
            ns_to_ms(pcm_send_queue_age_avg_ns_.load(std::memory_order_relaxed)),
            ns_to_ms(pcm_send_queue_age_max_ns_.load(std::memory_order_relaxed)),
            ns_to_ms(opus_send_queue_age_last_ns_.load(std::memory_order_relaxed)),
            ns_to_ms(opus_send_queue_age_avg_ns_.load(std::memory_order_relaxed)),
            ns_to_ms(opus_send_queue_age_max_ns_.load(std::memory_order_relaxed)),
            ns_to_ms(tx_encode_last_ns_.load(std::memory_order_relaxed)),
            ns_to_ms(tx_encode_avg_ns_.load(std::memory_order_relaxed)),
            ns_to_ms(tx_encode_max_ns_.load(std::memory_order_relaxed)),
            ns_to_ms(tx_send_pace_last_ns_.load(std::memory_order_relaxed)),
            ns_to_ms(tx_send_pace_avg_ns_.load(std::memory_order_relaxed)),
            ns_to_ms(tx_send_pace_max_ns_.load(std::memory_order_relaxed)),
            ns_to_ms(rx_decode_last_ns_.load(std::memory_order_relaxed)),
            ns_to_ms(rx_decode_avg_ns_.load(std::memory_order_relaxed)),
            ns_to_ms(rx_decode_max_ns_.load(std::memory_order_relaxed)),
            ns_to_ms(rx_playout_last_ns_.load(std::memory_order_relaxed)),
            ns_to_ms(rx_playout_avg_ns_.load(std::memory_order_relaxed)),
            ns_to_ms(rx_playout_max_ns_.load(std::memory_order_relaxed)));

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
            };
            const auto decoded_packet_rate = calculate_rate(
                p.opus_packets_decoded_in_callback,
                previous.opus_packets_decoded_in_callback, elapsed_sec);
            const auto queue_limit_drop_rate = calculate_rate(
                p.opus_queue_limit_drops, previous.opus_queue_limit_drops, elapsed_sec);
            const auto age_limit_drop_rate = calculate_rate(
                p.opus_age_limit_drops, previous.opus_age_limit_drops, elapsed_sec);
            const auto decode_overflow_drop_rate = calculate_rate(
                p.opus_decode_buffer_overflow_drops,
                previous.opus_decode_buffer_overflow_drops, elapsed_sec);
            const auto target_trim_rate = calculate_rate(
                p.opus_target_trim_drops, previous.opus_target_trim_drops, elapsed_sec);
            previous.jitter_depth_drops = p.jitter_depth_drops;
            previous.jitter_age_drops = p.jitter_age_drops;
            previous.pcm_concealment_frames = p.pcm_concealment_frames;
            previous.pcm_drift_drops = p.pcm_drift_drops;
            previous.opus_packets_decoded_in_callback = p.opus_packets_decoded_in_callback;
            previous.opus_queue_limit_drops = p.opus_queue_limit_drops;
            previous.opus_age_limit_drops = p.opus_age_limit_drops;
            previous.opus_decode_buffer_overflow_drops =
                p.opus_decode_buffer_overflow_drops;
            previous.opus_target_trim_drops = p.opus_target_trim_drops;

            Log::info(
                "Participant diag {}: ready={} q={} q_avg={} q_max={} q_drift={:.2f} "
                "jitter_buffer={} queue_limit={} frames pkt/cb={}/{} decoded_frames={} decoded_packets={} age_avg_ms={:.1f} drift_ppm last/avg/max={:.1f}/{:.1f}/{:.1f} underruns={} pcm_hold/drop={}/{} drops q/age={}/{} drop_detail limit/age/overflow={}/{}/{} seq gap/late={}/{} "
                "target_trim={} drop_rate pcm/q/hold/drift={:.1f}/{:.1f}/{:.1f}/{:.1f}/s",
                p.id, p.buffer_ready, p.queue_size, p.queue_size_avg, p.queue_size_max,
                p.queue_drift_packets, p.jitter_buffer_min_packets,
                p.opus_queue_limit_packets, p.last_packet_frame_count,
                p.last_callback_frame_count, p.opus_pcm_buffered_frames,
                p.opus_packets_decoded_in_callback, p.packet_age_avg_ms,
                p.receiver_drift_ppm_last, p.receiver_drift_ppm_avg,
                p.receiver_drift_ppm_abs_max,
                p.underrun_count, p.pcm_concealment_frames, p.pcm_drift_drops,
                p.jitter_depth_drops, p.jitter_age_drops, p.opus_queue_limit_drops,
                p.opus_age_limit_drops, p.opus_decode_buffer_overflow_drops,
                p.sequence_gaps, p.sequence_late_or_reordered, p.opus_target_trim_drops,
                drop_rate.pcm_send_per_sec, drop_rate.jitter_depth_per_sec,
                drop_rate.pcm_hold_per_sec, drop_rate.pcm_drift_drop_per_sec);
            Log::info(
                "Participant playout rates {}: decoded_packets={:.1f}/s ratio={:.4f} correction_callbacks={} drops limit/age/overflow/target={:.1f}/{:.1f}/{:.1f}/{:.1f}/s",
                p.id, decoded_packet_rate, p.opus_playout_rate_ratio,
                p.opus_rate_correction_callbacks, queue_limit_drop_rate, age_limit_drop_rate,
                decode_overflow_drop_rate, target_trim_rate);

            if (elapsed_sec > 0.0 &&
                (drop_rate.pcm_send_per_sec > 5.0 ||
                 drop_rate.jitter_depth_per_sec > 100.0 ||
                 drop_rate.jitter_age_per_sec > 5.0 ||
                 drop_rate.pcm_hold_per_sec > 5.0 ||
                 drop_rate.pcm_drift_drop_per_sec > 5.0)) {
                Log::warn(
                    "Audio health warning for participant {}: likely corrupt/robotic risk "
                    "(pcm_drop_rate={:.1f}/s opus_drop_rate={:.1f}/s "
                    "queue_drop_rate={:.1f}/s age_drop_rate={:.1f}/s "
                    "pcm_hold_rate={:.1f}/s pcm_drift_drop_rate={:.1f}/s)",
                    p.id, drop_rate.pcm_send_per_sec, drop_rate.opus_send_per_sec,
                    drop_rate.jitter_depth_per_sec, drop_rate.jitter_age_per_sec,
                    drop_rate.pcm_hold_per_sec, drop_rate.pcm_drift_drop_per_sec);
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
                recording_writer_.set_participant_metadata(info.participant_id, profile_id,
                                                           display_name);
                Log::info("Participant {} metadata: user='{}' display='{}'", info.participant_id,
                          profile_id, display_name);
                break;
            }
            case CtrlHdr::Cmd::METRONOME_SYNC: {
                if (bytes < sizeof(MetronomeSyncHdr)) {
                    break;
                }
                MetronomeSyncHdr sync{};
                std::memcpy(&sync, recv_buf_.data(), sizeof(MetronomeSyncHdr));
                schedule_metronome_sync(sync);
                metronome_sync_received_.fetch_add(1, std::memory_order_relaxed);
                Log::info("Metronome sync: bpm={:.1f} running={} beat={} seq={} effective_ns={}",
                          static_cast<double>(sync.bpm_milli) / 1000.0,
                          (sync.flags & METRONOME_FLAG_RUNNING) != 0, sync.beat_number,
                          sync.sequence, sync.effective_server_time_ns);
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
        auto offset =
            ((hdr.t2_server_recv - hdr.t1_client_send) + (hdr.t3_server_send - current_time)) /
            2;

        double rtt_ms = static_cast<double>(rtt) / 1e6;

        // Store RTT for GUI display (thread-safe atomic update)
        rtt_ms_.store(rtt_ms, std::memory_order_relaxed);
        if (!server_clock_ready_.exchange(true, std::memory_order_acq_rel)) {
            server_clock_offset_ns_.store(offset, std::memory_order_release);
        } else {
            const int64_t previous = server_clock_offset_ns_.load(std::memory_order_relaxed);
            server_clock_offset_ns_.store(((previous * 15) + offset) / 16,
                                          std::memory_order_release);
        }

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
            participant_manager_.with_participant(
                sender_id, [this](ParticipantData& participant) {
                    apply_default_opus_jitter_policy(participant);
                });
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
            observe_receiver_clock_drift(participant, packet);
            participant.last_packet_frame_count.store(packet.frame_count,
                                                      std::memory_order_relaxed);

            // Bounded jitter management: drop old packets if queue is too large.
            const size_t configured_queue_limit =
                std::max(get_opus_queue_limit_packets(),
                         opus_playout_target_queue_packets(participant) + 3);
            const size_t max_queue_packets =
                max_receive_queue_packets(packet, configured_queue_limit);
            participant.opus_queue_limit_packets = max_queue_packets;
            while (queue_size + 1 > max_queue_packets) {
                OpusPacket discarded;
                if (participant.opus_queue.try_dequeue(discarded)) {
                    queue_size--;
                    participant.jitter_depth_drops.fetch_add(1, std::memory_order_relaxed);
                    participant.opus_queue_limit_drops.fetch_add(1, std::memory_order_relaxed);
                } else {
                    break;
                }
            }

            if (queue_size < max_queue_packets) {
                participant.opus_queue.enqueue(packet);  // OpusPacket is trivially copyable
                size_t queue_after_enqueue = queue_size + 1;
                observe_participant_queue_depth(participant, queue_after_enqueue);
                participant.last_packet_time = packet.timestamp;

                // Mark buffer as ready once we have enough packets
                if (!participant.buffer_ready &&
                    queue_after_enqueue >= ready_threshold_packets(participant)) {
                    participant.buffer_ready = true;
                    participant.opus_consecutive_empty_callbacks = 0;
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

    void schedule_metronome_sync(const MetronomeSyncHdr& sync) {
        const uint32_t current_sequence =
            metronome_pending_sequence_.load(std::memory_order_acquire);
        if (sync.sequence != 0 && sync.sequence <= current_sequence) {
            return;
        }
        const int bpm_milli = std::clamp(static_cast<int>(sync.bpm_milli), 30000, 240000);
        metronome_pending_bpm_milli_.store(bpm_milli, std::memory_order_relaxed);
        metronome_pending_running_.store((sync.flags & METRONOME_FLAG_RUNNING) != 0,
                                         std::memory_order_relaxed);
        metronome_pending_beat_number_.store(sync.beat_number, std::memory_order_relaxed);
        const bool clock_ready = server_clock_ready_.load(std::memory_order_acquire);
        const int64_t effective_ns =
            sync.effective_server_time_ns > 0 && clock_ready
                ? sync.effective_server_time_ns
                : steady_now_ns() + server_clock_offset_ns_.load(std::memory_order_acquire) +
                      150'000'000LL;
        metronome_pending_effective_server_time_ns_.store(effective_ns,
                                                          std::memory_order_relaxed);
        metronome_pending_sequence_.store(sync.sequence == 0 ? current_sequence + 1 : sync.sequence,
                                          std::memory_order_release);
    }

    static int64_t ns_delta_to_samples(int64_t ns, size_t sample_rate) {
        return static_cast<int64_t>((static_cast<long double>(ns) *
                                     static_cast<long double>(sample_rate)) /
                                    1'000'000'000.0L);
    }

    static int64_t beat_interval_samples(int bpm_milli, size_t sample_rate) {
        return std::max<int64_t>(
            1, static_cast<int64_t>((static_cast<long double>(sample_rate) *
                                     60'000.0L) /
                                    static_cast<long double>(std::max(1, bpm_milli))));
    }

    void prepare_metronome_schedule(int64_t local_time_ns, size_t sample_rate) {
        const uint32_t pending_sequence =
            metronome_pending_sequence_.load(std::memory_order_acquire);
        if (pending_sequence == 0 || pending_sequence == metronome_prepared_sequence_) {
            return;
        }

        const int64_t effective_ns =
            metronome_pending_effective_server_time_ns_.load(std::memory_order_relaxed);
        const int64_t offset_ns = server_clock_offset_ns_.load(std::memory_order_acquire);
        const int64_t local_effective_ns = effective_ns - offset_ns;
        const int64_t delta_samples =
            ns_delta_to_samples(local_effective_ns - local_time_ns, sample_rate);
        metronome_prepared_effective_sample_ =
            metronome_audio_sample_cursor_ + delta_samples;
        metronome_prepared_sequence_ = pending_sequence;
    }

    void apply_due_metronome_schedule(size_t sample_rate) {
        if (metronome_prepared_sequence_ == 0 ||
            metronome_prepared_sequence_ == metronome_applied_sequence_ ||
            metronome_audio_sample_cursor_ < metronome_prepared_effective_sample_) {
            return;
        }

        const int bpm_milli =
            std::max(1, metronome_pending_bpm_milli_.load(std::memory_order_relaxed));
        const bool running = metronome_pending_running_.load(std::memory_order_relaxed);
        const uint32_t beat = metronome_pending_beat_number_.load(std::memory_order_relaxed);
        const int64_t interval_samples = beat_interval_samples(bpm_milli, sample_rate);

        metronome_bpm_milli_.store(bpm_milli, std::memory_order_release);
        metronome_running_.store(running, std::memory_order_release);
        metronome_beat_number_.store(beat, std::memory_order_release);
        metronome_epoch_sample_ =
            metronome_prepared_effective_sample_ - (static_cast<int64_t>(beat) * interval_samples);
        metronome_timeline_ready_ = true;
        metronome_applied_sequence_ = metronome_prepared_sequence_;
    }

    void mix_metronome_click(float* output_buffer, unsigned long frame_count, size_t out_channels) {
        const int bpm_milli = std::max(1, metronome_bpm_milli_.load(std::memory_order_acquire));
        const size_t sample_rate = static_cast<size_t>(std::max(1, audio_config_.sample_rate));
        const int64_t interval_samples = beat_interval_samples(bpm_milli, sample_rate);
        const size_t click_samples = std::max<size_t>(1, sample_rate / 35);
        prepare_metronome_schedule(steady_now_ns(), sample_rate);

        constexpr double PI = 3.14159265358979323846;
        for (unsigned long frame = 0; frame < frame_count; ++frame) {
            apply_due_metronome_schedule(sample_rate);

            if (!metronome_running_.load(std::memory_order_acquire) ||
                !metronome_timeline_ready_) {
                ++metronome_audio_sample_cursor_;
                continue;
            }

            const int64_t elapsed_samples =
                metronome_audio_sample_cursor_ - metronome_epoch_sample_;
            if (elapsed_samples < 0) {
                ++metronome_audio_sample_cursor_;
                continue;
            }

            const uint32_t beat_number =
                static_cast<uint32_t>(elapsed_samples / interval_samples) + 1;
            const size_t click_sample =
                static_cast<size_t>(elapsed_samples % interval_samples);
            metronome_beat_number_.store(beat_number, std::memory_order_release);

            if (click_sample < click_samples) {
                const bool downbeat = ((beat_number - 1) % 4) == 0;
                const double frequency = downbeat ? 1320.0 : 880.0;
                const double t = static_cast<double>(click_sample) /
                                 static_cast<double>(sample_rate);
                const double envelope =
                    std::exp(-7.0 * static_cast<double>(click_sample) /
                             static_cast<double>(click_samples));
                const float click =
                    static_cast<float>(std::sin(2.0 * PI * frequency * t) * envelope * 0.22);
                for (size_t channel = 0; channel < out_channels; ++channel) {
                    const size_t index = (frame * out_channels) + channel;
                    output_buffer[index] = std::clamp(output_buffer[index] + click, -1.0F, 1.0F);
                }
            }

            ++metronome_audio_sample_cursor_;
        }
    }

    void record_mono_block(RecordingWriter::TrackKind kind, uint32_t participant_id,
                           const float* samples, size_t frame_count) {
        recording_writer_.enqueue(kind, participant_id,
                                  static_cast<uint32_t>(audio_config_.sample_rate), samples,
                                  frame_count);
    }

    void record_master_mix(const float* output_buffer, unsigned long frame_count,
                           size_t out_channels) {
        if (!recording_writer_.is_active() || output_buffer == nullptr ||
            frame_count > RecordingWriter::MAX_FRAMES_PER_BLOCK) {
            return;
        }

        if (out_channels == 1) {
            record_mono_block(RecordingWriter::TrackKind::Master, 0, output_buffer, frame_count);
            return;
        }

        std::array<float, RecordingWriter::MAX_FRAMES_PER_BLOCK> mono{};
        for (unsigned long frame = 0; frame < frame_count; ++frame) {
            float sum = 0.0F;
            for (size_t channel = 0; channel < out_channels; ++channel) {
                sum += output_buffer[(frame * out_channels) + channel];
            }
            mono[frame] = sum / static_cast<float>(out_channels);
        }
        record_mono_block(RecordingWriter::TrackKind::Master, 0, mono.data(), frame_count);
    }

    struct BroadcastIpcFrame {
        uint32_t sample_rate = 48000;
        uint16_t frame_count = 0;
        std::array<float, 960> samples{};
    };

    void enqueue_broadcast_mix(const float* output_buffer, const float* input_buffer,
                               unsigned long frame_count, size_t out_channels) {
        if (!broadcast_ipc_running_.load(std::memory_order_acquire) || output_buffer == nullptr ||
            out_channels == 0 || frame_count == 0 || frame_count > 960) {
            return;
        }

        BroadcastIpcFrame frame;
        frame.sample_rate = static_cast<uint32_t>(audio_config_.sample_rate);
        frame.frame_count = static_cast<uint16_t>(frame_count);
        const bool include_mic =
            input_buffer != nullptr && !mic_muted_.load(std::memory_order_acquire);
        const float input_gain = input_gain_.load(std::memory_order_acquire);

        for (unsigned long i = 0; i < frame_count; ++i) {
            float sample = 0.0F;
            if (out_channels == 1) {
                sample = output_buffer[i];
            } else {
                for (size_t channel = 0; channel < out_channels; ++channel) {
                    sample += output_buffer[(i * out_channels) + channel];
                }
                sample /= static_cast<float>(out_channels);
            }
            if (include_mic) {
                sample += input_buffer[i] * input_gain;
            }
            frame.samples[i] = std::clamp(sample, -1.0F, 1.0F);
        }

        if (broadcast_queue_.try_enqueue(frame)) {
            broadcast_frames_produced_.fetch_add(1, std::memory_order_relaxed);
        } else {
            broadcast_enqueue_drops_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void broadcast_ipc_sender_loop() {
        try {
            asio::io_context io;
            udp::socket socket(io);
            socket.open(udp::v4());
            udp::endpoint endpoint(asio::ip::make_address("127.0.0.1"),
                                   broadcast_ipc_port_.load(std::memory_order_acquire));

            std::array<unsigned char, sizeof(JamBroadcastIpcHeader) + (960 * sizeof(float))>
                packet{};
            uint32_t sequence = 0;
            BroadcastIpcFrame frame;
            while (broadcast_ipc_running_.load(std::memory_order_acquire)) {
                bool sent_any = false;
                while (broadcast_queue_.try_dequeue(frame)) {
                    JamBroadcastIpcHeader header;
                    header.sequence = sequence++;
                    header.sample_rate = frame.sample_rate;
                    header.channels = 1;
                    header.frame_count = frame.frame_count;
                    header.format = static_cast<uint16_t>(JamBroadcastPcmFormat::Float32LE);
                    header.payload_bytes =
                        static_cast<uint16_t>(frame.frame_count * sizeof(float));
                    std::memcpy(packet.data(), &header, sizeof(header));
                    std::memcpy(packet.data() + sizeof(header), frame.samples.data(),
                                header.payload_bytes);

                    std::error_code ec;
                    socket.send_to(
                        asio::buffer(packet.data(), sizeof(header) + header.payload_bytes),
                        endpoint, 0, ec);
                    if (ec) {
                        broadcast_send_drops_.fetch_add(1, std::memory_order_relaxed);
                    } else {
                        broadcast_frames_sent_.fetch_add(1, std::memory_order_relaxed);
                    }
                    sent_any = true;
                }
                if (!sent_any) {
                    std::this_thread::sleep_for(2ms);
                }
            }
        } catch (const std::exception& e) {
            Log::error("Broadcast IPC sender stopped: {}", e.what());
        }
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
        const auto playout_start = std::chrono::steady_clock::now();
        client->participant_manager_.for_each([&](uint32_t         participant_id,
                                                  ParticipantData& participant) {
            observe_opus_pcm_depth(participant);
            participant.last_callback_frame_count.store(frame_count, std::memory_order_relaxed);
            if (participant.is_muted) {
                return;
            }

            if (!participant.buffer_ready) {
                const size_t queue_size = participant.opus_queue.size_approx();
                observe_participant_queue_depth(participant, queue_size);
                if (queue_size >= ready_threshold_packets(participant)) {
                    participant.buffer_ready = true;
                    participant.opus_consecutive_empty_callbacks = 0;
                    Log::info("Jitter buffer ready for participant {} ({} packets)",
                              participant_id, queue_size);
                } else {
                    return;
                }
            }

            double playout_ratio = opus_playout_rate_ratio(participant);
            if (participant.last_codec == AudioCodec::Opus &&
                participant.opus_pcm_buffered_frames >=
                    opus_resample_required_input_frames(
                        participant, frame_count, playout_ratio)) {
                mix_resampled_opus_pcm(participant, output_buffer, frame_count, out_channels,
                                       participant.gain, playout_ratio);
                observe_opus_pcm_depth(participant);
                observe_auto_jitter_stable(participant);
                participant.opus_consecutive_empty_callbacks = 0;
                active_count++;
                observe_participant_queue_depth(participant, participant.opus_queue.size_approx());
                return;
            }

            OpusPacket opus_packet;

            if (participant.opus_queue.try_dequeue(opus_packet)) {
                auto now = std::chrono::steady_clock::now();
                auto packet_age = now - opus_packet.timestamp;
                auto packet_age_ns =
                    std::chrono::duration_cast<std::chrono::nanoseconds>(packet_age).count();
                const auto max_packet_age_ns =
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        std::chrono::milliseconds(client->get_jitter_packet_age_limit_ms()))
                        .count();

                while (packet_age_ns > max_packet_age_ns) {
                    participant.jitter_age_drops.fetch_add(1, std::memory_order_relaxed);
                    participant.opus_age_limit_drops.fetch_add(1, std::memory_order_relaxed);
                    observe_auto_jitter_instability(participant);
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
                    const size_t expected_bytes = frame_count * sizeof(int16_t);
                    if (opus_packet.get_size() != expected_bytes) {
                        static int pcm_size_mismatch_count = 0;
                        if (++pcm_size_mismatch_count % 100 == 0) {
                            Log::warn("PCM size mismatch for participant {}: got {}, expected {}",
                                      participant_id, opus_packet.get_size(), expected_bytes);
                        }
                        return;
                    }
                    for (unsigned long i = 0; i < frame_count; ++i) {
                        int16_t sample = 0;
                        std::memcpy(&sample, opus_packet.get_data() + i * sizeof(sample),
                                    sizeof(sample));
                        participant.pcm_buffer[i] = static_cast<float>(sample) / 32767.0F;
                    }
                    decoded_samples = static_cast<int>(frame_count);
                } else {
                    const int decode_frame_count =
                        opus_packet.frame_count > 0 ? static_cast<int>(opus_packet.frame_count)
                                                    : static_cast<int>(frame_count);
                    // Decode into preallocated buffer (zero allocations)
                    const auto decode_start = std::chrono::steady_clock::now();
                    decoded_samples = participant.decoder->decode_into(
                        opus_packet.get_data(), static_cast<int>(opus_packet.get_size()),
                        participant.pcm_buffer.data(), decode_frame_count);
                    client->observe_rx_decode_time(std::chrono::steady_clock::now() -
                                                   decode_start);
                }

                if (decoded_samples <= 0) {
                    // Decode failed - use silence
                    static int decode_fail_count = 0;
                    if (++decode_fail_count % 100 == 0) {
                        Log::warn("Decode failed for participant {} ({} times)", participant_id,
                                  decode_fail_count);
                    }
                    observe_auto_jitter_instability(participant);
                    return;
                }

                if (static_cast<size_t>(decoded_samples) <=
                    RecordingWriter::MAX_FRAMES_PER_BLOCK) {
                    client->record_mono_block(RecordingWriter::TrackKind::Participant,
                                              participant_id, participant.pcm_buffer.data(),
                                              static_cast<size_t>(decoded_samples));
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
                        participant.opus_packets_decoded_in_callback.fetch_add(
                            1, std::memory_order_relaxed);
                    } else {
                        participant.opus_pcm_buffered_frames = 0;
                        participant.jitter_depth_drops.fetch_add(1, std::memory_order_relaxed);
                        participant.opus_decode_buffer_overflow_drops.fetch_add(
                            1, std::memory_order_relaxed);
                    }

                    double playout_ratio = opus_playout_rate_ratio(participant);
                    size_t required_input_frames = opus_resample_required_input_frames(
                        participant, frame_count, playout_ratio);
                    while (participant.opus_pcm_buffered_frames < required_input_frames) {
                        OpusPacket next_packet;
                        if (!participant.opus_queue.try_dequeue(next_packet) ||
                            next_packet.codec != AudioCodec::Opus) {
                            break;
                        }

                        const int next_decode_frame_count =
                            next_packet.frame_count > 0
                                ? static_cast<int>(next_packet.frame_count)
                                : static_cast<int>(frame_count);
                        const auto next_decode_start = std::chrono::steady_clock::now();
                        int next_decoded_samples = participant.decoder->decode_into(
                            next_packet.get_data(), static_cast<int>(next_packet.get_size()),
                            participant.pcm_buffer.data(), next_decode_frame_count);
                        client->observe_rx_decode_time(std::chrono::steady_clock::now() -
                                                       next_decode_start);
                        if (next_decoded_samples <= 0) {
                            break;
                        }

                        const size_t next_decoded_frames =
                            static_cast<size_t>(next_decoded_samples);
                        if (next_decoded_frames <= RecordingWriter::MAX_FRAMES_PER_BLOCK) {
                            client->record_mono_block(RecordingWriter::TrackKind::Participant,
                                                      participant_id,
                                                      participant.pcm_buffer.data(),
                                                      next_decoded_frames);
                        }
                        if (participant.opus_pcm_buffered_frames + next_decoded_frames >
                            participant.opus_pcm_buffer.size()) {
                            participant.opus_pcm_buffered_frames = 0;
                            participant.jitter_depth_drops.fetch_add(1, std::memory_order_relaxed);
                            participant.opus_decode_buffer_overflow_drops.fetch_add(
                                1, std::memory_order_relaxed);
                            break;
                        }

                        std::copy_n(participant.pcm_buffer.begin(), next_decoded_frames,
                                    participant.opus_pcm_buffer.begin() +
                                        static_cast<std::ptrdiff_t>(
                                            participant.opus_pcm_buffered_frames));
                        participant.opus_pcm_buffered_frames += next_decoded_frames;
                        participant.opus_packets_decoded_in_callback.fetch_add(
                            1, std::memory_order_relaxed);
                        playout_ratio = opus_playout_rate_ratio(participant);
                        required_input_frames = opus_resample_required_input_frames(
                            participant, frame_count, playout_ratio);
                    }

                    float rms = audio_analysis::calculate_rms(participant.pcm_buffer.data(),
                                                              decoded_samples);
                    participant.current_level = rms;

                    bool was_speaking       = participant.is_speaking;
                    participant.is_speaking = audio_analysis::detect_voice_activity(rms);

                    playout_ratio = opus_playout_rate_ratio(participant);
                    required_input_frames = opus_resample_required_input_frames(
                        participant, frame_count, playout_ratio);
                    if (participant.opus_pcm_buffered_frames >= required_input_frames) {
                        mix_resampled_opus_pcm(participant, output_buffer, frame_count,
                                               out_channels, participant.gain, playout_ratio);
                        observe_opus_pcm_depth(participant);
                        observe_auto_jitter_stable(participant);
                        participant.opus_consecutive_empty_callbacks = 0;
                        active_count++;
                    } else if (participant.opus_pcm_buffered_frames > 0) {
                        mix_available_opus_pcm_with_tail(participant, output_buffer, frame_count,
                                                        out_channels, participant.gain,
                                                        playout_ratio);
                        observe_opus_pcm_depth(participant);
                        participant.opus_consecutive_empty_callbacks = 0;
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
                    observe_opus_pcm_depth(participant);
                    return;
                }

                if (opus_packet.codec == AudioCodec::PcmInt16 &&
                    decoded_samples <= static_cast<int>(participant.last_pcm_buffer.size())) {
                    std::copy_n(participant.pcm_buffer.begin(), decoded_samples,
                                participant.last_pcm_buffer.begin());
                    participant.last_pcm_samples = static_cast<size_t>(decoded_samples);
                    participant.last_pcm_valid = true;
                    participant.pcm_concealment_used = false;
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

                // Track queue size history for diagnostics. Manual jitter control owns the
                // Opus playout target; do not auto-adjust it here.
                size_t current_queue_size = participant.opus_queue.size_approx();
                if (opus_packet.codec == AudioCodec::PcmInt16 &&
                    current_queue_size > pcm_drift_drop_threshold(participant)) {
                    OpusPacket discarded;
                    if (participant.opus_queue.try_dequeue(discarded)) {
                        current_queue_size--;
                        participant.pcm_drift_drops.fetch_add(1, std::memory_order_relaxed);
                        participant.jitter_depth_drops.fetch_add(1, std::memory_order_relaxed);
                    }
                }
                observe_participant_queue_depth(participant, current_queue_size);
                participant.queue_size_history[participant.history_index] = current_queue_size;
                participant.history_index =
                    (participant.history_index + 1) % participant.queue_size_history.size();
            } else {
                // Underrun - use PLC instead of silence for smoother audio
                size_t current_queue_size = participant.opus_queue.size_approx();
                observe_participant_queue_depth(participant, current_queue_size);

                if (participant.last_codec == AudioCodec::Opus &&
                    participant.opus_pcm_buffered_frames > 0) {
                    const double playout_ratio = opus_playout_rate_ratio(participant);
                    mix_available_opus_pcm_with_tail(participant, output_buffer, frame_count,
                                                    out_channels, participant.gain,
                                                    playout_ratio);
                    observe_opus_pcm_depth(participant);
                    participant.opus_consecutive_empty_callbacks = 0;
                    active_count++;
                    return;
                }

                int plc_samples = 0;
                if (participant.last_codec == AudioCodec::Opus) {
                    const auto plc_start = std::chrono::steady_clock::now();
                    plc_samples = participant.decoder->decode_plc(participant.pcm_buffer.data(),
                                                                  static_cast<int>(frame_count));
                    client->observe_rx_decode_time(std::chrono::steady_clock::now() - plc_start);
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

                // Handle Opus rebuffering state. Short empty callbacks are covered by
                // PLC/tail playout above; only a sustained run is a hard underrun.
                if (participant.buffer_ready) {
                    participant.opus_consecutive_empty_callbacks++;
                    if (participant.opus_consecutive_empty_callbacks >=
                        static_cast<int>(opus_rebuffer_empty_callback_threshold(participant))) {
                        participant.underrun_count++;
                        observe_auto_jitter_instability(participant);
                        participant.buffer_ready = false;
                        participant.opus_consecutive_empty_callbacks = 0;
                        if (participant.underrun_count == 1 ||
                            participant.underrun_count % 10 == 0) {
                            Log::info("Participant {} rebuffering (underruns: {}, PLC: {})",
                                      participant_id, participant.underrun_count,
                                      participant.plc_count);
                        }
                    }
                }
            }
        });
        client->observe_rx_playout_time(std::chrono::steady_clock::now() - playout_start);

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

        client->enqueue_broadcast_mix(output_buffer, input_buffer, frame_count, out_channels);
        client->mix_metronome_click(output_buffer, frame_count, out_channels);
        client->record_master_mix(output_buffer, frame_count, out_channels);

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
                client->record_mono_block(RecordingWriter::TrackKind::Self, 0, pcm_input.data(),
                                          frame_count);

                const size_t payload_bytes = frame_count * sizeof(int16_t);
                if (payload_bytes <= AUDIO_BUF_SIZE) {
                    std::array<unsigned char, AUDIO_BUF_SIZE> pcm_payload{};
                    for (unsigned long i = 0; i < frame_count; ++i) {
                        float clamped = std::clamp(pcm_input[i], -1.0F, 1.0F);
                        auto sample = static_cast<int16_t>(std::lrint(clamped * 32767.0F));
                        std::memcpy(pcm_payload.data() + i * sizeof(sample), &sample, sizeof(sample));
                    }
                    client->enqueue_pcm_send_frame(
                        pcm_payload.data(), static_cast<uint16_t>(payload_bytes),
                        static_cast<uint16_t>(frame_count),
                        static_cast<uint32_t>(client->audio_config_.sample_rate), callback_start);
                }
                return 0;
            }

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
            client->record_mono_block(RecordingWriter::TrackKind::Self, 0, opus_input.data(),
                                      frame_count);
            client->enqueue_opus_send_samples(
                opus_input.data(), frame_count,
                static_cast<uint32_t>(client->audio_config_.sample_rate), callback_start);
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
    std::atomic<size_t>      opus_jitter_buffer_packets_{DEFAULT_OPUS_JITTER_PACKETS};
    std::atomic<size_t>      opus_queue_limit_packets_{DEFAULT_OPUS_QUEUE_LIMIT_PACKETS};
    std::atomic<int>         jitter_packet_age_limit_ms_{DEFAULT_JITTER_PACKET_AGE_MS};
    std::atomic<bool>        opus_auto_jitter_default_{true};
    std::atomic<uint32_t>    audio_tx_sequence_{0};
    moodycamel::ConcurrentQueue<PcmSendFrame> pcm_send_queue_;
    moodycamel::ConcurrentQueue<OpusSendFrame> opus_send_queue_;
    std::array<float, 960>                     opus_tx_accumulator_{};
    size_t                                     opus_tx_accumulated_frames_ = 0;
    std::chrono::steady_clock::time_point      opus_tx_accumulator_capture_time_{};
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
    std::atomic<int64_t>                      opus_send_queue_age_last_ns_{0};
    std::atomic<int64_t>                      opus_send_queue_age_avg_ns_{0};
    std::atomic<int64_t>                      opus_send_queue_age_max_ns_{0};
    std::atomic<int64_t>                      tx_encode_last_ns_{0};
    std::atomic<int64_t>                      tx_encode_avg_ns_{0};
    std::atomic<int64_t>                      tx_encode_max_ns_{0};
    std::atomic<int64_t>                      tx_send_pace_last_ns_{0};
    std::atomic<int64_t>                      tx_send_pace_avg_ns_{0};
    std::atomic<int64_t>                      tx_send_pace_max_ns_{0};
    std::atomic<int64_t>                      rx_decode_last_ns_{0};
    std::atomic<int64_t>                      rx_decode_avg_ns_{0};
    std::atomic<int64_t>                      rx_decode_max_ns_{0};
    std::atomic<int64_t>                      rx_playout_last_ns_{0};
    std::atomic<int64_t>                      rx_playout_avg_ns_{0};
    std::atomic<int64_t>                      rx_playout_max_ns_{0};
    std::chrono::steady_clock::time_point     last_audio_packet_send_time_{};
    moodycamel::ConcurrentQueue<BroadcastIpcFrame> broadcast_queue_{256};
    std::atomic<bool>                         broadcast_ipc_running_{false};
    std::atomic<unsigned short>               broadcast_ipc_port_{0};
    std::thread                               broadcast_ipc_thread_;
    std::atomic<uint64_t>                     broadcast_frames_produced_{0};
    std::atomic<uint64_t>                     broadcast_frames_sent_{0};
    std::atomic<uint64_t>                     broadcast_enqueue_drops_{0};
    std::atomic<uint64_t>                     broadcast_send_drops_{0};

    ParticipantManager participant_manager_;
    WavFilePlayback    wav_playback_;
    RecordingWriter    recording_writer_;

    // WAV playback volume/gain (thread-safe with atomic)
    std::atomic<float> wav_gain_{1.0F};          // Default to 100% volume
    std::atomic<bool>  wav_muted_local_{false};  // Mute locally (still sends over network)

    std::atomic<int>      metronome_bpm_milli_{120000};
    std::atomic<bool>     metronome_running_{false};
    std::atomic<uint32_t> metronome_beat_number_{0};
    std::atomic<uint64_t> metronome_sync_sent_{0};
    std::atomic<uint64_t> metronome_sync_received_{0};
    std::atomic<int>      metronome_pending_bpm_milli_{120000};
    std::atomic<bool>     metronome_pending_running_{false};
    std::atomic<uint32_t> metronome_pending_beat_number_{0};
    std::atomic<int64_t>  metronome_pending_effective_server_time_ns_{0};
    std::atomic<uint32_t> metronome_pending_sequence_{0};
    uint32_t              metronome_prepared_sequence_ = 0;
    int64_t               metronome_prepared_effective_sample_ = 0;
    uint32_t              metronome_applied_sequence_ = 0;
    int64_t               metronome_epoch_sample_ = 0;
    int64_t               metronome_audio_sample_cursor_ = 0;
    bool                  metronome_timeline_ready_ = false;
    std::array<std::chrono::steady_clock::time_point, 8> tap_times_{};
    size_t                                             tap_count_ = 0;
    size_t                                             tap_index_ = 0;

    // Microphone mute (thread-safe with atomic)
    std::atomic<bool> mic_muted_{false};  // Mute mic (doesn't send to server)

    // Master input gain (thread-safe with atomic) - 1.0 = unity
    std::atomic<float> input_gain_{1.0F};

    // Own audio level tracking (thread-safe with atomic)
    std::atomic<float> own_audio_level_{0.0F};

    // RTT tracking (thread-safe with atomic)
    std::atomic<double> rtt_ms_{0.0};
    std::atomic<int64_t> server_clock_offset_ns_{0};
    std::atomic<bool>    server_clock_ready_{false};

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
        uint64_t opus_packets_decoded_in_callback = 0;
        uint64_t opus_queue_limit_drops = 0;
        uint64_t opus_age_limit_drops = 0;
        uint64_t opus_decode_buffer_overflow_drops = 0;
        uint64_t opus_target_trim_drops = 0;
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
    float fader_height = std::max(120.0F, available_height - 560.0F);

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
        if (ImGui::RadioButton("PCM LAN/exp##codec", codec_choice == 0)) {
            client.set_audio_codec(AudioCodec::PcmInt16);
        }
        JamGui::ShowTooltipOnHover(
            "Uncompressed reference/LAN mode; cross-machine PCM is still experimental");
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
        JamGui::ShowTooltipOnHover("Compressed internet mode; production candidate at 120 frames");

        ImGui::Spacing();
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        ImGui::Text("Jitter buffer:");
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        int jitter_packets = static_cast<int>(client.get_opus_jitter_buffer_packets());
        const bool jitter_enabled = client.get_audio_codec() == AudioCodec::Opus;
        if (!jitter_enabled) {
            ImGui::BeginDisabled();
        }
        ImGui::PushItemWidth(width - PADDING);
        if (ImGui::InputInt("##OpusJitterPackets", &jitter_packets, 1, 1)) {
            client.set_opus_jitter_buffer_packets(static_cast<size_t>(std::max(jitter_packets, 0)));
            if (client.get_opus_queue_limit_packets() <
                client.get_opus_jitter_buffer_packets()) {
                client.set_opus_queue_limit_packets(client.get_opus_jitter_buffer_packets());
            }
        }
        ImGui::PopItemWidth();
        if (!jitter_enabled) {
            ImGui::EndDisabled();
        }
        const double packet_ms =
            (static_cast<double>(client.get_audio_config().frames_per_buffer) * 1000.0) /
            static_cast<double>(client.get_audio_config().sample_rate);
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        ImGui::Text("%zu pkt, %.1f ms", client.get_opus_jitter_buffer_packets(),
                    client.get_opus_jitter_buffer_packets() * packet_ms);
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        bool auto_jitter_default = client.get_opus_auto_jitter_default();
        if (!jitter_enabled) {
            ImGui::BeginDisabled();
        }
        if (ImGui::Checkbox("Auto jitter##GlobalAutoJitter", &auto_jitter_default)) {
            client.set_opus_auto_jitter_default(auto_jitter_default);
        }
        if (!jitter_enabled) {
            ImGui::EndDisabled();
        }
        JamGui::ShowTooltipOnHover("Use auto jitter as the default for participants without custom settings");

        ImGui::Spacing();
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        ImGui::Text("Queue limit:");
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        int queue_limit_packets = static_cast<int>(client.get_opus_queue_limit_packets());
        if (!jitter_enabled) {
            ImGui::BeginDisabled();
        }
        ImGui::PushItemWidth(width - PADDING);
        if (ImGui::InputInt("##OpusQueueLimitPackets", &queue_limit_packets, 1, 4)) {
            client.set_opus_queue_limit_packets(
                static_cast<size_t>(std::max(queue_limit_packets, 0)));
        }
        ImGui::PopItemWidth();
        if (!jitter_enabled) {
            ImGui::EndDisabled();
        }
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        ImGui::Text("%zu pkt max", client.get_opus_queue_limit_packets());

        ImGui::Spacing();
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        ImGui::Text("Age limit:");
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        int age_limit_ms = client.get_jitter_packet_age_limit_ms();
        if (!jitter_enabled) {
            ImGui::BeginDisabled();
        }
        ImGui::PushItemWidth(width - PADDING);
        if (ImGui::InputInt("##JitterPacketAgeLimitMs", &age_limit_ms, 5, 20)) {
            client.set_jitter_packet_age_limit_ms(age_limit_ms);
        }
        ImGui::PopItemWidth();
        if (!jitter_enabled) {
            ImGui::EndDisabled();
        }
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        ImGui::Text("%d ms max", client.get_jitter_packet_age_limit_ms());

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // ========== METRONOME SECTION ==========
        Client::MetronomeState metronome = client.get_metronome_state();
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        ImGui::Text("Metronome:");
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (PADDING / 2.0F));
        static float metronome_draft_bpm = 120.0F;
        static bool metronome_bpm_editing = false;
        static bool metronome_bpm_dirty = false;
        static auto metronome_bpm_last_edit = std::chrono::steady_clock::now();
        constexpr auto METRONOME_BPM_DEBOUNCE = std::chrono::milliseconds(350);
        if (!metronome_bpm_editing && !metronome_bpm_dirty) {
            metronome_draft_bpm = metronome.bpm;
        }
        ImGui::PushItemWidth(width);
        if (ImGui::InputFloat("##MetronomeBpm", &metronome_draft_bpm, 1.0F, 5.0F, "%.1f BPM")) {
            metronome_draft_bpm = std::clamp(metronome_draft_bpm, 30.0F, 240.0F);
            metronome_bpm_dirty = true;
            metronome_bpm_last_edit = std::chrono::steady_clock::now();
        }
        metronome_bpm_editing = ImGui::IsItemActive();
        ImGui::PopItemWidth();
        if (metronome_bpm_dirty && !metronome_bpm_editing &&
            std::chrono::steady_clock::now() - metronome_bpm_last_edit >=
                METRONOME_BPM_DEBOUNCE) {
            client.commit_metronome_bpm(metronome_draft_bpm);
            metronome_bpm_dirty = false;
        }

        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (PADDING / 2.0F));
        if (ImGui::Button(metronome.running ? "Stop##Metronome" : "Start##Metronome",
                          ImVec2((width - style.ItemSpacing.x) * 0.5F, 0))) {
            if (metronome.running) {
                client.stop_metronome();
            } else {
                client.start_metronome();
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Tap##Metronome", ImVec2((width - style.ItemSpacing.x) * 0.5F, 0))) {
            client.tap_metronome_tempo();
        }
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        ImGui::Text("Beat: %u", metronome.beat_number);
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        ImGui::Text("Sync: %llu/%llu",
                    static_cast<unsigned long long>(metronome.sync_sent),
                    static_cast<unsigned long long>(metronome.sync_received));
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        ImGui::Text("Clock sync: %s", metronome.clock_ready ? "Locked" : "Syncing");
        char clock_tooltip[160];
        std::snprintf(clock_tooltip, sizeof(clock_tooltip),
                      "Raw monotonic-clock offset: %.2f ms. Large values are normal across machines.",
                      metronome.clock_offset_ms);
        JamGui::ShowTooltipOnHover(clock_tooltip);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // ========== RECORDING SECTION ==========
        Client::RecordingState recording = client.get_recording_state();
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        ImGui::Text("Recording:");
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (PADDING / 2.0F));
        if (recording.active) {
            if (ImGui::Button("Stop Recording", ImVec2(width, 0))) {
                client.stop_recording();
            }
        } else if (ImGui::Button("Start Recording", ImVec2(width, 0))) {
            client.start_recording();
        }
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        ImGui::Text("%s", recording.active ? "REC" : "Idle");
        if (!recording.folder.empty()) {
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            ImGui::TextWrapped("%s", recording.folder.c_str());
        }
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        ImGui::Text("Queued: %zu", recording.queued_blocks);
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        ImGui::Text("Dropped: %llu",
                    static_cast<unsigned long long>(recording.dropped_blocks));

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
struct ParticipantQualityStatus {
    const char* label;
    const char* reason;
    const char* action;
    ImVec4 color;
};

static ParticipantQualityStatus participant_quality_status(const ParticipantInfo& p) {
    if (!p.buffer_ready) {
        return {"Recovering", "waiting for playout buffer",
                "wait; reconnect if it stays here",
                ImVec4(1.0F, 0.8F, 0.2F, 1.0F)};
    }

    if (p.opus_queue_limit_drops > 0 || p.opus_decode_buffer_overflow_drops > 0) {
        return {"Poor", "queue overflow/drop",
                "raise queue limit or reduce network burstiness",
                ImVec4(1.0F, 0.35F, 0.25F, 1.0F)};
    }

    if (p.jitter_age_drops > 0 || p.opus_age_limit_drops > 0) {
        return {"Jittery", "packet age limit",
                "raise age limit for testing; prefer Ethernet",
                ImVec4(1.0F, 0.65F, 0.25F, 1.0F)};
    }

    if (p.underrun_count > 0 || p.plc_count > 0) {
        return {"Jittery", "underrun/PLC",
                "raise jitter target or enable auto",
                ImVec4(1.0F, 0.65F, 0.25F, 1.0F)};
    }

    if (p.sequence_gaps > 0 || p.sequence_late_or_reordered > 0) {
        return {"Jittery", "packet gap/reorder",
                "use Ethernet or raise jitter target",
                ImVec4(1.0F, 0.65F, 0.25F, 1.0F)};
    }

    if (p.receiver_drift_ppm_abs_max > 100.0) {
        return {"Jittery", "clock drift",
                "record long-session drift data",
                ImVec4(1.0F, 0.65F, 0.25F, 1.0F)};
    }

    return {"Stable", "within current target",
            "no change",
            ImVec4(0.35F, 0.85F, 0.45F, 1.0F)};
}

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
            const auto quality = participant_quality_status(p);
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            ImGui::TextColored(quality.color, "Quality: %s", quality.label);
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            ImGui::Text("Reason: %s", quality.reason);
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            ImGui::TextWrapped("Action: %s", quality.action);
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            ImGui::Text("Queue: %zu", p.queue_size);
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            ImGui::Text("Q avg/max: %zu/%zu", p.queue_size_avg, p.queue_size_max);
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            ImGui::Text("Q drift: %.2f", p.queue_drift_packets);
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            ImGui::Text("Jitter target:%s",
                        p.opus_jitter_auto_enabled
                            ? " auto"
                            : (p.opus_jitter_manual_override ? " custom" : " default"));
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            bool auto_jitter = p.opus_jitter_auto_enabled;
            if (ImGui::Checkbox("Auto##ParticipantJitterAuto", &auto_jitter)) {
                client.set_participant_opus_auto_jitter(p.id, auto_jitter);
            }
            JamGui::ShowTooltipOnHover("Automatically raise this participant's jitter on instability");
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            int participant_jitter = static_cast<int>(p.jitter_buffer_min_packets);
            ImGui::PushItemWidth(width - 42.0F);
            if (ImGui::InputInt("##ParticipantJitterPackets", &participant_jitter, 1, 1)) {
                client.set_participant_opus_jitter_buffer_packets(
                    p.id, static_cast<size_t>(std::max(participant_jitter, 0)));
            }
            ImGui::PopItemWidth();
            ImGui::SameLine();
            if (ImGui::Button("D##ParticipantJitterDefault")) {
                client.reset_participant_opus_jitter_buffer_packets(p.id);
            }
            JamGui::ShowTooltipOnHover("Use global default jitter for this participant");
            const double packet_ms =
                p.last_packet_frame_count > 0
                    ? (static_cast<double>(p.last_packet_frame_count) * 1000.0 / 48000.0)
                    : 0.0;
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            ImGui::Text("%zu pkt, %.1f ms", p.jitter_buffer_min_packets,
                        static_cast<double>(p.jitter_buffer_min_packets) * packet_ms);
            if (p.opus_jitter_auto_enabled ||
                p.opus_jitter_auto_increases > 0 ||
                p.opus_jitter_auto_decreases > 0) {
                ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
                ImGui::Text("Auto inc/dec: %llu/%llu",
                            static_cast<unsigned long long>(p.opus_jitter_auto_increases),
                            static_cast<unsigned long long>(p.opus_jitter_auto_decreases));
            }
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            ImGui::Text("Queue limit: %zu pkt", p.opus_queue_limit_packets);
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            ImGui::Text("Frames pkt/cb: %zu/%zu", p.last_packet_frame_count,
                        p.last_callback_frame_count);
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            ImGui::Text("Decoded: %zu frames", p.opus_pcm_buffered_frames);
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            ImGui::Text("Dec pkts: %llu",
                        static_cast<unsigned long long>(
                            p.opus_packets_decoded_in_callback));
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            ImGui::Text("Age: %.1f ms", p.packet_age_avg_ms);
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            ImGui::Text("Max age: %.1f ms", p.packet_age_max_ms);
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            ImGui::Text("Drift ppm: %.1f avg", p.receiver_drift_ppm_avg);
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
                ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
                ImGui::TextColored(
                    ImVec4(1.0F, 0.6F, 0.2F, 1.0F), "Why: %llu/%llu/%llu/%llu",
                    static_cast<unsigned long long>(p.opus_queue_limit_drops),
                    static_cast<unsigned long long>(p.opus_age_limit_drops),
                    static_cast<unsigned long long>(p.opus_decode_buffer_overflow_drops),
                    static_cast<unsigned long long>(p.opus_target_trim_drops));
            } else if (p.opus_target_trim_drops > 0) {
                ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
                ImGui::TextColored(ImVec4(1.0F, 0.6F, 0.2F, 1.0F), "Target trim: %llu",
                                   static_cast<unsigned long long>(
                                       p.opus_target_trim_drops));
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

            // Room
            ImGui::Text("Room: %s", client.get_room_id().c_str());

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
    std::optional<int> startup_jitter_packets;
    std::optional<int> startup_queue_limit_packets;
    std::optional<int> startup_age_limit_ms;
    bool startup_auto_jitter = false;
    bool startup_disable_auto_jitter = false;
    bool list_audio_devices = false;
    bool audio_open_smoke = false;
    bool low_latency_check = false;
    bool startup_config_smoke = false;
    std::optional<AudioCodec> startup_codec;
    std::string required_audio_api;
    std::string log_file_path;
    std::optional<int> broadcast_ipc_port;
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
        } else if ((arg == "--jitter" || arg == "--opus-jitter") && i + 1 < argc) {
            options.startup_jitter_packets = std::stoi(argv[++i]);
        } else if ((arg == "--queue-limit" || arg == "--opus-queue-limit") && i + 1 < argc) {
            options.startup_queue_limit_packets = std::stoi(argv[++i]);
        } else if ((arg == "--age-limit-ms" || arg == "--jitter-age-limit-ms") &&
                   i + 1 < argc) {
            options.startup_age_limit_ms = std::stoi(argv[++i]);
        } else if (arg == "--auto-jitter") {
            options.startup_auto_jitter = true;
        } else if (arg == "--no-auto-jitter") {
            options.startup_disable_auto_jitter = true;
        } else if (arg == "--list-audio-devices" || arg == "--audio-devices") {
            options.list_audio_devices = true;
        } else if (arg == "--audio-open-smoke") {
            options.audio_open_smoke = true;
        } else if (arg == "--startup-config-smoke" || arg == "--config-smoke") {
            options.startup_config_smoke = true;
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
        } else if (arg == "--log-file" && i + 1 < argc) {
            options.log_file_path = argv[++i];
        } else if (arg == "--broadcast-ipc-port" && i + 1 < argc) {
            options.broadcast_ipc_port = std::stoi(argv[++i]);
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
        auto startup_options = parse_startup_options(argc, argv);
        auto& log = Logger::instance();
        log.init(true, true, !startup_options.log_file_path.empty(),
                 startup_options.log_file_path, spdlog::level::info);
        if (!startup_options.log_file_path.empty()) {
            Log::info("Logging to {}", startup_options.log_file_path);
        }
        Log::info("Runtime: role=client platform={} arch={}", runtime_platform_name(),
                  runtime_arch_name());

        if (startup_options.list_audio_devices) {
            print_audio_backend_inventory();
            log.flush();
            return 0;
        }
        if (startup_options.low_latency_check) {
            const int result = run_low_latency_backend_check(startup_options);
            log.flush();
            return result;
        }
        if (!startup_options.required_audio_api.empty() &&
            !required_api_has_duplex_devices(startup_options.required_audio_api)) {
            Log::error("Required audio API '{}' does not have both input and output devices",
                       startup_options.required_audio_api);
            print_audio_backend_inventory();
            log.flush();
            return 2;
        }
        if (startup_options.audio_open_smoke) {
            const int result = run_audio_open_smoke(startup_options);
            log.flush();
            return result;
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
        if (startup_options.startup_jitter_packets.has_value()) {
            client_instance.set_opus_jitter_buffer_packets(
                static_cast<size_t>(std::max(*startup_options.startup_jitter_packets, 0)));
            Log::info("Startup Opus jitter override: {} packets",
                      *startup_options.startup_jitter_packets);
        }
        if (startup_options.startup_queue_limit_packets.has_value()) {
            client_instance.set_opus_queue_limit_packets(
                static_cast<size_t>(std::max(*startup_options.startup_queue_limit_packets, 0)));
            Log::info("Startup Opus queue limit override: {} packets",
                      *startup_options.startup_queue_limit_packets);
        }
        if (startup_options.startup_age_limit_ms.has_value()) {
            client_instance.set_jitter_packet_age_limit_ms(*startup_options.startup_age_limit_ms);
            Log::info("Startup packet age limit override: {} ms",
                      *startup_options.startup_age_limit_ms);
        }
        if (startup_options.startup_disable_auto_jitter) {
            client_instance.set_opus_auto_jitter_default(false);
            Log::info("Startup Opus auto jitter default disabled");
        } else if (startup_options.startup_auto_jitter) {
            client_instance.set_opus_auto_jitter_default(true);
            Log::info("Startup Opus auto jitter default enabled");
        }
        if (startup_options.startup_config_smoke) {
            Log::info(
                "Startup config smoke: codec={} frames={} jitter={} queue_limit={} "
                "age_limit_ms={} auto_jitter={} broadcast_ipc_port={}",
                client_instance.get_audio_codec() == AudioCodec::Opus ? "opus" : "pcm",
                client_instance.get_audio_config().frames_per_buffer,
                client_instance.get_opus_jitter_buffer_packets(),
                client_instance.get_opus_queue_limit_packets(),
                client_instance.get_jitter_packet_age_limit_ms(),
                client_instance.get_opus_auto_jitter_default() ? "true" : "false",
                startup_options.broadcast_ipc_port.has_value()
                    ? std::to_string(*startup_options.broadcast_ipc_port)
                    : "disabled");
            client_instance.stop_connection();
            log.flush();
            return 0;
        }
        if (startup_options.broadcast_ipc_port.has_value()) {
            const int port = *startup_options.broadcast_ipc_port;
            if (port <= 0 || port > 65535) {
                Log::error("Invalid broadcast IPC port: {}", port);
                log.flush();
                return 2;
            }
            client_instance.enable_broadcast_ipc(static_cast<uint16_t>(port));
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
        client_instance.disable_broadcast_ipc();
        client_instance.stop_audio_stream();
        client_instance.stop_connection();

        // Stop io_context and wait for network thread to finish
        io_context.stop();
        if (io_thread.joinable()) {
            io_thread.join();
        }
        log.flush();
    } catch (std::exception& e) {
        Log::error("ERR: {}", e.what());
        Logger::instance().flush();
    }
}
