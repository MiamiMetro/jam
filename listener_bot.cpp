#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <memory>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include <asio.hpp>
#include <asio/buffer.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <concurrentqueue.h>
#include <spdlog/common.h>

#include "audio_analysis.h"
#include "broadcast_hls.h"
#include "logger.h"
#include "message_validator.h"
#include "opus_decoder.h"
#include "packet_builder.h"
#include "participant_info.h"
#include "participant_manager.h"
#include "periodic_timer.h"
#include "protocol.h"

using asio::ip::udp;
using namespace std::chrono_literals;

// ListenerBot: A headless bot that receives audio, mixes it, and broadcasts to HLS
// No PortAudio, no ImGui, no encoding - just receive, decode, mix, broadcast
class ListenerBot {
public:
    ListenerBot(asio::io_context& io_context, const std::string& server_address, short server_port)
        : io_context_(io_context),
          socket_(io_context, udp::endpoint(udp::v4(), 0)),
          audio_config_{48000, 240},  // 48kHz, 240 frames = 5ms
          running_(true),
          ping_timer_(io_context, 500ms, [this]() { ping_timer_callback(); }),
          alive_timer_(io_context, 5s, [this]() { alive_timer_callback(); }),
          cleanup_timer_(io_context, 10s, [this]() { cleanup_timer_callback(); }) {
        Log::info("ListenerBot local port: {}", socket_.local_endpoint().port());

        // Connect to server
        start_connection(server_address, server_port);
    }

    ~ListenerBot() {
        stop();
    }

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

    void stop_connection() {
        Log::info("Disconnecting from server...");

        // Send LEAVE message synchronously (to ensure it's sent before shutdown)
        CtrlHdr chdr{};
        chdr.magic = CTRL_MAGIC;
        chdr.type  = CtrlHdr::Cmd::LEAVE;
        std::memcpy(ctrl_tx_buf_.data(), &chdr, sizeof(CtrlHdr));

        // Use blocking send for shutdown to ensure packet is sent
        std::error_code ec;
        socket_.send_to(asio::buffer(ctrl_tx_buf_.data(), sizeof(CtrlHdr)), server_endpoint_, 0,
                        ec);
        if (ec) {
            Log::warn("Failed to send LEAVE: {}", ec.message());
        }

        // Cancel pending async operations
        socket_.cancel();

        Log::info("Disconnected (no longer sending/receiving)");
    }

    // Start HLS broadcasting
    bool start_hls_broadcast(const HLSBroadcaster::Config& config = HLSBroadcaster::Config{}) {
        return hls_broadcaster_.start(config);
    }

    void stop_hls_broadcast() {
        hls_broadcaster_.stop();
    }

    bool is_hls_broadcasting() const {
        return hls_broadcaster_.is_running();
    }

    // Start the mix thread and writer thread (time-driven, not device-driven)
    void start_mixing() {
        if (mix_thread_.joinable()) {
            Log::warn("Mix thread already running");
            return;
        }

        Log::info("Starting mix thread ({}Hz, {} frames = {:.1f}ms per frame)",
                  audio_config_.sample_rate, audio_config_.frames_per_buffer,
                  (audio_config_.frames_per_buffer * 1000.0) / audio_config_.sample_rate);

        mix_thread_    = std::thread([this]() { mix_thread_loop(); });
        writer_thread_ = std::thread([this]() { writer_thread_loop(); });
    }

    // Stop the bot (stops mixing, broadcasting, connection)
    void stop() {
        if (!running_.load()) {
            return;
        }

        Log::info("Stopping ListenerBot...");
        running_.store(false);

        // Stop mix thread
        if (mix_thread_.joinable()) {
            mix_thread_.join();
        }

        // Stop writer thread (will drain remaining PCM frames)
        if (writer_thread_.joinable()) {
            writer_thread_.join();
        }

        // Stop HLS broadcasting
        stop_hls_broadcast();

        // Stop connection (synchronous LEAVE send)
        stop_connection();
    }

    void on_receive(std::error_code error_code, std::size_t bytes) {
        if (error_code) {
            do_receive();  // keep listening
            return;
        }

        // Optional: verify packet is from server (can be disabled for flexibility)
        if (remote_endpoint_ != server_endpoint_) {
            Log::warn("Received packet from unexpected endpoint: {}:{}, expected {}:{}",
                      remote_endpoint_.address().to_string(), remote_endpoint_.port(),
                      server_endpoint_.address().to_string(), server_endpoint_.port());
            // Continue processing anyway (some setups may use different ports)
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
        socket_.async_receive_from(asio::buffer(recv_buf_), remote_endpoint_,
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
    // Time-driven mix thread loop (replaces PortAudio callback)
    void mix_thread_loop() {
        const size_t frame_count = audio_config_.frames_per_buffer;
        const size_t channels    = 1;  // Mono output for HLS

        // Frame duration: 240 frames @ 48kHz = 5ms
        const auto frame_duration =
            std::chrono::microseconds((frame_count * 1'000'000) / audio_config_.sample_rate);

        // Pre-allocated output buffer (mono)
        std::vector<float> mixed_buffer(frame_count * channels, 0.0F);

        Log::info("Mix thread started (frame_duration={}us, {} frames)", frame_duration.count(),
                  frame_count);

        auto next_tick = std::chrono::steady_clock::now();

        while (running_.load()) {
            auto start = std::chrono::steady_clock::now();

            // Mix one frame
            mix_one_frame(mixed_buffer.data(), frame_count, channels);

            // Push to PCM queue (decoupled from FFmpeg write)
            // Use fixed-size array to avoid allocations
            std::array<float, 240> pcm_frame;
            std::memcpy(pcm_frame.data(), mixed_buffer.data(),
                        frame_count * channels * sizeof(float));

            // Non-blocking enqueue (drop if queue is full to prevent blocking)
            if (!pcm_queue_.enqueue(pcm_frame)) {
                static int drop_count = 0;
                if (++drop_count % 200 == 0) {
                    Log::warn("PCM queue full, dropping frames ({} drops)", drop_count);
                }
            }

            // Calculate next tick time (real-time discipline)
            next_tick += frame_duration;

            // Resync if we're too far behind (prevents drift accumulation)
            auto now = std::chrono::steady_clock::now();
            if (now > next_tick + 5 * frame_duration) {
                Log::warn("Mix thread too far behind, resyncing timing");
                next_tick = now;
            }

            // Sleep until next tick (don't drift)
            std::this_thread::sleep_until(next_tick);

            // Log if we're falling behind (warn if mix takes too long)
            auto elapsed = now - start;
            if (elapsed > frame_duration) {
                static int behind_count = 0;
                if (++behind_count % 200 == 0) {  // Log every 200 frames (1 second)
                    auto behind_us = std::chrono::duration_cast<std::chrono::microseconds>(
                                         elapsed - frame_duration)
                                         .count();
                    Log::warn(
                        "Mix thread falling behind by {}us (frame took {}us, target {}us)",
                        behind_us,
                        std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count(),
                        frame_duration.count());
                }
            }
        }

        Log::info("Mix thread stopped");
    }

    // Writer thread loop: pops PCM frames and writes to FFmpeg (decoupled from mixing)
    void writer_thread_loop() {
        const size_t frame_count = audio_config_.frames_per_buffer;
        Log::info("Writer thread started");

        while (running_.load() || pcm_queue_.size_approx() > 0) {
            std::array<float, 240> pcm_frame;

            // Try to dequeue a PCM frame (with timeout to allow shutdown check)
            if (pcm_queue_.try_dequeue(pcm_frame)) {
                // Write to HLS if broadcasting (this can block, but it's OK in separate thread)
                if (hls_broadcaster_.is_running()) {
                    hls_broadcaster_.write_audio(pcm_frame.data(), frame_count);
                }
            } else {
                // No data available, sleep briefly to avoid spinning
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }

        Log::info("Writer thread stopped");
    }

    // Mix one frame of audio (extracted from audio_callback logic)
    void mix_one_frame(float* output, size_t frame_count, size_t out_channels) {
        // Initialize output buffer to silence
        std::memset(output, 0, frame_count * out_channels * sizeof(float));

        // Mix audio from all active participants
        int active_count = 0;
        participant_manager_.for_each([&](uint32_t participant_id, ParticipantData& participant) {
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
                    audio_analysis::mix_with_gain(output, participant.pcm_buffer.data(),
                                                  decoded_samples, participant.gain);
                    active_count++;
                } else if (static_cast<size_t>(decoded_samples) == frame_count) {
                    // Mono input, mono/stereo output - duplicate channel if needed
                    if (out_channels == 1) {
                        audio_analysis::mix_with_gain(output, participant.pcm_buffer.data(),
                                                      frame_count, participant.gain);
                    } else {
                        audio_analysis::mix_mono_to_stereo(output, participant.pcm_buffer.data(),
                                                           frame_count, out_channels,
                                                           participant.gain);
                    }
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
                    // Log underrun with queue size info
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
            constexpr float HEADROOM = 0.5F;  // Headroom for broadcast
            float           gain     = HEADROOM / static_cast<float>(active_count);

            for (size_t i = 0; i < frame_count * out_channels; ++i) {
                output[i] *= gain;

                // Soft clip (safety limiter)
                output[i] = std::min(output[i], 1.0F);
                output[i] = std::max(output[i], -1.0F);
            }
        }
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
                // Other CTRL messages (JOIN, LEAVE, ALIVE) are not handled by bots
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
        // Bots don't need RTT tracking, but we still handle ping messages for protocol compliance
        // (No-op for bots)
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

            // Bots use mono (1 channel) for decoding
            if (!participant_manager_.register_participant(sender_id, audio_config_.sample_rate,
                                                           1)) {
                return;
            }
        }

        // Get opus data pointer
        const unsigned char* audio_data = reinterpret_cast<const unsigned char*>(
            recv_buf_.data() + sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t));

        // CRITICAL: Enqueue Opus packet, DON'T decode here
        // Decoding happens in time-driven mix thread
        participant_manager_.with_participant(sender_id, [&](ParticipantData& participant) {
            OpusPacket packet;
            // Use memcpy for zero-allocation copy (fixed buffer)
            if (encoded_bytes <= AUDIO_BUF_SIZE) {
                std::memcpy(packet.data.data(), audio_data, encoded_bytes);
                packet.size      = encoded_bytes;  // implicit conversion
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

    struct AudioConfig {
        int sample_rate;
        int frames_per_buffer;
    };

    asio::io_context& io_context_;
    udp::socket       socket_;
    udp::endpoint     server_endpoint_;
    udp::endpoint     remote_endpoint_;  // Actual sender endpoint (for receive)

    std::array<char, 1024>         recv_buf_;
    std::array<unsigned char, 128> sync_tx_buf_;
    std::array<unsigned char, 128> ctrl_tx_buf_;

    AudioConfig audio_config_;  // Store config for decoder initialization

    ParticipantManager participant_manager_;

    // HLS Broadcaster
    HLSBroadcaster hls_broadcaster_;

    // PCM queue (decouples mix thread from FFmpeg writes)
    moodycamel::ConcurrentQueue<std::array<float, 240>> pcm_queue_;

    // Mix thread (replaces PortAudio callback)
    std::thread       mix_thread_;
    std::thread       writer_thread_;  // FFmpeg writer thread
    std::atomic<bool> running_;

    PeriodicTimer ping_timer_;
    PeriodicTimer alive_timer_;
    PeriodicTimer cleanup_timer_;
};

int main(int argc, char* argv[]) {
    try {
        auto& log = Logger::instance();
        log.init(true, true, false, "", spdlog::level::info);

        // Parse command line arguments (optional)
        std::string server_address = "127.0.0.1";
        short       server_port    = 9999;
        std::string hls_output     = "hls";
        std::string hls_name       = "stream";

        if (argc >= 3) {
            server_address = argv[1];
            server_port    = static_cast<short>(std::atoi(argv[2]));
        }
        if (argc >= 4) {
            hls_output = argv[3];
        }
        if (argc >= 5) {
            hls_name = argv[4];
        }

        Log::info("ListenerBot starting...");
        Log::info("Server: {}:{}", server_address, server_port);

        asio::io_context io_context;

        // Work guard to prevent io_context from exiting when there's no work
        auto work = asio::make_work_guard(io_context);

        ListenerBot bot(io_context, server_address, server_port);

        // Start HLS broadcasting with CPU-optimized settings
        HLSBroadcaster::Config hls_config;
        hls_config.sample_rate   = 48000;
        hls_config.channels      = 1;      // Mono (reduces AAC CPU by ~40-50%)
        hls_config.bitrate       = 80000;  // 80 kbps AAC (balanced CPU/quality for mono)
        hls_config.output_path   = hls_output;
        hls_config.playlist_name = hls_name;
        hls_config.segment_duration =
            0.5F;  // 500ms segments (0.75s saves ~5-10% CPU if latency allows)
        hls_config.playlist_size = 6;
        hls_config.verbose       = true;  // Enable to see FFmpeg errors
        hls_config.low_latency   = true;  // Enable low-latency mode (fMP4)

        if (bot.start_hls_broadcast(hls_config)) {
            Log::info("HLS broadcasting started: {}/{}.m3u8", hls_output, hls_name);
        } else {
            Log::error("Failed to start HLS broadcasting");
        }

        // Start mix thread (time-driven, replaces PortAudio)
        bot.start_mixing();

        // Run network I/O in separate thread
        std::thread net_thread([&]() {
            Log::info("Network I/O thread started");
            io_context.run();
            Log::info("Network I/O thread stopped");
        });

        // Wait for network thread (blocks until io_context stops)
        // To stop: send SIGINT/Ctrl+C, which should trigger cleanup
        Log::info("ListenerBot running... (press Ctrl+C to stop)");

        // For now, wait on network thread (in real deployment, use signal handling)
        net_thread.join();

        // Cleanup: allow io_context to exit and stop bot
        work.reset();       // Release work guard (io_context may have already stopped)
        io_context.stop();  // Ensure it's stopped
        bot.stop();         // Stop threads gracefully

        Log::info("ListenerBot stopped");
    } catch (std::exception& e) {
        Log::error("ERR: {}", e.what());
        return 1;
    }

    return 0;
}