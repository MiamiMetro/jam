#include <algorithm>
#include <array>
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
#include <unordered_map>
#include <vector>

#include <asio.hpp>
#include <asio/buffer.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <concurrentqueue.h>
#include <opus.h>
#include <portaudio.h>
#include <spdlog/common.h>

#include "audio_stream.h"
#include "logger.h"
#include "opus_decoder.h"
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

        // Check audio stream initialization - fail gracefully if it fails
        if (!start_audio_stream(17, 15, config)) {
            Log::error("Failed to initialize audio stream - client will not function correctly");
            // Continue anyway, but audio_config_ will be zero-initialized
            // This prevents crashes but the client won't work properly
        }
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

        // Cancel pending async operations
        socket_.cancel();

        Log::info("Disconnected (no longer sending/receiving)");
    }

    bool start_audio_stream(PaDeviceIndex input_device, PaDeviceIndex output_device,
                            const AudioStream::AudioConfig& config = AudioStream::AudioConfig{}) {
        Log::info("Starting audio stream...");
        bool success =
            audio_.start_audio_stream(input_device, output_device, config, audio_callback, this);
        if (success) {
            audio_.print_latency_info();
            audio_config_ = config;  // Store config for decoder initialization

            // Initialize Opus encoder for sending own audio
            if (!audio_encoder_.create(config.sample_rate, audio_.get_input_channel_count(),
                                       OPUS_APPLICATION_VOIP, config.bitrate, config.complexity)) {
                Log::error("Failed to create Opus encoder");
                return false;
            }
        }
        return success;
    }

    void stop_audio_stream() {
        audio_.stop_audio_stream();
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
            //  do nothing
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
            ParticipantAudio new_participant;
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
            participant_audio_[sender_id] = std::move(new_participant);
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
            int frame_size = audio_config_.frames_per_buffer;
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
                    Log::info("Participant {} started speaking (level: {:.4f})", participant_id,
                              rms);
                } else if (!participant.is_speaking && was_speaking) {
                    // Just stopped speaking
                    Log::info("Participant {} stopped speaking", participant_id);
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

    // Per-participant audio buffers
    struct ParticipantAudio {
        moodycamel::ConcurrentQueue<std::vector<float>> audio_queue;
        std::unique_ptr<OpusDecoderWrapper>             decoder;
        bool                                            is_muted = false;
        float                                           gain     = 1.0F;
        std::chrono::steady_clock::time_point           last_packet_time;
        size_t                                          jitter_buffer_min_packets = 2;
        bool                                            buffer_ready              = false;
        int   underrun_count = 0;      // Track underruns per participant
        float current_level  = 0.0F;   // RMS audio level
        bool  is_speaking    = false;  // Voice activity detection
    };

    // Thread-safe access to participant_audio_ map
    std::mutex                                     participant_audio_mutex_;
    std::unordered_map<uint32_t, ParticipantAudio> participant_audio_;

    PeriodicTimer ping_timer_;
    PeriodicTimer alive_timer_;
};

int main() {
    try {
        auto& log = Logger::instance();
        log.init(true, true, false, "", spdlog::level::info);

        asio::io_context io_context;

        Client client_instance(io_context, "127.0.0.1", 9999);

        io_context.run();
    } catch (std::exception& e) {
        Log::error("ERR: {}", e.what());
    }
}