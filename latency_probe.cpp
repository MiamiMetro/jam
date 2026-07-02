#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <asio.hpp>
#include <asio/buffer.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <opus.h>

#include "audio_packet.h"
#include "message_validator.h"
#include "opus_decoder.h"
#include "opus_encoder.h"
#include "packet_builder.h"
#include "participant_info.h"
#include "performer_join_token.h"
#include "protocol.h"
#include "udp_port.h"

using asio::ip::udp;
using clock_type = std::chrono::steady_clock;
using namespace std::chrono_literals;

namespace {

constexpr int   SAMPLE_RATE = 48000;
constexpr int   CHANNELS = 1;
constexpr int   BITRATE = 96000;
constexpr int   COMPLEXITY = 5;
constexpr int   TOTAL_PACKETS = 220;
constexpr int   IMPULSE_PACKET = 20;
constexpr int   CLICK_SAMPLES = 32;
constexpr float CLICK_AMPLITUDE = 0.8F;
constexpr float DETECTION_THRESHOLD = 0.05F;
constexpr int   MAX_FRAME_SAMPLES = 960;
constexpr size_t PROBE_RECV_BUF_SIZE = 2048;
constexpr uint8_t PROBE_CODEC_OPUS = 0;
constexpr uint8_t PROBE_CODEC_PCM_INT16 = 1;

enum class ProbeCodec {
    Opus,
    PcmInt16,
};

void configure_probe_socket(udp::socket& socket) {
    std::error_code ec;
    socket.set_option(asio::socket_base::receive_buffer_size(UDP_SOCKET_BUFFER_BYTES), ec);
    socket.set_option(asio::socket_base::send_buffer_size(UDP_SOCKET_BUFFER_BYTES), ec);
}

struct ProbeConfig {
    int frame_size = 240;
    int jitter_min_packets = 3;
    int total_packets = TOTAL_PACKETS;
    ProbeCodec codec = ProbeCodec::Opus;
};

struct Args {
    std::string host = "127.0.0.1";
    uint16_t port = 9999;
    std::string server_id = "local-dev";
    std::string join_secret;
    int64_t join_token_ttl_ms = 120000;
    std::string room = "latency-probe";
    std::string sender_user = "latency-probe-sender";
    std::string receiver_user = "latency-probe-receiver";
    std::string sender_join_token;
    std::string receiver_join_token;
    bool require_clean = false;
    int max_allowed_gap_plc_run = -1;
    int min_decoder_resets = 0;
    bool sweep = false;
    int invalid_flood_packets = 0;
    int invalid_flood_interval_us = 0;
    int duration_seconds = 0;
    double playout_ppm = 0.0;
    bool v3_receive_smoke = false;
    ProbeConfig config;
};

struct ProbeMetrics {
    int sent_packets = 0;
    int encode_failures = 0;
    int raw_audio_packets = 0;
    int redundant_audio_packets = 0;
    int v2_audio_packets = 0;
    int receiver_queue_drops = 0;
    int invalid_audio_packets = 0;
    int received_packets = 0;
    int decoded_packets = 0;
    int plc_frames = 0;
    int gap_plc_frames = 0;
    int empty_plc_frames = 0;
    int max_gap_plc_run = 0;
    int decoder_resets = 0;
    int underruns = 0;
    int gap_waits = 0;
    int sequence_gaps = 0;
    int sequence_gap_recoveries = 0;
    int sequence_late_or_duplicate = 0;
    int sequence_unresolved_gaps = 0;
    int decode_failures = 0;
    int decoded_size_mismatches = 0;
    int non_finite_samples = 0;
    int out_of_range_samples = 0;
    int repeated_blocks = 0;
    int queue_depth_observations = 0;
    long long queue_depth_sum = 0;
    int min_queue_depth_after_ready = std::numeric_limits<int>::max();
    int max_queue_depth = 0;
    int final_queue_depth = 0;
    float max_discontinuity = 0.0F;
    int detected_output_sample = -1;
};

struct ProbeResult {
    ProbeConfig config;
    ProbeMetrics metrics;
    int latency_samples = -1;
    double latency_ms = -1.0;
};

class ProbeReceiver {
public:
    ProbeReceiver(asio::io_context& io_context, const udp::endpoint& server_endpoint,
                  const std::string& room, const std::string& user,
                  const std::string& join_token)
        : socket_(io_context, udp::endpoint(udp::v4(), 0)), server_endpoint_(server_endpoint),
          room_(room), user_(user), join_token_(join_token) {
        configure_probe_socket(socket_);
    }

    void start() {
        do_receive();
    }

    bool handle_test_packet(const std::vector<unsigned char>& packet) {
        if (packet.size() > recv_buf_.size()) {
            return false;
        }
        std::memcpy(recv_buf_.data(), packet.data(), packet.size());
        handle_receive(packet.size());
        return true;
    }

    void send_join() {
        send_join_packet(room_, user_);
    }

    void send_alive() {
        send_ctrl(CtrlHdr::Cmd::ALIVE);
    }

    void send_leave() {
        send_ctrl(CtrlHdr::Cmd::LEAVE);
    }

    ParticipantOpusDequeueStatus pop_packet(OpusPacket& packet, size_t gap_wait_packets) {
        return queue_.dequeue(packet, gap_wait_packets);
    }

    size_t queue_size() const {
        return queue_.size_approx();
    }

    int received_count() const {
        return received_count_.load(std::memory_order_relaxed);
    }

    int raw_audio_count() const {
        return raw_audio_count_.load(std::memory_order_relaxed);
    }

    int redundant_audio_count() const {
        return redundant_audio_count_.load(std::memory_order_relaxed);
    }

    int v2_audio_count() const {
        return v2_audio_count_.load(std::memory_order_relaxed);
    }

    int queue_drop_count() const {
        return queue_drop_count_.load(std::memory_order_relaxed);
    }

    int invalid_audio_count() const {
        return invalid_audio_count_.load(std::memory_order_relaxed);
    }

    int sequence_gap_count() const {
        return sequence_gap_count_.load(std::memory_order_relaxed);
    }

    int sequence_gap_recovery_count() const {
        return sequence_gap_recovery_count_.load(std::memory_order_relaxed);
    }

    int sequence_late_or_duplicate_count() const {
        return sequence_late_or_duplicate_count_.load(std::memory_order_relaxed);
    }

    int sequence_unresolved_gap_count() const {
        return sequence_unresolved_gap_count_.load(std::memory_order_relaxed);
    }

private:
    void send_ctrl(CtrlHdr::Cmd cmd) {
        CtrlHdr hdr{};
        hdr.magic = CTRL_MAGIC;
        hdr.type = cmd;
        socket_.send_to(asio::buffer(&hdr, sizeof(hdr)), server_endpoint_);
    }

    void send_join_packet(const std::string& room, const std::string& user) {
        JoinHdr hdr{};
        hdr.magic = CTRL_MAGIC;
        hdr.type = CtrlHdr::Cmd::JOIN;
        hdr.capabilities = AUDIO_SUPPORTED_CAPABILITIES;
        packet_builder::write_fixed(hdr.room_id, room);
        packet_builder::write_fixed(hdr.room_handle, room);
        packet_builder::write_fixed(hdr.profile_id, user);
        packet_builder::write_fixed(hdr.display_name, user);
        packet_builder::write_fixed(hdr.join_token, join_token_);
        socket_.send_to(asio::buffer(&hdr, sizeof(hdr)), server_endpoint_);
    }

    void do_receive() {
        socket_.async_receive_from(asio::buffer(recv_buf_), remote_endpoint_,
                                   [this](std::error_code ec, std::size_t bytes) {
                                       if (!ec) {
                                           handle_receive(bytes);
                                       }
                                       do_receive();
                                   });
    }

    void handle_receive(std::size_t bytes) {
        if (bytes < sizeof(MsgHdr)) {
            return;
        }

        MsgHdr hdr{};
        std::memcpy(&hdr, recv_buf_.data(), sizeof(hdr));
        if (hdr.magic == AUDIO_REDUNDANT_MAGIC) {
            raw_audio_count_.fetch_add(1, std::memory_order_relaxed);
            redundant_audio_count_.fetch_add(1, std::memory_order_relaxed);
            std::string reason;
            const auto* packet_data = reinterpret_cast<const unsigned char*>(recv_buf_.data());
            if (!audio_packet::validate_redundant_audio_packet_bytes(packet_data, bytes, &reason)) {
                invalid_audio_count_.fetch_add(1, std::memory_order_relaxed);
                return;
            }

            audio_packet::for_each_redundant_audio_child_reverse(
                packet_data, bytes,
                [this](const unsigned char* child, size_t child_len, uint8_t) {
                    handle_audio_packet(child, child_len);
                });
            return;
        }

        if (hdr.magic == AUDIO_V2_MAGIC || hdr.magic == AUDIO_V3_MAGIC) {
            raw_audio_count_.fetch_add(1, std::memory_order_relaxed);
            if (hdr.magic == AUDIO_V2_MAGIC) {
                v2_audio_count_.fetch_add(1, std::memory_order_relaxed);
            }
            const auto* packet_data = reinterpret_cast<const unsigned char*>(recv_buf_.data());
            handle_audio_packet(packet_data, bytes);
            return;
        }

        if (hdr.magic != AUDIO_MAGIC ||
            !message_validator::is_valid_audio_packet(
                bytes, sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t))) {
            return;
        }

        const auto* packet_data = reinterpret_cast<const unsigned char*>(recv_buf_.data());
        uint16_t encoded_bytes = packet_builder::extract_encoded_bytes(packet_data);
        size_t expected_size = sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t) + encoded_bytes;
        if (!message_validator::has_complete_payload(bytes, expected_size) ||
            !message_validator::is_encoded_bytes_valid(encoded_bytes, AUDIO_BUF_SIZE)) {
            return;
        }

        const unsigned char* audio_data = packet_builder::audio_v1_payload(packet_data);
        if (encoded_bytes < 1) {
            return;
        }

        OpusPacket packet;
        raw_audio_count_.fetch_add(1, std::memory_order_relaxed);
        if (audio_data[0] == PROBE_CODEC_OPUS) {
            packet.codec = AudioCodec::Opus;
        } else if (audio_data[0] == PROBE_CODEC_PCM_INT16) {
            packet.codec = AudioCodec::PcmInt16;
        } else {
            return;
        }
        const uint16_t payload_bytes = static_cast<uint16_t>(encoded_bytes - 1);
        std::memcpy(packet.data.data(), audio_data + 1, payload_bytes);
        packet.size = payload_bytes;
        packet.timestamp = clock_type::now();
        packet.sequence_valid = false;
        packet.sample_rate = SAMPLE_RATE;
        packet.frame_count = 0;
        packet.channels = CHANNELS;

        if (queue_.enqueue(packet)) {
            received_count_.fetch_add(1, std::memory_order_relaxed);
        } else {
            queue_drop_count_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void handle_audio_packet(const unsigned char* packet_data, std::size_t bytes) {
        std::string reason;
        if (!audio_packet::validate_audio_packet_bytes(packet_data, bytes, &reason)) {
            invalid_audio_count_.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        const auto audio = audio_packet::parse_audio_header(packet_data, bytes);
        if (!audio.valid ||
            (audio.magic != AUDIO_V2_MAGIC && audio.magic != AUDIO_V3_MAGIC)) {
            invalid_audio_count_.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        const auto sequence_delta = sequence_tracker_.record(audio.sequence);
        if (sequence_delta.gaps_detected > 0) {
            sequence_gap_count_.fetch_add(static_cast<int>(sequence_delta.gaps_detected),
                                          std::memory_order_relaxed);
        }
        if (sequence_delta.gaps_recovered > 0) {
            sequence_gap_recovery_count_.fetch_add(
                static_cast<int>(sequence_delta.gaps_recovered), std::memory_order_relaxed);
        }
        if (sequence_delta.late_or_duplicate) {
            sequence_late_or_duplicate_count_.fetch_add(1, std::memory_order_relaxed);
        }
        sequence_unresolved_gap_count_.store(
            static_cast<int>(sequence_tracker_.unresolved_gaps()), std::memory_order_relaxed);
        if (!sequence_arrival_should_enqueue(sequence_delta)) {
            return;
        }

        OpusPacket packet;
        const unsigned char* payload = audio_packet::audio_payload(packet_data, bytes);
        if (payload == nullptr) {
            invalid_audio_count_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        std::memcpy(packet.data.data(), payload, audio.payload_bytes);
        packet.size = audio.payload_bytes;
        packet.timestamp = clock_type::now();
        packet.codec = audio.codec;
        packet.sequence = audio.sequence;
        packet.sequence_valid = true;
        packet.sample_rate = audio.sample_rate;
        packet.frame_count = audio.frame_count;
        packet.channels = audio.channels;

        if (queue_.enqueue(packet)) {
            received_count_.fetch_add(1, std::memory_order_relaxed);
        } else {
            queue_drop_count_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    udp::socket socket_;
    udp::endpoint server_endpoint_;
    udp::endpoint remote_endpoint_;
    std::string room_;
    std::string user_;
    std::string join_token_;
    std::array<char, PROBE_RECV_BUF_SIZE> recv_buf_{};
    ParticipantOpusPacketQueue queue_;
    SequenceArrivalTracker sequence_tracker_;
    std::atomic<int> received_count_{0};
    std::atomic<int> raw_audio_count_{0};
    std::atomic<int> redundant_audio_count_{0};
    std::atomic<int> v2_audio_count_{0};
    std::atomic<int> queue_drop_count_{0};
    std::atomic<int> invalid_audio_count_{0};
    std::atomic<int> sequence_gap_count_{0};
    std::atomic<int> sequence_gap_recovery_count_{0};
    std::atomic<int> sequence_late_or_duplicate_count_{0};
    std::atomic<int> sequence_unresolved_gap_count_{0};
};

class ProbeSender {
public:
    ProbeSender(asio::io_context& io_context, const udp::endpoint& server_endpoint,
                const std::string& room, const std::string& user,
                const std::string& join_token)
        : socket_(io_context, udp::endpoint(udp::v4(), 0)), server_endpoint_(server_endpoint),
          room_(room), user_(user), join_token_(join_token) {
        configure_probe_socket(socket_);
    }

    void send_join() {
        send_join_packet(room_, user_);
    }

    void send_alive() {
        send_ctrl(CtrlHdr::Cmd::ALIVE);
    }

    void send_leave() {
        send_ctrl(CtrlHdr::Cmd::LEAVE);
    }

    bool send_audio_packet(ProbeCodec codec, uint32_t sequence, int frame_count,
                           const unsigned char* payload, size_t payload_bytes) {
        if (payload_bytes > AUDIO_BUF_SIZE) {
            return false;
        }

        const AudioCodec audio_codec =
            codec == ProbeCodec::Opus ? AudioCodec::Opus : AudioCodec::PcmInt16;
        auto packet = audio_packet::create_audio_packet_v2(
            audio_codec, sequence, SAMPLE_RATE, static_cast<uint16_t>(frame_count),
            CHANNELS, payload, static_cast<uint16_t>(payload_bytes));
        std::vector<const std::vector<unsigned char>*> children{packet.get()};
        for (const auto& previous_packet: recent_audio_packets_) {
            if (previous_packet != nullptr) {
                children.push_back(previous_packet.get());
            }
        }
        auto redundant_packet = audio_packet::create_redundant_audio_packet(
            children, AUDIO_REDUNDANT_TARGET_BYTES);
        auto wire_packet = redundant_packet != nullptr ? redundant_packet : packet;
        remember_recent_audio_packet(packet);

        std::error_code ec;
        socket_.send_to(asio::buffer(wire_packet->data(), wire_packet->size()), server_endpoint_,
                        0, ec);
        return !ec;
    }

private:
    void remember_recent_audio_packet(
        const std::shared_ptr<std::vector<unsigned char>>& packet) {
        if (packet == nullptr) {
            return;
        }
        recent_audio_packets_.insert(recent_audio_packets_.begin(), packet);
        if (recent_audio_packets_.size() >= MAX_AUDIO_REDUNDANT_PACKETS) {
            recent_audio_packets_.resize(MAX_AUDIO_REDUNDANT_PACKETS - 1);
        }
    }

    void send_ctrl(CtrlHdr::Cmd cmd) {
        CtrlHdr hdr{};
        hdr.magic = CTRL_MAGIC;
        hdr.type = cmd;
        socket_.send_to(asio::buffer(&hdr, sizeof(hdr)), server_endpoint_);
    }

    void send_join_packet(const std::string& room, const std::string& user) {
        JoinHdr hdr{};
        hdr.magic = CTRL_MAGIC;
        hdr.type = CtrlHdr::Cmd::JOIN;
        hdr.capabilities = AUDIO_SUPPORTED_CAPABILITIES;
        packet_builder::write_fixed(hdr.room_id, room);
        packet_builder::write_fixed(hdr.room_handle, room);
        packet_builder::write_fixed(hdr.profile_id, user);
        packet_builder::write_fixed(hdr.display_name, user);
        packet_builder::write_fixed(hdr.join_token, join_token_);
        socket_.send_to(asio::buffer(&hdr, sizeof(hdr)), server_endpoint_);
    }

    udp::socket socket_;
    udp::endpoint server_endpoint_;
    std::string room_;
    std::string user_;
    std::string join_token_;
    std::vector<std::shared_ptr<std::vector<unsigned char>>> recent_audio_packets_;
};

void fill_probe_frame(int packet_index, const ProbeConfig& config, std::vector<float>& frame) {
    std::fill(frame.begin(), frame.end(), 0.0F);
    if (packet_index == IMPULSE_PACKET) {
        int samples = std::min(CLICK_SAMPLES, config.frame_size);
        for (int i = 0; i < samples; ++i) {
            frame[static_cast<size_t>(i)] = CLICK_AMPLITUDE;
        }
    }
}

const char* codec_name(ProbeCodec codec) {
    switch (codec) {
        case ProbeCodec::Opus:
            return "opus";
        case ProbeCodec::PcmInt16:
            return "pcm_int16";
    }
    return "unknown";
}

void send_invalid_packet_flood(udp::endpoint server_endpoint, int packet_count,
                               int interval_us, clock_type::time_point start_time) {
    if (packet_count <= 0) {
        return;
    }

    asio::io_context io_context;
    udp::socket socket(io_context, udp::endpoint(udp::v4(), 0));
    std::array<unsigned char, sizeof(MsgHdr)> packet{};
    const uint32_t magics[] = {PING_MAGIC, CTRL_MAGIC, AUDIO_MAGIC, AUDIO_V2_MAGIC};

    std::this_thread::sleep_until(start_time);
    for (int i = 0; i < packet_count; ++i) {
        const uint32_t magic = magics[static_cast<size_t>(i) %
                                      (sizeof(magics) / sizeof(magics[0]))];
        std::memcpy(packet.data(), &magic, sizeof(magic));
        std::error_code ec;
        socket.send_to(asio::buffer(packet), server_endpoint, 0, ec);
        if (interval_us > 0) {
            std::this_thread::sleep_for(std::chrono::microseconds(interval_us));
        }
    }
}

bool decode_pcm_int16_packet(const OpusPacket& packet, const ProbeConfig& config,
                             std::array<float, MAX_FRAME_SAMPLES>& pcm) {
    if (packet.codec != AudioCodec::PcmInt16) {
        return false;
    }

    size_t payload_bytes = packet.get_size();
    size_t expected_bytes = static_cast<size_t>(config.frame_size) * sizeof(int16_t);
    if (payload_bytes != expected_bytes) {
        return false;
    }

    const unsigned char* payload = packet.get_data();
    for (int i = 0; i < config.frame_size; ++i) {
        int16_t sample = 0;
        std::memcpy(&sample, payload + static_cast<size_t>(i) * sizeof(sample), sizeof(sample));
        pcm[static_cast<size_t>(i)] = static_cast<float>(sample) / 32767.0F;
    }
    return true;
}

std::string create_probe_join_token(const Args& args, const std::string& profile_id) {
    if (args.join_secret.empty()) {
        return "";
    }

    performer_join_token::Claims claims;
    claims.expires_at_ms = performer_join_token::now_ms() + args.join_token_ttl_ms;
    claims.server_id = args.server_id;
    claims.room_id = args.room;
    claims.profile_id = profile_id;
    claims.role = "performer";
    claims.nonce = performer_join_token::random_nonce();
    return performer_join_token::create(claims, args.join_secret);
}

void inspect_samples(const std::array<float, MAX_FRAME_SAMPLES>& pcm, int decoded_samples,
                     int output_base_sample, const ProbeConfig& config, ProbeMetrics& metrics,
                     std::vector<float>& previous_block, bool& have_previous_block) {
    bool same_as_previous = have_previous_block && decoded_samples == config.frame_size;

    for (int i = 0; i < decoded_samples; ++i) {
        float sample = pcm[static_cast<size_t>(i)];
        if (!std::isfinite(sample)) {
            metrics.non_finite_samples++;
            continue;
        }
        if (sample < -1.0F || sample > 1.0F) {
            metrics.out_of_range_samples++;
        }
        if (i > 0) {
            float prev = pcm[static_cast<size_t>(i - 1)];
            metrics.max_discontinuity = std::max(metrics.max_discontinuity, std::abs(sample - prev));
        }
        if (metrics.detected_output_sample < 0 && std::abs(sample) >= DETECTION_THRESHOLD) {
            metrics.detected_output_sample = output_base_sample + i;
        }
        if (same_as_previous && previous_block[static_cast<size_t>(i)] != sample) {
            same_as_previous = false;
        }
    }

    if (same_as_previous) {
        metrics.repeated_blocks++;
    }

    if (decoded_samples == config.frame_size) {
        std::copy_n(pcm.begin(), static_cast<size_t>(config.frame_size), previous_block.begin());
        have_previous_block = true;
    }
}

void run_playout_loop(const ProbeConfig& config, ProbeReceiver& receiver, ProbeMetrics& metrics,
                      clock_type::time_point start_time, double playout_ppm) {
    OpusDecoderWrapper decoder;
    if (config.codec == ProbeCodec::Opus && !decoder.create(SAMPLE_RATE, CHANNELS)) {
        throw std::runtime_error("failed to create Opus decoder");
    }

    bool buffer_ready = false;
    std::array<float, MAX_FRAME_SAMPLES> pcm{};
    std::vector<float> decoded_pcm_fifo;
    std::vector<float> previous_block(static_cast<size_t>(config.frame_size), 0.0F);
    bool have_previous_block = false;
    const double playout_rate =
        static_cast<double>(SAMPLE_RATE) * (1.0 + (playout_ppm / 1'000'000.0));
    auto frame_duration = std::chrono::duration_cast<clock_type::duration>(
        std::chrono::duration<double>(static_cast<double>(config.frame_size) / playout_rate));

    auto output_decoded_fifo = [&](int output_base_sample) {
        if (decoded_pcm_fifo.size() < static_cast<size_t>(config.frame_size)) {
            return false;
        }
        std::copy_n(decoded_pcm_fifo.begin(), static_cast<size_t>(config.frame_size),
                    pcm.begin());
        decoded_pcm_fifo.erase(decoded_pcm_fifo.begin(),
                               decoded_pcm_fifo.begin() + config.frame_size);
        inspect_samples(pcm, config.frame_size, output_base_sample, config, metrics,
                        previous_block, have_previous_block);
        return true;
    };

    auto append_decoded_fifo = [&](const float* samples, int sample_count) {
        if (sample_count <= 0) {
            return;
        }
        decoded_pcm_fifo.insert(decoded_pcm_fifo.end(), samples, samples + sample_count);
    };
    int current_gap_plc_run = 0;
    auto note_gap_plc = [&]() {
        ++current_gap_plc_run;
        metrics.max_gap_plc_run =
            std::max(metrics.max_gap_plc_run, current_gap_plc_run);
    };
    auto note_real_audio = [&]() {
        current_gap_plc_run = 0;
    };

    for (int tick = 0; tick < config.total_packets + 80; ++tick) {
        std::this_thread::sleep_until(start_time + frame_duration * tick);
        if (tick % std::max(1, SAMPLE_RATE / config.frame_size) == 0) {
            receiver.send_alive();
        }

        int current_queue_depth = static_cast<int>(receiver.queue_size());
        metrics.final_queue_depth = current_queue_depth;
        metrics.max_queue_depth = std::max(metrics.max_queue_depth, current_queue_depth);
        if (!buffer_ready && current_queue_depth >= config.jitter_min_packets) {
            buffer_ready = true;
        }

        int output_base_sample = tick * config.frame_size;
        if (!buffer_ready) {
            continue;
        }

        if (current_queue_depth == 0 && decoded_pcm_fifo.empty() &&
            receiver.received_count() >= config.total_packets) {
            break;
        }

        metrics.queue_depth_observations++;
        metrics.queue_depth_sum += current_queue_depth;
        metrics.min_queue_depth_after_ready =
            std::min(metrics.min_queue_depth_after_ready, current_queue_depth);

        if (output_decoded_fifo(output_base_sample)) {
            continue;
        }

        OpusPacket packet;
        const auto dequeue_status =
            receiver.pop_packet(packet, static_cast<size_t>(config.jitter_min_packets));
        if (dequeue_status == ParticipantOpusDequeueStatus::Packet) {
            int decoded_samples = 0;
            if (packet.reset_decoder && packet.codec == AudioCodec::Opus) {
                decoder.reset();
                decoded_pcm_fifo.clear();
                metrics.decoder_resets++;
                note_real_audio();
            }
            if (packet.loss_concealment && packet.codec == AudioCodec::Opus) {
                decoded_samples = decoder.decode_plc(pcm.data(), config.frame_size);
                if (decoded_samples > 0) {
                    metrics.plc_frames++;
                    metrics.gap_plc_frames++;
                    note_gap_plc();
                }
            } else if (packet.codec == AudioCodec::Opus) {
                if (config.codec != ProbeCodec::Opus) {
                    metrics.decode_failures++;
                    continue;
                }
                decoded_samples = decoder.decode_into(packet.get_data(),
                                                      static_cast<int>(packet.get_size()),
                                                      pcm.data(), config.frame_size);
                if (decoded_samples <= 0) {
                    metrics.decode_failures++;
                    continue;
                }
                note_real_audio();
            } else if (decode_pcm_int16_packet(packet, config, pcm)) {
                decoded_samples = config.frame_size;
                note_real_audio();
            } else {
                metrics.decode_failures++;
                continue;
            }
            metrics.decoded_packets++;
            if (decoded_samples != config.frame_size) {
                metrics.decoded_size_mismatches++;
            }
            append_decoded_fifo(pcm.data(), decoded_samples);
            output_decoded_fifo(output_base_sample);
        } else if (dequeue_status == ParticipantOpusDequeueStatus::WaitingForGap) {
            metrics.gap_waits++;
            continue;
        } else if (receiver.received_count() < config.total_packets) {
            metrics.underruns++;
            if (config.codec == ProbeCodec::Opus) {
                int plc_samples = decoder.decode_plc(pcm.data(), config.frame_size);
                if (plc_samples > 0) {
                    metrics.plc_frames++;
                    metrics.empty_plc_frames++;
                    inspect_samples(pcm, plc_samples, output_base_sample, config, metrics,
                                    previous_block, have_previous_block);
                }
            }
        } else {
            break;
        }
    }
}

void run_sender_loop(const ProbeConfig& config, ProbeSender& sender, ProbeMetrics& metrics,
                     clock_type::time_point start_time) {
    OpusEncoderWrapper encoder;
    if (config.codec == ProbeCodec::Opus &&
        !encoder.create(SAMPLE_RATE, CHANNELS, OPUS_APPLICATION_VOIP, BITRATE, COMPLEXITY)) {
        throw std::runtime_error("failed to create Opus encoder");
    }

    std::vector<float> frame(static_cast<size_t>(config.frame_size), 0.0F);
    std::vector<unsigned char> encoded;
    std::vector<unsigned char> pcm_payload(static_cast<size_t>(config.frame_size) * sizeof(int16_t));
    uint32_t sequence = 0;
    auto frame_duration =
        std::chrono::duration_cast<clock_type::duration>(std::chrono::duration<double>(
            static_cast<double>(config.frame_size) / static_cast<double>(SAMPLE_RATE)));

    for (int packet_index = 0; packet_index < config.total_packets; ++packet_index) {
        std::this_thread::sleep_until(start_time + frame_duration * packet_index);
        if (packet_index % std::max(1, SAMPLE_RATE / config.frame_size) == 0) {
            sender.send_alive();
        }
        fill_probe_frame(packet_index, config, frame);
        bool sent = false;
        if (config.codec == ProbeCodec::Opus) {
            if (!encoder.encode(frame.data(), config.frame_size, encoded)) {
                metrics.encode_failures++;
                continue;
            }
            sent = sender.send_audio_packet(ProbeCodec::Opus, sequence++, config.frame_size,
                                            encoded.data(), encoded.size());
        } else {
            for (int i = 0; i < config.frame_size; ++i) {
                float clamped = std::clamp(frame[static_cast<size_t>(i)], -1.0F, 1.0F);
                auto sample = static_cast<int16_t>(std::lrint(clamped * 32767.0F));
                std::memcpy(pcm_payload.data() + static_cast<size_t>(i) * sizeof(sample), &sample,
                            sizeof(sample));
            }
            sent = sender.send_audio_packet(ProbeCodec::PcmInt16, sequence++, config.frame_size,
                                            pcm_payload.data(), pcm_payload.size());
        }
        if (sent) {
            metrics.sent_packets++;
        } else {
            metrics.encode_failures++;
        }
    }
}

ProbeResult run_probe(const Args& args, const ProbeConfig& config) {
    asio::io_context io_context;
    udp::resolver resolver(io_context);
    udp::endpoint server_endpoint =
        *resolver.resolve(udp::v4(), args.host, std::to_string(args.port)).begin();

    const std::string receiver_join_token =
        !args.receiver_join_token.empty() ? args.receiver_join_token
                                          : create_probe_join_token(args, args.receiver_user);
    const std::string sender_join_token =
        !args.sender_join_token.empty() ? args.sender_join_token
                                        : create_probe_join_token(args, args.sender_user);

    ProbeReceiver receiver(io_context, server_endpoint, args.room, args.receiver_user,
                           receiver_join_token);
    ProbeSender sender(io_context, server_endpoint, args.room, args.sender_user,
                       sender_join_token);

    receiver.start();
    std::thread io_thread([&io_context]() { io_context.run(); });

    receiver.send_join();
    sender.send_join();
    std::this_thread::sleep_for(200ms);

    ProbeMetrics metrics;
    auto start_time = clock_type::now() + 100ms;

    std::thread invalid_flood_thread;
    if (args.invalid_flood_packets > 0) {
        invalid_flood_thread = std::thread(send_invalid_packet_flood, server_endpoint,
                                           args.invalid_flood_packets,
                                           args.invalid_flood_interval_us, start_time);
    }

    std::thread playout_thread(run_playout_loop, std::cref(config), std::ref(receiver),
                               std::ref(metrics), start_time, args.playout_ppm);
    std::thread sender_thread(run_sender_loop, std::cref(config), std::ref(sender),
                              std::ref(metrics), start_time);

    sender_thread.join();
    if (invalid_flood_thread.joinable()) {
        invalid_flood_thread.join();
    }
    playout_thread.join();

    sender.send_leave();
    receiver.send_leave();
    std::this_thread::sleep_for(50ms);

    io_context.stop();
    if (io_thread.joinable()) {
        io_thread.join();
    }

    metrics.raw_audio_packets = receiver.raw_audio_count();
    metrics.redundant_audio_packets = receiver.redundant_audio_count();
    metrics.v2_audio_packets = receiver.v2_audio_count();
    metrics.receiver_queue_drops = receiver.queue_drop_count();
    metrics.invalid_audio_packets = receiver.invalid_audio_count();
    metrics.received_packets = receiver.received_count();
    metrics.sequence_gaps = receiver.sequence_gap_count();
    metrics.sequence_gap_recoveries = receiver.sequence_gap_recovery_count();
    metrics.sequence_late_or_duplicate = receiver.sequence_late_or_duplicate_count();
    metrics.sequence_unresolved_gaps = receiver.sequence_unresolved_gap_count();

    ProbeResult result;
    result.config = config;
    result.metrics = metrics;

    int injected_sample = IMPULSE_PACKET * config.frame_size;
    result.latency_samples = metrics.detected_output_sample >= 0
                                 ? metrics.detected_output_sample - injected_sample
                                 : -1;
    result.latency_ms = result.latency_samples >= 0
                            ? static_cast<double>(result.latency_samples) * 1000.0 / SAMPLE_RATE
                            : -1.0;
    return result;
}

bool has_corruption_indicators(const ProbeResult& result) {
    const auto& m = result.metrics;
    return result.latency_samples < 0 || m.encode_failures > 0 || m.plc_frames > 0 ||
           m.underruns > 0 || m.decode_failures > 0 || m.decoded_size_mismatches > 0 ||
           m.non_finite_samples > 0 || m.out_of_range_samples > 0;
}

bool has_delivery_indicators(const ProbeResult& result) {
    const auto& m = result.metrics;
    return m.sent_packets <= 0 || m.received_packets != m.sent_packets ||
           m.decoded_packets != m.sent_packets;
}

bool has_clean_failure_indicators(const ProbeResult& result) {
    return has_corruption_indicators(result) || has_delivery_indicators(result);
}

void print_result(const Args& args, const ProbeResult& result) {
    const auto& c = result.config;
    const auto& m = result.metrics;
    const double avg_queue =
        m.queue_depth_observations > 0
            ? static_cast<double>(m.queue_depth_sum) / static_cast<double>(m.queue_depth_observations)
            : 0.0;
    const int min_queue =
        m.min_queue_depth_after_ready == std::numeric_limits<int>::max()
            ? 0
            : m.min_queue_depth_after_ready;
    std::cout << "latency_probe v2\n";
    std::cout << "server: " << args.host << ":" << args.port << "\n";
    std::cout << "codec: " << codec_name(c.codec) << "\n";
    std::cout << "sample_rate: " << SAMPLE_RATE << "\n";
    std::cout << "frames_per_packet: " << c.frame_size << "\n";
    std::cout << "jitter_min_packets: " << c.jitter_min_packets << "\n";
    std::cout << "playout_ppm: " << args.playout_ppm << "\n";
    std::cout << "invalid_flood_packets: " << args.invalid_flood_packets << "\n";
    std::cout << "total_packets: " << c.total_packets << "\n";
    std::cout << "impulse_packet: " << IMPULSE_PACKET << "\n";
    std::cout << "sent_packets: " << m.sent_packets << "\n";
    std::cout << "encode_failures: " << m.encode_failures << "\n";
    std::cout << "raw_audio_packets: " << m.raw_audio_packets << "\n";
    std::cout << "redundant_audio_packets: " << m.redundant_audio_packets << "\n";
    std::cout << "v2_audio_packets: " << m.v2_audio_packets << "\n";
    std::cout << "receiver_queue_drops: " << m.receiver_queue_drops << "\n";
    std::cout << "invalid_audio_packets: " << m.invalid_audio_packets << "\n";
    std::cout << "received_packets: " << m.received_packets << "\n";
    std::cout << "decoded_packets: " << m.decoded_packets << "\n";
    std::cout << "missing_packets: " << (m.sent_packets - m.received_packets) << "\n";
    std::cout << "undecoded_packets: " << (m.sent_packets - m.decoded_packets) << "\n";
    std::cout << "detected_output_sample: " << m.detected_output_sample << "\n";
    std::cout << "latency_samples: " << result.latency_samples << "\n";
    std::cout << "latency_ms: " << result.latency_ms << "\n";
    std::cout << "avg_queue_depth: " << avg_queue << "\n";
    std::cout << "queue_drift_from_jitter: "
              << (avg_queue - static_cast<double>(c.jitter_min_packets)) << "\n";
    std::cout << "min_queue_depth_after_ready: " << min_queue << "\n";
    std::cout << "max_queue_depth: " << m.max_queue_depth << "\n";
    std::cout << "final_queue_depth: " << m.final_queue_depth << "\n";
    std::cout << "underruns: " << m.underruns << "\n";
    std::cout << "plc_frames: " << m.plc_frames << "\n";
    std::cout << "gap_plc_frames: " << m.gap_plc_frames << "\n";
    std::cout << "empty_plc_frames: " << m.empty_plc_frames << "\n";
    std::cout << "max_gap_plc_run: " << m.max_gap_plc_run << "\n";
    std::cout << "decoder_resets: " << m.decoder_resets << "\n";
    std::cout << "gap_waits: " << m.gap_waits << "\n";
    std::cout << "sequence_gaps: " << m.sequence_gaps << "\n";
    std::cout << "sequence_gap_recoveries: " << m.sequence_gap_recoveries << "\n";
    std::cout << "sequence_late_or_duplicate: " << m.sequence_late_or_duplicate << "\n";
    std::cout << "sequence_unresolved_gaps: " << m.sequence_unresolved_gaps << "\n";
    std::cout << "decode_failures: " << m.decode_failures << "\n";
    std::cout << "decoded_size_mismatches: " << m.decoded_size_mismatches << "\n";
    std::cout << "non_finite_samples: " << m.non_finite_samples << "\n";
    std::cout << "out_of_range_samples: " << m.out_of_range_samples << "\n";
    std::cout << "repeated_blocks: " << m.repeated_blocks << "\n";
    std::cout << "max_discontinuity: " << m.max_discontinuity << "\n";
    if (has_corruption_indicators(result)) {
        std::cout << "warning: corruption indicators were observed\n";
    }
    if (has_delivery_indicators(result)) {
        std::cout << "warning: packet delivery/decode mismatch was observed\n";
    }
}

void print_sweep_header() {
    std::cout << "codec,frames,jitter,playout_ppm,latency_ms,latency_samples,sent,received,decoded,max_queue,"
                 "avg_queue,queue_drift,min_queue,final_queue,raw_audio,redundant_audio,"
                 "v2_audio,encode_failures,underruns,plc,gap_plc,empty_plc,max_gap_plc_run,"
                 "decoder_resets,gap_waits,"
                 "seq_gaps,seq_recoveries,seq_late,seq_unresolved,decode_failures,"
                 "size_mismatch,non_finite,out_of_range,repeated_blocks,max_discontinuity,"
                 "status\n";
}

void print_sweep_row(const Args& args, const ProbeResult& result) {
    const auto& c = result.config;
    const auto& m = result.metrics;
    const double avg_queue =
        m.queue_depth_observations > 0
            ? static_cast<double>(m.queue_depth_sum) / static_cast<double>(m.queue_depth_observations)
            : 0.0;
    const int min_queue =
        m.min_queue_depth_after_ready == std::numeric_limits<int>::max()
            ? 0
            : m.min_queue_depth_after_ready;
    std::cout << codec_name(c.codec) << ',' << c.frame_size << ',' << c.jitter_min_packets << ','
              << args.playout_ppm << ',' << result.latency_ms << ',' << result.latency_samples << ',' << m.sent_packets << ','
              << m.received_packets << ',' << m.decoded_packets << ',' << m.max_queue_depth << ','
               << avg_queue << ',' << (avg_queue - static_cast<double>(c.jitter_min_packets)) << ','
              << min_queue << ',' << m.final_queue_depth << ',' << m.raw_audio_packets << ','
              << m.redundant_audio_packets << ',' << m.v2_audio_packets << ','
              << m.encode_failures << ',' << m.underruns << ',' << m.plc_frames << ','
              << m.gap_plc_frames << ',' << m.empty_plc_frames << ','
              << m.max_gap_plc_run << ',' << m.decoder_resets << ',' << m.gap_waits << ','
              << m.sequence_gaps << ',' << m.sequence_gap_recoveries << ','
              << m.sequence_late_or_duplicate << ',' << m.sequence_unresolved_gaps << ','
              << m.decode_failures << ',' << m.decoded_size_mismatches << ','
              << m.non_finite_samples << ',' << m.out_of_range_samples << ','
              << m.repeated_blocks << ',' << m.max_discontinuity << ','
              << (has_clean_failure_indicators(result) ? "warn" : "ok")
              << "\n";
}

Args parse_args(int argc, char** argv) {
    Args args;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "--server" || arg == "--host") && i + 1 < argc) {
            args.host = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            args.port = parse_udp_port(argv[++i], "--port");
        } else if (arg == "--server-id" && i + 1 < argc) {
            args.server_id = argv[++i];
        } else if (arg == "--join-secret" && i + 1 < argc) {
            args.join_secret = argv[++i];
        } else if (arg == "--join-token-ttl-ms" && i + 1 < argc) {
            args.join_token_ttl_ms = std::stoll(argv[++i]);
        } else if (arg == "--sender-join-token" && i + 1 < argc) {
            args.sender_join_token = argv[++i];
        } else if (arg == "--receiver-join-token" && i + 1 < argc) {
            args.receiver_join_token = argv[++i];
        } else if (arg == "--require-clean" || arg == "--fail-on-warning") {
            args.require_clean = true;
        } else if (arg == "--max-gap-plc-run" && i + 1 < argc) {
            args.max_allowed_gap_plc_run = std::stoi(argv[++i]);
        } else if (arg == "--min-decoder-resets" && i + 1 < argc) {
            args.min_decoder_resets = std::stoi(argv[++i]);
        } else if (arg == "--room" && i + 1 < argc) {
            args.room = argv[++i];
        } else if (arg == "--sender-user" && i + 1 < argc) {
            args.sender_user = argv[++i];
        } else if (arg == "--receiver-user" && i + 1 < argc) {
            args.receiver_user = argv[++i];
        } else if (arg == "--frames" && i + 1 < argc) {
            args.config.frame_size = std::stoi(argv[++i]);
        } else if (arg == "--jitter" && i + 1 < argc) {
            args.config.jitter_min_packets = std::stoi(argv[++i]);
        } else if (arg == "--packets" && i + 1 < argc) {
            args.config.total_packets = std::stoi(argv[++i]);
        } else if (arg == "--seconds" && i + 1 < argc) {
            args.duration_seconds = std::stoi(argv[++i]);
        } else if (arg == "--playout-ppm" && i + 1 < argc) {
            args.playout_ppm = std::stod(argv[++i]);
        } else if (arg == "--v3-receive-smoke") {
            args.v3_receive_smoke = true;
        } else if (arg == "--invalid-flood-packets" && i + 1 < argc) {
            args.invalid_flood_packets = std::stoi(argv[++i]);
        } else if (arg == "--invalid-flood-interval-us" && i + 1 < argc) {
            args.invalid_flood_interval_us = std::stoi(argv[++i]);
        } else if (arg == "--codec" && i + 1 < argc) {
            std::string codec = argv[++i];
            if (codec == "opus") {
                args.config.codec = ProbeCodec::Opus;
            } else if (codec == "pcm" || codec == "raw" || codec == "pcm_int16") {
                args.config.codec = ProbeCodec::PcmInt16;
            } else {
                throw std::runtime_error("unknown codec: " + codec);
            }
        } else if (arg == "--sweep") {
            args.sweep = true;
        }
    }
    if (args.duration_seconds > 0) {
        const int64_t total_samples =
            static_cast<int64_t>(args.duration_seconds) * static_cast<int64_t>(SAMPLE_RATE);
        args.config.total_packets =
            static_cast<int>((total_samples + args.config.frame_size - 1) / args.config.frame_size);
    }
    if (args.config.total_packets <= IMPULSE_PACKET) {
        throw std::runtime_error("--packets/--seconds must run past the impulse packet");
    }
    args.invalid_flood_packets = std::max(0, args.invalid_flood_packets);
    args.invalid_flood_interval_us = std::max(0, args.invalid_flood_interval_us);
    return args;
}

bool run_v3_receive_smoke() {
    auto require = [](bool condition, const std::string& message) {
        if (!condition) {
            std::cerr << message << "\n";
            return false;
        }
        return true;
    };
    auto make_v3 = [](uint32_t sequence, uint8_t first_byte) {
        const std::array<unsigned char, 3> payload{
            first_byte, static_cast<uint8_t>(first_byte + 1),
            static_cast<uint8_t>(first_byte + 2)};
        return audio_packet::create_audio_packet_v3(
            AudioCodec::Opus, sequence, SAMPLE_RATE,
            opus_network_clock::DEFAULT_FRAME_COUNT, CHANNELS, payload.data(),
            static_cast<uint16_t>(payload.size()), 987654321LL + sequence);
    };
    auto expect_packet = [&](ProbeReceiver& receiver, uint32_t sequence,
                             uint8_t first_byte, const std::string& label) {
        OpusPacket packet{};
        if (!require(receiver.pop_packet(packet, 0) == ParticipantOpusDequeueStatus::Packet,
                     label + ": packet was not queued")) {
            return false;
        }
        return require(packet.codec == AudioCodec::Opus, label + ": codec mismatch") &&
               require(packet.sequence_valid, label + ": sequence not marked valid") &&
               require(packet.sequence == sequence, label + ": sequence mismatch") &&
               require(packet.sample_rate == SAMPLE_RATE, label + ": sample rate mismatch") &&
               require(packet.frame_count == opus_network_clock::DEFAULT_FRAME_COUNT,
                       label + ": frame count mismatch") &&
               require(packet.channels == CHANNELS, label + ": channel count mismatch") &&
               require(packet.size == 3, label + ": payload size mismatch") &&
               require(packet.data[0] == first_byte, label + ": payload mismatch");
    };

    asio::io_context io_context;
    const udp::endpoint endpoint(asio::ip::make_address("127.0.0.1"), 9);
    ProbeReceiver receiver(io_context, endpoint, "v3-receive-smoke", "receiver", "");

    auto direct = make_v3(30, 0x21);
    if (!require(direct != nullptr, "failed to build direct V3 packet") ||
        !require(receiver.handle_test_packet(*direct), "failed to inject direct V3 packet")) {
        return false;
    }

    auto current = make_v3(32, 0x31);
    auto previous = make_v3(31, 0x41);
    auto redundant =
        audio_packet::create_redundant_audio_packet({current.get(), previous.get()});
    if (!require(current != nullptr && previous != nullptr,
                 "failed to build redundant V3 children") ||
        !require(redundant != nullptr, "failed to build redundant V3 packet") ||
        !require(receiver.handle_test_packet(*redundant),
                 "failed to inject redundant V3 packet")) {
        return false;
    }

    if (!expect_packet(receiver, 30, 0x21, "direct V3") ||
        !expect_packet(receiver, 31, 0x41, "redundant previous V3") ||
        !expect_packet(receiver, 32, 0x31, "redundant current V3")) {
        return false;
    }

    return require(receiver.raw_audio_count() == 2, "raw packet count mismatch") &&
           require(receiver.redundant_audio_count() == 1, "redundant packet count mismatch") &&
           require(receiver.v2_audio_count() == 0, "V3 packets should not increment V2 count") &&
           require(receiver.invalid_audio_count() == 0, "V3 smoke had invalid packet drops") &&
           require(receiver.received_count() == 3, "received packet count mismatch");
}

}  // namespace

int main(int argc, char** argv) {
    try {
        Args args = parse_args(argc, argv);

        if (args.v3_receive_smoke) {
            if (!run_v3_receive_smoke()) {
                return 2;
            }
            std::cout << "latency probe V3 receive smoke passed\n";
            return 0;
        }

        if (args.sweep) {
            const std::vector<int> frame_sizes{240, 120, 96, 64};
            const std::vector<int> jitter_values{3, 2, 1, 0};
            print_sweep_header();
            for (int frames: frame_sizes) {
                for (int jitter: jitter_values) {
                    ProbeConfig config{frames, jitter, args.config.total_packets,
                                       args.config.codec};
                    ProbeResult result = run_probe(args, config);
                    print_sweep_row(args, result);
                }
            }
            return 0;
        }

        ProbeResult result = run_probe(args, args.config);
        print_result(args, result);
        if (args.require_clean && has_clean_failure_indicators(result)) {
            return 3;
        }
        if (args.max_allowed_gap_plc_run >= 0 &&
            result.metrics.max_gap_plc_run > args.max_allowed_gap_plc_run) {
            return 4;
        }
        if (result.metrics.decoder_resets < args.min_decoder_resets) {
            return 5;
        }
        return result.metrics.detected_output_sample >= 0 ? 0 : 2;
    } catch (const std::exception& e) {
        std::cerr << "latency_probe failed: " << e.what() << "\n";
        return 1;
    }
}
