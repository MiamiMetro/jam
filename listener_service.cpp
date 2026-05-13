#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <optional>
#include <unordered_map>
#include <stdexcept>
#include <string>
#include <string_view>
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
#include "packet_builder.h"
#include "participant_info.h"
#include "participant_manager.h"
#include "periodic_timer.h"
#include "protocol.h"

using asio::ip::udp;
using namespace std::chrono_literals;
namespace fs = std::filesystem;

namespace {

constexpr int    kSampleRate = 48000;
constexpr size_t kFrameCount = 240;
constexpr size_t kOutputChannels = 1;
constexpr size_t kListenerJitterPackets = DEFAULT_OPUS_JITTER_PACKETS;
constexpr size_t kListenerQueueLimitPackets = DEFAULT_OPUS_QUEUE_LIMIT_PACKETS;
constexpr size_t kPcmQueueSoftLimit = 400;

std::string fixed_string(const char* data, size_t max_size) {
    size_t len = 0;
    while (len < max_size && data[len] != '\0') {
        ++len;
    }
    return std::string(data, len);
}

std::string sanitize_path_component(std::string value) {
    for (char& ch: value) {
        const bool allowed = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                             (ch >= '0' && ch <= '9') || ch == '-' || ch == '_';
        if (!allowed) {
            ch = '_';
        }
    }
    if (value.empty()) {
        return "room";
    }
    return value;
}

std::vector<std::string> split_colon_fields(const std::string& input) {
    std::vector<std::string> fields;
    size_t                   start = 0;
    while (start <= input.size()) {
        size_t pos = input.find(':', start);
        if (pos == std::string::npos) {
            fields.push_back(input.substr(start));
            break;
        }
        fields.push_back(input.substr(start, pos - start));
        start = pos + 1;
    }
    return fields;
}

bool is_loopback_host(const std::string& host) {
    return host == "127.0.0.1" || host == "localhost" || host == "::1";
}

struct RoomListenerConfig {
    std::string room_id;
    std::string room_handle;
    std::string profile_id;
    std::string display_name;
    std::string join_token;
};

struct ListenerServiceOptions {
    std::string                     server_address = "127.0.0.1";
    uint16_t                        server_port = 9999;
    fs::path                        hls_root = "hls";
    std::string                     ffmpeg_path = "ffmpeg";
    float                           segment_duration = 0.5F;
    float                           output_gain = 1.0F;
    int                             playlist_size = 6;
    int                             bitrate = 80000;
    bool                            hls_enabled = true;
    bool                            cleanup_hls_on_stop = true;
    bool                            simulate_ffmpeg_write_failures = false;
    bool                            allow_insecure_dev_joins = false;
    std::optional<int>              duration_ms;
    std::vector<std::pair<std::string, int>> room_stop_after_ms;
    std::vector<std::pair<std::string, int>> room_restart_after_ms;
    std::vector<RoomListenerConfig> rooms;
};

RoomListenerConfig parse_room_config(const std::string& spec) {
    auto fields = split_colon_fields(spec);
    if (fields.empty() || fields[0].empty()) {
        throw std::runtime_error("--room requires at least a room id");
    }

    RoomListenerConfig room;
    room.room_id = fields[0];
    room.join_token = fields.size() > 1 ? fields[1] : "";
    room.room_handle = fields.size() > 2 && !fields[2].empty() ? fields[2] : room.room_id;
    const std::string safe_id = sanitize_path_component(room.room_id);
    room.profile_id = fields.size() > 3 && !fields[3].empty() ? fields[3] : "listener-" + safe_id;
    room.display_name =
        fields.size() > 4 && !fields[4].empty() ? fields[4] : "Listener " + room.room_id;
    return room;
}

[[noreturn]] void throw_usage(const std::string& reason) {
    throw std::runtime_error(
        reason +
        "\nUsage: listener_service [--server host] [--port port] [--hls-root path]\n"
        "                        [--ffmpeg path] [--output-gain gain]\n"
        "                        [--no-hls] [--keep-hls-output]\n"
        "                        [--simulate-ffmpeg-write-failures]\n"
        "                        [--allow-insecure-dev-joins] [--duration-ms ms]\n"
        "                        [--stop-room-after room_id:ms]\n"
        "                        [--restart-room-after room_id:ms]\n"
        "                        --room room_id[:token[:room_handle[:profile_id[:display_name]]]]\n");
}

ListenerServiceOptions parse_options(int argc, char* argv[]) {
    ListenerServiceOptions options;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto require_value = [&](std::string_view name) -> std::string {
            if (i + 1 >= argc) {
                throw_usage(std::string(name) + " requires a value");
            }
            return argv[++i];
        };

        if (arg == "--server") {
            options.server_address = require_value(arg);
        } else if (arg == "--port") {
            const int port = std::stoi(require_value(arg));
            if (port <= 0 || port > 65535) {
                throw_usage("--port must be between 1 and 65535");
            }
            options.server_port = static_cast<uint16_t>(port);
        } else if (arg == "--hls-root") {
            options.hls_root = require_value(arg);
        } else if (arg == "--ffmpeg") {
            options.ffmpeg_path = require_value(arg);
        } else if (arg == "--segment-duration") {
            options.segment_duration = std::stof(require_value(arg));
            if (options.segment_duration < 0.5F) {
                throw_usage("--segment-duration must be at least 0.5 for valid HLS playlists");
            }
        } else if (arg == "--output-gain") {
            options.output_gain = std::stof(require_value(arg));
            if (options.output_gain <= 0.0F || options.output_gain > 16.0F) {
                throw_usage("--output-gain must be > 0 and <= 16");
            }
        } else if (arg == "--playlist-size") {
            options.playlist_size = std::stoi(require_value(arg));
            if (options.playlist_size <= 0) {
                throw_usage("--playlist-size must be positive");
            }
        } else if (arg == "--bitrate") {
            options.bitrate = std::stoi(require_value(arg));
            if (options.bitrate <= 0) {
                throw_usage("--bitrate must be positive");
            }
        } else if (arg == "--room") {
            options.rooms.push_back(parse_room_config(require_value(arg)));
        } else if (arg == "--no-hls") {
            options.hls_enabled = false;
        } else if (arg == "--keep-hls-output") {
            options.cleanup_hls_on_stop = false;
        } else if (arg == "--simulate-ffmpeg-write-failures") {
            options.simulate_ffmpeg_write_failures = true;
        } else if (arg == "--allow-insecure-dev-joins") {
            options.allow_insecure_dev_joins = true;
        } else if (arg == "--duration-ms") {
            const int duration = std::stoi(require_value(arg));
            if (duration <= 0) {
                throw_usage("--duration-ms must be positive");
            }
            options.duration_ms = duration;
        } else if (arg == "--stop-room-after") {
            const std::string spec = require_value(arg);
            const size_t      pos = spec.rfind(':');
            if (pos == std::string::npos || pos == 0 || pos + 1 >= spec.size()) {
                throw_usage("--stop-room-after requires room_id:ms");
            }
            const int delay_ms = std::stoi(spec.substr(pos + 1));
            if (delay_ms <= 0) {
                throw_usage("--stop-room-after delay must be positive");
            }
            options.room_stop_after_ms.emplace_back(spec.substr(0, pos), delay_ms);
        } else if (arg == "--restart-room-after") {
            const std::string spec = require_value(arg);
            const size_t      pos = spec.rfind(':');
            if (pos == std::string::npos || pos == 0 || pos + 1 >= spec.size()) {
                throw_usage("--restart-room-after requires room_id:ms");
            }
            const int delay_ms = std::stoi(spec.substr(pos + 1));
            if (delay_ms <= 0) {
                throw_usage("--restart-room-after delay must be positive");
            }
            options.room_restart_after_ms.emplace_back(spec.substr(0, pos), delay_ms);
        } else if (arg == "--help" || arg == "-h") {
            throw_usage("");
        } else {
            throw_usage("Unknown argument: " + arg);
        }
    }

    if (options.rooms.empty()) {
        throw_usage("At least one --room is required");
    }
    for (const auto& room: options.rooms) {
        if (room.join_token.empty() && !options.allow_insecure_dev_joins) {
            throw_usage("Room '" + room.room_id +
                        "' has no join token; use --allow-insecure-dev-joins for local/dev runs");
        }
    }
    if (!options.allow_insecure_dev_joins && is_loopback_host(options.server_address)) {
        Log::warn("Using token-required listener joins against a loopback server");
    }

    return options;
}

struct ParsedAudioPacket {
    uint32_t    sender_id = 0;
    uint32_t    sequence = 0;
    uint32_t    sample_rate = kSampleRate;
    uint16_t    frame_count = static_cast<uint16_t>(kFrameCount);
    uint16_t    payload_bytes = 0;
    uint8_t     channels = 1;
    AudioCodec  codec = AudioCodec::Opus;
    const char* payload = nullptr;
};

bool parse_audio_packet(const std::array<char, 1024>& recv_buf, size_t bytes,
                        ParsedAudioPacket& packet) {
    if (bytes < sizeof(MsgHdr)) {
        return false;
    }

    MsgHdr hdr{};
    std::memcpy(&hdr, recv_buf.data(), sizeof(MsgHdr));
    const auto* raw = reinterpret_cast<const unsigned char*>(recv_buf.data());

    if (hdr.magic == AUDIO_MAGIC) {
        constexpr size_t kHeaderBytes = sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t);
        if (bytes < kHeaderBytes) {
            return false;
        }

        packet.sender_id = packet_builder::extract_sender_id(raw);
        packet.payload_bytes = packet_builder::extract_encoded_bytes(raw);
        if (packet.payload_bytes == 0 || packet.payload_bytes > AUDIO_BUF_SIZE ||
            bytes < kHeaderBytes + packet.payload_bytes) {
            return false;
        }

        packet.sequence = 0;
        packet.sample_rate = kSampleRate;
        packet.frame_count = static_cast<uint16_t>(kFrameCount);
        packet.channels = 1;
        packet.codec = AudioCodec::Opus;
        packet.payload = recv_buf.data() + kHeaderBytes;
        return true;
    }

    if (hdr.magic == AUDIO_V2_MAGIC) {
        constexpr size_t kHeaderBytes = sizeof(AudioHdrV2) - AUDIO_BUF_SIZE;
        if (bytes < kHeaderBytes) {
            return false;
        }

        AudioHdrV2 audio{};
        std::memcpy(&audio, recv_buf.data(), kHeaderBytes);
        if (audio.payload_bytes == 0 || audio.payload_bytes > AUDIO_BUF_SIZE ||
            bytes < kHeaderBytes + audio.payload_bytes || audio.channels == 0 ||
            audio.frame_count == 0 || audio.sample_rate == 0) {
            return false;
        }

        packet.sender_id = audio.sender_id;
        packet.sequence = audio.sequence;
        packet.sample_rate = audio.sample_rate;
        packet.frame_count = audio.frame_count;
        packet.payload_bytes = audio.payload_bytes;
        packet.channels = audio.channels;
        packet.codec = audio.codec;
        packet.payload = recv_buf.data() + kHeaderBytes;
        return true;
    }

    return false;
}

struct RoomStats {
    std::atomic<uint64_t> malformed_packets{0};
    std::atomic<uint64_t> audio_packets{0};
    std::atomic<uint64_t> decoded_packets{0};
    std::atomic<uint64_t> decode_failures{0};
    std::atomic<uint64_t> underruns{0};
    std::atomic<uint64_t> queue_drops{0};
    std::atomic<uint64_t> pcm_queue_drops{0};
    std::atomic<uint64_t> ffmpeg_write_failures{0};
    std::atomic<uint64_t> mixed_frames{0};
};

}  // namespace

class RoomListener {
public:
    RoomListener(asio::io_context& io_context, const ListenerServiceOptions& options,
                 RoomListenerConfig config)
        : io_context_(io_context),
          socket_(io_context, udp::endpoint(udp::v4(), 0)),
          options_(options),
          config_(std::move(config)),
          room_slug_(sanitize_path_component(config_.room_id)),
          output_path_(options_.hls_root / room_slug_),
          ping_timer_(io_context, 500ms, [this]() { send_ping(); }),
          alive_timer_(io_context, 5s, [this]() { send_alive(); }),
          cleanup_timer_(io_context, 10s, [this]() { cleanup_participants(); }) {}

    RoomListener(const RoomListener&) = delete;
    RoomListener& operator=(const RoomListener&) = delete;

    ~RoomListener() {
        stop();
    }

    const std::string& room_id() const {
        return config_.room_id;
    }

    void start() {
        if (running_.exchange(true)) {
            return;
        }

        if (!socket_.is_open()) {
            socket_.open(udp::v4());
            socket_.bind(udp::endpoint(udp::v4(), 0));
        }

        udp::resolver               resolver(io_context_);
        udp::resolver::results_type endpoints =
            resolver.resolve(udp::v4(), options_.server_address, std::to_string(options_.server_port));
        server_endpoint_ = *endpoints.begin();

        Log::info("[room:{}] local UDP port {}", config_.room_id, socket_.local_endpoint().port());
        Log::info("[room:{}] connecting to {}:{}", config_.room_id,
                  server_endpoint_.address().to_string(), server_endpoint_.port());

        prepare_output_path();
        if (options_.hls_enabled) {
            start_hls();
        } else {
            Log::warn("[room:{}] HLS disabled; PCM output will be discarded", config_.room_id);
        }

        do_receive();
        send_join();
        mix_thread_ = std::thread([this]() { mix_thread_loop(); });
        writer_thread_ = std::thread([this]() { writer_thread_loop(); });
    }

    void stop() {
        if (!running_.exchange(false)) {
            return;
        }

        Log::info("[room:{}] stopping", config_.room_id);
        send_leave_blocking();

        std::error_code ec;
        socket_.cancel(ec);
        socket_.close(ec);

        if (mix_thread_.joinable()) {
            mix_thread_.join();
        }
        if (writer_thread_.joinable()) {
            writer_thread_.join();
        }

        hls_broadcaster_.stop();
        participant_manager_.clear();

        if (options_.cleanup_hls_on_stop && options_.hls_enabled) {
            std::error_code remove_ec;
            fs::remove_all(output_path_, remove_ec);
            if (remove_ec) {
                Log::warn("[room:{}] failed to cleanup HLS output {}: {}", config_.room_id,
                          output_path_.string(), remove_ec.message());
            }
        }

        Log::info(
            "[room:{}] stopped packets={} decoded={} decode_failures={} underruns={} drops={} "
            "pcm_drops={} ffmpeg_failures={}",
            config_.room_id, stats_.audio_packets.load(), stats_.decoded_packets.load(),
            stats_.decode_failures.load(), stats_.underruns.load(), stats_.queue_drops.load(),
            stats_.pcm_queue_drops.load(), stats_.ffmpeg_write_failures.load());
    }

private:
    void prepare_output_path() {
        std::error_code ec;
        if (fs::exists(output_path_, ec)) {
            fs::remove_all(output_path_, ec);
            if (ec) {
                throw std::runtime_error("Failed to clear HLS output " + output_path_.string() +
                                         ": " + ec.message());
            }
        }
        fs::create_directories(output_path_, ec);
        if (ec) {
            throw std::runtime_error("Failed to create HLS output " + output_path_.string() +
                                     ": " + ec.message());
        }
    }

    void start_hls() {
        HLSBroadcaster::Config hls_config;
        hls_config.sample_rate = kSampleRate;
        hls_config.channels = static_cast<int>(kOutputChannels);
        hls_config.bitrate = options_.bitrate;
        hls_config.output_path = output_path_.string();
        hls_config.playlist_name = "stream";
        hls_config.segment_duration = options_.segment_duration;
        hls_config.playlist_size = options_.playlist_size;
        hls_config.ffmpeg_path = options_.ffmpeg_path;
        hls_config.verbose = true;
        hls_config.low_latency = true;

        if (!hls_broadcaster_.start(hls_config)) {
            throw std::runtime_error("Failed to start HLS for room " + config_.room_id);
        }
        Log::info("[room:{}] HLS playlist: {}/stream.m3u8", config_.room_id,
                  output_path_.string());
    }

    void do_receive() {
        socket_.async_receive_from(asio::buffer(recv_buf_), remote_endpoint_,
                                   [this](std::error_code error_code, std::size_t bytes) {
                                       on_receive(error_code, bytes);
                                   });
    }

    void on_receive(std::error_code error_code, std::size_t bytes) {
        if (!running_.load()) {
            return;
        }
        if (error_code) {
            if (error_code != asio::error::operation_aborted) {
                Log::warn("[room:{}] receive error: {}", config_.room_id, error_code.message());
                do_receive();
            }
            return;
        }

        if (remote_endpoint_ != server_endpoint_) {
            Log::warn("[room:{}] packet from unexpected endpoint {}:{}", config_.room_id,
                      remote_endpoint_.address().to_string(), remote_endpoint_.port());
        }

        if (bytes >= sizeof(MsgHdr)) {
            MsgHdr hdr{};
            std::memcpy(&hdr, recv_buf_.data(), sizeof(MsgHdr));
            if (hdr.magic == PING_MAGIC && bytes >= sizeof(SyncHdr)) {
                handle_ping();
            } else if (hdr.magic == CTRL_MAGIC && bytes >= sizeof(CtrlHdr)) {
                handle_ctrl(bytes);
            } else if (hdr.magic == AUDIO_MAGIC || hdr.magic == AUDIO_V2_MAGIC) {
                handle_audio(bytes);
            } else {
                Log::warn("[room:{}] unknown packet magic=0x{:08x} bytes={}", config_.room_id,
                          hdr.magic, bytes);
            }
        }

        do_receive();
    }

    void send_buffer(const void* data, size_t len) {
        auto buf = std::make_shared<std::vector<unsigned char>>(len);
        std::memcpy(buf->data(), data, len);
        socket_.async_send_to(asio::buffer(*buf), server_endpoint_,
                              [room = config_.room_id, buf](std::error_code ec, std::size_t) {
                                  if (ec) {
                                      Log::warn("[room:{}] send error: {}", room, ec.message());
                                  }
                              });
    }

    void send_join() {
        JoinHdr join{};
        join.magic = CTRL_MAGIC;
        join.type = CtrlHdr::Cmd::JOIN;
        join.role = ClientRole::Listener;
        packet_builder::write_fixed(join.room_id, config_.room_id);
        packet_builder::write_fixed(join.room_handle, config_.room_handle);
        packet_builder::write_fixed(join.profile_id, config_.profile_id);
        packet_builder::write_fixed(join.display_name, config_.display_name);
        packet_builder::write_fixed(join.join_token, config_.join_token);
        send_buffer(&join, sizeof(join));
        Log::info("[room:{}] JOIN sent as '{}'", config_.room_id, config_.display_name);
    }

    void send_leave_blocking() {
        CtrlHdr leave{};
        leave.magic = CTRL_MAGIC;
        leave.type = CtrlHdr::Cmd::LEAVE;
        std::error_code ec;
        socket_.send_to(asio::buffer(&leave, sizeof(leave)), server_endpoint_, 0, ec);
        if (ec) {
            Log::warn("[room:{}] failed to send LEAVE: {}", config_.room_id, ec.message());
        }
    }

    void send_ping() {
        if (!running_.load()) {
            return;
        }
        SyncHdr ping{};
        ping.magic = PING_MAGIC;
        ping.seq = ping_seq_++;
        const auto now = std::chrono::steady_clock::now();
        ping.t1_client_send =
            std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        send_buffer(&ping, sizeof(ping));
    }

    void send_alive() {
        if (!running_.load()) {
            return;
        }
        CtrlHdr alive{};
        alive.magic = CTRL_MAGIC;
        alive.type = CtrlHdr::Cmd::ALIVE;
        send_buffer(&alive, sizeof(alive));
    }

    void handle_ping() {
        // Listener service does not expose RTT yet; the PING exchange keeps server state fresh.
    }

    void handle_ctrl(size_t bytes) {
        if (bytes < sizeof(CtrlHdr)) {
            return;
        }

        CtrlHdr ctrl{};
        std::memcpy(&ctrl, recv_buf_.data(), sizeof(ctrl));
        switch (ctrl.type) {
            case CtrlHdr::Cmd::PARTICIPANT_LEAVE:
                participant_manager_.remove_participant(ctrl.participant_id);
                break;
            case CtrlHdr::Cmd::PARTICIPANT_INFO:
                if (bytes >= sizeof(ParticipantInfoHdr)) {
                    ParticipantInfoHdr info{};
                    std::memcpy(&info, recv_buf_.data(), sizeof(info));
                    participant_manager_.set_participant_metadata(
                        info.participant_id,
                        fixed_string(info.profile_id.data(), info.profile_id.size()),
                        fixed_string(info.display_name.data(), info.display_name.size()));
                }
                break;
            default:
                break;
        }
    }

    void handle_audio(size_t bytes) {
        ParsedAudioPacket parsed;
        if (!parse_audio_packet(recv_buf_, bytes, parsed) || parsed.codec != AudioCodec::Opus) {
            stats_.malformed_packets.fetch_add(1, std::memory_order_relaxed);
            Log::warn("[room:{}] rejected malformed/unsupported audio packet (bytes={})",
                      config_.room_id, bytes);
            return;
        }

        stats_.audio_packets.fetch_add(1, std::memory_order_relaxed);
        const int decoder_channels = std::max<int>(1, parsed.channels);

        if (!participant_manager_.exists(parsed.sender_id)) {
            if (!participant_manager_.register_participant(parsed.sender_id,
                                                           static_cast<int>(parsed.sample_rate),
                                                           decoder_channels)) {
                return;
            }
            participant_manager_.with_participant(parsed.sender_id, [&](ParticipantData& p) {
                p.jitter_buffer_floor_packets = kListenerJitterPackets;
                p.jitter_buffer_min_packets = kListenerJitterPackets;
                p.opus_queue_limit_packets = kListenerQueueLimitPackets;
                p.opus_jitter_manual_override = true;
            });
        }

        participant_manager_.with_participant(parsed.sender_id, [&](ParticipantData& participant) {
            size_t queue_size = participant.opus_queue.size_approx();
            while (queue_size >= participant.opus_queue_limit_packets) {
                OpusPacket discarded;
                if (!participant.opus_queue.try_dequeue(discarded)) {
                    break;
                }
                --queue_size;
                participant.opus_queue_limit_drops.fetch_add(1, std::memory_order_relaxed);
                stats_.queue_drops.fetch_add(1, std::memory_order_relaxed);
            }

            OpusPacket packet;
            std::memcpy(packet.data.data(), parsed.payload, parsed.payload_bytes);
            packet.size = parsed.payload_bytes;
            packet.timestamp = std::chrono::steady_clock::now();
            packet.codec = parsed.codec;
            packet.sequence = parsed.sequence;
            packet.sample_rate = parsed.sample_rate;
            packet.frame_count = parsed.frame_count;
            packet.channels = parsed.channels;
            participant.opus_queue.enqueue(packet);
            participant.last_packet_time = packet.timestamp;
            participant.last_codec = packet.codec;
            participant.last_packet_frame_count.store(packet.frame_count,
                                                      std::memory_order_relaxed);

            if (!participant.buffer_ready &&
                participant.opus_queue.size_approx() >= participant.jitter_buffer_min_packets) {
                participant.buffer_ready = true;
                Log::info("[room:{}] participant {} buffer ready ({} packets)", config_.room_id,
                          parsed.sender_id, participant.opus_queue.size_approx());
            }
        });
    }

    void cleanup_participants() {
        constexpr auto kTimeout = 20s;
        auto           now = std::chrono::steady_clock::now();
        auto removed_ids = participant_manager_.remove_timed_out_participants(now, kTimeout);
        for (uint32_t id: removed_ids) {
            Log::info("[room:{}] removed stale participant {}", config_.room_id, id);
        }
    }

    void mix_thread_loop() {
        const auto frame_duration = std::chrono::microseconds(
            static_cast<int64_t>((kFrameCount * 1'000'000) / kSampleRate));
        std::array<float, kFrameCount> mixed{};
        auto                          next_tick = std::chrono::steady_clock::now();

        Log::info("[room:{}] mix thread started", config_.room_id);

        while (running_.load()) {
            mixed.fill(0.0F);
            mix_one_frame(mixed.data(), kFrameCount);

            if (pcm_queue_.size_approx() < kPcmQueueSoftLimit) {
                pcm_queue_.enqueue(mixed);
            } else {
                stats_.pcm_queue_drops.fetch_add(1, std::memory_order_relaxed);
            }

            next_tick += frame_duration;
            const auto now = std::chrono::steady_clock::now();
            if (now > next_tick + 5 * frame_duration) {
                next_tick = now;
            }
            std::this_thread::sleep_until(next_tick);
        }

        Log::info("[room:{}] mix thread stopped", config_.room_id);
    }

    void writer_thread_loop() {
        std::array<float, kFrameCount> frame{};
        Log::info("[room:{}] writer thread started", config_.room_id);

        while (running_.load() || pcm_queue_.size_approx() > 0) {
            if (!pcm_queue_.try_dequeue(frame)) {
                std::this_thread::sleep_for(1ms);
                continue;
            }
            if (options_.simulate_ffmpeg_write_failures) {
                stats_.ffmpeg_write_failures.fetch_add(1, std::memory_order_relaxed);
                continue;
            }
            if (options_.hls_enabled && hls_broadcaster_.is_running() &&
                !hls_broadcaster_.write_audio(frame.data(), kFrameCount)) {
                stats_.ffmpeg_write_failures.fetch_add(1, std::memory_order_relaxed);
            }
        }

        Log::info("[room:{}] writer thread stopped", config_.room_id);
    }

    void mix_one_frame(float* output, size_t frame_count) {
        int active_count = 0;

        participant_manager_.for_each([&](uint32_t participant_id, ParticipantData& participant) {
            if (participant.is_muted || !participant.buffer_ready) {
                return;
            }

            const int channels = std::max(1, participant.decoder->get_channels());
            size_t    output_offset = 0;
            float     rms_sum = 0.0F;
            size_t    rms_frames = 0;

            while (output_offset < frame_count) {
                OpusPacket packet;
                int        decoded_samples = 0;
                if (participant.opus_queue.try_dequeue(packet)) {
                    const int packet_frames =
                        packet.frame_count > 0 ? packet.frame_count : static_cast<uint16_t>(frame_count);
                    decoded_samples = participant.decoder->decode_into(
                        packet.get_data(), static_cast<int>(packet.get_size()),
                        participant.pcm_buffer.data(), packet_frames);
                    if (decoded_samples <= 0) {
                        stats_.decode_failures.fetch_add(1, std::memory_order_relaxed);
                        break;
                    }
                    stats_.decoded_packets.fetch_add(1, std::memory_order_relaxed);
                } else {
                    decoded_samples = participant.decoder->decode_plc(
                        participant.pcm_buffer.data(), static_cast<int>(frame_count - output_offset));
                    participant.plc_count++;
                    participant.underrun_count++;
                    stats_.underruns.fetch_add(1, std::memory_order_relaxed);
                    if (decoded_samples <= 0) {
                        participant.buffer_ready = false;
                        break;
                    }
                }

                const int decoded_frames = decoded_samples / channels;
                if (decoded_frames <= 0) {
                    break;
                }

                const size_t frames_to_mix =
                    std::min(frame_count - output_offset, static_cast<size_t>(decoded_frames));
                for (size_t frame = 0; frame < frames_to_mix; ++frame) {
                    float mono = 0.0F;
                    for (int ch = 0; ch < channels; ++ch) {
                        mono += participant.pcm_buffer[(frame * channels) + static_cast<size_t>(ch)];
                    }
                    mono /= static_cast<float>(channels);
                    output[output_offset + frame] += mono * participant.gain;
                    rms_sum += mono * mono;
                }
                output_offset += frames_to_mix;
                rms_frames += frames_to_mix;
            }

            if (output_offset == 0) {
                return;
            }

            const float rms = rms_frames == 0
                                  ? 0.0F
                                  : std::sqrt(rms_sum / static_cast<float>(rms_frames));
            participant.current_level = rms;
            participant.is_speaking = audio_analysis::detect_voice_activity(rms);
            active_count++;

            (void)participant_id;
        });

        if (active_count > 1) {
            const float gain = 0.85F / static_cast<float>(active_count);
            for (size_t i = 0; i < frame_count; ++i) {
                output[i] *= gain;
            }
        }

        for (size_t i = 0; i < frame_count; ++i) {
            output[i] = std::clamp(output[i] * options_.output_gain, -1.0F, 1.0F);
        }
        stats_.mixed_frames.fetch_add(1, std::memory_order_relaxed);
    }

    asio::io_context&            io_context_;
    udp::socket                  socket_;
    udp::endpoint                server_endpoint_;
    udp::endpoint                remote_endpoint_;
    const ListenerServiceOptions& options_;
    RoomListenerConfig           config_;
    std::string                  room_slug_;
    fs::path                     output_path_;

    std::array<char, 1024> recv_buf_{};
    ParticipantManager     participant_manager_;
    HLSBroadcaster         hls_broadcaster_;
    RoomStats              stats_;

    moodycamel::ConcurrentQueue<std::array<float, kFrameCount>> pcm_queue_;
    std::thread                                                mix_thread_;
    std::thread                                                writer_thread_;
    std::atomic<bool>                                          running_{false};
    uint32_t                                                   ping_seq_ = 0;

    PeriodicTimer ping_timer_;
    PeriodicTimer alive_timer_;
    PeriodicTimer cleanup_timer_;
};

class ListenerService {
public:
    ListenerService(asio::io_context& io_context, ListenerServiceOptions options)
        : io_context_(io_context), options_(std::move(options)) {
        rooms_.reserve(options_.rooms.size());
        for (const auto& room: options_.rooms) {
            rooms_.push_back(std::make_unique<RoomListener>(io_context_, options_, room));
        }
    }

    void start() {
        for (auto& room: rooms_) {
            room->start();
        }
        for (const auto& [room_id, delay_ms]: options_.room_stop_after_ms) {
            auto timer = std::make_unique<asio::steady_timer>(io_context_,
                                                              std::chrono::milliseconds(delay_ms));
            timer->async_wait([this, room_id](const std::error_code& ec) {
                if (!ec) {
                    stop_room(room_id);
                }
            });
            room_stop_timers_.push_back(std::move(timer));
        }
        for (const auto& [room_id, delay_ms]: options_.room_restart_after_ms) {
            auto timer = std::make_unique<asio::steady_timer>(io_context_,
                                                              std::chrono::milliseconds(delay_ms));
            timer->async_wait([this, room_id](const std::error_code& ec) {
                if (!ec) {
                    restart_room(room_id);
                }
            });
            room_stop_timers_.push_back(std::move(timer));
        }
    }

    void stop() {
        for (auto& room: rooms_) {
            room->stop();
        }
    }

private:
    void stop_room(const std::string& room_id) {
        for (auto& room: rooms_) {
            if (room->room_id() == room_id) {
                Log::info("[room:{}] stop requested", room_id);
                room->stop();
                return;
            }
        }
        Log::warn("[room:{}] stop requested for unknown room", room_id);
    }

    void restart_room(const std::string& room_id) {
        for (auto& room: rooms_) {
            if (room->room_id() == room_id) {
                Log::info("[room:{}] restart requested", room_id);
                room->stop();
                room->start();
                return;
            }
        }
        Log::warn("[room:{}] restart requested for unknown room", room_id);
    }

    asio::io_context&                      io_context_;
    ListenerServiceOptions                 options_;
    std::vector<std::unique_ptr<RoomListener>> rooms_;
    std::vector<std::unique_ptr<asio::steady_timer>> room_stop_timers_;
};

int main(int argc, char* argv[]) {
    try {
        auto& log = Logger::instance();
        log.init(true, true, false, "", spdlog::level::info);

        ListenerServiceOptions options = parse_options(argc, argv);

        Log::info("listener_service starting");
        Log::info("server={} port={} rooms={} hls_root={} hls_enabled={}", options.server_address,
                  options.server_port, options.rooms.size(), options.hls_root.string(),
                  options.hls_enabled);

        asio::io_context io_context;
        auto             work = asio::make_work_guard(io_context);
        const std::optional<int> duration_ms = options.duration_ms;
        ListenerService          service(io_context, std::move(options));

        asio::signal_set signals(io_context, SIGINT, SIGTERM);
        signals.async_wait([&](const std::error_code&, int signal_number) {
            Log::info("received signal {}; stopping listener_service", signal_number);
            service.stop();
            work.reset();
            io_context.stop();
        });

        service.start();

        std::unique_ptr<asio::steady_timer> duration_timer;
        if (duration_ms.has_value()) {
            duration_timer =
                std::make_unique<asio::steady_timer>(io_context, std::chrono::milliseconds(*duration_ms));
            duration_timer->async_wait([&](const std::error_code& ec) {
                if (!ec) {
                    Log::info("duration elapsed; stopping listener_service");
                    service.stop();
                    work.reset();
                    io_context.stop();
                }
            });
        }

        io_context.run();
        service.stop();
        Log::info("listener_service stopped");
    } catch (const std::exception& e) {
        Log::error("listener_service error: {}", e.what());
        return 1;
    }

    return 0;
}
