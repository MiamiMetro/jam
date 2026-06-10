#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
#include <memory>
#include <string>
#include <system_error>
#include <unordered_map>
#include <vector>

#include <asio.hpp>
#include <asio/buffer.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <spdlog/common.h>

#include "audio_packet.h"
#include "client_manager.h"
#include "endpoint_hash.h"
#include "logger.h"
#include "message_validator.h"
#include "performer_join_token.h"
#include "packet_builder.h"
#include "periodic_timer.h"
#include "protocol.h"
#include "sequence_tracker.h"
#include "server_config.h"

using asio::ip::udp;
using namespace std::chrono_literals;
using namespace server_config;

constexpr int64_t METRONOME_SCHEDULE_AHEAD_NS = 150'000'000;

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

struct ServerOptions {
    short       port = 9999;
    bool        allow_insecure_dev_joins = false;
    std::string server_id = "local-dev";
    std::string join_secret;
    std::string log_file_path;
};

template <size_t N>
std::string fixed_string(const Bytes<N>& bytes) {
    const auto end = std::find(bytes.begin(), bytes.end(), '\0');
    return std::string(bytes.begin(), end);
}

class Server {
public:
    Server(asio::io_context& io_context, const ServerOptions& options)
        : options_(options),
          socket_(io_context, udp::endpoint(udp::v4(), options.port)),
          alive_check_timer_(io_context, server_config::ALIVE_CHECK_INTERVAL,
                             [this]() { alive_check_timer_callback(); }) {
        // Optimize UDP socket buffers for high-throughput packet forwarding
        try {
            constexpr int SOCKET_BUFFER_BYTES = 4 * 1024 * 1024;
            socket_.set_option(asio::socket_base::receive_buffer_size(SOCKET_BUFFER_BYTES));
            socket_.set_option(asio::socket_base::send_buffer_size(SOCKET_BUFFER_BYTES));
            Log::info("UDP socket buffers optimized for packet forwarding ({} bytes)",
                      SOCKET_BUFFER_BYTES);
        } catch (const std::exception& e) {
            Log::warn("Failed to set socket buffer sizes: {}", e.what());
        }

        Log::info("SFU server ready: forwarding audio between clients");
        do_receive();
    }

    ~Server() {
        socket_.close();
    }

    void do_receive() {
        socket_.async_receive_from(asio::buffer(recv_buf_), remote_endpoint_,
                                   [this](std::error_code error_code, std::size_t bytes) {
                                       on_receive(error_code, bytes);
                                   });
    }

    void on_receive(std::error_code error_code, std::size_t bytes) {
        if (error_code) {
            handle_receive_error(error_code);
            return;
        }

        if (!message_validator::has_valid_header(bytes)) {
            do_receive();
            return;
        }

        MsgHdr hdr{};
        std::memcpy(&hdr, recv_buf_.data(), sizeof(MsgHdr));

        if (hdr.magic == PING_MAGIC) {
            handle_ping_message(bytes);
        } else if (hdr.magic == CTRL_MAGIC) {
            handle_ctrl_message(bytes);
        } else if (hdr.magic == AUDIO_MAGIC || hdr.magic == AUDIO_V2_MAGIC) {
            handle_audio_message(bytes);
        }

        do_receive();  // start next receive immediately
    }

    // Send with optional shared_ptr to keep data alive during async operation
    void send(void* data, std::size_t len, const udp::endpoint& target,
              const std::shared_ptr<std::vector<unsigned char>>& keep_alive = nullptr) {
        auto send_buffer = keep_alive;
        if (send_buffer == nullptr) {
            const auto* bytes = static_cast<const unsigned char*>(data);
            send_buffer = std::make_shared<std::vector<unsigned char>>(bytes, bytes + len);
        }

        socket_.async_send_to(asio::buffer(send_buffer->data(), send_buffer->size()), target,
                              [send_buffer](std::error_code error_code, std::size_t) {
                                  if (error_code) {
                                      Log::error("send error: {}", error_code.message());
                                  }
                              });
    }

private:
    struct UnknownEndpointInfo {
        std::chrono::steady_clock::time_point first_seen;
        std::chrono::steady_clock::time_point last_seen;
        std::chrono::steady_clock::time_point last_join_required_sent;
        uint64_t                              drops = 0;
        bool                                  first_log_emitted = false;
    };

    struct AudioForwardStats {
        uint64_t forwarded_total = 0;
        uint64_t sequence_gaps_total = 0;
        uint64_t sequence_gap_recoveries_total = 0;
        uint64_t sequence_unresolved_gaps = 0;
        uint64_t sequence_late_or_reordered_total = 0;
        uint64_t forwarded_interval = 0;
        uint64_t sequence_gaps_interval = 0;
        uint64_t sequence_gap_recoveries_interval = 0;
        uint64_t sequence_late_or_reordered_interval = 0;
        SequenceArrivalTracker sequence_tracker;
    };

    struct AudioIngressStats {
        udp::endpoint endpoint;
        uint64_t received_total = 0;
        uint64_t sequence_gaps_total = 0;
        uint64_t sequence_gap_recoveries_total = 0;
        uint64_t sequence_unresolved_gaps = 0;
        uint64_t sequence_late_or_reordered_total = 0;
        uint64_t received_interval = 0;
        uint64_t sequence_gaps_interval = 0;
        uint64_t sequence_gap_recoveries_interval = 0;
        uint64_t sequence_late_or_reordered_interval = 0;
        SequenceArrivalTracker sequence_tracker;
    };

    void handle_receive_error(std::error_code error_code) {
        if (error_code == asio::error::operation_aborted) {
            return;
        }

        Log::warn("UDP receive error: {}; keeping participants registered",
                  error_code.message());
        do_receive();  // keep listening
    }

    void handle_ping_message(std::size_t bytes) {
        if (!message_validator::is_valid_ping(bytes) || !client_manager_.exists(remote_endpoint_)) {
            return;
        }

        SyncHdr shdr{};
        std::memcpy(&shdr, recv_buf_.data(), sizeof(SyncHdr));
        auto now = std::chrono::steady_clock::now();
        auto nanoseconds =
            std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        shdr.t2_server_recv = nanoseconds;
        shdr.t3_server_send = nanoseconds;
        auto packet = std::make_shared<std::vector<unsigned char>>(sizeof(SyncHdr));
        std::memcpy(packet->data(), &shdr, sizeof(SyncHdr));
        send(packet->data(), packet->size(), remote_endpoint_, packet);
    }

    void handle_ctrl_message(std::size_t bytes) {
        if (bytes < sizeof(CtrlHdr)) {
            return;
        }

        CtrlHdr chdr{};
        std::memcpy(&chdr, recv_buf_.data(), sizeof(CtrlHdr));

        auto now = std::chrono::steady_clock::now();

        switch (chdr.type) {
            case CtrlHdr::Cmd::JOIN:
                handle_join(bytes, now);
                break;
            case CtrlHdr::Cmd::LEAVE: {
                Log::info("Client LEAVE: {}:{}", remote_endpoint_.address().to_string(),
                          remote_endpoint_.port());
                auto leaving_client = client_manager_.remove_client_with_info(remote_endpoint_);
                if (leaving_client.has_value() &&
                    leaving_client->role == ClientRole::Performer) {
                    broadcast_participant_leave(leaving_client->client_id);
                }
                break;
            }
            case CtrlHdr::Cmd::ALIVE: {
                if (client_manager_.exists(remote_endpoint_)) {
                    client_manager_.update_alive(remote_endpoint_, now);
                } else {
                    send_join_required(remote_endpoint_);
                }
                break;
            }
            case CtrlHdr::Cmd::PARTICIPANT_LEAVE:
                // Clients shouldn't send this, only server broadcasts it
                Log::warn("Client sent PARTICIPANT_LEAVE (should only come from server)");
                break;
            case CtrlHdr::Cmd::METRONOME_SYNC:
                handle_metronome_sync(bytes, now);
                break;
            default:
                Log::warn("Unknown CTRL cmd: {} from {}:{}", static_cast<int>(chdr.type),
                          remote_endpoint_.address().to_string(), remote_endpoint_.port());
                break;
        }
    }

    void handle_join(std::size_t bytes, std::chrono::steady_clock::time_point now) {
        if (bytes < JOIN_HDR_LEGACY_SIZE) {
            Log::warn("Rejecting JOIN from {}:{}: packet too small",
                      remote_endpoint_.address().to_string(), remote_endpoint_.port());
            return;
        }

        JoinHdr join{};
        std::memcpy(&join, recv_buf_.data(), std::min(bytes, sizeof(JoinHdr)));

        const std::string room_id      = fixed_string(join.room_id);
        const std::string profile_id   = fixed_string(join.profile_id);
        const std::string display_name = fixed_string(join.display_name);
        const std::string token        = fixed_string(join.join_token);
        const ClientRole  role = join.role == ClientRole::Listener ? ClientRole::Listener
                                                                    : ClientRole::Performer;
        const std::string role_name = role == ClientRole::Listener ? "listener" : "performer";

        if (room_id.empty() || profile_id.empty()) {
            Log::warn("Rejecting JOIN from {}:{}: missing room or profile id",
                      remote_endpoint_.address().to_string(), remote_endpoint_.port());
            return;
        }
        if (token.empty() && !options_.allow_insecure_dev_joins) {
            Log::warn("Rejecting JOIN from {}:{} room '{}': missing token",
                      remote_endpoint_.address().to_string(), remote_endpoint_.port(), room_id);
            return;
        }
        if (!token.empty() && !options_.allow_insecure_dev_joins) {
            const auto result = performer_join_token::validate(
                token, options_.join_secret, options_.server_id, room_id, profile_id, role_name);
            if (!result.ok) {
                Log::warn("Rejecting JOIN from {}:{} room '{}': {}",
                          remote_endpoint_.address().to_string(), remote_endpoint_.port(), room_id,
                          result.reason);
                return;
            }
        }

        auto registration = client_manager_.register_client(remote_endpoint_, now, room_id,
                                                            profile_id, display_name, role);
        for (uint32_t removed_client_id: registration.removed_client_ids) {
            Log::info("Removed stale duplicate participant ID {} for room='{}' user='{}'",
                      removed_client_id, room_id, profile_id);
            broadcast_participant_leave(removed_client_id);
        }

        uint32_t client_id = registration.client_id;
        Log::info("JOIN: {}:{} room='{}' user='{}' display='{}' role='{}' (ID: {}, {})",
                  remote_endpoint_.address().to_string(), remote_endpoint_.port(), room_id,
                  profile_id, display_name, role_name, client_id,
                  token.empty() ? "insecure-dev" : "token-present");
        send_join_ack(remote_endpoint_, client_id);
        if (role == ClientRole::Performer) {
            broadcast_participant_info(remote_endpoint_, client_id, profile_id, display_name);
        }
        send_existing_participant_info_to(remote_endpoint_);
    }

    void handle_audio_message(std::size_t bytes) {
        MsgHdr hdr{};
        std::memcpy(&hdr, recv_buf_.data(), sizeof(MsgHdr));

        const size_t min_audio_packet_size =
            hdr.magic == AUDIO_V2_MAGIC ? sizeof(AudioHdrV2) - AUDIO_BUF_SIZE
                                        : sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t);
        if (!message_validator::is_valid_audio_packet(bytes, min_audio_packet_size)) {
            Log::debug("Audio packet too small: {} bytes", bytes);
            return;
        }

        if (!client_manager_.exists(remote_endpoint_)) {
            record_unknown_audio_drop(remote_endpoint_);
            return;
        }

        if (!validate_complete_audio_packet(bytes)) {
            return;
        }

        client_manager_.update_alive(remote_endpoint_, std::chrono::steady_clock::now());

        // Get sender's client ID
        uint32_t sender_id = client_manager_.get_client_id(remote_endpoint_);

        // Embed sender_id in the packet
        packet_builder::embed_sender_id(reinterpret_cast<unsigned char*>(recv_buf_.data()),
                                        sender_id);

        // SFU: Forward audio packet to all other clients (not back to sender)
        // Copy packet data before forwarding since recv_buf_ will be reused by do_receive()
        auto packet_copy = std::make_shared<std::vector<unsigned char>>(recv_buf_.data(),
                                                                        recv_buf_.data() + bytes);
        record_audio_ingress(sender_id, remote_endpoint_, packet_copy->data(), bytes);
        forward_audio_to_others(remote_endpoint_, packet_copy->data(), bytes, packet_copy);
    }

    bool validate_complete_audio_packet(std::size_t bytes) {
        MsgHdr hdr{};
        std::memcpy(&hdr, recv_buf_.data(), sizeof(MsgHdr));
        if (hdr.magic != AUDIO_V2_MAGIC) {
            return true;
        }

        const auto* packet_data = reinterpret_cast<const unsigned char*>(recv_buf_.data());
        std::string reason;
        if (!audio_packet::validate_audio_packet_v2_bytes(packet_data, bytes, &reason)) {
            AudioHdrV2 audio{};
            uint16_t payload_bytes = 0;
            if (bytes >= audio_packet::v2_header_size()) {
                std::memcpy(&audio, packet_data, audio_packet::v2_header_size());
                payload_bytes = audio.payload_bytes;
            }
            ++invalid_audio_drops_since_log_;
            Log::warn(
                "Dropping invalid V2 audio from {}:{}: reason={} got {}, expected {} "
                "(payload_bytes={}, seq={})",
                remote_endpoint_.address().to_string(), remote_endpoint_.port(), reason, bytes,
                audio_packet::v2_header_size() + payload_bytes, payload_bytes, audio.sequence);
            return false;
        }

        return true;
    }

    void handle_metronome_sync(std::size_t bytes, std::chrono::steady_clock::time_point now) {
        if (bytes < sizeof(MetronomeSyncHdr)) {
            Log::debug("Metronome sync packet too small: {} bytes", bytes);
            return;
        }

        if (!client_manager_.exists(remote_endpoint_)) {
            Log::warn("Dropping metronome sync from unjoined endpoint {}:{}",
                      remote_endpoint_.address().to_string(), remote_endpoint_.port());
            send_join_required(remote_endpoint_);
            return;
        }

        client_manager_.update_alive(remote_endpoint_, now);

        MetronomeSyncHdr sync{};
        std::memcpy(&sync, recv_buf_.data(), sizeof(MetronomeSyncHdr));
        sync.sequence = ++metronome_sequence_;
        sync.effective_server_time_ns = steady_ns(now) + METRONOME_SCHEDULE_AHEAD_NS;
        std::memcpy(recv_buf_.data(), &sync, sizeof(MetronomeSyncHdr));

        auto packet_copy = std::make_shared<std::vector<unsigned char>>(
            recv_buf_.data(), recv_buf_.data() + sizeof(MetronomeSyncHdr));
        auto endpoints = client_manager_.get_room_endpoints_except(remote_endpoint_);
        endpoints.push_back(remote_endpoint_);
        for (const auto& endpoint: endpoints) {
            send(packet_copy->data(), packet_copy->size(), endpoint, packet_copy);
        }
    }

    static int64_t steady_ns(std::chrono::steady_clock::time_point time) {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(time.time_since_epoch())
            .count();
    }

    void record_unknown_audio_drop(const udp::endpoint& endpoint) {
        const auto now = std::chrono::steady_clock::now();
        cleanup_unknown_endpoints(now);

        ++unknown_audio_drops_since_log_;

        auto it = unknown_endpoints_.find(endpoint);
        if (it == unknown_endpoints_.end()) {
            if (unknown_endpoints_.size() < server_config::MAX_UNKNOWN_ENDPOINTS) {
                auto [inserted_it, inserted] = unknown_endpoints_.emplace(
                    endpoint, UnknownEndpointInfo{now, now, {}, 0, false});
                it = inserted_it;
                (void)inserted;
            }
        }

        if (it != unknown_endpoints_.end()) {
            it->second.last_seen = now;
            ++it->second.drops;
            constexpr auto JOIN_REQUIRED_INTERVAL = 1s;
            if (it->second.last_join_required_sent.time_since_epoch().count() == 0 ||
                now - it->second.last_join_required_sent >= JOIN_REQUIRED_INTERVAL) {
                send_join_required(endpoint);
                it->second.last_join_required_sent = now;
            }
            if (!it->second.first_log_emitted) {
                Log::warn("Dropping audio from unjoined endpoint {}:{}",
                          endpoint.address().to_string(), endpoint.port());
                it->second.first_log_emitted = true;
            }
        }

        if (now - last_unknown_audio_summary_ >= server_config::UNKNOWN_ENDPOINT_LOG_INTERVAL) {
            if (unknown_audio_drops_since_log_ > 0) {
                Log::warn("Dropped {} audio packets from unjoined endpoints in the last {} ms (tracking {} endpoints)",
                          unknown_audio_drops_since_log_,
                          std::chrono::duration_cast<std::chrono::milliseconds>(
                              server_config::UNKNOWN_ENDPOINT_LOG_INTERVAL)
                              .count(),
                          unknown_endpoints_.size());
                unknown_audio_drops_since_log_ = 0;
            }
            last_unknown_audio_summary_ = now;
        }
    }

    void cleanup_unknown_endpoints(std::chrono::steady_clock::time_point now) {
        for (auto it = unknown_endpoints_.begin(); it != unknown_endpoints_.end();) {
            if (now - it->second.last_seen > server_config::UNKNOWN_ENDPOINT_TTL) {
                it = unknown_endpoints_.erase(it);
            } else {
                ++it;
            }
        }
    }

    void alive_check_timer_callback() {
        auto now = std::chrono::steady_clock::now();
        auto timed_out_ids =
            client_manager_.remove_timed_out_clients(now, server_config::CLIENT_TIMEOUT);

        for (uint32_t timed_out_id: timed_out_ids) {
            Log::info("Client timed out (ID: {})", timed_out_id);
            broadcast_participant_leave(timed_out_id);
        }

        log_audio_forward_summary();
    }

    void broadcast_participant_leave(uint32_t participant_id) {
        // Broadcast to all clients that a participant has left
        auto buf = packet_builder::create_participant_leave_packet(participant_id);

        // Get endpoints from manager (safe copy)
        auto endpoints = client_manager_.get_all_endpoints();

        for (const auto& endpoint: endpoints) {
            send(buf->data(), sizeof(CtrlHdr), endpoint, buf);
        }
    }

    void send_join_ack(const udp::endpoint& endpoint, uint32_t participant_id) {
        auto buf = std::make_shared<std::vector<unsigned char>>(sizeof(CtrlHdr));
        CtrlHdr ack{};
        ack.magic = CTRL_MAGIC;
        ack.type = CtrlHdr::Cmd::JOIN_ACK;
        ack.participant_id = participant_id;
        std::memcpy(buf->data(), &ack, sizeof(CtrlHdr));
        send(buf->data(), buf->size(), endpoint, buf);
    }

    void send_join_required(const udp::endpoint& endpoint) {
        auto buf = std::make_shared<std::vector<unsigned char>>(sizeof(CtrlHdr));
        CtrlHdr required{};
        required.magic = CTRL_MAGIC;
        required.type = CtrlHdr::Cmd::JOIN_REQUIRED;
        std::memcpy(buf->data(), &required, sizeof(CtrlHdr));
        send(buf->data(), buf->size(), endpoint, buf);
    }

    void broadcast_participant_info(const udp::endpoint& joined_endpoint, uint32_t participant_id,
                                    const std::string& profile_id,
                                    const std::string& display_name) {
        auto buf = packet_builder::create_participant_info_packet(participant_id, profile_id,
                                                                  display_name);
        auto endpoints = client_manager_.get_room_endpoints_except(joined_endpoint);
        endpoints.push_back(joined_endpoint);

        for (const auto& endpoint: endpoints) {
            send(buf->data(), sizeof(ParticipantInfoHdr), endpoint, buf);
        }
    }

    void send_existing_participant_info_to(const udp::endpoint& joined_endpoint) {
        auto existing_clients = client_manager_.get_room_clients_except(joined_endpoint);
        for (const auto& [endpoint, info]: existing_clients) {
            if (info.role != ClientRole::Performer) {
                continue;
            }
            if (info.profile_id.empty() && info.display_name.empty()) {
                continue;
            }
            auto buf = packet_builder::create_participant_info_packet(
                info.client_id, info.profile_id, info.display_name);
            send(buf->data(), sizeof(ParticipantInfoHdr), joined_endpoint, buf);
        }
    }

    void forward_audio_to_others(
        const udp::endpoint& sender, void* packet_data, std::size_t packet_size,
        const std::shared_ptr<std::vector<unsigned char>>& keep_alive = nullptr) {
        // Forward the audio packet to clients in the same room except the sender
        // keep_alive ensures packet data remains valid during async sends

        auto endpoints = client_manager_.get_room_endpoints_except(sender);
        const uint32_t sender_id = client_manager_.get_client_id(sender);

        for (const auto& endpoint: endpoints) {
            record_audio_forward(sender_id, endpoint, packet_data, packet_size);
            send(packet_data, packet_size, endpoint, keep_alive);
        }
    }

    void record_audio_ingress(uint32_t sender_id, const udp::endpoint& endpoint, void* packet_data,
                              std::size_t packet_size) {
        if (sender_id == 0 || packet_size < sizeof(MsgHdr)) {
            return;
        }

        MsgHdr hdr{};
        std::memcpy(&hdr, packet_data, sizeof(MsgHdr));
        if (hdr.magic != AUDIO_V2_MAGIC || packet_size < audio_packet::v2_header_size()) {
            return;
        }

        AudioHdrV2 audio{};
        std::memcpy(&audio, packet_data, audio_packet::v2_header_size());
        auto& stats = audio_ingress_stats_[sender_id];
        stats.endpoint = endpoint;
        ++stats.received_total;
        ++stats.received_interval;
        const auto sequence_delta = stats.sequence_tracker.record(audio.sequence);
        if (sequence_delta.gaps_detected > 0) {
            stats.sequence_gaps_total += sequence_delta.gaps_detected;
            stats.sequence_gaps_interval += sequence_delta.gaps_detected;
        }
        if (sequence_delta.gaps_recovered > 0) {
            stats.sequence_gap_recoveries_total += sequence_delta.gaps_recovered;
            stats.sequence_gap_recoveries_interval += sequence_delta.gaps_recovered;
        }
        stats.sequence_unresolved_gaps = stats.sequence_tracker.unresolved_gaps();
        if (sequence_delta.late_or_duplicate) {
            ++stats.sequence_late_or_reordered_total;
            ++stats.sequence_late_or_reordered_interval;
        }
    }

    void record_audio_forward(uint32_t sender_id, const udp::endpoint& target, void* packet_data,
                              std::size_t packet_size) {
        if (sender_id == 0 || packet_size < sizeof(MsgHdr)) {
            return;
        }

        MsgHdr hdr{};
        std::memcpy(&hdr, packet_data, sizeof(MsgHdr));
        if (hdr.magic != AUDIO_V2_MAGIC || packet_size < sizeof(AudioHdrV2) - AUDIO_BUF_SIZE) {
            return;
        }

        const uint32_t target_id = client_manager_.get_client_id(target);
        if (target_id == 0) {
            return;
        }

        AudioHdrV2 audio{};
        std::memcpy(&audio, packet_data, audio_packet::v2_header_size());
        const uint64_t key = (static_cast<uint64_t>(sender_id) << 32) | target_id;
        auto& stats = audio_forward_stats_[key];
        ++stats.forwarded_total;
        ++stats.forwarded_interval;
        const auto sequence_delta = stats.sequence_tracker.record(audio.sequence);
        if (sequence_delta.gaps_detected > 0) {
            stats.sequence_gaps_total += sequence_delta.gaps_detected;
            stats.sequence_gaps_interval += sequence_delta.gaps_detected;
        }
        if (sequence_delta.gaps_recovered > 0) {
            stats.sequence_gap_recoveries_total += sequence_delta.gaps_recovered;
            stats.sequence_gap_recoveries_interval += sequence_delta.gaps_recovered;
        }
        stats.sequence_unresolved_gaps = stats.sequence_tracker.unresolved_gaps();
        if (sequence_delta.late_or_duplicate) {
            ++stats.sequence_late_or_reordered_total;
            ++stats.sequence_late_or_reordered_interval;
        }
    }

    void log_audio_forward_summary() {
        if (invalid_audio_drops_since_log_ > 0) {
            Log::warn("Dropped {} invalid/incomplete audio packets in the last interval",
                      invalid_audio_drops_since_log_);
            invalid_audio_drops_since_log_ = 0;
        }

        for (auto& [sender_id, stats]: audio_ingress_stats_) {
            if (stats.received_interval == 0 && stats.sequence_gaps_interval == 0 &&
                stats.sequence_late_or_reordered_interval == 0) {
                continue;
            }

            Log::info(
                "Ingress diag interval sender={} endpoint={}:{} received={} seq_gap={} "
                "gap_rate={:.1f}% seq_recovered={} seq_unresolved={} seq_late={} late={:.1f}% "
                "total received={} seq_gap={} seq_recovered={} seq_unresolved={} seq_late={}",
                sender_id, stats.endpoint.address().to_string(), stats.endpoint.port(),
                stats.received_interval, stats.sequence_gaps_interval,
                percent_missing(stats.sequence_gaps_interval, stats.received_interval),
                stats.sequence_gap_recoveries_interval, stats.sequence_unresolved_gaps,
                stats.sequence_late_or_reordered_interval,
                percent_of_packets(stats.sequence_late_or_reordered_interval,
                                   stats.received_interval),
                stats.received_total, stats.sequence_gaps_total,
                stats.sequence_gap_recoveries_total, stats.sequence_unresolved_gaps,
                stats.sequence_late_or_reordered_total);
            stats.received_interval = 0;
            stats.sequence_gaps_interval = 0;
            stats.sequence_gap_recoveries_interval = 0;
            stats.sequence_late_or_reordered_interval = 0;
        }

        for (auto& [key, stats]: audio_forward_stats_) {
            if (stats.forwarded_interval == 0 && stats.sequence_gaps_interval == 0 &&
                stats.sequence_late_or_reordered_interval == 0) {
                continue;
            }

            const uint32_t sender_id = static_cast<uint32_t>(key >> 32);
            const uint32_t target_id = static_cast<uint32_t>(key & 0xFFFFFFFFU);
            Log::info(
                "Forward diag interval sender={} target={} forwarded={} seq_gap={} gap_rate={:.1f}% "
                "seq_recovered={} seq_unresolved={} seq_late={} late={:.1f}% "
                "total forwarded={} seq_gap={} seq_recovered={} seq_unresolved={} seq_late={}",
                sender_id, target_id, stats.forwarded_interval, stats.sequence_gaps_interval,
                percent_missing(stats.sequence_gaps_interval, stats.forwarded_interval),
                stats.sequence_gap_recoveries_interval, stats.sequence_unresolved_gaps,
                stats.sequence_late_or_reordered_interval,
                percent_of_packets(stats.sequence_late_or_reordered_interval,
                                   stats.forwarded_interval),
                stats.forwarded_total,
                stats.sequence_gaps_total, stats.sequence_gap_recoveries_total,
                stats.sequence_unresolved_gaps, stats.sequence_late_or_reordered_total);
            stats.forwarded_interval = 0;
            stats.sequence_gaps_interval = 0;
            stats.sequence_gap_recoveries_interval = 0;
            stats.sequence_late_or_reordered_interval = 0;
        }
    }

    static double percent_missing(uint64_t missing_events, uint64_t received_packets) {
        const uint64_t denominator = missing_events + received_packets;
        if (denominator == 0) {
            return 0.0;
        }
        return (static_cast<double>(missing_events) * 100.0) /
               static_cast<double>(denominator);
    }

    static double percent_of_packets(uint64_t events, uint64_t packets) {
        if (packets == 0) {
            return 0.0;
        }
        return (static_cast<double>(events) * 100.0) / static_cast<double>(packets);
    }

    ServerOptions options_;
    udp::socket   socket_;

    ClientManager client_manager_;
    std::unordered_map<udp::endpoint, UnknownEndpointInfo, endpoint_hash> unknown_endpoints_;
    std::unordered_map<uint32_t, AudioIngressStats> audio_ingress_stats_;
    std::unordered_map<uint64_t, AudioForwardStats> audio_forward_stats_;
    uint64_t unknown_audio_drops_since_log_ = 0;
    uint64_t invalid_audio_drops_since_log_ = 0;
    uint32_t metronome_sequence_ = 0;
    std::chrono::steady_clock::time_point last_unknown_audio_summary_ =
        std::chrono::steady_clock::now();

    std::array<char, server_config::RECV_BUF_SIZE> recv_buf_;
    udp::endpoint                                  remote_endpoint_;

    PeriodicTimer alive_check_timer_;
};

ServerOptions parse_server_options(int argc, char** argv) {
    ServerOptions options;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--port" && i + 1 < argc) {
            options.port = static_cast<short>(std::stoi(argv[++i]));
        } else if (arg == "--server-id" && i + 1 < argc) {
            options.server_id = argv[++i];
        } else if (arg == "--join-secret" && i + 1 < argc) {
            options.join_secret = argv[++i];
        } else if (arg == "--log-file" && i + 1 < argc) {
            options.log_file_path = argv[++i];
        } else if (arg == "--allow-insecure-dev-joins") {
            options.allow_insecure_dev_joins = true;
        }
    }
    return options;
}

int main(int argc, char** argv) {
    try {
        asio::io_context io_context;
        auto             options = parse_server_options(argc, argv);

        auto& log = Logger::instance();
        log.init(true, false, !options.log_file_path.empty(), options.log_file_path,
                 spdlog::level::info);

        Log::info("Starting SFU server on 0.0.0.0:{}", options.port);
        Log::info("Runtime: role=server platform={} arch={}", runtime_platform_name(),
                  runtime_arch_name());
        if (!options.log_file_path.empty()) {
            Log::info("Logging to {}", options.log_file_path);
        }
        Log::info("Forwarding audio packets between clients");
        if (options.allow_insecure_dev_joins) {
            Log::warn("Insecure performer dev joins enabled");
        } else if (options.join_secret.empty()) {
            Log::warn("Join secret is not configured; JOIN packets will be rejected unless insecure dev joins are enabled");
        }

        Server server(io_context, options);

        io_context.run();
    } catch (std::exception& e) {
        Log::error("ERR: {}", e.what());
    }
}
