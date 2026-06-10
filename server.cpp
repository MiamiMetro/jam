#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
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
#include "udp_port.h"

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
    uint16_t    port = 9999;
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
            socket_.set_option(asio::socket_base::receive_buffer_size(UDP_SOCKET_BUFFER_BYTES));
            socket_.set_option(asio::socket_base::send_buffer_size(UDP_SOCKET_BUFFER_BYTES));
            Log::info("UDP socket buffers optimized for packet forwarding ({} bytes)",
                      UDP_SOCKET_BUFFER_BYTES);
        } catch (const std::exception& e) {
            Log::warn("Failed to set socket buffer sizes: {}", e.what());
        }

        Log::info("SFU server ready: forwarding audio between clients");
        do_receive();
    }

    ~Server() {
        socket_.close();
    }

    uint16_t local_port() const {
        return socket_.local_endpoint().port();
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
        } else if (hdr.magic == AUDIO_MAGIC || hdr.magic == AUDIO_V2_MAGIC ||
                   hdr.magic == AUDIO_REDUNDANT_MAGIC) {
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
        uint16_t last_frame_count = 0;
        SequenceArrivalTracker sequence_tracker;
    };

    struct PingStats {
        udp::endpoint endpoint;
        uint64_t received_total = 0;
        uint64_t reply_queued_total = 0;
        uint64_t sequence_gaps_total = 0;
        uint64_t sequence_gap_recoveries_total = 0;
        uint64_t sequence_unresolved_gaps = 0;
        uint64_t sequence_late_or_reordered_total = 0;
        uint64_t received_interval = 0;
        uint64_t reply_queued_interval = 0;
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
        const auto now = std::chrono::steady_clock::now();
        const uint32_t client_id = client_manager_.get_client_id(remote_endpoint_);
        client_manager_.update_alive(remote_endpoint_, now);
        record_ping_received(client_id, remote_endpoint_, shdr.seq);
        auto nanoseconds =
            std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        shdr.t2_server_recv = nanoseconds;
        shdr.t3_server_send = nanoseconds;
        auto packet = std::make_shared<std::vector<unsigned char>>(sizeof(SyncHdr));
        std::memcpy(packet->data(), &shdr, sizeof(SyncHdr));
        record_ping_reply_queued(client_id);
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
        const uint32_t client_capabilities = join.capabilities & AUDIO_CAP_REDUNDANCY;

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

        auto registration = client_manager_.register_client(
            remote_endpoint_, now, room_id, profile_id, display_name, role,
            client_capabilities);
        for (uint32_t removed_client_id: registration.removed_client_ids) {
            Log::info("Removed stale duplicate participant ID {} for room='{}' user='{}'",
                      removed_client_id, room_id, profile_id);
            broadcast_participant_leave(removed_client_id);
        }

        uint32_t client_id = registration.client_id;
        Log::info(
                  "JOIN: {}:{} room='{}' user='{}' display='{}' role='{}' "
                  "(ID: {}, {}, capabilities=0x{:08x})",
                  remote_endpoint_.address().to_string(), remote_endpoint_.port(), room_id,
                  profile_id, display_name, role_name, client_id,
                  token.empty() ? "insecure-dev" : "token-present", client_capabilities);
        send_join_ack(remote_endpoint_, client_id);
        if (role == ClientRole::Performer) {
            broadcast_participant_info(remote_endpoint_, client_id, profile_id, display_name);
        }
        send_existing_participant_info_to(remote_endpoint_);
    }

    void handle_audio_message(std::size_t bytes) {
        MsgHdr hdr{};
        std::memcpy(&hdr, recv_buf_.data(), sizeof(MsgHdr));
        if (hdr.magic == AUDIO_REDUNDANT_MAGIC) {
            handle_redundant_audio_message(bytes);
            return;
        }

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

    void handle_redundant_audio_message(std::size_t bytes) {
        if (bytes < audio_packet::redundant_header_size()) {
            Log::debug("Redundant audio packet too small: {} bytes", bytes);
            return;
        }

        if (!client_manager_.exists(remote_endpoint_)) {
            record_unknown_audio_drop(remote_endpoint_);
            return;
        }

        const auto* packet_data = reinterpret_cast<const unsigned char*>(recv_buf_.data());
        std::string reason;
        if (!audio_packet::validate_redundant_audio_packet_bytes(packet_data, bytes, &reason)) {
            ++invalid_audio_drops_since_log_;
            Log::warn("Dropping invalid redundant audio from {}:{}: reason={} bytes={}",
                      remote_endpoint_.address().to_string(), remote_endpoint_.port(), reason,
                      bytes);
            return;
        }

        client_manager_.update_alive(remote_endpoint_, std::chrono::steady_clock::now());
        const uint32_t sender_id = client_manager_.get_client_id(remote_endpoint_);
        auto packet_copy = std::make_shared<std::vector<unsigned char>>(recv_buf_.data(),
                                                                        recv_buf_.data() + bytes);
        if (!audio_packet::embed_sender_id_in_redundant_audio_packet(
                packet_copy->data(), packet_copy->size(), sender_id, &reason)) {
            ++invalid_audio_drops_since_log_;
            Log::warn("Dropping redundant audio that could not be stamped: reason={}", reason);
            return;
        }

        audio_packet::for_each_redundant_audio_child(
            packet_copy->data(), packet_copy->size(),
            [&](unsigned char* child, size_t child_len, uint8_t index) {
                if (index == 0) {
                    record_audio_ingress(sender_id, remote_endpoint_, child, child_len);
                }
            });
        forward_audio_to_others(remote_endpoint_, packet_copy->data(), packet_copy->size(),
                                packet_copy);
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
        auto buf = std::make_shared<std::vector<unsigned char>>(sizeof(JoinAckHdr));
        JoinAckHdr ack{};
        ack.magic = CTRL_MAGIC;
        ack.type = CtrlHdr::Cmd::JOIN_ACK;
        ack.participant_id = participant_id;
        ack.capabilities = AUDIO_CAP_REDUNDANCY;
        std::memcpy(buf->data(), &ack, sizeof(JoinAckHdr));
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

    void send_audio_path_stats(uint32_t sender_id, const AudioIngressStats& stats) {
        if (sender_id == 0 || !client_manager_.exists(stats.endpoint)) {
            return;
        }

        auto buf = std::make_shared<std::vector<unsigned char>>(sizeof(AudioPathStatsHdr));
        AudioPathStatsHdr path{};
        path.magic = CTRL_MAGIC;
        path.type = CtrlHdr::Cmd::AUDIO_PATH_STATS;
        path.participant_id = sender_id;
        path.interval_received = static_cast<uint32_t>(
            std::min<uint64_t>(stats.received_interval,
                               std::numeric_limits<uint32_t>::max()));
        path.interval_sequence_gaps = static_cast<uint32_t>(
            std::min<uint64_t>(stats.sequence_gaps_interval,
                               std::numeric_limits<uint32_t>::max()));
        path.total_received = static_cast<uint32_t>(
            std::min<uint64_t>(stats.received_total,
                               std::numeric_limits<uint32_t>::max()));
        path.total_sequence_gaps = static_cast<uint32_t>(
            std::min<uint64_t>(stats.sequence_gaps_total,
                               std::numeric_limits<uint32_t>::max()));
        path.observed_frame_count = stats.last_frame_count;
        std::memcpy(buf->data(), &path, sizeof(AudioPathStatsHdr));
        send(buf->data(), buf->size(), stats.endpoint, buf);
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
            record_audio_forward_datagram(sender_id, endpoint, packet_data, packet_size);
            MsgHdr hdr{};
            std::memcpy(&hdr, packet_data, sizeof(MsgHdr));
            if (hdr.magic == AUDIO_REDUNDANT_MAGIC &&
                !client_manager_.client_supports(endpoint, AUDIO_CAP_REDUNDANCY)) {
                auto fallback = first_redundant_child_copy(packet_data, packet_size);
                if (fallback != nullptr) {
                    send(fallback->data(), fallback->size(), endpoint, fallback);
                }
            } else {
                send(packet_data, packet_size, endpoint, keep_alive);
            }
        }
    }

    std::shared_ptr<std::vector<unsigned char>> first_redundant_child_copy(
        void* packet_data, std::size_t packet_size) {
        std::shared_ptr<std::vector<unsigned char>> fallback;
        std::string reason;
        audio_packet::for_each_redundant_audio_child(
            static_cast<unsigned char*>(packet_data), packet_size,
            [&](unsigned char* child, size_t child_len, uint8_t index) {
                if (index != 0 || fallback != nullptr) {
                    return;
                }
                fallback = std::make_shared<std::vector<unsigned char>>(child,
                                                                        child + child_len);
            },
            &reason);
        return fallback;
    }

    void record_audio_forward_datagram(uint32_t sender_id, const udp::endpoint& target,
                                       void* packet_data, std::size_t packet_size) {
        if (packet_size < sizeof(MsgHdr)) {
            return;
        }

        MsgHdr hdr{};
        std::memcpy(&hdr, packet_data, sizeof(MsgHdr));
        if (hdr.magic != AUDIO_REDUNDANT_MAGIC) {
            record_audio_forward(sender_id, target, packet_data, packet_size);
            return;
        }

        audio_packet::for_each_redundant_audio_child(
            static_cast<unsigned char*>(packet_data), packet_size,
            [&](unsigned char* child, size_t child_len, uint8_t index) {
                if (index == 0) {
                    record_audio_forward(sender_id, target, child, child_len);
                }
            });
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
        stats.last_frame_count = audio.frame_count;
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

    void record_ping_received(uint32_t client_id, const udp::endpoint& endpoint,
                              uint32_t sequence) {
        if (client_id == 0) {
            return;
        }

        auto& stats = ping_stats_[client_id];
        stats.endpoint = endpoint;
        ++stats.received_total;
        ++stats.received_interval;
        const auto sequence_delta = stats.sequence_tracker.record(sequence);
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

    void record_ping_reply_queued(uint32_t client_id) {
        if (client_id == 0) {
            return;
        }

        auto& stats = ping_stats_[client_id];
        ++stats.reply_queued_total;
        ++stats.reply_queued_interval;
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
            send_audio_path_stats(sender_id, stats);
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

        for (auto& [client_id, stats]: ping_stats_) {
            if (stats.received_interval == 0 && stats.reply_queued_interval == 0 &&
                stats.sequence_gaps_interval == 0 &&
                stats.sequence_late_or_reordered_interval == 0) {
                continue;
            }

            Log::info(
                "Ping diag interval client={} endpoint={}:{} received={} reply_queued={} "
                "seq_gap={} gap_rate={:.1f}% seq_recovered={} seq_unresolved={} seq_late={} "
                "late={:.1f}% total received={} reply_queued={} seq_gap={} seq_recovered={} "
                "seq_unresolved={} seq_late={}",
                client_id, stats.endpoint.address().to_string(), stats.endpoint.port(),
                stats.received_interval, stats.reply_queued_interval,
                stats.sequence_gaps_interval,
                percent_missing(stats.sequence_gaps_interval, stats.received_interval),
                stats.sequence_gap_recoveries_interval, stats.sequence_unresolved_gaps,
                stats.sequence_late_or_reordered_interval,
                percent_of_packets(stats.sequence_late_or_reordered_interval,
                                   stats.received_interval),
                stats.received_total, stats.reply_queued_total, stats.sequence_gaps_total,
                stats.sequence_gap_recoveries_total, stats.sequence_unresolved_gaps,
                stats.sequence_late_or_reordered_total);
            stats.received_interval = 0;
            stats.reply_queued_interval = 0;
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
    std::unordered_map<uint32_t, PingStats> ping_stats_;
    uint64_t unknown_audio_drops_since_log_ = 0;
    uint64_t invalid_audio_drops_since_log_ = 0;
    uint32_t metronome_sequence_ = 0;
    std::chrono::steady_clock::time_point last_unknown_audio_summary_ =
        std::chrono::steady_clock::now();

    std::array<char, server_config::RECV_BUF_SIZE> recv_buf_;
    udp::endpoint                                  remote_endpoint_;

    PeriodicTimer alive_check_timer_;
};

void require_smoke(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

uint32_t packet_magic(const std::vector<unsigned char>& packet) {
    require_smoke(packet.size() >= sizeof(MsgHdr), "packet too small for magic");
    uint32_t magic = 0;
    std::memcpy(&magic, packet.data(), sizeof(magic));
    return magic;
}

uint32_t packet_u32_at(const std::vector<unsigned char>& packet, size_t offset) {
    require_smoke(packet.size() >= offset + sizeof(uint32_t), "packet too small for u32");
    uint32_t value = 0;
    std::memcpy(&value, packet.data() + offset, sizeof(value));
    return value;
}

std::vector<unsigned char> make_smoke_join_packet(const std::string& name,
                                                  uint32_t capabilities) {
    JoinHdr join{};
    join.magic = CTRL_MAGIC;
    join.type = CtrlHdr::Cmd::JOIN;
    join.role = ClientRole::Performer;
    join.capabilities = capabilities;
    packet_builder::write_fixed(join.room_id, "redundancy-smoke");
    packet_builder::write_fixed(join.room_handle, "redundancy-smoke");
    packet_builder::write_fixed(join.profile_id, name);
    packet_builder::write_fixed(join.display_name, name);

    std::vector<unsigned char> packet(sizeof(join));
    std::memcpy(packet.data(), &join, sizeof(join));
    return packet;
}

void send_smoke_packet(udp::socket& socket, const udp::endpoint& endpoint,
                       const std::vector<unsigned char>& packet) {
    socket.send_to(asio::buffer(packet), endpoint);
}

template <typename Predicate>
std::vector<unsigned char> receive_smoke_until(udp::socket& socket, Predicate&& predicate,
                                               std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::array<unsigned char, server_config::RECV_BUF_SIZE> buffer{};

    while (std::chrono::steady_clock::now() < deadline) {
        std::error_code ec;
        const auto available = socket.available(ec);
        if (ec) {
            throw std::runtime_error("socket available failed: " + ec.message());
        }

        if (available > 0) {
            udp::endpoint sender;
            const auto bytes = socket.receive_from(asio::buffer(buffer), sender, 0, ec);
            if (ec) {
                throw std::runtime_error("socket receive failed: " + ec.message());
            }

            std::vector<unsigned char> packet(buffer.begin(), buffer.begin() + bytes);
            if (predicate(packet)) {
                return packet;
            }
        } else {
            std::this_thread::sleep_for(2ms);
        }
    }

    throw std::runtime_error("timed out waiting for expected UDP packet");
}

void join_smoke_client(udp::socket& socket, const udp::endpoint& server_endpoint,
                       const std::string& name, uint32_t capabilities) {
    const auto join = make_smoke_join_packet(name, capabilities);
    send_smoke_packet(socket, server_endpoint, join);
    receive_smoke_until(
        socket,
        [](const std::vector<unsigned char>& packet) {
            if (packet.size() < sizeof(CtrlHdr) || packet_magic(packet) != CTRL_MAGIC) {
                return false;
            }
            CtrlHdr ctrl{};
            std::memcpy(&ctrl, packet.data(), sizeof(ctrl));
            return ctrl.type == CtrlHdr::Cmd::JOIN_ACK;
        },
        1500ms);
}

int run_redundancy_relay_smoke() {
    asio::io_context server_io;
    ServerOptions options;
    options.port = 0;
    options.allow_insecure_dev_joins = true;
    options.server_id = "redundancy-relay-smoke";

    Server server(server_io, options);
    const udp::endpoint server_endpoint(asio::ip::make_address("127.0.0.1"),
                                        server.local_port());

    std::thread server_thread([&server_io]() { server_io.run(); });
    try {
        asio::io_context client_io;
        udp::socket rx_new(client_io, udp::endpoint(udp::v4(), 0));
        udp::socket rx_legacy(client_io, udp::endpoint(udp::v4(), 0));
        udp::socket tx(client_io, udp::endpoint(udp::v4(), 0));

        join_smoke_client(rx_new, server_endpoint, "rx-new", AUDIO_CAP_REDUNDANCY);
        join_smoke_client(rx_legacy, server_endpoint, "rx-legacy", 0);
        join_smoke_client(tx, server_endpoint, "tx", AUDIO_CAP_REDUNDANCY);

        const std::array<unsigned char, 3> previous_payload{1, 2, 3};
        const std::array<unsigned char, 3> current_payload{4, 5, 6};
        auto previous = audio_packet::create_audio_packet_v2(
            AudioCodec::Opus, 0, opus_network_clock::SAMPLE_RATE,
            opus_network_clock::DEFAULT_FRAME_COUNT, 1, previous_payload.data(),
            static_cast<uint16_t>(previous_payload.size()));
        auto current = audio_packet::create_audio_packet_v2(
            AudioCodec::Opus, 1, opus_network_clock::SAMPLE_RATE,
            opus_network_clock::DEFAULT_FRAME_COUNT, 1, current_payload.data(),
            static_cast<uint16_t>(current_payload.size()));
        auto redundant =
            audio_packet::create_redundant_audio_packet({current.get(), previous.get()});
        require_smoke(redundant != nullptr, "redundant packet should build");

        send_smoke_packet(tx, server_endpoint, *redundant);

        auto redundant_forward = receive_smoke_until(
            rx_new,
            [](const std::vector<unsigned char>& packet) {
                return packet.size() >= audio_packet::redundant_header_size() &&
                       packet_magic(packet) == AUDIO_REDUNDANT_MAGIC;
            },
            1500ms);
        auto legacy_forward = receive_smoke_until(
            rx_legacy,
            [](const std::vector<unsigned char>& packet) {
                return packet.size() >= audio_packet::v2_header_size() &&
                       packet_magic(packet) == AUDIO_V2_MAGIC;
            },
            1500ms);

        require_smoke(redundant_forward.size() == redundant->size(),
                      "redundant receiver should get full redundant datagram");
        require_smoke(legacy_forward.size() == current->size(),
                      "legacy receiver should get current v2 fallback only");

        const uint32_t sender_id = packet_u32_at(legacy_forward, sizeof(MsgHdr));
        std::array<uint32_t, 2> child_sender_ids{};
        std::array<uint32_t, 2> child_sequences{};
        int child_count = 0;
        const auto* redundant_bytes = redundant_forward.data();
        audio_packet::for_each_redundant_audio_child(
            redundant_bytes, redundant_forward.size(),
            [&](const unsigned char* child, size_t, uint8_t index) {
                require_smoke(index < child_sender_ids.size(),
                              "unexpected redundant child index");
                AudioHdrV2 hdr{};
                std::memcpy(&hdr, child, audio_packet::v2_header_size());
                child_sender_ids[index] = hdr.sender_id;
                child_sequences[index] = hdr.sequence;
                ++child_count;
            });

        require_smoke(child_count == 2, "redundant receiver should get two children");
        require_smoke(child_sender_ids[0] == sender_id && child_sender_ids[1] == sender_id,
                      "server should stamp sender id into every redundant child");
        require_smoke(child_sequences[0] == 1 && child_sequences[1] == 0,
                      "redundant children should preserve current-then-previous order");
        require_smoke(packet_u32_at(legacy_forward, sizeof(MsgHdr) + sizeof(uint32_t)) == 1,
                      "legacy fallback should forward current packet");

        server_io.stop();
        server_thread.join();
        std::cout << "server redundancy relay smoke passed\n";
        return 0;
    } catch (...) {
        server_io.stop();
        server_thread.join();
        throw;
    }
}

ServerOptions parse_server_options(int argc, char** argv) {
    ServerOptions options;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--port" && i + 1 < argc) {
            options.port = parse_udp_port(argv[++i], "--port");
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

bool has_arg(int argc, char** argv, const std::string& expected) {
    for (int i = 1; i < argc; ++i) {
        if (argv[i] == expected) {
            return true;
        }
    }
    return false;
}

int main(int argc, char** argv) {
    try {
        asio::io_context io_context;
        auto             options = parse_server_options(argc, argv);

        auto& log = Logger::instance();
        log.init(true, false, !options.log_file_path.empty(), options.log_file_path,
                 spdlog::level::info);

        if (has_arg(argc, argv, "--redundancy-relay-smoke")) {
            return run_redundancy_relay_smoke();
        }

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
