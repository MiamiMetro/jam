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
#include <utility>
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
#include "server_rate_limiter.h"
#include "server_config.h"
#include "session_crypto.h"
#include "udp_port.h"
#include "udp_socket_config.h"

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
          socket_(io_context),
          alive_check_timer_(io_context, server_config::ALIVE_CHECK_INTERVAL,
                             [this]() { alive_check_timer_callback(); }) {
        std::error_code socket_error;
        const auto protocol =
            udp_network::open_dual_stack_socket(socket_, options.port, socket_error);
        if (socket_error) {
            throw std::runtime_error("Failed to bind UDP socket: " +
                                     socket_error.message());
        }
        const auto local = socket_.local_endpoint();
        Log::info("UDP socket bound on {}:{} ({})",
                  udp_network::format_address_for_display(local.address()), local.port(),
                  protocol == udp::v6() ? "IPv6 dual-stack" : "IPv4 fallback");

        // Optimize UDP socket buffers for high-throughput packet forwarding
        std::error_code buffer_error;
        udp_network::configure_low_latency_buffers(socket_, buffer_error);
        if (!buffer_error) {
            Log::info("UDP socket buffers optimized for packet forwarding ({} bytes)",
                      UDP_SOCKET_BUFFER_BYTES);
        } else {
            Log::warn("Failed to set socket buffer sizes: {}", buffer_error.message());
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

    bool is_dual_stack_socket() const {
        std::error_code ec;
        const auto      local = socket_.local_endpoint(ec);
        return !ec && local.protocol() == udp::v6();
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
                   hdr.magic == AUDIO_V3_MAGIC || hdr.magic == AUDIO_REDUNDANT_MAGIC) {
            handle_audio_message(bytes);
        } else if (hdr.magic == SECURE_AUDIO_MAGIC) {
            handle_secure_audio_message(bytes);
        }

        do_receive();  // start next receive immediately
    }

    // Send with optional shared_ptr to keep data alive during async operation
    void send(void* data, std::size_t len, const udp::endpoint& target,
              const std::shared_ptr<std::vector<unsigned char>>& keep_alive = nullptr) {
        const auto qos = socket_qos_.ensure_flow(socket_, target);
        if (qos.newly_configured &&
            (!qos.ok() || qos.detail.find("failed") != std::string::npos)) {
            Log::warn("UDP QoS not fully active for {}:{}: {}",
                      udp_network::format_address_for_display(target.address()), target.port(),
                      qos.detail);
        }

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

    struct UsedTokenNonce {
        udp::endpoint endpoint;
        int64_t       expires_at_ms = 0;
        std::string   room_id;
        std::string   profile_id;
        std::string   role;
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
        if (!rate_limiter_.allow_control(remote_endpoint_, now)) {
            return;
        }
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
        if (chdr.type != CtrlHdr::Cmd::JOIN && client_manager_.exists(remote_endpoint_) &&
            !rate_limiter_.allow_control(remote_endpoint_, now)) {
            return;
        }

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

    void cleanup_used_token_nonces() {
        const int64_t now_ms = performer_join_token::now_ms();
        for (auto it = used_token_nonces_.begin(); it != used_token_nonces_.end();) {
            if (it->second.expires_at_ms < now_ms) {
                it = used_token_nonces_.erase(it);
            } else {
                ++it;
            }
        }
    }

    bool reserve_token_nonce(const performer_join_token::ValidatedToken& token,
                             const udp::endpoint& endpoint) {
        cleanup_used_token_nonces();
        const std::string nonce_key = session_crypto::nonce_replay_key(token.claims);
        auto it = used_token_nonces_.find(nonce_key);
        if (it != used_token_nonces_.end() && it->second.endpoint != endpoint) {
            return false;
        }

        used_token_nonces_[nonce_key] = UsedTokenNonce{
            endpoint,
            token.claims.expires_at_ms,
            token.claims.room_id,
            token.claims.profile_id,
            token.claims.role,
        };
        return true;
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
        const uint32_t client_capabilities = join.capabilities & AUDIO_SUPPORTED_CAPABILITIES;

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
        std::optional<ClientManager::ClientSecurityConfig> security;
        if (!token.empty() && !options_.allow_insecure_dev_joins) {
            const auto result = performer_join_token::validate_with_claims(
                token, options_.join_secret, options_.server_id, room_id, profile_id, role_name);
            if (!result.ok) {
                Log::warn("Rejecting JOIN from {}:{} room '{}': {}",
                          remote_endpoint_.address().to_string(), remote_endpoint_.port(), room_id,
                          result.reason);
                return;
            }
            if (!reserve_token_nonce(result, remote_endpoint_)) {
                Log::warn("Rejecting JOIN from {}:{} room '{}': token nonce replay",
                          remote_endpoint_.address().to_string(), remote_endpoint_.port(), room_id);
                return;
            }
            ClientManager::ClientSecurityConfig config;
            config.session_key = session_crypto::derive_key_from_join_token(result);
            config.token_nonce_key = session_crypto::nonce_replay_key(result.claims);
            security = config;
        }

        uint32_t registered_capabilities = client_capabilities;
        if (security.has_value()) {
            registered_capabilities |= AUDIO_CAP_SECURE_AUDIO;
        } else {
            registered_capabilities &= ~AUDIO_CAP_SECURE_AUDIO;
        }

        auto registration = client_manager_.register_client(
            remote_endpoint_, now, room_id, profile_id, display_name, role,
            registered_capabilities, security);
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
                  token.empty() ? "insecure-dev" : "token-present", registered_capabilities);
        uint32_t ack_capabilities = AUDIO_SUPPORTED_CAPABILITIES;
        if (!security.has_value()) {
            ack_capabilities &= ~AUDIO_CAP_SECURE_AUDIO;
        }
        send_join_ack(remote_endpoint_, client_id, ack_capabilities);
        if (role == ClientRole::Performer) {
            broadcast_participant_info(remote_endpoint_, client_id, profile_id, display_name);
        }
        send_existing_participant_info_to(remote_endpoint_);
    }

    bool extract_audio_rate_shape(const unsigned char* packet_data, std::size_t bytes,
                                  uint32_t& sample_rate, uint16_t& frame_count) {
        if (packet_data == nullptr || bytes < sizeof(MsgHdr)) {
            return false;
        }

        MsgHdr hdr{};
        std::memcpy(&hdr, packet_data, sizeof(MsgHdr));
        if (hdr.magic == AUDIO_REDUNDANT_MAGIC) {
            bool found = false;
            std::string reason;
            audio_packet::for_each_redundant_audio_child(
                packet_data, bytes,
                [&](const unsigned char* child, size_t child_len, uint8_t index) {
                    if (index != 0 || found) {
                        return;
                    }
                    const auto parsed = audio_packet::parse_audio_header(child, child_len);
                    if (parsed.valid) {
                        sample_rate = parsed.sample_rate;
                        frame_count = parsed.frame_count;
                        found = true;
                    }
                },
                &reason);
            return found;
        }

        if (hdr.magic == AUDIO_V2_MAGIC || hdr.magic == AUDIO_V3_MAGIC) {
            const auto parsed = audio_packet::parse_audio_header(packet_data, bytes);
            if (!parsed.valid) {
                return false;
            }
            sample_rate = parsed.sample_rate;
            frame_count = parsed.frame_count;
            return true;
        }

        if (hdr.magic == AUDIO_MAGIC) {
            sample_rate = 48000;
            frame_count = 480;
            return true;
        }

        return false;
    }

    bool allow_audio_rate(const unsigned char* packet_data, std::size_t bytes) {
        uint32_t sample_rate = 0;
        uint16_t frame_count = 0;
        const auto now = std::chrono::steady_clock::now();
        if (!extract_audio_rate_shape(packet_data, bytes, sample_rate, frame_count)) {
            rate_limiter_.allow_strict(remote_endpoint_, now);
            return false;
        }

        if (rate_limiter_.allow_authenticated_audio(remote_endpoint_, sample_rate,
                                                    frame_count, now)) {
            return true;
        }

        const uint64_t drop_count = ++rate_limited_audio_drops_total_;
        if (drop_count == 1 || drop_count % 100 == 0) {
            Log::warn("Rate-limited audio from {}:{} sample_rate={} frame_count={} drops={}",
                      remote_endpoint_.address().to_string(), remote_endpoint_.port(),
                      sample_rate, frame_count, drop_count);
        }
        return false;
    }

    void handle_audio_message(std::size_t bytes) {
        handle_plain_audio_message(reinterpret_cast<unsigned char*>(recv_buf_.data()), bytes,
                                   false);
    }

    void handle_secure_audio_message(std::size_t bytes) {
        const auto now = std::chrono::steady_clock::now();
        if (bytes < SECURE_PACKET_HEADER_BYTES + SECURE_PACKET_TAG_BYTES) {
            rate_limiter_.allow_strict(remote_endpoint_, now);
            return;
        }

        if (!client_manager_.exists(remote_endpoint_)) {
            if (rate_limiter_.allow_unknown(remote_endpoint_, now)) {
                record_unknown_audio_drop(remote_endpoint_);
            }
            return;
        }

        const auto security = client_manager_.get_security(remote_endpoint_);
        if (!security.has_value()) {
            if (rate_limiter_.allow_strict(remote_endpoint_, now)) {
                Log::warn("Dropping secure audio from endpoint without session key {}:{}",
                          remote_endpoint_.address().to_string(), remote_endpoint_.port());
            }
            return;
        }

        uint64_t nonce = 0;
        size_t plaintext_bytes = 0;
        const auto* packet_data = reinterpret_cast<const unsigned char*>(recv_buf_.data());
        if (!session_crypto::open_audio_packet(
                security->session_key, packet_data, bytes, nonce,
                secure_plaintext_buf_.data(), secure_plaintext_buf_.size(),
                plaintext_bytes)) {
            if (rate_limiter_.allow_strict(remote_endpoint_, now)) {
                Log::warn("Dropping audio with invalid auth tag from {}:{} bytes={}",
                          remote_endpoint_.address().to_string(), remote_endpoint_.port(),
                          bytes);
            }
            return;
        }

        if (!client_manager_.accept_audio_nonce(remote_endpoint_, nonce)) {
            if (rate_limiter_.allow_strict(remote_endpoint_, now)) {
                Log::warn("Dropping replayed secure audio from {}:{} nonce={}",
                          remote_endpoint_.address().to_string(), remote_endpoint_.port(),
                          nonce);
            }
            return;
        }

        handle_plain_audio_message(secure_plaintext_buf_.data(), plaintext_bytes, true);
    }

    void handle_plain_audio_message(unsigned char* packet_data, std::size_t bytes,
                                    bool authenticated) {
        if (packet_data == nullptr || bytes < sizeof(MsgHdr)) {
            rate_limiter_.allow_strict(remote_endpoint_, std::chrono::steady_clock::now());
            return;
        }

        MsgHdr hdr{};
        std::memcpy(&hdr, packet_data, sizeof(MsgHdr));
        if (hdr.magic == AUDIO_REDUNDANT_MAGIC) {
            handle_redundant_audio_message(packet_data, bytes, authenticated);
            return;
        }

        const size_t min_audio_packet_size =
            hdr.magic == AUDIO_V2_MAGIC
                ? audio_packet::v2_header_size()
                : (hdr.magic == AUDIO_V3_MAGIC
                       ? audio_packet::v3_header_size()
                       : sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t));
        if (!message_validator::is_valid_audio_packet(bytes, min_audio_packet_size)) {
            if (rate_limiter_.allow_strict(remote_endpoint_,
                                           std::chrono::steady_clock::now())) {
                Log::debug("Audio packet too small: {} bytes", bytes);
            }
            return;
        }

        if (!client_manager_.exists(remote_endpoint_)) {
            if (rate_limiter_.allow_unknown(remote_endpoint_,
                                            std::chrono::steady_clock::now())) {
                record_unknown_audio_drop(remote_endpoint_);
            }
            return;
        }

        if (!authenticated && client_manager_.has_session_key(remote_endpoint_)) {
            if (rate_limiter_.allow_strict(remote_endpoint_,
                                           std::chrono::steady_clock::now())) {
                Log::warn("Dropping plaintext audio from signed session {}:{}",
                          remote_endpoint_.address().to_string(), remote_endpoint_.port());
            }
            return;
        }

        if (!validate_complete_audio_packet(packet_data, bytes)) {
            return;
        }
        if (!allow_audio_rate(packet_data, bytes)) {
            return;
        }

        client_manager_.update_alive(remote_endpoint_, std::chrono::steady_clock::now());

        // Get sender's client ID
        uint32_t sender_id = client_manager_.get_client_id(remote_endpoint_);

        // Embed sender_id in the packet
        packet_builder::embed_sender_id(packet_data, sender_id);

        // SFU: Forward audio packet to all other clients (not back to sender)
        // Copy packet data before forwarding since recv_buf_ will be reused by do_receive()
        auto packet_copy = std::make_shared<std::vector<unsigned char>>(packet_data,
                                                                        packet_data + bytes);
        record_audio_ingress(sender_id, remote_endpoint_, packet_copy->data(), bytes);
        forward_audio_to_others(remote_endpoint_, packet_copy->data(), bytes, packet_copy);
    }

    void handle_redundant_audio_message(unsigned char* packet_data, std::size_t bytes,
                                        bool authenticated) {
        if (bytes < audio_packet::redundant_header_size()) {
            if (rate_limiter_.allow_strict(remote_endpoint_,
                                           std::chrono::steady_clock::now())) {
                Log::debug("Redundant audio packet too small: {} bytes", bytes);
            }
            return;
        }

        if (!client_manager_.exists(remote_endpoint_)) {
            if (rate_limiter_.allow_unknown(remote_endpoint_,
                                            std::chrono::steady_clock::now())) {
                record_unknown_audio_drop(remote_endpoint_);
            }
            return;
        }

        if (!authenticated && client_manager_.has_session_key(remote_endpoint_)) {
            if (rate_limiter_.allow_strict(remote_endpoint_,
                                           std::chrono::steady_clock::now())) {
                Log::warn("Dropping plaintext redundant audio from signed session {}:{}",
                          remote_endpoint_.address().to_string(), remote_endpoint_.port());
            }
            return;
        }

        std::string reason;
        if (!audio_packet::validate_redundant_audio_packet_bytes(packet_data, bytes, &reason)) {
            ++invalid_audio_drops_since_log_;
            if (rate_limiter_.allow_strict(remote_endpoint_,
                                           std::chrono::steady_clock::now())) {
                Log::warn("Dropping invalid redundant audio from {}:{}: reason={} bytes={}",
                          remote_endpoint_.address().to_string(), remote_endpoint_.port(),
                          reason, bytes);
            }
            return;
        }
        if (!allow_audio_rate(packet_data, bytes)) {
            return;
        }

        client_manager_.update_alive(remote_endpoint_, std::chrono::steady_clock::now());
        const uint32_t sender_id = client_manager_.get_client_id(remote_endpoint_);
        auto packet_copy = std::make_shared<std::vector<unsigned char>>(packet_data,
                                                                        packet_data + bytes);
        if (!audio_packet::embed_sender_id_in_redundant_audio_packet(
                packet_copy->data(), packet_copy->size(), sender_id, &reason)) {
            ++invalid_audio_drops_since_log_;
            Log::warn("Dropping redundant audio that could not be stamped: reason={}", reason);
            return;
        }

        audio_packet::for_each_redundant_audio_child_reverse(
            packet_copy->data(), packet_copy->size(),
            [&](const unsigned char* child, size_t child_len, uint8_t index) {
                record_audio_ingress(sender_id, remote_endpoint_, child, child_len,
                                     index == 0);
            });
        forward_audio_to_others(remote_endpoint_, packet_copy->data(), packet_copy->size(),
                                packet_copy);
    }

    bool validate_complete_audio_packet(const unsigned char* packet_data, std::size_t bytes) {
        MsgHdr hdr{};
        std::memcpy(&hdr, packet_data, sizeof(MsgHdr));
        if (hdr.magic != AUDIO_V2_MAGIC && hdr.magic != AUDIO_V3_MAGIC) {
            return true;
        }

        std::string reason;
        if (!audio_packet::validate_audio_packet_bytes(packet_data, bytes, &reason)) {
            const auto parsed = audio_packet::parse_audio_header(packet_data, bytes);
            ++invalid_audio_drops_since_log_;
            if (rate_limiter_.allow_strict(remote_endpoint_,
                                           std::chrono::steady_clock::now())) {
                Log::warn(
                    "Dropping invalid audio from {}:{}: reason={} magic=0x{:08x} got {} "
                    "payload_bytes={} seq={}",
                    remote_endpoint_.address().to_string(), remote_endpoint_.port(), reason,
                    hdr.magic, bytes, parsed.payload_bytes, parsed.sequence);
            }
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

    void send_join_ack(const udp::endpoint& endpoint, uint32_t participant_id,
                       uint32_t capabilities) {
        auto buf = std::make_shared<std::vector<unsigned char>>(sizeof(JoinAckHdr));
        JoinAckHdr ack{};
        ack.magic = CTRL_MAGIC;
        ack.type = CtrlHdr::Cmd::JOIN_ACK;
        ack.participant_id = participant_id;
        ack.capabilities = capabilities & AUDIO_SUPPORTED_CAPABILITIES;
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
        path.interval_unrecovered_sequence_gaps = static_cast<uint32_t>(
            std::min<uint64_t>(
                unrecovered_gap_count(stats.sequence_gaps_interval,
                                      stats.sequence_gap_recoveries_interval),
                std::numeric_limits<uint32_t>::max()));
        path.total_received = static_cast<uint32_t>(
            std::min<uint64_t>(stats.received_total,
                               std::numeric_limits<uint32_t>::max()));
        path.total_sequence_gaps = static_cast<uint32_t>(
            std::min<uint64_t>(stats.sequence_gaps_total,
                               std::numeric_limits<uint32_t>::max()));
        path.total_unrecovered_sequence_gaps = static_cast<uint32_t>(
            std::min<uint64_t>(
                unrecovered_gap_count(stats.sequence_gaps_total,
                                      stats.sequence_gap_recoveries_total),
                std::numeric_limits<uint32_t>::max()));
        path.observed_frame_count = stats.last_frame_count;
        std::memcpy(buf->data(), &path, sizeof(AudioPathStatsHdr));
        send(buf->data(), buf->size(), stats.endpoint, buf);
    }

    void broadcast_participant_info(const udp::endpoint& joined_endpoint, uint32_t participant_id,
                                    const std::string& profile_id,
                                    const std::string& display_name) {
        const uint32_t capabilities =
            client_manager_.get_client_capabilities(joined_endpoint);
        auto buf = packet_builder::create_participant_info_packet(
            participant_id, profile_id, display_name, capabilities);
        auto endpoints = client_manager_.get_room_endpoints_except(joined_endpoint);
        endpoints.push_back(joined_endpoint);

        for (const auto& endpoint: endpoints) {
            send(buf->data(), buf->size(), endpoint, buf);
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
                info.client_id, info.profile_id, info.display_name, info.capabilities);
            send(buf->data(), buf->size(), joined_endpoint, buf);
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
            auto fallback = packet_for_receiver_capabilities(endpoint, packet_data, packet_size);
            if (fallback != nullptr) {
                auto secure_packet =
                    secure_packet_for_receiver(endpoint, fallback->data(), fallback->size());
                if (secure_packet != nullptr) {
                    send(secure_packet->data(), secure_packet->size(), endpoint, secure_packet);
                } else if (!client_manager_.has_session_key(endpoint)) {
                    send(fallback->data(), fallback->size(), endpoint, fallback);
                }
                continue;
            }

            auto secure_packet = secure_packet_for_receiver(
                endpoint, static_cast<const unsigned char*>(packet_data), packet_size);
            if (secure_packet != nullptr) {
                send(secure_packet->data(), secure_packet->size(), endpoint, secure_packet);
            } else if (!client_manager_.has_session_key(endpoint)) {
                send(packet_data, packet_size, endpoint, keep_alive);
            }
        }
    }

    std::shared_ptr<std::vector<unsigned char>> secure_packet_for_receiver(
        const udp::endpoint& endpoint, const unsigned char* packet_data,
        std::size_t packet_size) {
        const auto security = client_manager_.get_security(endpoint);
        if (!security.has_value()) {
            return nullptr;
        }

        const uint64_t nonce = client_manager_.next_secure_send_nonce(endpoint);
        if (nonce == 0) {
            return nullptr;
        }

        auto secure_packet = std::make_shared<std::vector<unsigned char>>(
            SECURE_PACKET_HEADER_BYTES + packet_size + SECURE_PACKET_TAG_BYTES);
        size_t bytes_written = 0;
        if (!session_crypto::seal_audio_packet(
                security->session_key, nonce, packet_data, packet_size,
                secure_packet->data(), secure_packet->size(), bytes_written)) {
            return nullptr;
        }
        secure_packet->resize(bytes_written);
        return secure_packet;
    }

    std::shared_ptr<std::vector<unsigned char>> packet_for_receiver_capabilities(
        const udp::endpoint& endpoint, void* packet_data, std::size_t packet_size) {
        MsgHdr hdr{};
        std::memcpy(&hdr, packet_data, sizeof(MsgHdr));

        const bool receiver_supports_timestamp =
            client_manager_.client_supports(endpoint, AUDIO_CAP_CAPTURE_TIMESTAMP);
        const bool receiver_supports_redundancy =
            client_manager_.client_supports(endpoint, AUDIO_CAP_REDUNDANCY);

        if (hdr.magic == AUDIO_REDUNDANT_MAGIC) {
            if (!receiver_supports_redundancy) {
                auto fallback = first_redundant_child_copy(packet_data, packet_size);
                if (fallback != nullptr && !receiver_supports_timestamp &&
                    packet_magic(fallback->data(), fallback->size()) == AUDIO_V3_MAGIC) {
                    return audio_packet::strip_audio_v3_timestamp(fallback->data(),
                                                                  fallback->size());
                }
                return fallback;
            }
            if (!receiver_supports_timestamp) {
                return redundant_without_timestamps_copy(packet_data, packet_size);
            }
            return nullptr;
        }

        if (hdr.magic == AUDIO_V3_MAGIC && !receiver_supports_timestamp) {
            return audio_packet::strip_audio_v3_timestamp(
                static_cast<const unsigned char*>(packet_data), packet_size);
        }

        return nullptr;
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

    std::shared_ptr<std::vector<unsigned char>> redundant_without_timestamps_copy(
        void* packet_data, std::size_t packet_size) {
        std::vector<std::shared_ptr<std::vector<unsigned char>>> converted_children;
        std::vector<const std::vector<unsigned char>*> child_refs;
        std::string reason;

        const bool ok = audio_packet::for_each_redundant_audio_child(
            static_cast<unsigned char*>(packet_data), packet_size,
            [&](unsigned char* child, size_t child_len, uint8_t) {
                auto child_copy = std::make_shared<std::vector<unsigned char>>(
                    child, child + child_len);
                if (packet_magic(child_copy->data(), child_copy->size()) == AUDIO_V3_MAGIC) {
                    child_copy = audio_packet::strip_audio_v3_timestamp(
                        child_copy->data(), child_copy->size());
                }
                if (child_copy != nullptr) {
                    converted_children.push_back(child_copy);
                }
            },
            &reason);
        if (!ok || converted_children.empty()) {
            return nullptr;
        }

        child_refs.reserve(converted_children.size());
        for (const auto& child: converted_children) {
            child_refs.push_back(child.get());
        }
        return audio_packet::create_redundant_audio_packet(child_refs);
    }

    static uint32_t packet_magic(const unsigned char* packet_data, std::size_t packet_size) {
        if (packet_data == nullptr || packet_size < sizeof(MsgHdr)) {
            return 0;
        }
        uint32_t magic = 0;
        std::memcpy(&magic, packet_data, sizeof(magic));
        return magic;
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

    void record_audio_ingress(uint32_t sender_id, const udp::endpoint& endpoint,
                              const void* packet_data, std::size_t packet_size,
                              bool count_received = true) {
        if (sender_id == 0 || packet_size < sizeof(MsgHdr)) {
            return;
        }

        const auto parsed = audio_packet::parse_audio_header(
            static_cast<const unsigned char*>(packet_data), packet_size);
        if (!parsed.valid ||
            (parsed.magic != AUDIO_V2_MAGIC && parsed.magic != AUDIO_V3_MAGIC)) {
            return;
        }

        auto& stats = audio_ingress_stats_[sender_id];
        stats.endpoint = endpoint;
        stats.last_frame_count = parsed.frame_count;
        if (count_received) {
            ++stats.received_total;
            ++stats.received_interval;
        }
        const auto sequence_delta = stats.sequence_tracker.record(parsed.sequence);
        if (sequence_delta.gaps_detected > 0) {
            stats.sequence_gaps_total += sequence_delta.gaps_detected;
            stats.sequence_gaps_interval += sequence_delta.gaps_detected;
        }
        if (sequence_delta.gaps_recovered > 0) {
            stats.sequence_gap_recoveries_total += sequence_delta.gaps_recovered;
            stats.sequence_gap_recoveries_interval += sequence_delta.gaps_recovered;
        }
        stats.sequence_unresolved_gaps = stats.sequence_tracker.unresolved_gaps();
        if (sequence_delta.late_or_duplicate &&
            (count_received || sequence_delta.gaps_recovered > 0)) {
            ++stats.sequence_late_or_reordered_total;
            ++stats.sequence_late_or_reordered_interval;
        }
    }

    void record_audio_forward(uint32_t sender_id, const udp::endpoint& target, void* packet_data,
                              std::size_t packet_size) {
        if (sender_id == 0 || packet_size < sizeof(MsgHdr)) {
            return;
        }

        const auto parsed = audio_packet::parse_audio_header(
            static_cast<const unsigned char*>(packet_data), packet_size);
        if (!parsed.valid ||
            (parsed.magic != AUDIO_V2_MAGIC && parsed.magic != AUDIO_V3_MAGIC)) {
            return;
        }

        const uint32_t target_id = client_manager_.get_client_id(target);
        if (target_id == 0) {
            return;
        }

        const uint64_t key = (static_cast<uint64_t>(sender_id) << 32) | target_id;
        auto& stats = audio_forward_stats_[key];
        ++stats.forwarded_total;
        ++stats.forwarded_interval;
        const auto sequence_delta = stats.sequence_tracker.record(parsed.sequence);
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
                "net_gap={} gap_rate={:.1f}% seq_recovered={} seq_unresolved={} "
                "seq_late={} late={:.1f}% total received={} seq_gap={} net_gap={} "
                "seq_recovered={} seq_unresolved={} seq_late={}",
                sender_id, stats.endpoint.address().to_string(), stats.endpoint.port(),
                stats.received_interval, stats.sequence_gaps_interval,
                unrecovered_gap_count(stats.sequence_gaps_interval,
                                      stats.sequence_gap_recoveries_interval),
                percent_missing(unrecovered_gap_count(
                                    stats.sequence_gaps_interval,
                                    stats.sequence_gap_recoveries_interval),
                                stats.received_interval),
                stats.sequence_gap_recoveries_interval, stats.sequence_unresolved_gaps,
                stats.sequence_late_or_reordered_interval,
                percent_of_packets(stats.sequence_late_or_reordered_interval,
                                   stats.received_interval),
                stats.received_total, stats.sequence_gaps_total,
                unrecovered_gap_count(stats.sequence_gaps_total,
                                      stats.sequence_gap_recoveries_total),
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

    static uint64_t unrecovered_gap_count(uint64_t gaps, uint64_t recoveries) {
        return gaps > recoveries ? gaps - recoveries : 0;
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
    std::unordered_map<std::string, UsedTokenNonce> used_token_nonces_;
    std::unordered_map<uint32_t, AudioIngressStats> audio_ingress_stats_;
    std::unordered_map<uint64_t, AudioForwardStats> audio_forward_stats_;
    std::unordered_map<uint32_t, PingStats> ping_stats_;
    server_rate_limiter::ProtocolRateLimiter rate_limiter_;
    udp_network::UdpSocketQos socket_qos_;
    uint64_t unknown_audio_drops_since_log_ = 0;
    uint64_t invalid_audio_drops_since_log_ = 0;
    uint64_t rate_limited_audio_drops_total_ = 0;
    uint32_t metronome_sequence_ = 0;
    std::chrono::steady_clock::time_point last_unknown_audio_summary_ =
        std::chrono::steady_clock::now();

    std::array<char, server_config::RECV_BUF_SIZE> recv_buf_;
    std::array<unsigned char, server_config::RECV_BUF_SIZE> secure_plaintext_buf_;
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
                                                  uint32_t capabilities,
                                                  const std::string& room =
                                                      "redundancy-smoke",
                                                  const std::string& token = "") {
    JoinHdr join{};
    join.magic = CTRL_MAGIC;
    join.type = CtrlHdr::Cmd::JOIN;
    join.role = ClientRole::Performer;
    join.capabilities = capabilities;
    packet_builder::write_fixed(join.room_id, room);
    packet_builder::write_fixed(join.room_handle, room);
    packet_builder::write_fixed(join.profile_id, name);
    packet_builder::write_fixed(join.display_name, name);
    packet_builder::write_fixed(join.join_token, token);

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

template <typename Predicate>
bool receive_smoke_maybe(udp::socket& socket, Predicate&& predicate,
                         std::chrono::milliseconds timeout,
                         std::vector<unsigned char>* out = nullptr) {
    try {
        auto packet = receive_smoke_until(socket, std::forward<Predicate>(predicate), timeout);
        if (out != nullptr) {
            *out = std::move(packet);
        }
        return true;
    } catch (...) {
        return false;
    }
}

JoinAckHdr join_smoke_client(udp::socket& socket, const udp::endpoint& server_endpoint,
                             const std::string& name, uint32_t capabilities,
                             const std::string& room = "redundancy-smoke",
                             const std::string& token = "") {
    const auto join = make_smoke_join_packet(name, capabilities, room, token);
    send_smoke_packet(socket, server_endpoint, join);
    const auto ack_packet = receive_smoke_until(
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
    JoinAckHdr ack{};
    std::memcpy(&ack, ack_packet.data(), std::min(ack_packet.size(), sizeof(ack)));
    return ack;
}

std::string make_security_smoke_token(const std::string& secret,
                                      const std::string& server_id,
                                      const std::string& room,
                                      const std::string& profile) {
    performer_join_token::Claims claims;
    claims.expires_at_ms = performer_join_token::now_ms() + 120000;
    claims.server_id = server_id;
    claims.room_id = room;
    claims.profile_id = profile;
    claims.role = "performer";
    claims.nonce = performer_join_token::random_nonce();
    return performer_join_token::create(claims, secret);
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

int run_timestamp_relay_smoke() {
    asio::io_context server_io;
    ServerOptions options;
    options.port = 0;
    options.allow_insecure_dev_joins = true;
    options.server_id = "timestamp-relay-smoke";

    Server server(server_io, options);
    const udp::endpoint server_endpoint(asio::ip::make_address("127.0.0.1"),
                                        server.local_port());

    std::thread server_thread([&server_io]() { server_io.run(); });
    try {
        asio::io_context client_io;
        udp::socket rx_timestamp(client_io, udp::endpoint(udp::v4(), 0));
        udp::socket rx_legacy(client_io, udp::endpoint(udp::v4(), 0));
        udp::socket tx(client_io, udp::endpoint(udp::v4(), 0));

        join_smoke_client(rx_timestamp, server_endpoint, "rx-timestamp",
                          AUDIO_CAP_REDUNDANCY | AUDIO_CAP_CAPTURE_TIMESTAMP);
        join_smoke_client(rx_legacy, server_endpoint, "rx-legacy",
                          AUDIO_CAP_REDUNDANCY);
        join_smoke_client(tx, server_endpoint, "tx",
                          AUDIO_CAP_REDUNDANCY | AUDIO_CAP_CAPTURE_TIMESTAMP);

        const std::array<unsigned char, 4> payload{9, 8, 7, 6};
        auto timestamped = audio_packet::create_audio_packet_v3(
            AudioCodec::Opus, 11, opus_network_clock::SAMPLE_RATE,
            opus_network_clock::DEFAULT_FRAME_COUNT, 1, payload.data(),
            static_cast<uint16_t>(payload.size()), 123456789LL);

        send_smoke_packet(tx, server_endpoint, *timestamped);

        auto timestamp_forward = receive_smoke_until(
            rx_timestamp,
            [](const std::vector<unsigned char>& packet) {
                return packet.size() >= audio_packet::v3_header_size() &&
                       packet_magic(packet) == AUDIO_V3_MAGIC;
            },
            1500ms);
        auto legacy_forward = receive_smoke_until(
            rx_legacy,
            [](const std::vector<unsigned char>& packet) {
                return packet.size() >= audio_packet::v2_header_size() &&
                       packet_magic(packet) == AUDIO_V2_MAGIC;
            },
            1500ms);

        const auto timestamp_parsed =
            audio_packet::parse_audio_header(timestamp_forward.data(), timestamp_forward.size());
        require_smoke(timestamp_parsed.valid, "timestamp receiver should get valid v3");
        require_smoke(timestamp_parsed.capture_server_time_ns == 123456789LL,
                      "timestamp receiver should preserve capture timestamp");

        const auto legacy_parsed =
            audio_packet::parse_audio_header(legacy_forward.data(), legacy_forward.size());
        require_smoke(legacy_parsed.valid, "legacy receiver should get valid audio");
        require_smoke(legacy_parsed.magic == AUDIO_V2_MAGIC,
                      "legacy receiver should get v2 fallback");
        require_smoke(legacy_parsed.sequence == 11,
                      "legacy fallback should preserve sequence");

        server_io.stop();
        server_thread.join();
        std::cout << "server timestamp relay smoke passed\n";
        return 0;
    } catch (...) {
        server_io.stop();
        server_thread.join();
        throw;
    }
}

int run_dual_stack_relay_smoke() {
    asio::io_context server_io;
    ServerOptions    options;
    options.port = 0;
    options.allow_insecure_dev_joins = true;
    options.server_id = "dual-stack-relay-smoke";

    Server server(server_io, options);
    if (!server.is_dual_stack_socket()) {
        std::cout << "server dual-stack relay smoke skipped: IPv6 dual-stack unavailable\n";
        return 0;
    }

    const uint16_t server_port = server.local_port();
    const udp::endpoint server_v4(asio::ip::make_address("127.0.0.1"), server_port);
    const udp::endpoint server_v6(asio::ip::make_address("::1"), server_port);

    std::thread server_thread([&server_io]() { server_io.run(); });
    try {
        asio::io_context client_io;
        udp::socket      v4_client(client_io, udp::endpoint(udp::v4(), 0));
        udp::socket      v6_client(client_io);
        std::error_code  ec;
        v6_client.open(udp::v6(), ec);
        if (!ec) {
            v6_client.bind(udp::endpoint(udp::v6(), 0), ec);
        }
        if (ec) {
            server_io.stop();
            server_thread.join();
            std::cout << "server dual-stack relay smoke skipped: IPv6 loopback unavailable\n";
            return 0;
        }

        const std::string room = "dual-stack-smoke";
        const auto        v4_ack =
            join_smoke_client(v4_client, server_v4, "v4-client", AUDIO_CAP_REDUNDANCY, room);
        const auto v6_ack =
            join_smoke_client(v6_client, server_v6, "v6-client", AUDIO_CAP_REDUNDANCY, room);
        require_smoke(v4_ack.participant_id != 0, "v4 client should join");
        require_smoke(v6_ack.participant_id != 0, "v6 client should join");

        const std::array<unsigned char, 3> v4_payload{4, 5, 6};
        auto v4_packet = audio_packet::create_audio_packet_v2(
            AudioCodec::Opus, 10, opus_network_clock::SAMPLE_RATE,
            opus_network_clock::DEFAULT_FRAME_COUNT, 1, v4_payload.data(),
            static_cast<uint16_t>(v4_payload.size()));
        require_smoke(v4_packet != nullptr, "v4 packet should build");
        send_smoke_packet(v4_client, server_v4, *v4_packet);

        const auto v6_forward = receive_smoke_until(
            v6_client,
            [](const std::vector<unsigned char>& packet) {
                return packet.size() >= audio_packet::v2_header_size() &&
                       packet_magic(packet) == AUDIO_V2_MAGIC;
            },
            1500ms);
        const auto v6_parsed =
            audio_packet::parse_audio_header(v6_forward.data(), v6_forward.size());
        require_smoke(v6_parsed.valid, "v6 receiver should get valid v4 audio");
        require_smoke(v6_parsed.sender_id == v4_ack.participant_id,
                      "v4 sender id should be stamped on v6 forward");

        const std::array<unsigned char, 3> v6_payload{7, 8, 9};
        auto v6_packet = audio_packet::create_audio_packet_v2(
            AudioCodec::Opus, 11, opus_network_clock::SAMPLE_RATE,
            opus_network_clock::DEFAULT_FRAME_COUNT, 1, v6_payload.data(),
            static_cast<uint16_t>(v6_payload.size()));
        require_smoke(v6_packet != nullptr, "v6 packet should build");
        send_smoke_packet(v6_client, server_v6, *v6_packet);

        const auto v4_forward = receive_smoke_until(
            v4_client,
            [](const std::vector<unsigned char>& packet) {
                return packet.size() >= audio_packet::v2_header_size() &&
                       packet_magic(packet) == AUDIO_V2_MAGIC;
            },
            1500ms);
        const auto v4_parsed =
            audio_packet::parse_audio_header(v4_forward.data(), v4_forward.size());
        require_smoke(v4_parsed.valid, "v4 receiver should get valid v6 audio");
        require_smoke(v4_parsed.sender_id == v6_ack.participant_id,
                      "v6 sender id should be stamped on v4 forward");

        server_io.stop();
        server_thread.join();
        std::cout << "server dual-stack relay smoke passed\n";
        return 0;
    } catch (...) {
        server_io.stop();
        server_thread.join();
        throw;
    }
}

int run_security_smoke() {
    asio::io_context server_io;
    ServerOptions options;
    options.port = 0;
    options.server_id = "security-smoke";
    options.join_secret = "security-smoke-secret";

    Server server(server_io, options);
    const udp::endpoint server_endpoint(asio::ip::make_address("127.0.0.1"),
                                        server.local_port());

    std::thread server_thread([&server_io]() { server_io.run(); });
    try {
        asio::io_context client_io;
        udp::socket rx(client_io, udp::endpoint(udp::v4(), 0));
        udp::socket tx(client_io, udp::endpoint(udp::v4(), 0));
        udp::socket replay(client_io, udp::endpoint(udp::v4(), 0));

        const std::string room = "security-smoke-room";
        const std::string rx_token = make_security_smoke_token(
            options.join_secret, options.server_id, room, "rx-secure");
        const std::string tx_token = make_security_smoke_token(
            options.join_secret, options.server_id, room, "tx-secure");
        const auto rx_key = session_crypto::derive_key_from_join_token_string(rx_token);
        const auto tx_key = session_crypto::derive_key_from_join_token_string(tx_token);
        require_smoke(rx_key.has_value(), "receiver key should derive from token");
        require_smoke(tx_key.has_value(), "sender key should derive from token");

        const auto rx_ack = join_smoke_client(
            rx, server_endpoint, "rx-secure", AUDIO_SUPPORTED_CAPABILITIES, room, rx_token);
        const auto tx_ack = join_smoke_client(
            tx, server_endpoint, "tx-secure", AUDIO_SUPPORTED_CAPABILITIES, room, tx_token);
        require_smoke((rx_ack.capabilities & AUDIO_CAP_SECURE_AUDIO) != 0,
                      "receiver should get secure audio capability");
        require_smoke((tx_ack.capabilities & AUDIO_CAP_SECURE_AUDIO) != 0,
                      "sender should get secure audio capability");

        const std::array<unsigned char, 4> payload{0x41, 0x42, 0x43, 0x44};
        auto plaintext_audio = audio_packet::create_audio_packet_v2(
            AudioCodec::Opus, 1, opus_network_clock::SAMPLE_RATE,
            opus_network_clock::DEFAULT_FRAME_COUNT, 1, payload.data(),
            static_cast<uint16_t>(payload.size()));
        require_smoke(plaintext_audio != nullptr, "plaintext smoke audio should build");

        send_smoke_packet(tx, server_endpoint, *plaintext_audio);
        const auto is_audio_or_secure = [](const std::vector<unsigned char>& packet) {
            return packet.size() >= sizeof(MsgHdr) &&
                   (packet_magic(packet) == AUDIO_V2_MAGIC ||
                    packet_magic(packet) == AUDIO_V3_MAGIC ||
                    packet_magic(packet) == AUDIO_REDUNDANT_MAGIC ||
                    packet_magic(packet) == SECURE_AUDIO_MAGIC);
        };
        require_smoke(!receive_smoke_maybe(rx, is_audio_or_secure, 250ms),
                      "signed session plaintext audio must not be relayed");

        std::vector<unsigned char> secure_audio(
            SECURE_PACKET_HEADER_BYTES + plaintext_audio->size() + SECURE_PACKET_TAG_BYTES);
        size_t secure_bytes = 0;
        require_smoke(session_crypto::seal_audio_packet(
                          *tx_key, 1, plaintext_audio->data(), plaintext_audio->size(),
                          secure_audio.data(), secure_audio.size(), secure_bytes),
                      "sender secure audio should seal");
        secure_audio.resize(secure_bytes);
        send_smoke_packet(tx, server_endpoint, secure_audio);

        std::vector<unsigned char> secure_forward;
        require_smoke(receive_smoke_maybe(rx, is_audio_or_secure, 1500ms, &secure_forward),
                      "receiver should get secure forwarded audio");
        require_smoke(packet_magic(secure_forward) == SECURE_AUDIO_MAGIC,
                      "forwarded audio should be secure");

        std::array<unsigned char, 2048> opened{};
        uint64_t forward_nonce = 0;
        size_t opened_bytes = 0;
        require_smoke(session_crypto::open_audio_packet(
                          *rx_key, secure_forward.data(), secure_forward.size(),
                          forward_nonce, opened.data(), opened.size(), opened_bytes),
                      "receiver should open secure forwarded audio");
        const auto parsed = audio_packet::parse_audio_header(opened.data(), opened_bytes);
        require_smoke(parsed.valid && parsed.magic == AUDIO_V2_MAGIC,
                      "opened forwarded audio should be valid v2");
        require_smoke(parsed.sender_id == tx_ack.participant_id,
                      "server should stamp sender id before encryption");

        send_smoke_packet(tx, server_endpoint, secure_audio);
        require_smoke(!receive_smoke_maybe(rx, is_audio_or_secure, 250ms),
                      "replayed secure audio nonce must not be relayed");

        const auto replay_join =
            make_smoke_join_packet("tx-secure", AUDIO_SUPPORTED_CAPABILITIES, room, tx_token);
        send_smoke_packet(replay, server_endpoint, replay_join);
        const bool replay_join_acked = receive_smoke_maybe(
            replay,
            [](const std::vector<unsigned char>& packet) {
                if (packet.size() < sizeof(CtrlHdr) || packet_magic(packet) != CTRL_MAGIC) {
                    return false;
                }
                CtrlHdr ctrl{};
                std::memcpy(&ctrl, packet.data(), sizeof(ctrl));
                return ctrl.type == CtrlHdr::Cmd::JOIN_ACK;
            },
            300ms);
        require_smoke(!replay_join_acked,
                      "token nonce replay from another endpoint must not join");

        server_io.stop();
        server_thread.join();
        std::cout << "server security smoke passed\n";
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
        if (has_arg(argc, argv, "--timestamp-relay-smoke")) {
            return run_timestamp_relay_smoke();
        }
        if (has_arg(argc, argv, "--dual-stack-relay-smoke")) {
            return run_dual_stack_relay_smoke();
        }
        if (has_arg(argc, argv, "--security-smoke")) {
            return run_security_smoke();
        }

        Log::info("Starting SFU server on [::]:{} (dual-stack preferred)", options.port);
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
        return 1;
    }
}
