#pragma once

#include <chrono>

using namespace std::chrono_literals;

// Server configuration constants
namespace server_config {

constexpr auto   ALIVE_CHECK_INTERVAL = 5s;
constexpr auto   CLIENT_TIMEOUT       = 15s;
constexpr auto   UNKNOWN_ENDPOINT_TTL = 30s;
constexpr auto   UNKNOWN_ENDPOINT_LOG_INTERVAL = 5s;
constexpr auto   METRICS_LOG_INTERVAL = 10s;
constexpr size_t RECV_BUF_SIZE        = 1024;
constexpr size_t MAX_UNKNOWN_ENDPOINTS = 4096;
constexpr size_t DEFAULT_MAX_CLIENTS = 256;
constexpr size_t DEFAULT_MAX_ACTIVE_ROOMS = 64;
constexpr size_t DEFAULT_MAX_PERFORMERS_PER_ROOM = 7;
constexpr size_t DEFAULT_IP_PACKETS_PER_SECOND = 500;
constexpr size_t DEFAULT_IP_BYTES_PER_SECOND = 512 * 1024;
constexpr size_t DEFAULT_ROOM_PACKETS_PER_SECOND = 1200;
constexpr size_t DEFAULT_PARTICIPANT_PACKETS_PER_SECOND = 300;

}  // namespace server_config
