#pragma once

#include <chrono>

using namespace std::chrono_literals;

// Server configuration constants
namespace server_config {

constexpr auto   ALIVE_CHECK_INTERVAL = 5s;
constexpr auto   CLIENT_TIMEOUT       = 15s;
constexpr auto   UNKNOWN_ENDPOINT_TTL = 30s;
constexpr auto   UNKNOWN_ENDPOINT_LOG_INTERVAL = 5s;
constexpr size_t RECV_BUF_SIZE        = 1024;
constexpr size_t MAX_UNKNOWN_ENDPOINTS = 4096;

}  // namespace server_config
