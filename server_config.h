#pragma once

#include <chrono>

using namespace std::chrono_literals;

// Server configuration constants

namespace server_config {
constexpr auto   ALIVE_CHECK_INTERVAL = 5s;
constexpr auto   CLIENT_TIMEOUT       = 15s;
constexpr size_t RECV_BUF_SIZE        = 1024;
constexpr auto   MIX_INTERVAL         = 10ms;

// SRT connection retry settings
constexpr int MAX_SRT_RETRY_ATTEMPTS      = 3;
constexpr int SRT_RETRY_FAILURE_THRESHOLD = 1500;  // ~15 seconds at 10ms intervals

}  // namespace server_config
