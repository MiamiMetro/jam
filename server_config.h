#pragma once

#include <chrono>

using namespace std::chrono_literals;

// Server configuration constants
namespace server_config {

constexpr auto   ALIVE_CHECK_INTERVAL = 5s;
constexpr auto   CLIENT_TIMEOUT       = 15s;
constexpr size_t RECV_BUF_SIZE        = 1024;

}  // namespace server_config
