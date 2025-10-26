#pragma once

#include <asio.hpp>
#include <chrono>
#include <functional>
#include <utility>
#include "logger.h"

class PeriodicTimer {
public:
    PeriodicTimer(asio::io_context& io_context, std::chrono::steady_clock::duration interval,
                  std::function<void()> callback)
        : timer_(io_context),
          interval_(interval),
          callback_(std::move(callback)),
          next_tick_(std::chrono::steady_clock::now() + interval) {
        timer_.expires_at(next_tick_);  // Use absolute time from the start
        timer_.async_wait([this](std::error_code error_code) { on_timeout(error_code); });
    }

    void start() {
        next_tick_ = std::chrono::steady_clock::now() + interval_;
        timer_.expires_at(next_tick_);
        timer_.async_wait([this](std::error_code error_code) { on_timeout(error_code); });
    }
    void stop() {
        timer_.cancel();
    }

private:
    asio::steady_timer                    timer_;
    std::chrono::steady_clock::duration   interval_;
    std::chrono::steady_clock::time_point next_tick_;
    std::function<void()>                 callback_;

    void on_timeout(std::error_code error_code) {
        if (error_code) {
            Log::error("Timer error: {}", error_code.message());
            return;
        }
        callback_();
        next_tick_ += interval_;        // Accumulate time to prevent drift
        timer_.expires_at(next_tick_);  // Use absolute time, not relative
        timer_.async_wait([this](std::error_code error_code) { on_timeout(error_code); });
    }
};