#pragma once

#include <asio.hpp>
#include <chrono>
#include <functional>
#include <utility>
#include "logger.hpp"

class periodic_timer {
  private:
    asio::steady_timer _timer;
    std::chrono::steady_clock::duration _interval;
    std::chrono::steady_clock::time_point _next_tick;
    std::function<void()> _callback;

    void on_timeout(std::error_code error_code) {
        if (error_code) {
            Log::error("Timer error: {}", error_code.message());
            return;
        }
        _callback();
        _next_tick += _interval;       // Accumulate time to prevent drift
        _timer.expires_at(_next_tick); // Use absolute time, not relative
        _timer.async_wait([this](std::error_code error_code) { on_timeout(error_code); });
    }

  public:
    periodic_timer(asio::io_context &io_context, std::chrono::steady_clock::duration interval, std::function<void()> callback)
        : _timer(io_context), _interval(interval), _callback(std::move(callback)),
          _next_tick(std::chrono::steady_clock::now() + interval) {
        _timer.expires_at(_next_tick); // Use absolute time from the start
        _timer.async_wait([this](std::error_code error_code) { on_timeout(error_code); });
    }

    void start() {
        _next_tick = std::chrono::steady_clock::now() + _interval;
        _timer.expires_at(_next_tick);
        _timer.async_wait([this](std::error_code error_code) { on_timeout(error_code); });
    }
    void stop() { _timer.cancel(); }
};