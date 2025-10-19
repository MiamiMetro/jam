#pragma once

#include <asio.hpp>
#include <chrono>
#include <functional>
#include <iostream>

class periodic_timer {
  private:
    asio::steady_timer _timer;
    std::chrono::steady_clock::duration _interval;
    std::chrono::steady_clock::time_point _next_tick;
    std::function<void()> _callback;

    void on_timeout(std::error_code ec) {
        if (ec) {
            std::cerr << "Timer error: " << ec.message() << "\n";
            return;
        }
        _callback();
        _next_tick += _interval;       // Accumulate time to prevent drift
        _timer.expires_at(_next_tick); // Use absolute time, not relative
        _timer.async_wait([this](std::error_code ec) { on_timeout(ec); });
    }

  public:
    periodic_timer(asio::io_context &io, std::chrono::steady_clock::duration interval, std::function<void()> callback)
        : _timer(io), _interval(interval), _callback(callback),
          _next_tick(std::chrono::steady_clock::now() + interval) {
        _timer.expires_at(_next_tick); // Use absolute time from the start
        _timer.async_wait([this](std::error_code ec) { on_timeout(ec); });
    }

    void start() {
        _next_tick = std::chrono::steady_clock::now() + _interval;
        _timer.expires_at(_next_tick);
        _timer.async_wait([this](std::error_code ec) { on_timeout(ec); });
    }
    void stop() { _timer.cancel(); }
};