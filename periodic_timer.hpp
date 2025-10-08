#include <asio.hpp>
#include <chrono>
#include <functional>
#include <iostream>

class periodic_timer {
  private:
    asio::steady_timer _timer;
    std::chrono::steady_clock::duration _interval;
    std::function<void()> _callback;

    void on_timeout(std::error_code ec) {
        if (ec) {
            std::cerr << "Timer error: " << ec.message() << "\n";
            return;
        }
        _callback();
        _timer.expires_after(_interval);
        _timer.async_wait([this](std::error_code ec) { on_timeout(ec); });
    }

  public:
    periodic_timer(asio::io_context &io, std::chrono::steady_clock::duration interval, std::function<void()> callback)
        : _timer(io), _interval(interval), _callback(callback) {
        _timer.expires_after(_interval);
        _timer.async_wait([this](std::error_code ec) { on_timeout(ec); });
    }
};