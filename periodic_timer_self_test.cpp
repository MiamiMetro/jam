#include "periodic_timer.h"

#include <asio.hpp>

#include <chrono>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <system_error>
#include <thread>

using namespace std::chrono_literals;

namespace {

class LegacyCatchupTimer {
public:
    LegacyCatchupTimer(asio::io_context& io_context,
                       std::chrono::steady_clock::duration interval,
                       std::function<void()> callback)
        : timer_(io_context),
          interval_(interval),
          next_tick_(std::chrono::steady_clock::now() + interval),
          callback_(std::move(callback)) {
        timer_.expires_at(next_tick_);
        timer_.async_wait([this](std::error_code error_code) {
            on_timeout(error_code);
        });
    }

private:
    asio::steady_timer                  timer_;
    std::chrono::steady_clock::duration interval_;
    std::chrono::steady_clock::time_point next_tick_;
    std::function<void()>               callback_;

    void on_timeout(std::error_code error_code) {
        if (error_code) {
            return;
        }
        callback_();
        next_tick_ += interval_;
        timer_.expires_at(next_tick_);
        timer_.async_wait([this](std::error_code next_error) {
            on_timeout(next_error);
        });
    }
};

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}

struct ProbeResult {
    int total_callbacks = 0;
    int immediate_callbacks = 0;
};

template <typename Timer>
ProbeResult probe_callbacks_after_delayed_io_thread() {
    asio::io_context io_context;
    asio::steady_timer stop_timer(io_context);
    ProbeResult result;
    std::chrono::steady_clock::time_point first_callback_time{};

    Timer timer(io_context, 10ms, [&]() {
        const auto now = std::chrono::steady_clock::now();
        ++result.total_callbacks;
        if (result.total_callbacks == 1) {
            first_callback_time = now;
            stop_timer.expires_after(25ms);
            stop_timer.async_wait([&](std::error_code) {
                io_context.stop();
            });
            ++result.immediate_callbacks;
        } else if (now - first_callback_time <= 2ms) {
            ++result.immediate_callbacks;
        }
        if (result.total_callbacks >= 20) {
            io_context.stop();
        }
    });

    asio::post(io_context, []() {
        std::this_thread::sleep_for(75ms);
    });

    io_context.run();
    return result;
}

}  // namespace

int main() {
    const ProbeResult legacy =
        probe_callbacks_after_delayed_io_thread<LegacyCatchupTimer>();
    require(legacy.immediate_callbacks > 1,
            "legacy catch-up timer did not reproduce the missed-tick burst");

    const ProbeResult current =
        probe_callbacks_after_delayed_io_thread<PeriodicTimer>();
    require(current.immediate_callbacks == 1,
            "PeriodicTimer replayed missed ticks after a delayed IO thread");

    std::cout << "periodic timer self-test passed: legacy burst callbacks="
              << legacy.immediate_callbacks << " legacy total=" << legacy.total_callbacks
              << " current burst callbacks=" << current.immediate_callbacks
              << " current total=" << current.total_callbacks << '\n';
    return 0;
}
