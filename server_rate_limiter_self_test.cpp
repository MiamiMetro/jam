#include "server_rate_limiter.h"

#include <chrono>
#include <cstdlib>
#include <iostream>

#include <asio/ip/address.hpp>

using asio::ip::udp;
using namespace std::chrono_literals;

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}

udp::endpoint endpoint(uint16_t port) {
    return udp::endpoint(asio::ip::make_address("127.0.0.1"), port);
}

void test_authenticated_low_latency_audio_is_not_throttled() {
    server_rate_limiter::ProtocolRateLimiter limiter;
    const auto ep = endpoint(10001);
    const auto start = std::chrono::steady_clock::now();

    for (int i = 0; i < 800; ++i) {
        const auto now = start + std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                                     std::chrono::duration<double>(
                                         static_cast<double>(i) / 400.0));
        require(limiter.allow_authenticated_audio(ep, 48000, 120, now),
                "400 pps authenticated 120-frame audio should pass");
    }
}

void test_authenticated_flood_is_throttled() {
    server_rate_limiter::ProtocolRateLimiter limiter;
    const auto ep = endpoint(10002);
    const auto now = std::chrono::steady_clock::now();

    int allowed = 0;
    for (int i = 0; i < 2000; ++i) {
        if (limiter.allow_authenticated_audio(ep, 48000, 120, now)) {
            ++allowed;
        }
    }

    require(allowed >= 1500, "audio burst should allow a generous startup burst");
    require(allowed < 2000, "same-timestamp audio flood should be throttled");
}

void test_unknown_strict_burst() {
    server_rate_limiter::ProtocolRateLimiter limiter;
    const auto ep = endpoint(10003);
    const auto now = std::chrono::steady_clock::now();

    for (int i = 0; i < 20; ++i) {
        require(limiter.allow_unknown(ep, now), "unknown burst packet should pass");
    }
    require(!limiter.allow_unknown(ep, now), "unknown packet 21 should be throttled");
}

void test_control_burst() {
    server_rate_limiter::ProtocolRateLimiter limiter;
    const auto ep = endpoint(10004);
    const auto now = std::chrono::steady_clock::now();

    for (int i = 0; i < 240; ++i) {
        require(limiter.allow_control(ep, now), "control burst packet should pass");
    }
    require(!limiter.allow_control(ep, now), "control packet 241 should be throttled");
}

}  // namespace

int main() {
    test_authenticated_low_latency_audio_is_not_throttled();
    test_authenticated_flood_is_throttled();
    test_unknown_strict_burst();
    test_control_burst();

    std::cout << "server rate limiter self-test passed\n";
    return 0;
}
