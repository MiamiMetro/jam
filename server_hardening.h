#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>

class TokenBucket {
public:
    bool allow(size_t cost, size_t capacity, double refill_per_second,
               std::chrono::steady_clock::time_point now) {
        if (capacity == 0 || refill_per_second <= 0.0) {
            return false;
        }
        if (!initialized_) {
            tokens_ = static_cast<double>(capacity);
            last_refill_ = now;
            initialized_ = true;
        }

        const auto elapsed = std::chrono::duration<double>(now - last_refill_).count();
        if (elapsed > 0.0) {
            tokens_ = std::min(static_cast<double>(capacity), tokens_ + elapsed * refill_per_second);
            last_refill_ = now;
        }

        if (tokens_ < static_cast<double>(cost)) {
            return false;
        }
        tokens_ -= static_cast<double>(cost);
        return true;
    }

    std::chrono::steady_clock::time_point last_seen() const {
        return last_refill_;
    }

private:
    bool initialized_ = false;
    double tokens_ = 0.0;
    std::chrono::steady_clock::time_point last_refill_{};
};

struct ServerMetrics {
    std::atomic<uint64_t> packets_rx{0};
    std::atomic<uint64_t> packets_tx{0};
    std::atomic<uint64_t> bytes_rx{0};
    std::atomic<uint64_t> bytes_tx{0};
    std::atomic<uint64_t> joins_accepted{0};
    std::atomic<uint64_t> joins_rejected{0};
    std::atomic<uint64_t> malformed_packets{0};
    std::atomic<uint64_t> unauthorized_drops{0};
    std::atomic<uint64_t> rate_limit_drops{0};
    std::atomic<uint64_t> capacity_rejects{0};
};
