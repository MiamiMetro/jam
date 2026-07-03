#pragma once

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <unordered_map>

#include <asio/ip/udp.hpp>

#include "endpoint_hash.h"

namespace server_rate_limiter {

class TokenBucket {
public:
    bool allow(std::chrono::steady_clock::time_point now, double rate_per_second,
               double burst_tokens, double cost = 1.0) {
        rate_per_second = std::max(0.0, rate_per_second);
        burst_tokens = std::max(0.0, burst_tokens);
        cost = std::max(0.0, cost);

        if (last_refill_.time_since_epoch().count() == 0) {
            tokens_ = burst_tokens;
            last_refill_ = now;
        } else if (now > last_refill_) {
            const double elapsed_seconds =
                std::chrono::duration<double>(now - last_refill_).count();
            tokens_ = std::min(burst_tokens, tokens_ + elapsed_seconds * rate_per_second);
            last_refill_ = now;
        }

        if (tokens_ + 1e-9 < cost) {
            return false;
        }
        tokens_ -= cost;
        return true;
    }

private:
    double tokens_ = 0.0;
    std::chrono::steady_clock::time_point last_refill_{};
};

class ProtocolRateLimiter {
public:
    using endpoint = asio::ip::udp::endpoint;
    using time_point = std::chrono::steady_clock::time_point;

    bool allow_unknown(const endpoint& ep, time_point now) {
        return unknown_[ep].allow(now, 20.0, 20.0);
    }

    bool allow_strict(const endpoint& ep, time_point now) {
        return strict_[ep].allow(now, 20.0, 20.0);
    }

    bool allow_control(const endpoint& ep, time_point now) {
        return control_[ep].allow(now, 120.0, 240.0);
    }

    bool allow_authenticated_audio(const endpoint& ep, uint32_t sample_rate,
                                   uint16_t frame_count, time_point now) {
        if (sample_rate == 0 || frame_count == 0) {
            return allow_strict(ep, now);
        }

        const double packet_rate =
            std::ceil(static_cast<double>(sample_rate) / static_cast<double>(frame_count));
        const double allowed_rate = std::max(600.0, packet_rate * 2.0);
        return audio_[ep].allow(now, allowed_rate, allowed_rate * 2.0);
    }

    void erase(const endpoint& ep) {
        unknown_.erase(ep);
        strict_.erase(ep);
        control_.erase(ep);
        audio_.erase(ep);
    }

private:
    std::unordered_map<endpoint, TokenBucket, endpoint_hash> unknown_;
    std::unordered_map<endpoint, TokenBucket, endpoint_hash> strict_;
    std::unordered_map<endpoint, TokenBucket, endpoint_hash> control_;
    std::unordered_map<endpoint, TokenBucket, endpoint_hash> audio_;
};

}  // namespace server_rate_limiter
