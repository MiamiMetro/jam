#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>

namespace join_reliability {

class State {
public:
    explicit State(std::chrono::steady_clock::duration retry_interval)
        : retry_interval_(retry_interval) {}

    void reset() {
        join_confirmed_.store(false, std::memory_order_release);
        participant_id_.store(0, std::memory_order_release);
        server_capabilities_.store(0, std::memory_order_release);
        last_join_sent_ = {};
    }

    bool should_send_join(std::chrono::steady_clock::time_point now) const {
        if (is_join_confirmed()) {
            return false;
        }
        return last_join_sent_.time_since_epoch().count() == 0 ||
               now - last_join_sent_ >= retry_interval_;
    }

    void mark_join_sent(std::chrono::steady_clock::time_point now) {
        last_join_sent_ = now;
    }

    void mark_join_ack(uint32_t participant_id, uint32_t server_capabilities = 0) {
        participant_id_.store(participant_id, std::memory_order_release);
        server_capabilities_.store(server_capabilities, std::memory_order_release);
        join_confirmed_.store(true, std::memory_order_release);
    }

    void mark_join_required() {
        join_confirmed_.store(false, std::memory_order_release);
        participant_id_.store(0, std::memory_order_release);
        server_capabilities_.store(0, std::memory_order_release);
        last_join_sent_ = {};
    }

    bool is_join_confirmed() const {
        return join_confirmed_.load(std::memory_order_acquire);
    }

    bool can_send_audio() const {
        return is_join_confirmed();
    }

    uint32_t participant_id() const {
        return participant_id_.load(std::memory_order_acquire);
    }

    uint32_t server_capabilities() const {
        return server_capabilities_.load(std::memory_order_acquire);
    }

    bool server_supports(uint32_t capability) const {
        return (server_capabilities() & capability) != 0;
    }

private:
    std::chrono::steady_clock::duration     retry_interval_;
    std::chrono::steady_clock::time_point   last_join_sent_{};
    std::atomic<bool>                       join_confirmed_{false};
    std::atomic<uint32_t>                   participant_id_{0};
    std::atomic<uint32_t>                   server_capabilities_{0};
};

}  // namespace join_reliability
