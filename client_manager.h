#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <vector>

#include <asio/ip/udp.hpp>

#include "client_info.h"
#include "endpoint_hash.h"

// Thread-safe client lifecycle manager
class ClientManager {
public:
    using endpoint   = asio::ip::udp::endpoint;
    using time_point = std::chrono::steady_clock::time_point;

    ClientManager() : next_client_id_(1) {}

    // Register a new client (returns assigned client ID)
    uint32_t register_client(const endpoint& ep, time_point now) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto&                       client = clients_[ep];
        if (client.client_id == 0) {
            client.client_id = next_client_id_++;
        }
        client.last_alive = now;
        return client.client_id;
    }

    // Update client last_alive timestamp
    void update_alive(const endpoint& ep, time_point now) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto                        it = clients_.find(ep);
        if (it != clients_.end()) {
            it->second.last_alive = now;
        }
    }

    // Remove a client (returns their ID, or 0 if not found)
    uint32_t remove_client(const endpoint& ep) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto                        it = clients_.find(ep);
        if (it != clients_.end()) {
            uint32_t id = it->second.client_id;
            clients_.erase(it);
            return id;
        }
        return 0;
    }

    // Check if client exists
    bool exists(const endpoint& ep) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return clients_.contains(ep);
    }

    // Get client ID (returns 0 if not found)
    uint32_t get_client_id(const endpoint& ep) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto                        it = clients_.find(ep);
        return it != clients_.end() ? it->second.client_id : 0;
    }

    // Check if any clients exist
    bool empty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return clients_.empty();
    }

    // Get count of clients
    size_t count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return clients_.size();
    }

    // Get all client endpoints (copy for safe iteration)
    std::vector<endpoint> get_all_endpoints() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<endpoint>       endpoints;
        endpoints.reserve(clients_.size());
        for (const auto& [ep, info]: clients_) {
            endpoints.push_back(ep);
        }
        return endpoints;
    }

    // Get all endpoints except one (for forwarding)
    std::vector<endpoint> get_endpoints_except(const endpoint& exclude) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<endpoint>       endpoints;
        endpoints.reserve(clients_.size());
        for (const auto& [ep, info]: clients_) {
            if (ep != exclude) {
                endpoints.push_back(ep);
            }
        }
        return endpoints;
    }

    // Remove timed out clients (returns list of timed out client IDs)
    std::vector<uint32_t> remove_timed_out_clients(time_point now, std::chrono::seconds timeout) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<uint32_t>       timed_out_ids;

        for (auto it = clients_.begin(); it != clients_.end();) {
            if (now - it->second.last_alive > timeout) {
                timed_out_ids.push_back(it->second.client_id);
                it = clients_.erase(it);
            } else {
                ++it;
            }
        }

        return timed_out_ids;
    }

    // Access client info with lock (use with caution - callback must be fast)
    template <typename Func>
    void with_client(const endpoint& ep, Func&& func) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto                        it = clients_.find(ep);
        if (it != clients_.end()) {
            func(it->second);
        }
    }

    // Access client info with lock (const version)
    template <typename Func>
    void with_client(const endpoint& ep, Func&& func) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto                        it = clients_.find(ep);
        if (it != clients_.end()) {
            func(it->second);
        }
    }

private:
    mutable std::mutex                                      mutex_;
    std::unordered_map<endpoint, ClientInfo, endpoint_hash> clients_;
    uint32_t                                                next_client_id_;
};
