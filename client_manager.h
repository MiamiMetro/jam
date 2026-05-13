#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
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

    struct RegistrationResult {
        uint32_t              client_id = 0;
        std::vector<uint32_t> removed_client_ids;
    };

    RegistrationResult register_client(const endpoint& ep, time_point now, std::string room_id,
                                       std::string profile_id, std::string display_name,
                                       ClientRole role) {
        std::lock_guard<std::mutex> lock(mutex_);

        RegistrationResult result;
        auto existing = clients_.find(ep);
        const bool can_reuse_existing =
            existing != clients_.end() && existing->second.room_id == room_id &&
            existing->second.profile_id == profile_id;

        if (can_reuse_existing) {
            auto& client = existing->second;
            client.last_alive           = now;
            client.display_name         = std::move(display_name);
            client.role                 = role;
            client.joined_with_metadata = true;
            result.client_id            = client.client_id;
        } else {
            if (existing != clients_.end()) {
                if (existing->second.role == ClientRole::Performer) {
                    result.removed_client_ids.push_back(existing->second.client_id);
                }
                clients_.erase(existing);
            }

            ClientInfo client;
            client.client_id = next_client_id_++;
            client.joined_at = now;
            client.last_alive = now;
            client.room_id = room_id;
            client.profile_id = profile_id;
            client.display_name = std::move(display_name);
            client.role = role;
            client.joined_with_metadata = true;
            result.client_id = client.client_id;
            clients_[ep] = std::move(client);
        }

        for (auto it = clients_.begin(); it != clients_.end();) {
            if (it->first != ep && it->second.room_id == room_id &&
                it->second.profile_id == profile_id) {
                if (it->second.role == ClientRole::Performer) {
                    result.removed_client_ids.push_back(it->second.client_id);
                }
                it = clients_.erase(it);
            } else {
                ++it;
            }
        }

        return result;
    }

    RegistrationResult register_performer_client(const endpoint& ep, time_point now,
                                                 std::string room_id, std::string profile_id,
                                                 std::string display_name) {
        return register_client(ep, now, std::move(room_id), std::move(profile_id),
                               std::move(display_name), ClientRole::Performer);
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

    std::optional<ClientInfo> remove_client_with_info(const endpoint& ep) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto                        it = clients_.find(ep);
        if (it == clients_.end()) {
            return std::nullopt;
        }
        ClientInfo info = it->second;
        clients_.erase(it);
        return info;
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

    ClientRole get_client_role(const endpoint& ep) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto                        it = clients_.find(ep);
        return it != clients_.end() ? it->second.role : ClientRole::Performer;
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

    std::vector<endpoint> get_room_endpoints_except(const endpoint& exclude) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<endpoint>       endpoints;
        auto                        sender_it = clients_.find(exclude);
        if (sender_it == clients_.end()) {
            return endpoints;
        }

        const std::string& room_id = sender_it->second.room_id;
        endpoints.reserve(clients_.size());
        for (const auto& [ep, info]: clients_) {
            if (ep != exclude && info.room_id == room_id) {
                endpoints.push_back(ep);
            }
        }
        return endpoints;
    }

    std::vector<std::pair<endpoint, ClientInfo>> get_room_clients_except(
        const endpoint& exclude) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::pair<endpoint, ClientInfo>> clients;
        auto sender_it = clients_.find(exclude);
        if (sender_it == clients_.end()) {
            return clients;
        }

        const std::string& room_id = sender_it->second.room_id;
        clients.reserve(clients_.size());
        for (const auto& [ep, info]: clients_) {
            if (ep != exclude && info.room_id == room_id) {
                clients.emplace_back(ep, info);
            }
        }
        return clients;
    }

    // Remove timed out clients (returns list of timed out client IDs)
    std::vector<uint32_t> remove_timed_out_clients(time_point now, std::chrono::seconds timeout) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<uint32_t>       timed_out_ids;

        for (auto it = clients_.begin(); it != clients_.end();) {
            if (now - it->second.last_alive > timeout) {
                if (it->second.role == ClientRole::Performer) {
                    timed_out_ids.push_back(it->second.client_id);
                }
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
