#pragma once

#include <cstddef>
#include <functional>
#include <string_view>

#include <asio/ip/udp.hpp>

// Hash functor for udp::endpoint to use in unordered_map
struct endpoint_hash {
    size_t operator()(const asio::ip::udp::endpoint& endpoint) const {
        // Avoid string allocations - hash IP bytes + port directly
        size_t address_hash = 0;
        if (endpoint.address().is_v4()) {
            address_hash = std::hash<uint32_t>{}(endpoint.address().to_v4().to_uint());
        } else {
            auto bytes   = endpoint.address().to_v6().to_bytes();
            address_hash = std::hash<std::string_view>{}(
                std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
        }
        size_t port_hash = std::hash<unsigned short>{}(endpoint.port());
        return address_hash ^ (port_hash << 1);  // Combine hashes
    }
};
