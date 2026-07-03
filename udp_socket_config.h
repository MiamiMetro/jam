#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <system_error>
#include <unordered_map>

#include <asio/error.hpp>
#include <asio/ip/address.hpp>
#include <asio/ip/address_v6.hpp>
#include <asio/ip/udp.hpp>
#include <asio/ip/v6_only.hpp>
#include <asio/socket_base.hpp>

#include "endpoint_hash.h"
#include "protocol.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>
#include <qos2.h>
#else
#include <cerrno>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

namespace udp_network {

using asio::ip::udp;

constexpr int EF_DSCP_VALUE    = 46;
constexpr int EF_TRAFFIC_CLASS = EF_DSCP_VALUE << 2;

struct QosResult {
    bool          requested             = false;
    bool          newly_configured      = false;
    bool          socket_option_applied = false;
    bool          qwave_flow_added      = false;
    bool          explicit_dscp_applied = false;
    unsigned long error_code            = 0;
    std::string   detail;

    bool ok() const {
        return socket_option_applied || qwave_flow_added || explicit_dscp_applied;
    }
};

inline std::string format_address_for_display(const asio::ip::address& address) {
    if (address.is_v6() && address.to_v6().is_v4_mapped()) {
        return asio::ip::make_address_v4(asio::ip::v4_mapped, address.to_v6()).to_string();
    }
    return address.to_string();
}

inline bool socket_uses_ipv6(const udp::socket& socket) {
    std::error_code ec;
    const auto      local = socket.local_endpoint(ec);
    return !ec && local.protocol() == udp::v6();
}

inline udp::endpoint normalize_endpoint_for_socket(const udp::socket& socket,
                                                   const udp::endpoint& endpoint) {
    if (socket_uses_ipv6(socket) && endpoint.address().is_v4()) {
        return udp::endpoint(
            asio::ip::make_address_v6(asio::ip::v4_mapped, endpoint.address().to_v4()),
            endpoint.port());
    }
    return endpoint;
}

inline std::optional<udp::endpoint> choose_endpoint_for_socket(
    const udp::socket& socket, const udp::resolver::results_type& results) {
    const bool use_ipv6 = socket_uses_ipv6(socket);
    for (const auto& entry : results) {
        const auto endpoint = entry.endpoint();
        if (use_ipv6) {
            return normalize_endpoint_for_socket(socket, endpoint);
        }
        if (endpoint.address().is_v4()) {
            return endpoint;
        }
        if (endpoint.address().is_v6() && endpoint.address().to_v6().is_v4_mapped()) {
            return udp::endpoint(
                asio::ip::make_address_v4(asio::ip::v4_mapped, endpoint.address().to_v6()),
                endpoint.port());
        }
    }
    return std::nullopt;
}

inline udp open_dual_stack_socket(udp::socket& socket, uint16_t port, std::error_code& ec) {
    std::error_code ignored;
    if (socket.is_open()) {
        socket.close(ignored);
    }

    socket.open(udp::v6(), ec);
    if (!ec) {
        socket.set_option(asio::ip::v6_only(false), ec);
        if (!ec) {
            socket.bind(udp::endpoint(udp::v6(), port), ec);
            if (!ec) {
                return udp::v6();
            }
        }
        socket.close(ignored);
    }

    socket.open(udp::v4(), ec);
    if (!ec) {
        socket.bind(udp::endpoint(udp::v4(), port), ec);
        if (!ec) {
            return udp::v4();
        }
        socket.close(ignored);
    }

    return udp::v4();
}

inline udp open_compatible_socket(udp::socket& socket, const udp::endpoint& target,
                                  uint16_t port, std::error_code& ec) {
    const auto protocol = open_dual_stack_socket(socket, port, ec);
    if (!ec && target.address().is_v6() && protocol != udp::v6()) {
        std::error_code ignored;
        socket.close(ignored);
        ec = asio::error::address_family_not_supported;
    }
    return protocol;
}

inline void configure_low_latency_buffers(udp::socket& socket, std::error_code& ec) {
    socket.set_option(asio::socket_base::receive_buffer_size(UDP_SOCKET_BUFFER_BYTES), ec);
    if (ec) {
        return;
    }
    socket.set_option(asio::socket_base::send_buffer_size(UDP_SOCKET_BUFFER_BYTES), ec);
}

class UdpSocketQos {
public:
    UdpSocketQos() = default;
    UdpSocketQos(const UdpSocketQos&) = delete;
    UdpSocketQos& operator=(const UdpSocketQos&) = delete;
    ~UdpSocketQos() {
        reset();
    }

    QosResult ensure_flow(udp::socket& socket, const udp::endpoint& endpoint);
    void reset();

private:
    bool socket_option_applied_ = false;

#ifdef _WIN32
    HANDLE qos_handle_ = nullptr;
    std::unordered_map<udp::endpoint, QOS_FLOWID, endpoint_hash> flows_;
    std::unordered_map<udp::endpoint, QosResult, endpoint_hash> failed_flows_;
    std::optional<QosResult> handle_failure_;

    bool ensure_qos_handle(QosResult& result);
#endif
};

#ifdef _WIN32
inline bool endpoint_to_sockaddr(const udp::endpoint& endpoint, sockaddr_storage& storage,
                                 int& length, bool unmap_v4_mapped) {
    std::memset(&storage, 0, sizeof(storage));
    if (endpoint.address().is_v4() ||
        (unmap_v4_mapped && endpoint.address().is_v6() &&
         endpoint.address().to_v6().is_v4_mapped())) {
        auto* addr = reinterpret_cast<sockaddr_in*>(&storage);
        addr->sin_family = AF_INET;
        addr->sin_port   = htons(endpoint.port());
        const auto v4_address =
            endpoint.address().is_v4()
                ? endpoint.address().to_v4()
                : asio::ip::make_address_v4(asio::ip::v4_mapped, endpoint.address().to_v6());
        const auto bytes = v4_address.to_bytes();
        std::memcpy(&addr->sin_addr, bytes.data(), bytes.size());
        length = sizeof(sockaddr_in);
        return true;
    }

    auto* addr6 = reinterpret_cast<sockaddr_in6*>(&storage);
    addr6->sin6_family = AF_INET6;
    addr6->sin6_port   = htons(endpoint.port());
    addr6->sin6_scope_id = endpoint.address().to_v6().scope_id();
    const auto bytes = endpoint.address().to_v6().to_bytes();
    std::memcpy(&addr6->sin6_addr, bytes.data(), bytes.size());
    length = sizeof(sockaddr_in6);
    return true;
}

inline bool UdpSocketQos::ensure_qos_handle(QosResult& result) {
    if (qos_handle_ != nullptr) {
        return true;
    }
    if (handle_failure_.has_value()) {
        result = *handle_failure_;
        result.newly_configured = false;
        return false;
    }

    QOS_VERSION version{};
    version.MajorVersion = 1;
    version.MinorVersion = 0;
    if (QOSCreateHandle(&version, &qos_handle_) != 0) {
        return true;
    }

    result.error_code = GetLastError();
    result.detail = "QOSCreateHandle failed with error " + std::to_string(result.error_code);
    handle_failure_ = result;
    handle_failure_->newly_configured = false;
    return false;
}

inline QosResult UdpSocketQos::ensure_flow(udp::socket& socket,
                                           const udp::endpoint& endpoint) {
    QosResult result;
    result.requested = true;

    const udp::endpoint normalized = normalize_endpoint_for_socket(socket, endpoint);
    if (flows_.find(normalized) != flows_.end()) {
        result.qwave_flow_added = true;
        result.detail = "qWAVE flow already configured";
        return result;
    }
    if (const auto failed = failed_flows_.find(normalized); failed != failed_flows_.end()) {
        result = failed->second;
        result.requested = true;
        result.newly_configured = false;
        return result;
    }

    result.newly_configured = true;
    if (!ensure_qos_handle(result)) {
        return result;
    }

    auto cache_failure = [&]() {
        auto cached = result;
        cached.newly_configured = false;
        failed_flows_[normalized] = cached;
    };

    auto add_socket_to_flow = [&](bool unmap_v4_mapped, QOS_FLOWID& flow_id) {
        sockaddr_storage storage{};
        int              storage_length = 0;
        if (!endpoint_to_sockaddr(normalized, storage, storage_length, unmap_v4_mapped)) {
            result.detail = "endpoint address family is not supported by qWAVE";
            result.error_code = ERROR_INVALID_PARAMETER;
            return false;
        }
        if (QOSAddSocketToFlow(qos_handle_, socket.native_handle(),
                               reinterpret_cast<PSOCKADDR>(&storage), QOSTrafficTypeVoice,
                               QOS_NON_ADAPTIVE_FLOW, &flow_id) != 0) {
            return true;
        }
        result.error_code = GetLastError();
        return false;
    };

    QOS_FLOWID flow_id = 0;
    bool       flow_added = add_socket_to_flow(true, flow_id);
    if (!flow_added && result.error_code == ERROR_INVALID_PARAMETER &&
        normalized.address().is_v6() && normalized.address().to_v6().is_v4_mapped()) {
        flow_id = 0;
        flow_added = add_socket_to_flow(false, flow_id);
    }
    if (!flow_added) {
        result.detail = "QOSAddSocketToFlow failed with error " +
                        std::to_string(result.error_code);
        cache_failure();
        return result;
    }

    flows_.emplace(normalized, flow_id);
    result.qwave_flow_added = true;

    DWORD dscp = EF_DSCP_VALUE;
    if (QOSSetFlow(qos_handle_, flow_id, QOSSetOutgoingDSCPValue, sizeof(dscp), &dscp, 0,
                   nullptr) != 0) {
        result.explicit_dscp_applied = true;
        result.detail = "qWAVE flow configured with EF DSCP";
        return result;
    }

    result.error_code = GetLastError();
    result.detail = "qWAVE flow configured; explicit EF DSCP failed with error " +
                    std::to_string(result.error_code);
    return result;
}

inline void UdpSocketQos::reset() {
    flows_.clear();
    failed_flows_.clear();
    handle_failure_.reset();
    if (qos_handle_ != nullptr) {
        QOSCloseHandle(qos_handle_);
        qos_handle_ = nullptr;
    }
    socket_option_applied_ = false;
}
#else
inline bool apply_socket_traffic_class(udp::socket& socket, int level, int option,
                                       QosResult& result) {
    const int value = EF_TRAFFIC_CLASS;
    if (::setsockopt(socket.native_handle(), level, option, &value, sizeof(value)) == 0) {
        result.socket_option_applied = true;
        return true;
    }
    result.error_code = static_cast<unsigned long>(errno);
    return false;
}

inline QosResult UdpSocketQos::ensure_flow(udp::socket& socket,
                                           const udp::endpoint&) {
    QosResult result;
    result.requested = true;
    if (socket_option_applied_) {
        result.socket_option_applied = true;
        result.detail = "DSCP EF socket option already configured";
        return result;
    }

    result.newly_configured = true;
    std::error_code ec;
    const auto      local = socket.local_endpoint(ec);
    if (ec) {
        result.detail = "local endpoint unavailable: " + ec.message();
        return result;
    }

    bool applied = false;
    if (local.protocol() == udp::v4()) {
        applied = apply_socket_traffic_class(socket, IPPROTO_IP, IP_TOS, result);
    } else {
#ifdef IPV6_TCLASS
        applied = apply_socket_traffic_class(socket, IPPROTO_IPV6, IPV6_TCLASS, result);
#endif
        applied = apply_socket_traffic_class(socket, IPPROTO_IP, IP_TOS, result) || applied;
    }

    if (applied) {
        socket_option_applied_ = true;
        result.detail = "DSCP EF socket option configured";
    } else if (result.detail.empty()) {
        result.detail = "DSCP EF socket option failed with errno " +
                        std::to_string(result.error_code);
    }
    return result;
}

inline void UdpSocketQos::reset() {
    socket_option_applied_ = false;
}
#endif

}  // namespace udp_network
