#include "udp_socket_config.h"

#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <thread>

using asio::ip::udp;
using namespace std::chrono_literals;

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}

void test_dscp_constants() {
    require(udp_network::EF_DSCP_VALUE == 46, "EF DSCP must be 46");
    require(udp_network::EF_TRAFFIC_CLASS == 0xB8, "EF traffic class must be 0xB8");
}

void test_endpoint_display_and_normalization() {
    asio::io_context io;
    udp::socket      socket(io);
    std::error_code  ec;
    const auto       protocol = udp_network::open_dual_stack_socket(socket, 0, ec);
    require(!ec, "socket should open");

    const udp::endpoint v4(asio::ip::make_address("127.0.0.1"), 9999);
    const auto normalized = udp_network::normalize_endpoint_for_socket(socket, v4);
    if (protocol == udp::v6()) {
        require(normalized.address().is_v6(),
                "dual-stack socket should use mapped v4 endpoint");
        require(udp_network::format_address_for_display(normalized.address()) ==
                    "127.0.0.1",
                "mapped v4 display should be unmapped");
    } else {
        require(normalized.address().is_v4(), "v4 fallback should keep v4 endpoint");
    }
}

void test_dual_stack_ipv4_compatibility() {
    asio::io_context io;
    udp::socket      receiver(io);
    std::error_code  ec;
    const auto       protocol = udp_network::open_dual_stack_socket(receiver, 0, ec);
    require(!ec, "receiver should open");
    if (protocol != udp::v6()) {
        return;
    }

    udp::socket sender(io, udp::endpoint(udp::v4(), 0));
    const std::array<unsigned char, 4> payload{1, 2, 3, 4};
    sender.send_to(asio::buffer(payload),
                   udp::endpoint(asio::ip::make_address("127.0.0.1"),
                                 receiver.local_endpoint().port()),
                   0, ec);
    require(!ec, "v4 sender should send to dual-stack socket");

    receiver.non_blocking(true);
    std::array<unsigned char, 8> buffer{};
    udp::endpoint               remote;
    const auto                  deadline = std::chrono::steady_clock::now() + 500ms;
    bool                        received = false;
    while (std::chrono::steady_clock::now() < deadline) {
        const auto bytes = receiver.receive_from(asio::buffer(buffer), remote, 0, ec);
        if (!ec && bytes == payload.size()) {
            received = std::memcmp(buffer.data(), payload.data(), payload.size()) == 0;
            break;
        }
        if (ec != asio::error::would_block && ec != asio::error::try_again) {
            break;
        }
        std::this_thread::sleep_for(5ms);
    }
    require(received, "dual-stack socket should receive IPv4 datagram");
}

void test_qos_is_non_fatal() {
    asio::io_context io;
    udp::socket      socket(io);
    std::error_code  ec;
    udp_network::open_dual_stack_socket(socket, 0, ec);
    require(!ec, "QoS test socket should open");

    udp_network::UdpSocketQos qos;
    const auto result = qos.ensure_flow(
        socket, udp_network::normalize_endpoint_for_socket(
                    socket, udp::endpoint(asio::ip::make_address("127.0.0.1"), 9)));
    require(result.requested, "QoS should be requested");
}

}  // namespace

int main() {
    test_dscp_constants();
    test_endpoint_display_and_normalization();
    test_dual_stack_ipv4_compatibility();
    test_qos_is_non_fatal();
    std::cout << "udp socket config self-test passed\n";
    return 0;
}
