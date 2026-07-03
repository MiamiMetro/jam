# Phase 5 Track B Network Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Track B only: DSCP/QoS marking for low-latency UDP audio and IPv4/IPv6 dual-stack socket support.

**Architecture:** Put platform-specific socket behavior behind a small header so the large client and server only request "low latency UDP socket" and "QoS flow for this peer." Open server and client sockets as IPv6 dual-stack when the OS supports it, falling back to IPv4 if IPv6 is unavailable. Use qWAVE destination flows on Windows and socket-level `IP_TOS`/`IPV6_TCLASS` elsewhere.

**Tech Stack:** C++23, standalone Asio UDP, Win32 qWAVE (`qos2.h`, `Qwave.lib`) on Windows, POSIX `setsockopt` for `IP_TOS` and `IPV6_TCLASS`, CMake/CTest self-tests and smoke tests.

## Global Constraints

- Current planning base: `main` at `2ea7d93`.
- Execute exactly one Phase 5 track in this session: Track B network only.
- Do not implement Track C operations or Track E devices in this session.
- Track A security and Track D testing are already done; do not reopen those tracks except to keep their tests passing.
- Tracker rule: one branch per phase; this work runs on branch `phase5-track-b-network`.
- Tracker rule: one commit per implementation task; build plus full `ctest` after each task that changes buildable code or CTest registrations.
- DSCP target is Expedited Forwarding: DSCP value `46`, traffic-class byte `0xB8`.
- Windows must use qWAVE; plain `IP_TOS` is intentionally not used there.
- POSIX must use `IP_TOS` for IPv4 and `IPV6_TCLASS` for IPv6 sockets.
- IPv6 support must preserve IPv4 clients and probes that use `127.0.0.1`.

---

## Current HEAD Citation Check

- `LOW_LATENCY_ACTION_PLAN.md:191-192` defines Track B as DSCP/QoS marking with qWAVE on Windows plus dual-stack IPv4/IPv6 sockets.
- `LOW_LATENCY_AUDIT.md:118-123` reports no network QoS marking; `rg "IP_TOS|DSCP|qwave|QOS" -g"*.cpp" -g"*.h"` still finds no implementation in current HEAD.
- `LOW_LATENCY_AUDIT.md:161-163` reports IPv4-only sockets; current HEAD still has primary client/server construction at `client.cpp:261` and `server.cpp:89` using `udp::endpoint(udp::v4(), ...)`.
- `client.cpp:327` resolves only `udp::v4()`, so IPv6 hostnames and literals are ignored.
- `client.cpp:1913-1915` rebinds the client UDP path with a new IPv4-only socket.
- `client.cpp:1816-1817` and `server.cpp:95-96` only set large socket buffers.
- Microsoft qWAVE API check: `QOSCreateHandle` must be called before other qWAVE functions and links with `Qwave.lib` (https://learn.microsoft.com/en-us/windows/win32/api/qos2/nf-qos2-qoscreatehandle).
- Microsoft qWAVE API check: `QOSAddSocketToFlow` supports unconnected UDP sockets when `DestAddr` supplies the remote IP and port; IPv4/v6 mixed addresses are not supported (https://learn.microsoft.com/en-us/windows/win32/api/qos2/nf-qos2-qosaddsockettoflow).
- Microsoft qWAVE API check: `QOSSetFlow(QOSSetOutgoingDSCPValue)` sets an outgoing DSCP value but can fail for insufficient privileges, so the implementation must keep the qWAVE traffic flow even if explicit EF is denied (https://learn.microsoft.com/en-us/windows/win32/api/qos2/nf-qos2-qossetflow).

## File Structure

- Create `udp_socket_config.h`: owns dual-stack UDP open/bind helpers, endpoint normalization for IPv4-mapped IPv6, DSCP constants, POSIX traffic-class socket options, and Windows qWAVE per-destination flow management.
- Create `udp_socket_config_self_test.cpp`: validates DSCP constants, dual-stack fallback/open behavior, IPv4 compatibility when a dual-stack socket is available, endpoint normalization, and non-fatal QoS configuration.
- Modify `CMakeLists.txt`: build/register `udp_socket_config_self_test`; link `Qwave` to the self-test on Windows.
- Modify `cmake/server.cmake`: link `Qwave` to `server` on Windows.
- Modify `cmake/client.cmake`: link `Qwave` to `client` on Windows.
- Modify `server.cpp`: open the main socket through `udp_socket_config.h`, apply buffer and QoS setup, ensure a qWAVE flow for each send target, and add a dual-stack relay smoke.
- Modify `client.cpp`: open the main socket through `udp_socket_config.h`, resolve both address families, normalize IPv4 destinations on dual-stack sockets, rebind with the active protocol, apply QoS for the server flow, and preserve UI/test display of IPv4-mapped addresses.
- Modify `LOW_LATENCY_ACTION_PLAN.md`: add the Track B plan link, mark Track B done, and record local validation.

---

### Task 1: UDP Socket Helper and Self-Test

**Files:**
- Create: `udp_socket_config.h`
- Create: `udp_socket_config_self_test.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Produces: `udp_network::EF_DSCP_VALUE -> int`
- Produces: `udp_network::EF_TRAFFIC_CLASS -> int`
- Produces: `udp_network::format_address_for_display(const asio::ip::address&) -> std::string`
- Produces: `udp_network::normalize_endpoint_for_socket(const asio::ip::udp::socket&, const asio::ip::udp::endpoint&) -> asio::ip::udp::endpoint`
- Produces: `udp_network::choose_endpoint_for_socket(const asio::ip::udp::socket&, const asio::ip::udp::resolver::results_type&) -> std::optional<asio::ip::udp::endpoint>`
- Produces: `udp_network::open_dual_stack_socket(asio::ip::udp::socket&, uint16_t, std::error_code&) -> asio::ip::udp`
- Produces: `udp_network::open_compatible_socket(asio::ip::udp::socket&, const asio::ip::udp::endpoint&, uint16_t, std::error_code&) -> asio::ip::udp`
- Produces: `udp_network::configure_low_latency_buffers(asio::ip::udp::socket&, std::error_code&) -> void`
- Produces: `udp_network::UdpSocketQos::ensure_flow(asio::ip::udp::socket&, const asio::ip::udp::endpoint&) -> udp_network::QosResult`
- Consumed by: Task 2 client/server integration.

- [ ] **Step 1: Add the helper header**

Create `udp_socket_config.h` with these implementation points:

```cpp
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <system_error>
#include <unordered_map>

#include <asio/error.hpp>
#include <asio/ip/address.hpp>
#include <asio/ip/address_v6.hpp>
#include <asio/ip/udp.hpp>
#include <asio/socket_base.hpp>

#include "endpoint_hash.h"
#include "protocol.h"

namespace udp_network {

constexpr int EF_DSCP_VALUE = 46;
constexpr int EF_TRAFFIC_CLASS = EF_DSCP_VALUE << 2;

struct QosResult {
    bool requested = false;
    bool newly_configured = false;
    bool socket_option_applied = false;
    bool qwave_flow_added = false;
    bool explicit_dscp_applied = false;
    unsigned long error_code = 0;
    std::string detail;

    bool ok() const {
        return socket_option_applied || qwave_flow_added || explicit_dscp_applied;
    }
};

std::string format_address_for_display(const asio::ip::address& address);
asio::ip::udp::endpoint normalize_endpoint_for_socket(
    const asio::ip::udp::socket& socket, const asio::ip::udp::endpoint& endpoint);
std::optional<asio::ip::udp::endpoint> choose_endpoint_for_socket(
    const asio::ip::udp::socket& socket, const asio::ip::udp::resolver::results_type& results);
asio::ip::udp open_dual_stack_socket(asio::ip::udp::socket& socket, uint16_t port,
                                     std::error_code& ec);
asio::ip::udp open_compatible_socket(asio::ip::udp::socket& socket,
                                     const asio::ip::udp::endpoint& target,
                                     uint16_t port, std::error_code& ec);
void configure_low_latency_buffers(asio::ip::udp::socket& socket, std::error_code& ec);

class UdpSocketQos {
public:
    UdpSocketQos() = default;
    UdpSocketQos(const UdpSocketQos&) = delete;
    UdpSocketQos& operator=(const UdpSocketQos&) = delete;
    ~UdpSocketQos();

    QosResult ensure_flow(asio::ip::udp::socket& socket,
                          const asio::ip::udp::endpoint& endpoint);
    void reset();

private:
    bool socket_option_applied_ = false;
};

}  // namespace udp_network
```

The implementation below the declarations must:

- Return `127.0.0.1` from `format_address_for_display()` when the input is `::ffff:127.0.0.1`.
- Open `udp::v6()`, set `asio::ip::v6_only(false)`, bind `udp::v6()` first, and fall back to `udp::v4()` only if dual-stack open/bind fails.
- Convert IPv4 endpoints to IPv4-mapped IPv6 endpoints when a socket's local protocol is IPv6.
- On non-Windows, call `setsockopt(IPPROTO_IP, IP_TOS, 0xB8)` and `setsockopt(IPPROTO_IPV6, IPV6_TCLASS, 0xB8)` as applicable, treating at least one successful traffic-class option as success.
- On Windows, create qWAVE flows with `QOSAddSocketToFlow(..., QOSTrafficTypeVoice, QOS_NON_ADAPTIVE_FLOW, ...)`, then attempt `QOSSetFlow(..., QOSSetOutgoingDSCPValue, DWORD{46}, ...)`; explicit DSCP failure must be reported in `QosResult` but must not abort networking.

- [ ] **Step 2: Add the self-test**

Create `udp_socket_config_self_test.cpp` with these cases:

```cpp
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
    udp::socket socket(io);
    std::error_code ec;
    const auto protocol = udp_network::open_dual_stack_socket(socket, 0, ec);
    require(!ec, "socket should open");

    udp::endpoint v4(asio::ip::make_address("127.0.0.1"), 9999);
    const auto normalized = udp_network::normalize_endpoint_for_socket(socket, v4);
    if (protocol == udp::v6()) {
        require(normalized.address().is_v6(), "dual-stack socket should use mapped v4 endpoint");
        require(udp_network::format_address_for_display(normalized.address()) == "127.0.0.1",
                "mapped v4 display should be unmapped");
    } else {
        require(normalized.address().is_v4(), "v4 fallback should keep v4 endpoint");
    }
}

void test_dual_stack_ipv4_compatibility() {
    asio::io_context io;
    udp::socket receiver(io);
    std::error_code ec;
    const auto protocol = udp_network::open_dual_stack_socket(receiver, 0, ec);
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
    udp::endpoint remote;
    const auto deadline = std::chrono::steady_clock::now() + 500ms;
    bool received = false;
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
    udp::socket socket(io);
    std::error_code ec;
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
```

- [ ] **Step 3: Register the self-test**

Modify `CMakeLists.txt` inside `if(JAM_BUILD_TESTS)`:

```cmake
add_executable(udp_socket_config_self_test udp_socket_config_self_test.cpp)
target_link_libraries(udp_socket_config_self_test PRIVATE asio)
if(WIN32)
    target_link_libraries(udp_socket_config_self_test PRIVATE Qwave)
endif()
```

Register it with:

```cmake
jam_add_executable_test(udp_socket_config_self_test)
```

- [ ] **Step 4: Build and run full CTest**

Run:

```powershell
cmake --build build --config Release --target udp_socket_config_self_test
ctest --test-dir build -C Release --output-on-failure
```

Expected: `udp_socket_config_self_test` passes and the full suite remains green.

- [ ] **Step 5: Commit Task 1**

```powershell
git add udp_socket_config.h udp_socket_config_self_test.cpp CMakeLists.txt
git commit -m "feat: add udp socket network configuration helper"
```

---

### Task 2: Client/Server Dual-Stack and QoS Integration

**Files:**
- Modify: `client.cpp`
- Modify: `server.cpp`
- Modify: `cmake/client.cmake`
- Modify: `cmake/server.cmake`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: Task 1 `udp_network::*` helpers.
- Produces: server socket binds dual-stack when available and still accepts IPv4 clients.
- Produces: client resolver accepts IPv4 and IPv6 endpoints and stores normalized endpoints compatible with the active socket.
- Produces: client/server send paths call `UdpSocketQos::ensure_flow()` before outbound datagrams.
- Produces: CTest `server_dual_stack_relay_smoke`.

- [ ] **Step 1: Link qWAVE on Windows**

Modify `cmake/server.cmake`:

```cmake
if(WIN32)
    target_link_libraries(server PRIVATE Qwave)
endif()
```

Modify the existing Windows block in `cmake/client.cmake`:

```cmake
if(WIN32)
    target_link_libraries(client PRIVATE Avrt Qwave)
endif()
```

- [ ] **Step 2: Integrate the server socket helper**

In `server.cpp`, include `udp_socket_config.h`. Change the constructor to initialize `socket_(io_context)` and call `udp_network::open_dual_stack_socket(socket_, options.port, ec)`. Replace direct buffer setup with `udp_network::configure_low_latency_buffers(socket_, ec)` and log whether the bound local endpoint is IPv6 dual-stack or IPv4 fallback.

Add a private member:

```cpp
udp_network::UdpSocketQos socket_qos_;
```

In `send(...)`, call:

```cpp
const auto qos = socket_qos_.ensure_flow(socket_, target);
if (qos.newly_configured && !qos.ok()) {
    Log::warn("UDP QoS not active for {}:{}: {}", 
              udp_network::format_address_for_display(target.address()), target.port(),
              qos.detail);
}
```

before `socket_.async_send_to(...)`.

- [ ] **Step 3: Add server dual-stack relay smoke**

Add `run_dual_stack_relay_smoke()` to `server.cpp`. It must start a server on port `0` with insecure dev joins, join one IPv4 loopback client and one IPv6 loopback client to the same room, send a V2 audio packet from the IPv4 client to the IPv6 client, send another V2 audio packet from the IPv6 client to the IPv4 client, and fail if either relay is missing.

Register the command-line flag in `main`:

```cpp
if (has_arg(argc, argv, "--dual-stack-relay-smoke")) {
    Logger::instance().init(true, false, false);
    return run_dual_stack_relay_smoke();
}
```

Register it in `CMakeLists.txt`:

```cmake
add_test(NAME server_dual_stack_relay_smoke
         COMMAND $<TARGET_FILE:server> --dual-stack-relay-smoke)
```

- [ ] **Step 4: Integrate the client socket helper**

In `client.cpp`, include `udp_socket_config.h`. Change the constructor to initialize `socket_(io_context)`, open it with `udp_network::open_dual_stack_socket(socket_, 0, ec)`, configure buffers, and log the active protocol and port.

In `start_connection`, replace `resolver.resolve(udp::v4(), ...)` with protocol-agnostic resolution, choose an endpoint with `udp_network::choose_endpoint_for_socket(socket_, endpoints)`, normalize it with `udp_network::normalize_endpoint_for_socket(socket_, chosen)`, and store that normalized endpoint.

Change `get_server_address()` to return:

```cpp
return udp_network::format_address_for_display(current_server_endpoint().address());
```

In both async and sync send paths, call `socket_qos_.ensure_flow(socket_, outbound.endpoint)` while holding `socket_mutex_`; warn only when a newly configured flow reports failure.

In `rebind_udp_socket_and_rejoin`, create the replacement socket with `udp_network::open_compatible_socket(replacement, target, 0, ec)`, configure buffers, move it into `socket_`, reset `socket_qos_`, and reapply QoS for `target`.

- [ ] **Step 5: Build and run targeted network smokes plus full CTest**

Run:

```powershell
cmake --build build --config Release
ctest --test-dir build -C Release -R "udp_socket_config_self_test|server_dual_stack_relay_smoke|server_security_smoke|server_redundancy_relay_smoke|client_udp_endpoint_guard_smoke" --output-on-failure
ctest --test-dir build -C Release --output-on-failure
```

Expected: targeted network/security compatibility smokes pass and the full suite remains green.

- [ ] **Step 6: Commit Task 2**

```powershell
git add client.cpp server.cpp cmake/client.cmake cmake/server.cmake CMakeLists.txt
git commit -m "feat: enable udp qos and dual-stack sockets"
```

---

### Task 3: Tracker Update and Acceptance Record

**Files:**
- Modify: `LOW_LATENCY_ACTION_PLAN.md`

**Interfaces:**
- Consumes: Task 1 and Task 2 validation output.
- Produces: tracker status for Phase 5 Track B.

- [ ] **Step 1: Update detailed plan list**

Add Track B to the detailed plans list:

```markdown
- Phase 5 Track B: `docs/superpowers/plans/2026-07-03-phase5-track-b-network.md` (written)
```

- [ ] **Step 2: Mark Track B done**

Replace the Track B bullet in Phase 5 with a done summary:

```markdown
- Track B (network): Done on branch `phase5-track-b-network`. UDP sockets now prefer
  IPv6 dual-stack binds with IPv4 fallback, clients resolve both IPv4 and IPv6
  endpoints, IPv4 destinations are normalized to IPv4-mapped IPv6 when needed, and
  outbound UDP flows request EF QoS via qWAVE on Windows or `IP_TOS`/`IPV6_TCLASS`
  elsewhere.
```

- [ ] **Step 3: Add validation snapshot**

Add a Track B local validation snapshot listing:

```markdown
Track B local validation snapshot (2026-07-03):

- Release build command: `cmake --build build --config Release`.
- Targeted network smoke command: `ctest --test-dir build -C Release -R "udp_socket_config_self_test|server_dual_stack_relay_smoke|server_security_smoke|server_redundancy_relay_smoke|client_udp_endpoint_guard_smoke" --output-on-failure`.
- Full test command: `ctest --test-dir build -C Release --output-on-failure`.
```

Fill in the observed test count, runtime, and any skip note for IPv6 unavailable only after the commands run.

- [ ] **Step 4: Commit Task 3**

```powershell
git add LOW_LATENCY_ACTION_PLAN.md
git commit -m "docs: mark phase5 track b network done"
```

---

## Acceptance

- `udp_socket_config_self_test` proves EF constants, endpoint normalization, dual-stack IPv4 compatibility when available, and non-fatal QoS setup.
- Server dual-stack relay smoke passes with one IPv4 loopback client and one IPv6 loopback client.
- Existing Track A security smoke still passes.
- Existing endpoint guard smoke still passes and displays IPv4 loopback as `127.0.0.1`, not `::ffff:127.0.0.1`.
- Full Release `ctest` passes after the implementation.
- `LOW_LATENCY_ACTION_PLAN.md` records Track B as done and does not change Track C or Track E status.
