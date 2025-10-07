#include "check.hpp" // your throw_if_err helper
#include <array>
#include <asio.hpp>
#include <iostream>

using asio::ip::udp;

asio::io_context io;
udp::socket sock(io);

struct SyncHdr {
    uint32_t magic;
    uint32_t seq;
    int64_t t1_client_send;
    int64_t t2_server_recv;
    int64_t t3_server_send;
};

void do_receive();

void on_receive(std::error_code ec, std::size_t bytes, std::shared_ptr<std::array<char, 1024>> buf,
                std::shared_ptr<udp::endpoint> remote) {
    if (ec) {
        std::cerr << "receive error: " << ec.message() << "\n";
        do_receive(); // keep listening
        return;
    }

    std::cout << "Got " << bytes << " bytes from " << remote->address().to_string() << ":" << remote->port() << "\n";

    // Update header
    SyncHdr hdr{};
    if (bytes >= sizeof(SyncHdr)) {
        std::memcpy(&hdr, buf->data(), sizeof(SyncHdr));
        auto now = std::chrono::steady_clock::now();
        auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        hdr.t2_server_recv = ns;
        hdr.t3_server_send = ns;
        std::memcpy(buf->data(), &hdr, sizeof(SyncHdr));
    }

    // Send response (buf and remote kept alive by lambda)
    sock.async_send_to(asio::buffer(*buf, bytes), *remote, [buf, remote](std::error_code ec, std::size_t) {
        if (ec)
            std::cerr << "send error: " << ec.message() << "\n";
    });

    do_receive(); // start next receive immediately
}

void do_receive() {
    // ✅ NEW buffer and endpoint per request
    auto buf = std::make_shared<std::array<char, 1024>>();
    auto remote = std::make_shared<udp::endpoint>();

    sock.async_receive_from(asio::buffer(*buf), *remote, [buf, remote](std::error_code ec, std::size_t bytes) {
        on_receive(ec, bytes, buf, remote);
    });
}

int main() {
    try {
        sock.open(udp::v4());
        sock.bind(udp::endpoint(udp::v4(), 9999)); // fixed port

        std::cout << "Echo server listening on 127.0.0.1:9999\n";
        do_receive(); // kick off the first async receive
        io.run();     // run event loop
    } catch (std::exception &e) {
        std::cerr << "ERR: " << e.what() << "\n";
    }
}
