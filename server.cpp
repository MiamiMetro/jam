#include "check.hpp" // your throw_if_err helper
#include <array>
#include <asio.hpp>
#include <iostream>

using asio::ip::udp;

asio::io_context io;
udp::socket sock(io);
udp::endpoint remote;
std::array<char, 1024> buf; // single buffer for receiving

struct SyncHdr {
    uint32_t magic;
    uint32_t seq;
    int64_t t1_client_send;
    int64_t t2_server_recv;
    int64_t t3_server_send;
};

void do_receive();

void on_send(std::error_code ec, std::size_t bytes) {
    if (ec) {
        std::cerr << "send error: " << ec.message() << "\n";
        return;
    }
    // after sending, we go back to listening
    do_receive();
}

void on_receive(std::error_code ec, std::size_t bytes) {
    if (ec) {
        std::cerr << "receive error: " << ec.message() << "\n";
        return;
    }
    std::cout << "Got " << bytes << " bytes from " << remote.address().to_string() << ":" << remote.port() << " -> "
              << std::string(buf.data(), bytes) << "\n";

    // echo back the same data
    SyncHdr hdr{};
    if (bytes >= sizeof(SyncHdr)) {
        std::memcpy(&hdr, buf.data(), sizeof(SyncHdr));
        // update timestamps
        auto now = std::chrono::steady_clock::now();

        auto t2 = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        hdr.t2_server_recv = t2;

        auto t3 = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        hdr.t3_server_send = t3; // immediate reply
        
        // copy back updated header
        std::memcpy(buf.data(), &hdr, sizeof(SyncHdr));
    } else {
        std::cerr << "Warning: received packet too small for header\n";
    }
    
    sock.async_send_to(asio::buffer(buf, bytes), remote, on_send);
}

void do_receive() { sock.async_receive_from(asio::buffer(buf), remote, on_receive); }

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
