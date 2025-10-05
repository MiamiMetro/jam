#include "check.hpp" // your throw_if_err helper
#include <array>
#include <asio.hpp>
#include <chrono> // for milliseconds
#include <iostream>
using namespace std::chrono_literals;

#include <cstdint>
#include <cstring> // for memcpy
#include <unordered_map>

// --- statistics for live ping meter ---
double g_min_rtt = 1e9; // start high
double g_max_rtt = 0.0;
double g_sum_rtt = 0.0;
double g_prev_rtt = 0.0;
double g_jitter = 0.0;
uint64_t g_count = 0;

// --- ping header we put at the start of the UDP payload ---
struct SyncHdr {
    uint32_t magic;
    uint32_t seq;
    int64_t t1_client_send;
    int64_t t2_server_recv;
    int64_t t3_server_send;
};

constexpr uint32_t PING_MAGIC = 0x50494E47; // 'PING'

// --- client-side state to measure RTT ---
uint32_t g_seq = 0;
std::unordered_map<uint32_t, std::chrono::steady_clock::time_point> g_sent_times;

// Optional: a TX buffer separate from recv_buf
std::array<unsigned char, 1024> tx_buf;

// forward-declare
void schedule_timer();
void do_receive();
void do_send();

using asio::ip::udp;

asio::io_context io;
udp::socket sock(io);
udp::endpoint server_endpoint;
udp::endpoint remote;
std::array<char, 1024> recv_buf;
// --- add global timer ---
asio::steady_timer timer(io);

void on_timer(std::error_code ec) {
    if (ec)
        return; // timer cancelled or io stopped

    do_send();        // send one ping
    schedule_timer(); // schedule next tick
}

void schedule_timer() {
    timer.expires_after(1ms);   // 1 ms interval
    timer.async_wait(on_timer); // register callback
}

void on_receive(std::error_code ec, std::size_t bytes) {
    if (ec) {
        std::cerr << "receive error: " << ec.message() << "\n";
        return;
    }

    if (bytes < sizeof(SyncHdr)) {
        std::cerr << "recv too small (" << bytes << ")\n";
        do_receive();
        return;
    }

    // Parse header from the start of recv_buf
    SyncHdr hdr{};
    std::memcpy(&hdr, recv_buf.data(), sizeof(SyncHdr));

    if (hdr.magic != PING_MAGIC) {
        std::cerr << "bad magic, ignoring packet\n";
        do_receive();
        return;
    }

    auto now = std::chrono::steady_clock::now();
    auto t4 = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
    auto rtt = (t4 - hdr.t1_client_send) - (hdr.t3_server_send - hdr.t2_server_recv);
    auto offset = ((hdr.t2_server_recv - hdr.t1_client_send) + (hdr.t3_server_send - t4)) / 2.0;

    double rtt_ms = rtt / 1e6;
    double offset_ms = offset / 1e6;

    // update statistics
    g_count++;
    g_sum_rtt += rtt_ms;
    if (rtt_ms < g_min_rtt)
        g_min_rtt = rtt_ms;
    if (rtt_ms > g_max_rtt)
        g_max_rtt = rtt_ms;
    if (g_count > 1)
        g_jitter = std::abs(rtt_ms - g_prev_rtt);
    g_prev_rtt = rtt_ms;

    // compute average
    double avg = g_sum_rtt / g_count;

    // print live stats
    std::cout << "seq " << hdr.seq << " RTT " << rtt_ms << " ms"
              << " | offset " << offset_ms << " ms"
              << " | avg " << avg << " | min " << g_min_rtt << " | max " << g_max_rtt << " | jitter " << g_jitter
              << " | count " << g_count << std::string(20, ' ') << "\r" << std::flush;

    do_receive(); // keep listening
}

void on_send(std::error_code ec, std::size_t bytes) {
    if (ec) {
        std::cerr << "send error: " << ec.message() << "\n";
        return;
    }
    // std::cout << "Sent " << bytes << " bytes\n";
    // optionally, wait or immediately send again
}

void do_receive() { sock.async_receive_from(asio::buffer(recv_buf), remote, on_receive); }

void do_send() {
    // 1) Prepare header
    SyncHdr hdr{};
    hdr.magic = PING_MAGIC;
    hdr.seq = ++g_seq; // start from 1
    auto now = std::chrono::steady_clock::now();
    hdr.t1_client_send = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();

    // 2) Copy header into tx_buf
    static_assert(sizeof(SyncHdr) <= 1024, "Header too big for buffer");
    std::memcpy(tx_buf.data(), &hdr, sizeof(SyncHdr));

    // 3) (Optional) add some payload after the header if you want to test size:
    const char *payload = "ping from client";
    std::size_t payload_len = std::strlen(payload);
    std::memcpy(tx_buf.data() + sizeof(SyncHdr), payload, payload_len);

    // 4) Remember send-time locally (for RTT)
    g_sent_times[hdr.seq] = now;

    // 5) Send header + payload in one UDP datagram
    std::size_t total_len = sizeof(SyncHdr) + payload_len;
    sock.async_send_to(asio::buffer(tx_buf), server_endpoint, on_send);
}

int main() {
    try {
        // 1) open socket on any port
        sock.open(udp::v4());
        sock.bind(udp::endpoint(udp::v4(), 0)); // bind to any free local port

        // 2) define where to send
        server_endpoint = udp::endpoint(asio::ip::make_address("127.0.0.1"), 9999);

        // 3) start listening and send first packet
        // do_send();
        do_receive();

        schedule_timer(); // start periodic sends
        io.run();         // 4) event loop
    } catch (std::exception &e) {
        std::cerr << "ERR: " << e.what() << "\n";
    }
}