#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <string>
#include <system_error>
#include <vector>

#include <asio.hpp>
#include <asio/buffer.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <concurrentqueue.h>
#include <opus.h>
#include <portaudio.h>
#include <spdlog/common.h>

#include "audio_stream.h"
#include "logger.h"
#include "periodic_timer.h"
#include "protocol.h"

using asio::ip::udp;
using namespace std::chrono_literals;

class Client {
public:
    Client(asio::io_context& io_context, const std::string& server_address, short server_port)
        : io_context_(io_context),
          socket_(io_context, udp::endpoint(udp::v4(), 0)),
          ping_timer_(io_context, 500ms, [this]() { ping_timer_callback(); }),
          alive_timer_(io_context, 5s, [this]() { alive_timer_callback(); }) {
        Log::info("Client local port: {}", socket_.local_endpoint().port());

        // Start audio stream with configuration
        AudioStream::AudioConfig config;
        config.sample_rate       = 48000;
        config.bitrate           = 64000;
        config.complexity        = 2;
        config.frames_per_buffer = 240;
        config.input_gain        = 1.0F;
        config.output_gain       = 1.0F;

        start_audio_stream(17, 15, config);
        // start_audio_stream(38, 40, config);
        // Connect to server
        start_connection(server_address, server_port);
    }

    // Start connection to server (or switch to new server)
    void start_connection(const std::string& server_address, short server_port) {
        Log::info("Connecting to {}:{}...", server_address, server_port);

        // Resolve hostname or IP address
        udp::resolver               resolver(io_context_);
        udp::resolver::results_type endpoints =
            resolver.resolve(udp::v4(), server_address, std::to_string(server_port));
        server_endpoint_ = *endpoints.begin();

        Log::info("Resolved to: {}:{}", server_endpoint_.address().to_string(),
                  server_endpoint_.port());

        do_receive();

        Log::info("Connected and receiving!");

        // Send JOIN message
        CtrlHdr chdr{};
        chdr.magic = CTRL_MAGIC;
        chdr.type  = CtrlHdr::Cmd::JOIN;
        std::memcpy(ctrl_tx_buf_.data(), &chdr, sizeof(CtrlHdr));
        send(ctrl_tx_buf_.data(), sizeof(CtrlHdr));
    }

    // Stop connection (stops sending/receiving UDP packets)
    void stop_connection() {
        Log::info("Disconnecting from server...");

        // Cancel pending async operations
        socket_.cancel();

        Log::info("Disconnected (no longer sending/receiving)");
    }

    bool start_audio_stream(PaDeviceIndex input_device, PaDeviceIndex output_device,
                            const AudioStream::AudioConfig& config = AudioStream::AudioConfig{}) {
        Log::info("Starting audio stream...");
        bool success =
            audio_.start_audio_stream(input_device, output_device, config, audio_callback, this);
        if (success) {
            audio_.print_latency_info();
        }
        return success;
    }

    void stop_audio_stream() {
        audio_.stop_audio_stream();
    }

    void on_receive(std::error_code error_code, std::size_t bytes) {
        if (error_code) {
            // std::cerr << "receive error: " << error_code.message() << "\n";
            do_receive();  // keep listening
            return;
        }

        if (bytes < sizeof(MsgHdr)) {
            do_receive();
            return;
        }

        MsgHdr hdr{};
        std::memcpy(&hdr, recv_buf_.data(), sizeof(MsgHdr));

        if (hdr.magic == PING_MAGIC && bytes >= sizeof(SyncHdr)) {
            handle_ping_message(bytes);
        } else if (hdr.magic == CTRL_MAGIC && bytes >= sizeof(CtrlHdr)) {
        } else if (hdr.magic == AUDIO_MAGIC && bytes >= sizeof(MsgHdr) + sizeof(uint16_t)) {
            handle_audio_message(bytes);
        } else {
            // Log unknown message with hex dump for debugging
            std::string hex_dump;
            hex_dump.reserve(bytes * 3);
            for (size_t i = 0; i < std::min(bytes, size_t(32)); ++i) {
                char hex[4];
                std::snprintf(hex, sizeof(hex), "%02x ", static_cast<unsigned char>(recv_buf_[i]));
                hex_dump += hex;
            }
            Log::warn("Unknown message (magic=0x{:08x}, bytes={}, hex={}...)", hdr.magic, bytes,
                      hex_dump);
        }

        do_receive();  // keep listening
    }

    void do_receive() {
        socket_.async_receive_from(asio::buffer(recv_buf_), server_endpoint_,
                                   [this](std::error_code error_code, std::size_t bytes) {
                                       on_receive(error_code, bytes);
                                   });
    }

    void send(void* data, std::size_t len) {
        socket_.async_send_to(asio::buffer(data, len), server_endpoint_,
                              [](std::error_code error_code, std::size_t) {
                                  if (error_code) {
                                      Log::error("send error: {}", error_code.message());
                                  }
                              });
    }

private:
    void ping_timer_callback() {
        static uint32_t seq = 0;
        SyncHdr         shdr{};
        shdr.magic = PING_MAGIC;
        shdr.seq   = seq++;
        auto now   = std::chrono::steady_clock::now();
        shdr.t1_client_send =
            std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        std::memcpy(sync_tx_buf_.data(), &shdr, sizeof(SyncHdr));
        send(sync_tx_buf_.data(), sizeof(SyncHdr));
    }

    void alive_timer_callback() {
        CtrlHdr chdr{};
        chdr.magic = CTRL_MAGIC;
        chdr.type  = CtrlHdr::Cmd::ALIVE;
        std::memcpy(ctrl_tx_buf_.data(), &chdr, sizeof(CtrlHdr));
        send(ctrl_tx_buf_.data(), sizeof(CtrlHdr));
    }

    void handle_ping_message(std::size_t /*bytes*/) {
        SyncHdr hdr{};
        std::memcpy(&hdr, recv_buf_.data(), sizeof(SyncHdr));

        auto now = std::chrono::steady_clock::now();
        auto current_time =
            std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        auto rtt = (current_time - hdr.t1_client_send) - (hdr.t3_server_send - hdr.t2_server_recv);
        auto offset =
            ((hdr.t2_server_recv - hdr.t1_client_send) + (hdr.t3_server_send - current_time)) / 2;

        double rtt_ms    = static_cast<double>(rtt) / 1e6;
        double offset_ms = static_cast<double>(offset) / 1e6;

        // print live stats
        Log::debug("seq {} RTT {:.5f} ms | offset {:.5f} ms", hdr.seq, rtt_ms, offset_ms);
    }

    void handle_audio_message(std::size_t bytes) {
        uint16_t encoded_bytes;
        std::memcpy(&encoded_bytes, recv_buf_.data() + sizeof(MsgHdr), sizeof(uint16_t));
        size_t expected_size = sizeof(MsgHdr) + sizeof(uint16_t) + encoded_bytes;

        if (bytes < expected_size) {
            Log::error("Incomplete audio packet: got {}, expected {} (encoded_bytes={})", bytes,
                       expected_size, encoded_bytes);
            do_receive();
            return;
        }

        // Additional safety check: ensure encoded_bytes is reasonable
        if (encoded_bytes > AUDIO_BUF_SIZE) {
            Log::error("Invalid audio packet: encoded_bytes {} exceeds max {}", encoded_bytes,
                       AUDIO_BUF_SIZE);
            do_receive();
            return;
        }

        const unsigned char* audio_data = reinterpret_cast<const unsigned char*>(
            recv_buf_.data() + sizeof(MsgHdr) + sizeof(uint16_t));

        std::vector<float> decoded_data;
        if (encoded_bytes > 0) {
        }

        if (!decoded_data.empty()) {
        }
    }

    static int audio_callback(const void* input, void* output, unsigned long frame_count,
                              const PaStreamCallbackTimeInfo* /*unused*/,
                              PaStreamCallbackFlags /*unused*/, void* user_data) {
        const auto* input_buffer  = static_cast<const float*>(input);
        auto*       output_buffer = static_cast<float*>(output);

        return paContinue;
    }

    asio::io_context& io_context_;
    udp::socket       socket_;
    udp::endpoint     server_endpoint_;

    std::array<char, 1024>         recv_buf_;
    std::array<unsigned char, 128> sync_tx_buf_;
    std::array<unsigned char, 128> ctrl_tx_buf_;

    AudioStream audio_;

    PeriodicTimer ping_timer_;
    PeriodicTimer alive_timer_;
};

int main() {
    try {
        auto& log = Logger::instance();
        log.init(true, true, false, "", spdlog::level::info);

        asio::io_context io_context;

        Client client_instance(io_context, "127.0.0.1", 9999);

        io_context.run();
    } catch (std::exception& e) {
        Log::error("ERR: {}", e.what());
    }
}