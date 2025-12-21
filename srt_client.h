#pragma once

#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>

#include <asio.hpp>
#include <asio/io_context.hpp>
#include <srt.h>

#include "logger.h"

class SrtClient {
public:
    SrtClient(asio::io_context& io_context, const std::string& host, int port, int latency_ms = 200)
        : io_context_(io_context),
          host_(host),
          port_(port),
          latency_ms_(latency_ms),
          sock_(SRT_INVALID_SOCK),
          running_(true) {
        // Resolve address using ASIO (handles DNS resolution and IPv4/IPv6)
        resolve_address();
        if (!init_srt()) {
            Log::error("SRT initialization failed");
            throw std::runtime_error("SRT initialization failed");
        }
    }

    ~SrtClient() {
        running_ = false;
        if (reconnect_thread_.joinable()) {
            reconnect_thread_.join();
        }
        if (sock_ != SRT_INVALID_SOCK) {
            srt_close(sock_);
        }
        cleanup_srt();
    }

    // Non-copyable
    SrtClient(const SrtClient&)            = delete;
    SrtClient& operator=(const SrtClient&) = delete;

    // Not movable (contains reference member)
    SrtClient(SrtClient&&) = delete;

    bool connect() {
        std::lock_guard<std::mutex> lock(sock_mutex_);
        if (sock_ != SRT_INVALID_SOCK) {
            srt_close(sock_);
        }

        sock_ = create_socket();
        if (sock_ == SRT_INVALID_SOCK) {
            return false;
        }

        if (!connect_socket(sock_)) {
            srt_close(sock_);
            sock_ = SRT_INVALID_SOCK;
            return false;
        }

        Log::info("Connected to SRT endpoint {}:{}", host_, port_);
        return true;
    }

    // Send data (non-blocking)
    // Returns: bytes sent on success, SRT_ERROR on failure
    int send(const void* data, int len) {
        std::lock_guard<std::mutex> lock(sock_mutex_);
        if (sock_ == SRT_INVALID_SOCK) {
            return SRT_ERROR;
        }

        // Check socket state - only send if connected
        SRT_SOCKSTATUS status = srt_getsockstate(sock_);
        if (status != SRTS_CONNECTED) {
            return SRT_ERROR;
        }

        int result = srt_send(sock_, reinterpret_cast<const char*>(data), len);
        if (result == SRT_ERROR) {
            int err = srt_getlasterror(nullptr);
            if (err == SRT_EASYNCSND || err == SRT_ECONGEST) {
                // Congestion - expected with non-blocking send
                return SRT_ERROR;
            }
            // Connection broken - trigger reconnection
            Log::warn("SRT send error: {} (status: {}), will reconnect", srt_getlasterror_str(),
                      static_cast<int>(status));
            srt_close(sock_);
            sock_ = SRT_INVALID_SOCK;
            start_reconnect();
            return SRT_ERROR;
        }

        return result;
    }

    bool is_connected() const {
        std::lock_guard<std::mutex> lock(sock_mutex_);
        if (sock_ == SRT_INVALID_SOCK) {
            return false;
        }
        SRT_SOCKSTATUS status = srt_getsockstate(sock_);
        return status == SRTS_CONNECTED;
    }

    void start_reconnect(int max_attempts = -1) {
        if (!reconnect_thread_.joinable()) {
            reconnect_thread_ =
                std::thread([this, max_attempts]() { reconnect_with_backoff(max_attempts); });
        }
    }

    void disconnect() {
        std::lock_guard<std::mutex> lock(sock_mutex_);
        if (sock_ != SRT_INVALID_SOCK) {
            srt_close(sock_);
            sock_ = SRT_INVALID_SOCK;
            Log::info("Disconnected from SRT endpoint {}:{}", host_, port_);
        }
    }

private:
    static bool init_srt() {
        srt_startup();
        return true;
    }

    static void cleanup_srt() {
        srt_cleanup();
    }

    SRTSOCKET create_socket() {
        SRTSOCKET sock = srt_create_socket();
        if (sock == SRT_INVALID_SOCK) {
            Log::error("Failed to create SRT socket: {}", srt_getlasterror_str());
            return SRT_INVALID_SOCK;
        }

        // Set non-blocking send (SRTO_SNDSYN = 0)
        int sndsyn = 0;
        if (srt_setsockopt(sock, 0, SRTO_SNDSYN, &sndsyn, sizeof(sndsyn)) == SRT_ERROR) {
            Log::error("Failed to set SRTO_SNDSYN: {}", srt_getlasterror_str());
            srt_close(sock);
            return SRT_INVALID_SOCK;
        }

        // Set latency
        if (srt_setsockopt(sock, 0, SRTO_LATENCY, &latency_ms_, sizeof(latency_ms_)) == SRT_ERROR) {
            Log::error("Failed to set SRTO_LATENCY: {}", srt_getlasterror_str());
            srt_close(sock);
            return SRT_INVALID_SOCK;
        }

        return sock;
    }

    void resolve_address() {
        try {
            // Use ASIO resolver for DNS resolution and address parsing
            asio::ip::tcp::resolver               resolver(io_context_);
            asio::ip::tcp::resolver::results_type endpoints =
                resolver.resolve(host_, std::to_string(port_));

            // Find first IPv4 address
            for (const auto& endpoint: endpoints) {
                if (endpoint.endpoint().address().is_v4()) {
                    resolved_address_ = endpoint.endpoint().address().to_v4();
                    return;
                }
            }

            // If no IPv4 found, try parsing as direct IP address
            std::error_code ec;
            auto            addr = asio::ip::make_address_v4(host_, ec);
            if (!ec) {
                resolved_address_ = addr;
                return;
            }

            Log::error("Failed to resolve address: {} (no IPv4 address found)", host_);
            throw std::runtime_error("Failed to resolve address");
        } catch (const std::exception& e) {
            Log::error("Address resolution error: {}", e.what());
            throw;
        }
    }

    bool connect_socket(SRTSOCKET sock) {
        // Convert ASIO address to sockaddr_in for SRT
        sockaddr_in sa;
        std::memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port   = htons(port_);

        // Convert ASIO IPv4 address to network byte order
        auto bytes = resolved_address_.to_bytes();
        std::memcpy(&sa.sin_addr, bytes.data(), bytes.size());

        if (srt_connect(sock, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == SRT_ERROR) {
            Log::error("Failed to connect: {}", srt_getlasterror_str());
            return false;
        }

        return true;
    }

    void reconnect_with_backoff(int max_attempts = -1) {
        int       backoff_ms     = 100;
        const int max_backoff_ms = 5000;
        int       attempts       = 0;

        while (running_) {
            attempts++;
            if (max_attempts > 0 && attempts > max_attempts) {
                Log::warn("SRT reconnection stopped after {} attempts", max_attempts);
                return;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms));

            {
                std::lock_guard<std::mutex> lock(sock_mutex_);
                if (sock_ != SRT_INVALID_SOCK) {
                    srt_close(sock_);
                    sock_ = SRT_INVALID_SOCK;
                }

                sock_ = create_socket();
                if (sock_ == SRT_INVALID_SOCK) {
                    backoff_ms =
                        (backoff_ms * 2 < max_backoff_ms) ? (backoff_ms * 2) : max_backoff_ms;
                    continue;
                }

                if (connect_socket(sock_)) {
                    Log::info("Reconnected to SRT endpoint {}:{}", host_, port_);
                    return;
                }

                srt_close(sock_);
                sock_ = SRT_INVALID_SOCK;
            }
            backoff_ms = (backoff_ms * 2 < max_backoff_ms) ? (backoff_ms * 2) : max_backoff_ms;
        }
    }

    asio::io_context&    io_context_;
    std::string          host_;
    int                  port_;
    int                  latency_ms_;
    asio::ip::address_v4 resolved_address_;
    mutable std::mutex   sock_mutex_;
    SRTSOCKET            sock_;
    std::thread          reconnect_thread_;
    std::atomic<bool>    running_;
};
