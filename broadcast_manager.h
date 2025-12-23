#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>

#include <asio/io_context.hpp>

#include "logger.h"
#include "server_config.h"
#include "srt_client.h"

// Manages SRT broadcast connection and state
class BroadcastManager {
public:
    BroadcastManager(asio::io_context& io_context, const std::string& srt_host, int srt_port,
                     bool initially_enabled = false)
        : srt_client_(io_context, srt_host, srt_port),
          enabled_(initially_enabled),
          connection_attempts_(0) {}

    // Enable broadcasting (attempts SRT connection)
    bool enable() {
        if (enabled_.load()) {
            Log::info("Broadcast already enabled");
            return srt_client_.is_connected();
        }

        enabled_.store(true);

        if (!srt_client_.is_connected()) {
            if (!srt_client_.connect()) {
                connection_attempts_ = 1;
                Log::warn("SRT connection failed (attempt 1/{}). Will retry in background...",
                          server_config::MAX_SRT_RETRY_ATTEMPTS);
                srt_client_.start_reconnect(server_config::MAX_SRT_RETRY_ATTEMPTS - 1);
                return false;
            } else {
                Log::info("Broadcast enabled: SRT connected");
                return true;
            }
        } else {
            Log::info("Broadcast enabled: SRT already connected");
            return true;
        }
    }

    // Disable broadcasting (disconnects SRT)
    void disable() {
        if (!enabled_.load()) {
            Log::info("Broadcast already disabled");
            return;
        }

        enabled_.store(false);
        srt_client_.disconnect();
        Log::info("Broadcast disabled");
    }

    // Check if broadcasting is enabled
    bool is_enabled() const {
        return enabled_.load();
    }

    // Check if SRT connection is active
    bool is_connected() const {
        return srt_client_.is_connected();
    }

    // Send audio frame via SRT
    // Returns: bytes sent on success, SRT_ERROR on error, 0 if not connected
    int send_audio_frame(const int16_t* data, size_t bytes) {
        if (!enabled_.load()) {
            return 0;  // Broadcasting disabled
        }

        if (!srt_client_.is_connected()) {
            return 0;  // Not connected
        }

        return srt_client_.send(data, bytes);
    }

    // Manually trigger reconnect attempts
    void start_reconnect(int max_attempts) {
        connection_attempts_ = 1;
        srt_client_.start_reconnect(max_attempts - 1);
    }

    // Get number of connection attempts
    int get_connection_attempts() const {
        return connection_attempts_.load();
    }

    // Reset connection attempts counter
    void reset_connection_attempts() {
        connection_attempts_ = 0;
    }

private:
    SrtClient         srt_client_;
    std::atomic<bool> enabled_;
    std::atomic<int>  connection_attempts_;
};
