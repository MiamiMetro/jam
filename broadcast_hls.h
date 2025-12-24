#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "logger.h"

namespace fs = std::filesystem;

// Header-only HLS broadcast library using FFmpeg
// Pipes mixed audio to FFmpeg which creates HLS segments for nginx to serve
class HLSBroadcaster {
public:
    struct Config {
        int         sample_rate = 48000;
        int         channels    = 1;
        int         bitrate     = 80000;  // Audio bitrate in bps (80k default, optimized for mono)
        std::string output_path = "hls";  // Output directory for HLS segments
        std::string playlist_name = "stream";  // Playlist filename (without .m3u8)
        float segment_duration    = 0.5F;  // HLS segment duration in seconds (0.5 for low latency)
        int   playlist_size       = 6;     // Number of segments in playlist
        std::string ffmpeg_path   = "ffmpeg";  // Path to ffmpeg executable
        bool        verbose       = false;     // Show FFmpeg output
        bool        low_latency   = true;      // Enable low-latency optimizations
    };

    HLSBroadcaster() = default;
    ~HLSBroadcaster() {
        stop();
    }

    // Disable copy/move
    HLSBroadcaster(const HLSBroadcaster&)            = delete;
    HLSBroadcaster& operator=(const HLSBroadcaster&) = delete;

    bool start(const Config& config) {
        if (is_running_.load()) {
            Log::warn("HLS broadcaster already running");
            return false;
        }

        config_ = config;

        // Create output directory if it doesn't exist
        try {
            if (!fs::exists(config_.output_path)) {
                fs::create_directories(config_.output_path);
                Log::info("Created HLS output directory: {}", config_.output_path);
            }
        } catch (const std::exception& e) {
            Log::error("Failed to create HLS output directory: {}", e.what());
            return false;
        }

        // Build FFmpeg command
        // Input: raw PCM float32le from stdin
        // Output: HLS segments with AAC audio
        std::string cmd = config_.ffmpeg_path;
        // Low-latency flags
        if (config_.low_latency) {
            cmd += " -fflags nobuffer";
            cmd += " -flags low_delay";
        }

        // Input format: raw PCM, float32le, specified sample rate and channels
        cmd += " -f f32le";
        cmd += " -ar " + std::to_string(config_.sample_rate);
        cmd += " -ac " + std::to_string(config_.channels);
        cmd += " -i pipe:0";

        // Audio encoding: AAC with optimized CPU settings
        cmd += " -c:a aac";
        cmd += " -profile:a aac_low";  // AAC-LC profile (lowest CPU, widely supported)
        cmd += " -b:a " + std::to_string(config_.bitrate);
        cmd += " -ar " + std::to_string(config_.sample_rate);
        cmd += " -threads 1";  // Limit FFmpeg threads (prevents stealing cores from Jam server)

        // HLS options
        cmd += " -f hls";

        // Use string formatting for float segment duration
        char segment_time_str[32];
        std::snprintf(segment_time_str, sizeof(segment_time_str), "%.1f", config_.segment_duration);
        cmd += " -hls_time " + std::string(segment_time_str);

        cmd += " -hls_list_size " + std::to_string(config_.playlist_size);

        // Use epoch-based sequence numbering for restart-safe monotonic segments
        cmd += " -hls_start_number_source epoch";

        // Low-latency HLS: use fMP4 segments with more flags
        if (config_.low_latency) {
            cmd += " -hls_segment_type fmp4";
            // Remove append_list - it causes issues when FFmpeg restarts
            cmd += " -hls_flags independent_segments+program_date_time+delete_segments";
            // Use %d for monotonic sequence numbers (epoch-based via hls_start_number_source)
            cmd += " -hls_segment_filename \"" + config_.output_path + "/" + config_.playlist_name +
                   "_%d.m4s\"";
        } else {
            // Remove append_list - it causes issues when FFmpeg restarts
            cmd += " -hls_flags delete_segments";
            // Use %d for monotonic sequence numbers (epoch-based via hls_start_number_source)
            cmd += " -hls_segment_filename \"" + config_.output_path + "/" + config_.playlist_name +
                   "_%d.ts\"";
        }

        // Output playlist
        cmd += " -y \"" + config_.output_path + "/" + config_.playlist_name + ".m3u8\"";

        // Suppress FFmpeg output unless verbose
        if (!config_.verbose) {
#ifdef _WIN32
            cmd += " 2>nul";
#else
            cmd += " 2>/dev/null";
#endif
        } else {
            Log::info("FFmpeg verbose mode enabled - errors will be shown in console");
        }

        Log::info("Starting HLS broadcast with command: {}", cmd);

#ifdef _WIN32
        if (!start_windows(cmd)) {
            return false;
        }
#else
        if (!start_unix(cmd)) {
            return false;
        }
#endif

        is_running_.store(true);
        Log::info("HLS broadcast started ({}Hz, {}ch, {}bps)", config_.sample_rate,
                  config_.channels, config_.bitrate);
        Log::info("HLS playlist: {}/{}.m3u8", config_.output_path, config_.playlist_name);
        return true;
    }

    void stop() {
        if (!is_running_.load()) {
            return;
        }

        Log::info("Stopping HLS broadcast...");
        is_running_.store(false);

#ifdef _WIN32
        if (process_handle_ != nullptr) {
            // Close stdin pipe to signal EOF to FFmpeg
            if (stdin_write_ != nullptr) {
                CloseHandle(stdin_write_);
                stdin_write_ = nullptr;
            }

            // Wait for process to exit gracefully
            DWORD wait_result = WaitForSingleObject(process_handle_, 5000);
            if (wait_result == WAIT_TIMEOUT) {
                Log::warn("FFmpeg did not exit gracefully, terminating...");
                TerminateProcess(process_handle_, 1);
            }

            CloseHandle(process_handle_);
            CloseHandle(thread_handle_);
            process_handle_ = nullptr;
            thread_handle_  = nullptr;
        }
#else
        if (ffmpeg_pid_ > 0) {
            // Close stdin pipe to signal EOF to FFmpeg
            if (stdin_fd_ >= 0) {
                close(stdin_fd_);
                stdin_fd_ = -1;
            }

            // Wait for process to exit gracefully
            int   status;
            pid_t result = waitpid(ffmpeg_pid_, &status, WNOHANG);
            if (result == 0) {
                // Still running, give it a moment
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                result = waitpid(ffmpeg_pid_, &status, WNOHANG);
                if (result == 0) {
                    Log::warn("FFmpeg did not exit gracefully, terminating...");
                    kill(ffmpeg_pid_, SIGTERM);
                    waitpid(ffmpeg_pid_, &status, 0);
                }
            }
            ffmpeg_pid_ = -1;
        }
#endif

        Log::info("HLS broadcast stopped");
    }

    // Write audio samples to FFmpeg stdin
    // data: float32 PCM samples, interleaved if stereo
    // sample_count: number of samples per channel
    bool write_audio(const float* data, size_t sample_count) {
        if (!is_running_.load()) {
            return false;
        }

        size_t byte_count = sample_count * config_.channels * sizeof(float);

#ifdef _WIN32
        if (stdin_write_ == nullptr) {
            return false;
        }

        DWORD bytes_written = 0;
        BOOL  success =
            WriteFile(stdin_write_, data, static_cast<DWORD>(byte_count), &bytes_written, nullptr);
        if ((success == 0) || bytes_written != byte_count) {
            static int error_count = 0;
            if (++error_count % 100 == 0) {
                Log::error("Failed to write to FFmpeg stdin (error count: {})", error_count);
            }
            return false;
        }
#else
        if (stdin_fd_ < 0) {
            return false;
        }

        ssize_t bytes_written = write(stdin_fd_, data, byte_count);
        if (bytes_written != static_cast<ssize_t>(byte_count)) {
            static int error_count = 0;
            if (++error_count % 100 == 0) {
                Log::error("Failed to write to FFmpeg stdin (error count: {})", error_count);
            }
            return false;
        }
#endif

        return true;
    }

    bool is_running() const {
        return is_running_.load();
    }

    Config get_config() const {
        return config_;
    }

private:
#ifdef _WIN32
    bool start_windows(const std::string& cmd) {
        SECURITY_ATTRIBUTES sa;
        sa.nLength              = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle       = TRUE;
        sa.lpSecurityDescriptor = nullptr;

        // Create pipe for stdin
        HANDLE stdin_read = nullptr;
        if (CreatePipe(&stdin_read, &stdin_write_, &sa, 0) == 0) {
            Log::error("Failed to create stdin pipe");
            return false;
        }

        // Ensure write handle is not inherited
        SetHandleInformation(stdin_write_, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOA        si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb         = sizeof(si);
        si.dwFlags    = STARTF_USESTDHANDLES;
        si.hStdInput  = stdin_read;
        si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        si.hStdError  = GetStdHandle(STD_ERROR_HANDLE);

        ZeroMemory(&pi, sizeof(pi));

        // Create process (don't use CREATE_NO_WINDOW if verbose to see output)
        DWORD creation_flags = config_.verbose ? 0 : CREATE_NO_WINDOW;
        if (CreateProcessA(nullptr, const_cast<char*>(cmd.c_str()), nullptr, nullptr, TRUE,
                           creation_flags, nullptr, nullptr, &si, &pi) == 0) {
            Log::error("Failed to start FFmpeg process (error code: {})", GetLastError());
            CloseHandle(stdin_read);
            CloseHandle(stdin_write_);
            stdin_write_ = nullptr;
            return false;
        }

        // Close read end of pipe (FFmpeg owns it now)
        CloseHandle(stdin_read);

        process_handle_ = pi.hProcess;
        thread_handle_  = pi.hThread;
        return true;
    }

    HANDLE process_handle_ = nullptr;
    HANDLE thread_handle_  = nullptr;
    HANDLE stdin_write_    = nullptr;
#else
    bool start_unix(const std::string& cmd) {
        int pipe_fds[2];
        if (pipe(pipe_fds) == -1) {
            Log::error("Failed to create pipe");
            return false;
        }

        pid_t pid = fork();
        if (pid == -1) {
            Log::error("Failed to fork process");
            close(pipe_fds[0]);
            close(pipe_fds[1]);
            return false;
        }

        if (pid == 0) {
            // Child process
            // Redirect stdin to pipe read end
            dup2(pipe_fds[0], STDIN_FILENO);
            close(pipe_fds[0]);
            close(pipe_fds[1]);

            // Execute FFmpeg
            execl("/bin/sh", "sh", "-c", cmd.c_str(), nullptr);
            _exit(1);  // Should never reach here
        } else {
            // Parent process
            close(pipe_fds[0]);  // Close read end
            stdin_fd_   = pipe_fds[1];
            ffmpeg_pid_ = pid;
            return true;
        }
    }

    pid_t ffmpeg_pid_ = -1;
    int   stdin_fd_   = -1;
#endif

    std::atomic<bool> is_running_{false};
    Config            config_;
};
