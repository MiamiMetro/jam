#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "logger.h"

class FfmpegSrtPublisher {
public:
    struct Config {
        int sample_rate = 48000;
        int channels = 1;
        int bitrate = 96000;
        std::string srt_url;
        std::string ffmpeg_path = "ffmpeg";
        bool verbose = false;
    };

    FfmpegSrtPublisher() = default;
    ~FfmpegSrtPublisher() {
        stop();
    }

    FfmpegSrtPublisher(const FfmpegSrtPublisher&) = delete;
    FfmpegSrtPublisher& operator=(const FfmpegSrtPublisher&) = delete;

    bool start(const Config& config) {
        if (running_.load()) {
            return false;
        }
        if (config.srt_url.empty()) {
            Log::error("SRT URL is required");
            return false;
        }

        config_ = config;
        const std::string cmd = build_command(config_);
        Log::info("Starting FFmpeg SRT publisher: {}", cmd);

#ifdef _WIN32
        if (!start_windows(cmd)) {
            return false;
        }
#else
        if (!start_unix(cmd)) {
            return false;
        }
#endif
        running_.store(true);
        return true;
    }

    void stop() {
        if (!running_.exchange(false)) {
            return;
        }

#ifdef _WIN32
        if (stdin_write_ != nullptr) {
            CloseHandle(stdin_write_);
            stdin_write_ = nullptr;
        }
        if (process_handle_ != nullptr) {
            const DWORD wait_result = WaitForSingleObject(process_handle_, 5000);
            if (wait_result == WAIT_TIMEOUT) {
                Log::warn("FFmpeg publisher did not exit, terminating");
                TerminateProcess(process_handle_, 1);
            }
            CloseHandle(process_handle_);
            CloseHandle(thread_handle_);
            process_handle_ = nullptr;
            thread_handle_ = nullptr;
        }
#else
        if (stdin_fd_ >= 0) {
            close(stdin_fd_);
            stdin_fd_ = -1;
        }
        if (ffmpeg_pid_ > 0) {
            int status = 0;
            pid_t result = waitpid(ffmpeg_pid_, &status, WNOHANG);
            if (result == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                result = waitpid(ffmpeg_pid_, &status, WNOHANG);
                if (result == 0) {
                    Log::warn("FFmpeg publisher did not exit, terminating");
                    kill(ffmpeg_pid_, SIGTERM);
                    waitpid(ffmpeg_pid_, &status, 0);
                }
            }
            ffmpeg_pid_ = -1;
        }
#endif
    }

    bool write_audio(const float* samples, size_t sample_count_per_channel) {
        if (!running_.load()) {
            return false;
        }

        const size_t byte_count =
            sample_count_per_channel * static_cast<size_t>(config_.channels) * sizeof(float);
#ifdef _WIN32
        if (stdin_write_ == nullptr) {
            return false;
        }
        DWORD written = 0;
        const BOOL ok =
            WriteFile(stdin_write_, samples, static_cast<DWORD>(byte_count), &written, nullptr);
        return ok != 0 && written == byte_count;
#else
        if (stdin_fd_ < 0) {
            return false;
        }
        const ssize_t written = write(stdin_fd_, samples, byte_count);
        return written == static_cast<ssize_t>(byte_count);
#endif
    }

    bool is_running() const {
        return running_.load();
    }

private:
    static std::string quote(const std::string& value) {
        std::string escaped = "\"";
        for (char ch: value) {
            if (ch == '"') {
                escaped += "\\\"";
            } else {
                escaped += ch;
            }
        }
        escaped += "\"";
        return escaped;
    }

    static std::string build_command(const Config& config) {
        std::string cmd = quote(config.ffmpeg_path);
        cmd += " -hide_banner";
        if (!config.verbose) {
            cmd += " -loglevel warning";
        }
        cmd += " -f f32le";
        cmd += " -ar " + std::to_string(config.sample_rate);
        cmd += " -ac " + std::to_string(config.channels);
        cmd += " -i pipe:0";
        cmd += " -c:a aac";
        cmd += " -profile:a aac_low";
        cmd += " -b:a " + std::to_string(config.bitrate);
        cmd += " -ar " + std::to_string(config.sample_rate);
        cmd += " -ac " + std::to_string(config.channels);
        cmd += " -threads 1";
        cmd += " -f mpegts";
        cmd += " " + quote(config.srt_url);
        return cmd;
    }

#ifdef _WIN32
    bool start_windows(const std::string& cmd) {
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = TRUE;

        HANDLE stdin_read = nullptr;
        if (CreatePipe(&stdin_read, &stdin_write_, &sa, 0) == 0) {
            Log::error("Failed to create FFmpeg stdin pipe");
            return false;
        }
        SetHandleInformation(stdin_write_, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOA si{};
        PROCESS_INFORMATION pi{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = stdin_read;
        si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

        const DWORD flags = config_.verbose ? 0 : CREATE_NO_WINDOW;
        std::string mutable_cmd = cmd;
        if (CreateProcessA(nullptr, mutable_cmd.data(), nullptr, nullptr, TRUE, flags, nullptr,
                           nullptr, &si, &pi) == 0) {
            Log::error("Failed to start FFmpeg publisher (error {})", GetLastError());
            CloseHandle(stdin_read);
            CloseHandle(stdin_write_);
            stdin_write_ = nullptr;
            return false;
        }

        CloseHandle(stdin_read);
        process_handle_ = pi.hProcess;
        thread_handle_ = pi.hThread;
        return true;
    }

    HANDLE process_handle_ = nullptr;
    HANDLE thread_handle_ = nullptr;
    HANDLE stdin_write_ = nullptr;
#else
    bool start_unix(const std::string& cmd) {
        int pipe_fds[2];
        if (pipe(pipe_fds) == -1) {
            Log::error("Failed to create FFmpeg stdin pipe");
            return false;
        }

        const pid_t pid = fork();
        if (pid == -1) {
            Log::error("Failed to fork FFmpeg publisher");
            close(pipe_fds[0]);
            close(pipe_fds[1]);
            return false;
        }

        if (pid == 0) {
            dup2(pipe_fds[0], STDIN_FILENO);
            close(pipe_fds[0]);
            close(pipe_fds[1]);
            execl("/bin/sh", "sh", "-c", cmd.c_str(), nullptr);
            _exit(1);
        }

        close(pipe_fds[0]);
        stdin_fd_ = pipe_fds[1];
        ffmpeg_pid_ = pid;
        return true;
    }

    pid_t ffmpeg_pid_ = -1;
    int stdin_fd_ = -1;
#endif

    std::atomic<bool> running_{false};
    Config config_;
};

