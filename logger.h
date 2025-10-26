#pragma once
#include <filesystem>
#include <mutex>
#include <spdlog/async.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

class Logger {
public:
    // Non-copyable singleton
    Logger(const Logger&)            = delete;
    Logger& operator=(const Logger&) = delete;

    // Access singleton instance
    static Logger& instance() {
        static Logger inst;
        return inst;
    }

    // Initialize logger
    void init(bool use_stdout = true, bool use_stderr = true, bool use_file = false,
              const std::string&        file_path = "logs/app.log",
              spdlog::level::level_enum lvl       = spdlog::level::debug);

    // Enable / disable sinks dynamically (thread-safe)
    void enable_stdout(bool enable);
    void enable_stderr(bool enable);
    void enable_file(bool enable);

    // Core logging API
    template <typename... Args>
    void info(spdlog::format_string_t<Args...> fmt, Args&&... args) {
        if (logger_) {
            logger_->info(fmt, std::forward<Args>(args)...);
        }
    }

    template <typename... Args>
    void warn(spdlog::format_string_t<Args...> fmt, Args&&... args) {
        if (logger_) {
            logger_->warn(fmt, std::forward<Args>(args)...);
        }
    }

    template <typename... Args>
    void error(spdlog::format_string_t<Args...> fmt, Args&&... args) {
        if (logger_) {
            logger_->error(fmt, std::forward<Args>(args)...);
        }
    }

    template <typename... Args>
    void debug(spdlog::format_string_t<Args...> fmt, Args&&... args) {
        if (logger_) {
            logger_->debug(fmt, std::forward<Args>(args)...);
        }
    }

    void flush();

private:
    Logger()  = default;
    ~Logger() = default;

    void rebuild_logger_locked();

    std::mutex                      mutex_;
    std::shared_ptr<spdlog::logger> logger_;

    std::shared_ptr<spdlog::sinks::stdout_color_sink_mt> stdout_sink_;
    std::shared_ptr<spdlog::sinks::stderr_color_sink_mt> stderr_sink_;
    std::shared_ptr<spdlog::sinks::basic_file_sink_mt>   file_sink_;

    bool stdout_enabled_ = true;
    bool stderr_enabled_ = true;
    bool file_enabled_   = false;

    spdlog::level::level_enum level_ = spdlog::level::debug;
};

void Logger::init(bool use_stdout, bool use_stderr, bool use_file, const std::string& file_path,
                  spdlog::level::level_enum lvl) {
    std::scoped_lock lock(mutex_);
    stdout_enabled_ = use_stdout;
    stderr_enabled_ = use_stderr;
    file_enabled_   = use_file;
    level_          = lvl;

    // Prepare sinks
    if (use_stdout && !stdout_sink_) {
        stdout_sink_ = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        stdout_sink_->set_pattern("[%T] [%^%l%$] %v");
        stdout_sink_->set_level(spdlog::level::debug);
    }

    if (use_stderr && !stderr_sink_) {
        stderr_sink_ = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
        stderr_sink_->set_pattern("[%T] [%^%l%$] %v");
        stderr_sink_->set_level(spdlog::level::warn);
    }

    if (use_file && !file_sink_) {
        try {
            std::filesystem::path path(file_path);
            if (!path.parent_path().empty())
                std::filesystem::create_directories(path.parent_path());

            // Check existing log file size before creating sink
            if (std::filesystem::exists(path)) {
                auto file_size = std::filesystem::file_size(path);
                if (file_size >= 1024 * 1024) {
                    // Size in MB
                    double size_mb = static_cast<double>(file_size) / (1024.0 * 1024.0);
                    fprintf(stdout, "Logger: Existing log file size: %.2f MB\n", size_mb);
                } else if (file_size >= 1024) {
                    // Size in KB
                    double size_kb = static_cast<double>(file_size) / 1024.0;
                    fprintf(stdout, "Logger: Existing log file size: %.2f KB\n", size_kb);
                } else {
                    // Size in bytes
                    fprintf(stdout, "Logger: Existing log file size: %llu bytes\n",
                            static_cast<unsigned long long>(file_size));
                }
            } else {
                fprintf(stdout, "Logger: Creating new log file\n");
            }

            file_sink_ = std::make_shared<spdlog::sinks::basic_file_sink_mt>(file_path, true);
            file_sink_->set_pattern("[%Y-%m-%d %T.%e] [%^%l%$] %v");
        } catch (const std::exception& e) {
            fprintf(stderr, "Logger: failed to create log file (%s): %s\n", file_path.c_str(),
                    e.what());
        }
    }

    // Build and configure async logger
    spdlog::init_thread_pool(8192, 1);
    rebuild_logger_locked();

    spdlog::set_default_logger(logger_);
    spdlog::flush_every(std::chrono::milliseconds(3000));
}

void Logger::rebuild_logger_locked() {
    std::vector<spdlog::sink_ptr> sinks;
    if (stdout_enabled_ && stdout_sink_) {
        sinks.push_back(stdout_sink_);
    }
    if (stderr_enabled_ && stderr_sink_) {
        sinks.push_back(stderr_sink_);
    }
    if (file_enabled_ && file_sink_) {
        sinks.push_back(file_sink_);
    }

    if (sinks.empty()) {
        logger_.reset();
        return;
    }

    logger_ = std::make_shared<spdlog::async_logger>("core", sinks.begin(), sinks.end(),
                                                     spdlog::thread_pool(),
                                                     spdlog::async_overflow_policy::block);
    logger_->set_level(level_);
    logger_->flush_on(spdlog::level::warn);
}

void Logger::enable_stdout(bool enable) {
    std::scoped_lock lock(mutex_);
    stdout_enabled_ = enable;
    rebuild_logger_locked();
}

void Logger::enable_stderr(bool enable) {
    std::scoped_lock lock(mutex_);
    stderr_enabled_ = enable;
    rebuild_logger_locked();
}

void Logger::enable_file(bool enable) {
    std::scoped_lock lock(mutex_);
    file_enabled_ = enable;
    rebuild_logger_locked();
}

void Logger::flush() {
    std::scoped_lock lock(mutex_);
    if (logger_) {
        logger_->flush();
    }
}

// Clean namespace for easy logging
namespace Log {
template <typename... Args>
inline void info(spdlog::format_string_t<Args...> fmt, Args&&... args) {
    ::Logger::instance().info(fmt, std::forward<Args>(args)...);
}

template <typename... Args>
inline void warn(spdlog::format_string_t<Args...> fmt, Args&&... args) {
    ::Logger::instance().warn(fmt, std::forward<Args>(args)...);
}

template <typename... Args>
inline void error(spdlog::format_string_t<Args...> fmt, Args&&... args) {
    ::Logger::instance().error(fmt, std::forward<Args>(args)...);
}

template <typename... Args>
inline void debug(spdlog::format_string_t<Args...> fmt, Args&&... args) {
    ::Logger::instance().debug(fmt, std::forward<Args>(args)...);
}
}  // namespace Log
