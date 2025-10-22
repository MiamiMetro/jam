#pragma once
#include <filesystem>
#include <mutex>
#include <spdlog/async.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

class logger {
  public:
    // Non-copyable singleton
    logger(const logger &) = delete;
    logger &operator=(const logger &) = delete;

    // Access singleton instance
    static logger &instance() {
        static logger inst;
        return inst;
    }

    // Initialize logger
    void init(bool use_stdout = true, bool use_stderr = true, bool use_file = false,
              const std::string &file_path = "logs/app.log", spdlog::level::level_enum lvl = spdlog::level::debug);

    // Enable / disable sinks dynamically (thread-safe)
    void enable_stdout(bool enable);
    void enable_stderr(bool enable);
    void enable_file(bool enable);

    // Core logging API
    template <typename... Args> void info(spdlog::format_string_t<Args...> fmt, Args &&...args) {
        if (m_logger)
            m_logger->info(fmt, std::forward<Args>(args)...);
    }

    template <typename... Args> void warn(spdlog::format_string_t<Args...> fmt, Args &&...args) {
        if (m_logger)
            m_logger->warn(fmt, std::forward<Args>(args)...);
    }

    template <typename... Args> void error(spdlog::format_string_t<Args...> fmt, Args &&...args) {
        if (m_logger)
            m_logger->error(fmt, std::forward<Args>(args)...);
    }

    template <typename... Args> void debug(spdlog::format_string_t<Args...> fmt, Args &&...args) {
        if (m_logger)
            m_logger->debug(fmt, std::forward<Args>(args)...);
    }

    void flush();

  private:
    logger() = default;
    ~logger() = default;

    void rebuild_logger_locked();

    std::mutex m_mutex;
    std::shared_ptr<spdlog::logger> m_logger;

    std::shared_ptr<spdlog::sinks::stdout_color_sink_mt> m_stdout_sink;
    std::shared_ptr<spdlog::sinks::stderr_color_sink_mt> m_stderr_sink;
    std::shared_ptr<spdlog::sinks::basic_file_sink_mt> m_file_sink;

    bool m_stdout_enabled = true;
    bool m_stderr_enabled = true;
    bool m_file_enabled = false;

    spdlog::level::level_enum m_level = spdlog::level::debug;
};

void logger::init(bool use_stdout, bool use_stderr, bool use_file, const std::string &file_path,
                  spdlog::level::level_enum lvl) {
    std::scoped_lock lock(m_mutex);
    m_stdout_enabled = use_stdout;
    m_stderr_enabled = use_stderr;
    m_file_enabled = use_file;
    m_level = lvl;

    // Prepare sinks
    if (use_stdout && !m_stdout_sink) {
        m_stdout_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        m_stdout_sink->set_pattern("[%T] [%^%l%$] %v");
        m_stdout_sink->set_level(spdlog::level::debug);
    }

    if (use_stderr && !m_stderr_sink) {
        m_stderr_sink = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
        m_stderr_sink->set_pattern("[%T] [%^%l%$] %v");
        m_stderr_sink->set_level(spdlog::level::warn);
    }

    if (use_file && !m_file_sink) {
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

            m_file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(file_path, true);
            m_file_sink->set_pattern("[%Y-%m-%d %T.%e] [%^%l%$] %v");
        } catch (const std::exception &e) {
            fprintf(stderr, "Logger: failed to create log file (%s): %s\n", file_path.c_str(), e.what());
        }
    }

    // Build and configure async logger
    spdlog::init_thread_pool(8192, 1);
    rebuild_logger_locked();

    spdlog::set_default_logger(m_logger);
    spdlog::flush_every(std::chrono::milliseconds(3000));
}

void logger::rebuild_logger_locked() {
    std::vector<spdlog::sink_ptr> sinks;
    if (m_stdout_enabled && m_stdout_sink)
        sinks.push_back(m_stdout_sink);
    if (m_stderr_enabled && m_stderr_sink)
        sinks.push_back(m_stderr_sink);
    if (m_file_enabled && m_file_sink)
        sinks.push_back(m_file_sink);

    if (sinks.empty()) {
        m_logger.reset();
        return;
    }

    m_logger = std::make_shared<spdlog::async_logger>("core", sinks.begin(), sinks.end(), spdlog::thread_pool(),
                                                      spdlog::async_overflow_policy::block);
    m_logger->set_level(m_level);
    m_logger->flush_on(spdlog::level::warn);
}

void logger::enable_stdout(bool enable) {
    std::scoped_lock lock(m_mutex);
    m_stdout_enabled = enable;
    rebuild_logger_locked();
}

void logger::enable_stderr(bool enable) {
    std::scoped_lock lock(m_mutex);
    m_stderr_enabled = enable;
    rebuild_logger_locked();
}

void logger::enable_file(bool enable) {
    std::scoped_lock lock(m_mutex);
    m_file_enabled = enable;
    rebuild_logger_locked();
}

void logger::flush() {
    std::scoped_lock lock(m_mutex);
    if (m_logger)
        m_logger->flush();
}

// Clean namespace for easy logging
namespace Log {
template <typename... Args> inline void info(spdlog::format_string_t<Args...> fmt, Args &&...args) {
    ::logger::instance().info(fmt, std::forward<Args>(args)...);
}

template <typename... Args> inline void warn(spdlog::format_string_t<Args...> fmt, Args &&...args) {
    ::logger::instance().warn(fmt, std::forward<Args>(args)...);
}

template <typename... Args> inline void error(spdlog::format_string_t<Args...> fmt, Args &&...args) {
    ::logger::instance().error(fmt, std::forward<Args>(args)...);
}

template <typename... Args> inline void debug(spdlog::format_string_t<Args...> fmt, Args &&...args) {
    ::logger::instance().debug(fmt, std::forward<Args>(args)...);
}
} // namespace Log
