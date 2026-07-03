#pragma once

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <DbgHelp.h>
#else
#include <unistd.h>
#endif

namespace crash_reporter {

struct Options {
    std::filesystem::path report_dir = "crash_reports/server";
    std::string process_name = "server";
    std::string platform = "unknown";
    std::string arch = "unknown";
    bool write_minidump = true;
};

namespace detail {
inline std::mutex& options_mutex() {
    static std::mutex mutex;
    return mutex;
}

inline Options& installed_options() {
    static Options options;
    return options;
}

inline std::terminate_handler& previous_terminate_handler() {
    static std::terminate_handler handler = nullptr;
    return handler;
}

#ifdef _WIN32
inline LPTOP_LEVEL_EXCEPTION_FILTER& previous_exception_filter() {
    static LPTOP_LEVEL_EXCEPTION_FILTER filter = nullptr;
    return filter;
}
#endif
}  // namespace detail

inline void append_json_string(std::ostringstream& out, std::string_view value) {
    static constexpr char HEX[] = "0123456789abcdef";
    out << '"';
    for (unsigned char ch: value) {
        switch (ch) {
            case '"':
                out << "\\\"";
                break;
            case '\\':
                out << "\\\\";
                break;
            case '\b':
                out << "\\b";
                break;
            case '\f':
                out << "\\f";
                break;
            case '\n':
                out << "\\n";
                break;
            case '\r':
                out << "\\r";
                break;
            case '\t':
                out << "\\t";
                break;
            default:
                if (ch < 0x20) {
                    out << "\\u00" << HEX[(ch >> 4) & 0x0F] << HEX[ch & 0x0F];
                } else {
                    out << static_cast<char>(ch);
                }
                break;
        }
    }
    out << '"';
}

inline uint32_t process_id() {
#ifdef _WIN32
    return static_cast<uint32_t>(::GetCurrentProcessId());
#else
    return static_cast<uint32_t>(::getpid());
#endif
}

inline int64_t unix_time_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

inline std::string report_stem(const Options& options, int64_t timestamp_ms,
                               uint32_t pid) {
    std::string process = options.process_name.empty() ? "process" : options.process_name;
    for (char& ch: process) {
        const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                        (ch >= '0' && ch <= '9') || ch == '-' || ch == '_';
        if (!ok) {
            ch = '_';
        }
    }
    return process + "-" + std::to_string(pid) + "-" + std::to_string(timestamp_ms);
}

#ifdef _WIN32
inline bool write_minidump_file(const std::filesystem::path& dump_path,
                                EXCEPTION_POINTERS* exception_pointers) {
    if (exception_pointers == nullptr) {
        return false;
    }

    HANDLE file = ::CreateFileW(dump_path.wstring().c_str(), GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    MINIDUMP_EXCEPTION_INFORMATION exception_info{};
    exception_info.ThreadId = ::GetCurrentThreadId();
    exception_info.ExceptionPointers = exception_pointers;
    exception_info.ClientPointers = FALSE;

    const BOOL ok = ::MiniDumpWriteDump(
        ::GetCurrentProcess(), ::GetCurrentProcessId(), file, MiniDumpNormal,
        &exception_info, nullptr, nullptr);
    ::CloseHandle(file);
    if (!ok) {
        std::error_code ignored;
        std::filesystem::remove(dump_path, ignored);
    }
    return ok == TRUE;
}
#endif

inline std::filesystem::path write_report(const Options& options, std::string_view reason,
                                          void* native_exception) {
    std::filesystem::create_directories(options.report_dir);

    const int64_t timestamp_ms = unix_time_ms();
    const uint32_t pid = process_id();
    const std::string stem = report_stem(options, timestamp_ms, pid);
    const auto metadata_path = options.report_dir / (stem + ".json");
    const auto dump_path = options.report_dir / (stem + ".dmp");

    bool minidump_written = false;
#ifdef _WIN32
    if (options.write_minidump && native_exception != nullptr) {
        minidump_written =
            write_minidump_file(dump_path,
                                static_cast<EXCEPTION_POINTERS*>(native_exception));
    }
#else
    (void)native_exception;
#endif

    std::ostringstream json;
    json << '{';
    json << "\"schema\":\"jam_crash_report_v1\"";
    json << ",\"timestamp_unix_ms\":" << timestamp_ms;
    json << ",\"pid\":" << pid;
    json << ",\"process\":";
    append_json_string(json, options.process_name);
    json << ",\"platform\":";
    append_json_string(json, options.platform);
    json << ",\"arch\":";
    append_json_string(json, options.arch);
    json << ",\"reason\":";
    append_json_string(json, reason);
    json << ",\"minidump\":";
    if (minidump_written) {
        append_json_string(json, dump_path.string());
    } else {
        json << "null";
    }
    json << "}\n";

    std::ofstream out(metadata_path, std::ios::binary);
    out << json.str();
    out.flush();
    if (!out) {
        throw std::runtime_error("failed to write crash report metadata");
    }
    return metadata_path;
}

inline Options installed_options_snapshot() {
    std::scoped_lock lock(detail::options_mutex());
    return detail::installed_options();
}

inline void write_report_noexcept(std::string_view reason, void* native_exception) noexcept {
    try {
        (void)write_report(installed_options_snapshot(), reason, native_exception);
    } catch (...) {
    }
}

inline void terminate_handler() {
    write_report_noexcept("std::terminate", nullptr);
    const auto previous = detail::previous_terminate_handler();
    if (previous != nullptr) {
        previous();
    }
    std::abort();
}

#ifdef _WIN32
inline LONG WINAPI unhandled_exception_filter(EXCEPTION_POINTERS* exception_pointers) {
    std::ostringstream reason;
    reason << "unhandled exception";
    if (exception_pointers != nullptr && exception_pointers->ExceptionRecord != nullptr) {
        reason << " 0x" << std::hex
               << exception_pointers->ExceptionRecord->ExceptionCode;
    }
    write_report_noexcept(reason.str(), exception_pointers);

    const auto previous = detail::previous_exception_filter();
    if (previous != nullptr) {
        return previous(exception_pointers);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}
#endif

inline void install(const Options& options) {
    {
        std::scoped_lock lock(detail::options_mutex());
        detail::installed_options() = options;
    }

    detail::previous_terminate_handler() = std::set_terminate(terminate_handler);
#ifdef _WIN32
    detail::previous_exception_filter() =
        ::SetUnhandledExceptionFilter(unhandled_exception_filter);
#endif
}

}  // namespace crash_reporter
