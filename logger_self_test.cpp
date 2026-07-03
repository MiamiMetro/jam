#include "logger.h"

#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

void require(bool ok, const char* message) {
    if (!ok) {
        throw std::runtime_error(message);
    }
}

int main() {
    const auto dir = std::filesystem::temp_directory_path() / "jam_logger_self_test";
    std::filesystem::remove_all(dir);
    const auto log_path = dir / "server.log";

    Logger::instance().init(false, false, true, log_path.string(),
                            spdlog::level::info, 512, 2);
    for (int i = 0; i < 300; ++i) {
        Log::info("rotating logger self-test line {} abcdefghijklmnopqrstuvwxyz", i);
    }
    Logger::instance().flush();
    std::this_thread::sleep_for(std::chrono::milliseconds(250));

    size_t file_count = 0;
    size_t oversized = 0;
    for (const auto& entry: std::filesystem::directory_iterator(dir)) {
        if (entry.path().filename().string().starts_with("server")) {
            ++file_count;
            if (std::filesystem::file_size(entry.path()) > 1024) {
                ++oversized;
            }
        }
    }
    require(file_count >= 2, "rotation did not create rotated log files");
    require(file_count <= 3, "rotation exceeded active plus retained file count");
    require(oversized == 0, "rotated files exceeded expected test bound");
    std::cout << "logger rotation self-test passed\n";
}
