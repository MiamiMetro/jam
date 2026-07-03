#include "crash_reporter.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

void require(bool ok, const char* message) {
    if (!ok) {
        throw std::runtime_error(message);
    }
}

int main() {
    const auto dir =
        std::filesystem::temp_directory_path() / "jam_crash_reporter_self_test";
    std::filesystem::remove_all(dir);

    crash_reporter::Options options;
    options.report_dir = dir;
    options.process_name = "server";
    options.platform = "test-platform";
    options.arch = "test-arch";

    const auto report = crash_reporter::write_report(options, "self-test crash", nullptr);
    require(std::filesystem::exists(report), "crash metadata file was not written");
    {
        std::ifstream in(report, std::ios::binary);
        std::string body((std::istreambuf_iterator<char>(in)),
                         std::istreambuf_iterator<char>());
        require(body.find("\"process\":\"server\"") != std::string::npos,
                "process missing");
        require(body.find("\"reason\":\"self-test crash\"") != std::string::npos,
                "reason missing");
        require(body.find("\"platform\":\"test-platform\"") != std::string::npos,
                "platform missing");
    }
    std::filesystem::remove_all(dir);
    std::cout << "crash reporter self-test passed\n";
}
