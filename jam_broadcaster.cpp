#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <exception>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include <asio.hpp>
#include <asio/ip/udp.hpp>
#include <spdlog/common.h>

#include "ffmpeg_srt_publisher.h"
#include "jam_broadcast_ipc.h"
#include "logger.h"

using asio::ip::udp;
using namespace std::chrono_literals;

namespace {

std::atomic<bool> g_stop{false};

void signal_handler(int) {
    g_stop.store(true);
}

struct Options {
    bool test_tone = false;
    int ipc_port = 0;
    std::string srt_url;
    std::string ffmpeg_path = "ffmpeg";
    int duration_ms = 0;
    int sample_rate = 48000;
    int channels = 1;
    int frame_ms = 20;
    int bitrate = 96000;
    bool verbose_ffmpeg = false;
};

[[noreturn]] void usage(const std::string& reason) {
    throw std::runtime_error(
        reason +
        "\nUsage:\n"
        "  jam_broadcaster --test-tone --srt-url <url> [--duration-ms ms]\n"
        "  jam_broadcaster --ipc-port <port> --srt-url <url> [--duration-ms ms]\n"
        "\nOptions:\n"
        "  --ffmpeg <path>       FFmpeg executable path\n"
        "  --sample-rate <hz>    PCM sample rate, default 48000\n"
        "  --frame-ms <ms>       Test tone frame size, default 20\n"
        "  --bitrate <bps>       AAC bitrate, default 96000\n"
        "  --verbose-ffmpeg      Show FFmpeg output\n");
}

Options parse_options(int argc, char** argv) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto require_value = [&](const std::string& name) -> std::string {
            if (i + 1 >= argc) {
                usage(name + " requires a value");
            }
            return argv[++i];
        };

        if (arg == "--test-tone") {
            options.test_tone = true;
        } else if (arg == "--ipc-port") {
            options.ipc_port = std::stoi(require_value(arg));
        } else if (arg == "--srt-url") {
            options.srt_url = require_value(arg);
        } else if (arg == "--ffmpeg") {
            options.ffmpeg_path = require_value(arg);
        } else if (arg == "--duration-ms") {
            options.duration_ms = std::stoi(require_value(arg));
        } else if (arg == "--sample-rate") {
            options.sample_rate = std::stoi(require_value(arg));
        } else if (arg == "--frame-ms") {
            options.frame_ms = std::stoi(require_value(arg));
        } else if (arg == "--bitrate") {
            options.bitrate = std::stoi(require_value(arg));
        } else if (arg == "--verbose-ffmpeg") {
            options.verbose_ffmpeg = true;
        } else if (arg == "--help" || arg == "-h") {
            usage("");
        } else {
            usage("Unknown argument: " + arg);
        }
    }

    const int modes = (options.test_tone ? 1 : 0) + (options.ipc_port > 0 ? 1 : 0);
    if (modes != 1) {
        usage("Select exactly one input mode");
    }
    if (options.srt_url.empty()) {
        usage("--srt-url is required");
    }
    if (options.sample_rate <= 0 || options.channels != 1 || options.frame_ms <= 0 ||
        options.bitrate <= 0) {
        usage("Invalid audio options");
    }
    return options;
}

void start_publisher(FfmpegSrtPublisher& publisher, const Options& options) {
    FfmpegSrtPublisher::Config config;
    config.sample_rate = options.sample_rate;
    config.channels = options.channels;
    config.bitrate = options.bitrate;
    config.srt_url = options.srt_url;
    config.ffmpeg_path = options.ffmpeg_path;
    config.verbose = options.verbose_ffmpeg;
    if (!publisher.start(config)) {
        throw std::runtime_error("Failed to start FFmpeg SRT publisher");
    }
}

bool restart_publisher(FfmpegSrtPublisher& publisher, const Options& options, uint64_t& reconnects) {
    publisher.stop();
    ++reconnects;
    Log::warn("Restarting FFmpeg SRT publisher, attempt {}", reconnects);
    std::this_thread::sleep_for(500ms);
    try {
        start_publisher(publisher, options);
        return true;
    } catch (const std::exception& e) {
        Log::error("FFmpeg SRT publisher restart failed: {}", e.what());
        return false;
    }
}

void run_test_tone(const Options& options) {
    FfmpegSrtPublisher publisher;
    start_publisher(publisher, options);
    const int frame_count = (options.sample_rate * options.frame_ms) / 1000;
    if (frame_count <= 0) {
        throw std::runtime_error("Invalid frame size");
    }

    std::vector<float> frame(static_cast<size_t>(frame_count));
    const auto start = std::chrono::steady_clock::now();
    float phase = 0.0F;
    constexpr float frequency = 440.0F;
    constexpr float pi = 3.14159265358979323846F;
    const float phase_step = (2.0F * pi * frequency) / static_cast<float>(options.sample_rate);
    uint64_t frames_written = 0;
    uint64_t write_failures = 0;
    uint64_t reconnects = 0;

    while (!g_stop.load()) {
        if (options.duration_ms > 0 &&
            std::chrono::steady_clock::now() - start >= std::chrono::milliseconds(options.duration_ms)) {
            break;
        }

        for (float& sample: frame) {
            sample = std::sin(phase) * 0.15F;
            phase += phase_step;
            if (phase > 2.0F * pi) {
                phase -= 2.0F * pi;
            }
        }

        if (publisher.write_audio(frame.data(), frame.size())) {
            ++frames_written;
        } else {
            ++write_failures;
            restart_publisher(publisher, options, reconnects);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(options.frame_ms));
    }

    publisher.stop();
    std::cout << "frames_written=" << frames_written << "\n";
    std::cout << "write_failures=" << write_failures << "\n";
    std::cout << "reconnects=" << reconnects << "\n";
}

void run_ipc(const Options& options) {
    FfmpegSrtPublisher publisher;
    start_publisher(publisher, options);

    asio::io_context io;
    udp::socket socket(io, udp::endpoint(udp::v4(), static_cast<unsigned short>(options.ipc_port)));
    socket.non_blocking(true);

    std::array<unsigned char, 8192> buffer{};
    udp::endpoint sender;
    const auto start = std::chrono::steady_clock::now();
    uint64_t packets_received = 0;
    uint64_t packets_dropped = 0;
    uint64_t frames_written = 0;
    uint64_t write_failures = 0;
    uint64_t reconnects = 0;
    uint32_t expected_sequence = 0;
    bool have_sequence = false;

    while (!g_stop.load()) {
        if (options.duration_ms > 0 &&
            std::chrono::steady_clock::now() - start >= std::chrono::milliseconds(options.duration_ms)) {
            break;
        }

        std::error_code ec;
        const size_t bytes = socket.receive_from(asio::buffer(buffer), sender, 0, ec);
        if (ec == asio::error::would_block || ec == asio::error::try_again) {
            std::this_thread::sleep_for(2ms);
            continue;
        }
        if (ec) {
            throw std::runtime_error("IPC receive failed: " + ec.message());
        }
        if (bytes < sizeof(JamBroadcastIpcHeader)) {
            ++packets_dropped;
            continue;
        }

        JamBroadcastIpcHeader header{};
        std::memcpy(&header, buffer.data(), sizeof(header));
        if (header.magic != JAM_BROADCAST_IPC_MAGIC ||
            header.version != JAM_BROADCAST_IPC_VERSION ||
            header.header_bytes != sizeof(JamBroadcastIpcHeader) ||
            header.format != static_cast<uint16_t>(JamBroadcastPcmFormat::Float32LE) ||
            header.channels != 1 ||
            header.sample_rate != static_cast<uint32_t>(options.sample_rate)) {
            ++packets_dropped;
            continue;
        }
        if (header.payload_bytes != header.frame_count * sizeof(float) ||
            bytes < sizeof(JamBroadcastIpcHeader) + header.payload_bytes) {
            ++packets_dropped;
            continue;
        }

        if (have_sequence && header.sequence != expected_sequence) {
            packets_dropped += header.sequence - expected_sequence;
        }
        expected_sequence = header.sequence + 1;
        have_sequence = true;

        const auto* payload =
            reinterpret_cast<const float*>(buffer.data() + sizeof(JamBroadcastIpcHeader));
        ++packets_received;
        if (publisher.write_audio(payload, header.frame_count)) {
            ++frames_written;
        } else {
            ++write_failures;
            restart_publisher(publisher, options, reconnects);
        }
    }

    publisher.stop();
    std::cout << "packets_received=" << packets_received << "\n";
    std::cout << "packets_dropped=" << packets_dropped << "\n";
    std::cout << "frames_written=" << frames_written << "\n";
    std::cout << "write_failures=" << write_failures << "\n";
    std::cout << "reconnects=" << reconnects << "\n";
}

}  // namespace

int main(int argc, char** argv) {
    Logger::instance().init(true, true, false, "logs/jam_broadcaster.log", spdlog::level::info);
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
#ifndef _WIN32
    std::signal(SIGPIPE, SIG_IGN);
#endif

    try {
        const Options options = parse_options(argc, argv);
        if (options.test_tone) {
            run_test_tone(options);
        } else {
            run_ipc(options);
        }
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }
    return 0;
}
