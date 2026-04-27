#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <iostream>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <asio.hpp>
#include <asio/buffer.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <opus.h>

#include "audio_packet.h"
#include "message_validator.h"
#include "opus_decoder.h"
#include "opus_encoder.h"
#include "packet_builder.h"
#include "protocol.h"

using asio::ip::udp;
using clock_type = std::chrono::steady_clock;
using namespace std::chrono_literals;

namespace {

constexpr int   SAMPLE_RATE = 48000;
constexpr int   CHANNELS = 1;
constexpr int   BITRATE = 64000;
constexpr int   COMPLEXITY = 2;
constexpr int   TOTAL_PACKETS = 220;
constexpr int   IMPULSE_PACKET = 20;
constexpr int   CLICK_SAMPLES = 32;
constexpr float CLICK_AMPLITUDE = 0.8F;
constexpr float DETECTION_THRESHOLD = 0.05F;
constexpr int   MAX_FRAME_SAMPLES = 960;
constexpr uint8_t PROBE_CODEC_OPUS = 0;
constexpr uint8_t PROBE_CODEC_PCM_INT16 = 1;

enum class ProbeCodec {
    Opus,
    PcmInt16,
};

struct ProbeConfig {
    int frame_size = 240;
    int jitter_min_packets = 3;
    int total_packets = TOTAL_PACKETS;
    ProbeCodec codec = ProbeCodec::Opus;
};

struct Args {
    std::string host = "127.0.0.1";
    unsigned short port = 9999;
    bool sweep = false;
    int duration_seconds = 0;
    double playout_ppm = 0.0;
    ProbeConfig config;
};

struct ReceivedPacket {
    std::array<unsigned char, AUDIO_BUF_SIZE> data{};
    uint16_t encoded_bytes = 0;
};

struct ProbeMetrics {
    int sent_packets = 0;
    int encode_failures = 0;
    int received_packets = 0;
    int decoded_packets = 0;
    int plc_frames = 0;
    int underruns = 0;
    int decode_failures = 0;
    int decoded_size_mismatches = 0;
    int non_finite_samples = 0;
    int out_of_range_samples = 0;
    int repeated_blocks = 0;
    int queue_depth_observations = 0;
    long long queue_depth_sum = 0;
    int min_queue_depth_after_ready = std::numeric_limits<int>::max();
    int max_queue_depth = 0;
    int final_queue_depth = 0;
    float max_discontinuity = 0.0F;
    int detected_output_sample = -1;
};

struct ProbeResult {
    ProbeConfig config;
    ProbeMetrics metrics;
    int latency_samples = -1;
    double latency_ms = -1.0;
};

class ProbeReceiver {
public:
    ProbeReceiver(asio::io_context& io_context, const udp::endpoint& server_endpoint)
        : socket_(io_context, udp::endpoint(udp::v4(), 0)), server_endpoint_(server_endpoint) {}

    void start() {
        do_receive();
    }

    void send_join() {
        send_ctrl(CtrlHdr::Cmd::JOIN);
    }

    void send_alive() {
        send_ctrl(CtrlHdr::Cmd::ALIVE);
    }

    void send_leave() {
        send_ctrl(CtrlHdr::Cmd::LEAVE);
    }

    bool pop_packet(ReceivedPacket& packet) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.empty()) {
            return false;
        }
        packet = queue_.front();
        queue_.pop_front();
        return true;
    }

    size_t queue_size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

    int received_count() const {
        return received_count_.load(std::memory_order_relaxed);
    }

private:
    void send_ctrl(CtrlHdr::Cmd cmd) {
        CtrlHdr hdr{};
        hdr.magic = CTRL_MAGIC;
        hdr.type = cmd;
        socket_.send_to(asio::buffer(&hdr, sizeof(hdr)), server_endpoint_);
    }

    void do_receive() {
        socket_.async_receive_from(asio::buffer(recv_buf_), remote_endpoint_,
                                   [this](std::error_code ec, std::size_t bytes) {
                                       if (!ec) {
                                           handle_receive(bytes);
                                       }
                                       do_receive();
                                   });
    }

    void handle_receive(std::size_t bytes) {
        if (!message_validator::is_valid_audio_packet(
                bytes, sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t))) {
            return;
        }

        MsgHdr hdr{};
        std::memcpy(&hdr, recv_buf_.data(), sizeof(hdr));
        if (hdr.magic != AUDIO_MAGIC) {
            return;
        }

        const auto* packet_data = reinterpret_cast<const unsigned char*>(recv_buf_.data());
        uint16_t encoded_bytes = packet_builder::extract_encoded_bytes(packet_data);
        size_t expected_size = sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t) + encoded_bytes;
        if (!message_validator::has_complete_payload(bytes, expected_size) ||
            !message_validator::is_encoded_bytes_valid(encoded_bytes, AUDIO_BUF_SIZE)) {
            return;
        }

        const unsigned char* audio_data =
            packet_data + sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t);

        ReceivedPacket packet;
        std::memcpy(packet.data.data(), audio_data, encoded_bytes);
        packet.encoded_bytes = encoded_bytes;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push_back(packet);
        }
        received_count_.fetch_add(1, std::memory_order_relaxed);
    }

    udp::socket socket_;
    udp::endpoint server_endpoint_;
    udp::endpoint remote_endpoint_;
    std::array<char, 1024> recv_buf_{};
    mutable std::mutex mutex_;
    std::deque<ReceivedPacket> queue_;
    std::atomic<int> received_count_{0};
};

class ProbeSender {
public:
    ProbeSender(asio::io_context& io_context, const udp::endpoint& server_endpoint)
        : socket_(io_context, udp::endpoint(udp::v4(), 0)), server_endpoint_(server_endpoint) {}

    void send_join() {
        send_ctrl(CtrlHdr::Cmd::JOIN);
    }

    void send_alive() {
        send_ctrl(CtrlHdr::Cmd::ALIVE);
    }

    void send_leave() {
        send_ctrl(CtrlHdr::Cmd::LEAVE);
    }

    bool send_audio_packet(uint8_t codec, const unsigned char* payload, size_t payload_bytes) {
        if (payload_bytes + 1 > AUDIO_BUF_SIZE) {
            return false;
        }

        std::vector<unsigned char> probe_payload;
        probe_payload.reserve(payload_bytes + 1);
        probe_payload.push_back(codec);
        probe_payload.insert(probe_payload.end(), payload, payload + payload_bytes);

        auto packet = audio_packet::create_audio_packet(probe_payload);
        std::error_code ec;
        socket_.send_to(asio::buffer(packet->data(), packet->size()), server_endpoint_, 0, ec);
        return !ec;
    }

private:
    void send_ctrl(CtrlHdr::Cmd cmd) {
        CtrlHdr hdr{};
        hdr.magic = CTRL_MAGIC;
        hdr.type = cmd;
        socket_.send_to(asio::buffer(&hdr, sizeof(hdr)), server_endpoint_);
    }

    udp::socket socket_;
    udp::endpoint server_endpoint_;
};

void fill_probe_frame(int packet_index, const ProbeConfig& config, std::vector<float>& frame) {
    std::fill(frame.begin(), frame.end(), 0.0F);
    if (packet_index == IMPULSE_PACKET) {
        int samples = std::min(CLICK_SAMPLES, config.frame_size);
        for (int i = 0; i < samples; ++i) {
            frame[static_cast<size_t>(i)] = CLICK_AMPLITUDE;
        }
    }
}

const char* codec_name(ProbeCodec codec) {
    switch (codec) {
        case ProbeCodec::Opus:
            return "opus";
        case ProbeCodec::PcmInt16:
            return "pcm_int16";
    }
    return "unknown";
}

bool decode_pcm_int16_packet(const ReceivedPacket& packet, const ProbeConfig& config,
                             std::array<float, MAX_FRAME_SAMPLES>& pcm) {
    if (packet.encoded_bytes < 1 || packet.data[0] != PROBE_CODEC_PCM_INT16) {
        return false;
    }

    size_t payload_bytes = static_cast<size_t>(packet.encoded_bytes - 1);
    size_t expected_bytes = static_cast<size_t>(config.frame_size) * sizeof(int16_t);
    if (payload_bytes != expected_bytes) {
        return false;
    }

    const unsigned char* payload = packet.data.data() + 1;
    for (int i = 0; i < config.frame_size; ++i) {
        int16_t sample = 0;
        std::memcpy(&sample, payload + static_cast<size_t>(i) * sizeof(sample), sizeof(sample));
        pcm[static_cast<size_t>(i)] = static_cast<float>(sample) / 32767.0F;
    }
    return true;
}

void inspect_samples(const std::array<float, MAX_FRAME_SAMPLES>& pcm, int decoded_samples,
                     int output_base_sample, const ProbeConfig& config, ProbeMetrics& metrics,
                     std::vector<float>& previous_block, bool& have_previous_block) {
    bool same_as_previous = have_previous_block && decoded_samples == config.frame_size;

    for (int i = 0; i < decoded_samples; ++i) {
        float sample = pcm[static_cast<size_t>(i)];
        if (!std::isfinite(sample)) {
            metrics.non_finite_samples++;
            continue;
        }
        if (sample < -1.0F || sample > 1.0F) {
            metrics.out_of_range_samples++;
        }
        if (i > 0) {
            float prev = pcm[static_cast<size_t>(i - 1)];
            metrics.max_discontinuity = std::max(metrics.max_discontinuity, std::abs(sample - prev));
        }
        if (metrics.detected_output_sample < 0 && std::abs(sample) >= DETECTION_THRESHOLD) {
            metrics.detected_output_sample = output_base_sample + i;
        }
        if (same_as_previous && previous_block[static_cast<size_t>(i)] != sample) {
            same_as_previous = false;
        }
    }

    if (same_as_previous) {
        metrics.repeated_blocks++;
    }

    if (decoded_samples == config.frame_size) {
        std::copy_n(pcm.begin(), static_cast<size_t>(config.frame_size), previous_block.begin());
        have_previous_block = true;
    }
}

void run_playout_loop(const ProbeConfig& config, ProbeReceiver& receiver, ProbeMetrics& metrics,
                      clock_type::time_point start_time, double playout_ppm) {
    OpusDecoderWrapper decoder;
    if (config.codec == ProbeCodec::Opus && !decoder.create(SAMPLE_RATE, CHANNELS)) {
        throw std::runtime_error("failed to create Opus decoder");
    }

    bool buffer_ready = false;
    std::array<float, MAX_FRAME_SAMPLES> pcm{};
    std::vector<float> previous_block(static_cast<size_t>(config.frame_size), 0.0F);
    bool have_previous_block = false;
    const double playout_rate =
        static_cast<double>(SAMPLE_RATE) * (1.0 + (playout_ppm / 1'000'000.0));
    auto frame_duration = std::chrono::duration_cast<clock_type::duration>(
        std::chrono::duration<double>(static_cast<double>(config.frame_size) / playout_rate));

    for (int tick = 0; tick < config.total_packets + 80; ++tick) {
        std::this_thread::sleep_until(start_time + frame_duration * tick);
        if (tick % std::max(1, SAMPLE_RATE / config.frame_size) == 0) {
            receiver.send_alive();
        }

        int current_queue_depth = static_cast<int>(receiver.queue_size());
        metrics.final_queue_depth = current_queue_depth;
        metrics.max_queue_depth = std::max(metrics.max_queue_depth, current_queue_depth);
        if (!buffer_ready && current_queue_depth >= config.jitter_min_packets) {
            buffer_ready = true;
        }

        int output_base_sample = tick * config.frame_size;
        if (!buffer_ready) {
            continue;
        }

        if (current_queue_depth == 0 && receiver.received_count() >= config.total_packets) {
            break;
        }

        metrics.queue_depth_observations++;
        metrics.queue_depth_sum += current_queue_depth;
        metrics.min_queue_depth_after_ready =
            std::min(metrics.min_queue_depth_after_ready, current_queue_depth);

        ReceivedPacket packet;
        if (receiver.pop_packet(packet)) {
            int decoded_samples = 0;
            if (config.codec == ProbeCodec::Opus) {
                if (packet.encoded_bytes < 1 || packet.data[0] != PROBE_CODEC_OPUS) {
                    metrics.decode_failures++;
                    continue;
                }
                decoded_samples = decoder.decode_into(packet.data.data() + 1, packet.encoded_bytes - 1,
                                                      pcm.data(), config.frame_size);
                if (decoded_samples <= 0) {
                    metrics.decode_failures++;
                    continue;
                }
            } else if (decode_pcm_int16_packet(packet, config, pcm)) {
                decoded_samples = config.frame_size;
            } else {
                metrics.decode_failures++;
                continue;
            }
            metrics.decoded_packets++;
            if (decoded_samples != config.frame_size) {
                metrics.decoded_size_mismatches++;
            }
            inspect_samples(pcm, decoded_samples, output_base_sample, config, metrics,
                            previous_block, have_previous_block);
        } else if (receiver.received_count() < config.total_packets) {
            metrics.underruns++;
            if (config.codec == ProbeCodec::Opus) {
                int plc_samples = decoder.decode_plc(pcm.data(), config.frame_size);
                if (plc_samples > 0) {
                    metrics.plc_frames++;
                    inspect_samples(pcm, plc_samples, output_base_sample, config, metrics,
                                    previous_block, have_previous_block);
                }
            }
        } else {
            break;
        }
    }
}

void run_sender_loop(const ProbeConfig& config, ProbeSender& sender, ProbeMetrics& metrics,
                     clock_type::time_point start_time) {
    OpusEncoderWrapper encoder;
    if (config.codec == ProbeCodec::Opus &&
        !encoder.create(SAMPLE_RATE, CHANNELS, OPUS_APPLICATION_VOIP, BITRATE, COMPLEXITY)) {
        throw std::runtime_error("failed to create Opus encoder");
    }

    std::vector<float> frame(static_cast<size_t>(config.frame_size), 0.0F);
    std::vector<unsigned char> encoded;
    std::vector<unsigned char> pcm_payload(static_cast<size_t>(config.frame_size) * sizeof(int16_t));
    auto frame_duration =
        std::chrono::duration_cast<clock_type::duration>(std::chrono::duration<double>(
            static_cast<double>(config.frame_size) / static_cast<double>(SAMPLE_RATE)));

    for (int packet_index = 0; packet_index < config.total_packets; ++packet_index) {
        std::this_thread::sleep_until(start_time + frame_duration * packet_index);
        if (packet_index % std::max(1, SAMPLE_RATE / config.frame_size) == 0) {
            sender.send_alive();
        }
        fill_probe_frame(packet_index, config, frame);
        bool sent = false;
        if (config.codec == ProbeCodec::Opus) {
            if (!encoder.encode(frame.data(), config.frame_size, encoded)) {
                metrics.encode_failures++;
                continue;
            }
            sent = sender.send_audio_packet(PROBE_CODEC_OPUS, encoded.data(), encoded.size());
        } else {
            for (int i = 0; i < config.frame_size; ++i) {
                float clamped = std::clamp(frame[static_cast<size_t>(i)], -1.0F, 1.0F);
                auto sample = static_cast<int16_t>(std::lrint(clamped * 32767.0F));
                std::memcpy(pcm_payload.data() + static_cast<size_t>(i) * sizeof(sample), &sample,
                            sizeof(sample));
            }
            sent = sender.send_audio_packet(PROBE_CODEC_PCM_INT16, pcm_payload.data(),
                                            pcm_payload.size());
        }
        if (sent) {
            metrics.sent_packets++;
        } else {
            metrics.encode_failures++;
        }
    }
}

ProbeResult run_probe(const Args& args, const ProbeConfig& config) {
    asio::io_context io_context;
    udp::resolver resolver(io_context);
    udp::endpoint server_endpoint =
        *resolver.resolve(udp::v4(), args.host, std::to_string(args.port)).begin();

    ProbeReceiver receiver(io_context, server_endpoint);
    ProbeSender sender(io_context, server_endpoint);

    receiver.start();
    std::thread io_thread([&io_context]() { io_context.run(); });

    receiver.send_join();
    sender.send_join();
    std::this_thread::sleep_for(200ms);

    ProbeMetrics metrics;
    auto start_time = clock_type::now() + 100ms;

    std::thread playout_thread(run_playout_loop, std::cref(config), std::ref(receiver),
                               std::ref(metrics), start_time, args.playout_ppm);
    std::thread sender_thread(run_sender_loop, std::cref(config), std::ref(sender),
                              std::ref(metrics), start_time);

    sender_thread.join();
    playout_thread.join();

    sender.send_leave();
    receiver.send_leave();
    std::this_thread::sleep_for(50ms);

    io_context.stop();
    if (io_thread.joinable()) {
        io_thread.join();
    }

    metrics.received_packets = receiver.received_count();

    ProbeResult result;
    result.config = config;
    result.metrics = metrics;

    int injected_sample = IMPULSE_PACKET * config.frame_size;
    result.latency_samples = metrics.detected_output_sample >= 0
                                 ? metrics.detected_output_sample - injected_sample
                                 : -1;
    result.latency_ms = result.latency_samples >= 0
                            ? static_cast<double>(result.latency_samples) * 1000.0 / SAMPLE_RATE
                            : -1.0;
    return result;
}

bool has_corruption_indicators(const ProbeResult& result) {
    const auto& m = result.metrics;
    return result.latency_samples < 0 || m.encode_failures > 0 || m.plc_frames > 0 ||
           m.underruns > 0 || m.decode_failures > 0 || m.decoded_size_mismatches > 0 ||
           m.non_finite_samples > 0 || m.out_of_range_samples > 0;
}

void print_result(const Args& args, const ProbeResult& result) {
    const auto& c = result.config;
    const auto& m = result.metrics;
    const double avg_queue =
        m.queue_depth_observations > 0
            ? static_cast<double>(m.queue_depth_sum) / static_cast<double>(m.queue_depth_observations)
            : 0.0;
    const int min_queue =
        m.min_queue_depth_after_ready == std::numeric_limits<int>::max()
            ? 0
            : m.min_queue_depth_after_ready;
    std::cout << "latency_probe v1\n";
    std::cout << "server: " << args.host << ":" << args.port << "\n";
    std::cout << "codec: " << codec_name(c.codec) << "\n";
    std::cout << "sample_rate: " << SAMPLE_RATE << "\n";
    std::cout << "frames_per_packet: " << c.frame_size << "\n";
    std::cout << "jitter_min_packets: " << c.jitter_min_packets << "\n";
    std::cout << "playout_ppm: " << args.playout_ppm << "\n";
    std::cout << "total_packets: " << c.total_packets << "\n";
    std::cout << "impulse_packet: " << IMPULSE_PACKET << "\n";
    std::cout << "sent_packets: " << m.sent_packets << "\n";
    std::cout << "encode_failures: " << m.encode_failures << "\n";
    std::cout << "received_packets: " << m.received_packets << "\n";
    std::cout << "decoded_packets: " << m.decoded_packets << "\n";
    std::cout << "detected_output_sample: " << m.detected_output_sample << "\n";
    std::cout << "latency_samples: " << result.latency_samples << "\n";
    std::cout << "latency_ms: " << result.latency_ms << "\n";
    std::cout << "avg_queue_depth: " << avg_queue << "\n";
    std::cout << "queue_drift_from_jitter: "
              << (avg_queue - static_cast<double>(c.jitter_min_packets)) << "\n";
    std::cout << "min_queue_depth_after_ready: " << min_queue << "\n";
    std::cout << "max_queue_depth: " << m.max_queue_depth << "\n";
    std::cout << "final_queue_depth: " << m.final_queue_depth << "\n";
    std::cout << "underruns: " << m.underruns << "\n";
    std::cout << "plc_frames: " << m.plc_frames << "\n";
    std::cout << "decode_failures: " << m.decode_failures << "\n";
    std::cout << "decoded_size_mismatches: " << m.decoded_size_mismatches << "\n";
    std::cout << "non_finite_samples: " << m.non_finite_samples << "\n";
    std::cout << "out_of_range_samples: " << m.out_of_range_samples << "\n";
    std::cout << "repeated_blocks: " << m.repeated_blocks << "\n";
    std::cout << "max_discontinuity: " << m.max_discontinuity << "\n";
    if (has_corruption_indicators(result)) {
        std::cout << "warning: corruption indicators were observed\n";
    }
}

void print_sweep_header() {
    std::cout << "codec,frames,jitter,playout_ppm,latency_ms,latency_samples,sent,received,decoded,max_queue,"
                 "avg_queue,queue_drift,min_queue,final_queue,encode_failures,underruns,plc,"
                 "decode_failures,size_mismatch,non_finite,out_of_range,repeated_blocks,"
                 "max_discontinuity,status\n";
}

void print_sweep_row(const Args& args, const ProbeResult& result) {
    const auto& c = result.config;
    const auto& m = result.metrics;
    const double avg_queue =
        m.queue_depth_observations > 0
            ? static_cast<double>(m.queue_depth_sum) / static_cast<double>(m.queue_depth_observations)
            : 0.0;
    const int min_queue =
        m.min_queue_depth_after_ready == std::numeric_limits<int>::max()
            ? 0
            : m.min_queue_depth_after_ready;
    std::cout << codec_name(c.codec) << ',' << c.frame_size << ',' << c.jitter_min_packets << ','
              << args.playout_ppm << ',' << result.latency_ms << ',' << result.latency_samples << ',' << m.sent_packets << ','
              << m.received_packets << ',' << m.decoded_packets << ',' << m.max_queue_depth << ','
              << avg_queue << ',' << (avg_queue - static_cast<double>(c.jitter_min_packets)) << ','
              << min_queue << ',' << m.final_queue_depth << ',' << m.encode_failures << ','
              << m.underruns << ',' << m.plc_frames << ',' << m.decode_failures << ','
              << m.decoded_size_mismatches << ',' << m.non_finite_samples << ','
              << m.out_of_range_samples << ',' << m.repeated_blocks << ','
              << m.max_discontinuity << ',' << (has_corruption_indicators(result) ? "warn" : "ok")
              << "\n";
}

Args parse_args(int argc, char** argv) {
    Args args;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "--server" || arg == "--host") && i + 1 < argc) {
            args.host = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            args.port = static_cast<unsigned short>(std::stoi(argv[++i]));
        } else if (arg == "--frames" && i + 1 < argc) {
            args.config.frame_size = std::stoi(argv[++i]);
        } else if (arg == "--jitter" && i + 1 < argc) {
            args.config.jitter_min_packets = std::stoi(argv[++i]);
        } else if (arg == "--packets" && i + 1 < argc) {
            args.config.total_packets = std::stoi(argv[++i]);
        } else if (arg == "--seconds" && i + 1 < argc) {
            args.duration_seconds = std::stoi(argv[++i]);
        } else if (arg == "--playout-ppm" && i + 1 < argc) {
            args.playout_ppm = std::stod(argv[++i]);
        } else if (arg == "--codec" && i + 1 < argc) {
            std::string codec = argv[++i];
            if (codec == "opus") {
                args.config.codec = ProbeCodec::Opus;
            } else if (codec == "pcm" || codec == "raw" || codec == "pcm_int16") {
                args.config.codec = ProbeCodec::PcmInt16;
            } else {
                throw std::runtime_error("unknown codec: " + codec);
            }
        } else if (arg == "--sweep") {
            args.sweep = true;
        }
    }
    if (args.duration_seconds > 0) {
        const int64_t total_samples =
            static_cast<int64_t>(args.duration_seconds) * static_cast<int64_t>(SAMPLE_RATE);
        args.config.total_packets =
            static_cast<int>((total_samples + args.config.frame_size - 1) / args.config.frame_size);
    }
    if (args.config.total_packets <= IMPULSE_PACKET) {
        throw std::runtime_error("--packets/--seconds must run past the impulse packet");
    }
    return args;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        Args args = parse_args(argc, argv);

        if (args.sweep) {
            const std::vector<int> frame_sizes{240, 120, 96, 64};
            const std::vector<int> jitter_values{3, 2, 1, 0};
            print_sweep_header();
            for (int frames: frame_sizes) {
                for (int jitter: jitter_values) {
                    ProbeConfig config{frames, jitter, args.config.total_packets,
                                       args.config.codec};
                    ProbeResult result = run_probe(args, config);
                    print_sweep_row(args, result);
                }
            }
            return 0;
        }

        ProbeResult result = run_probe(args, args.config);
        print_result(args, result);
        return result.metrics.detected_output_sample >= 0 ? 0 : 2;
    } catch (const std::exception& e) {
        std::cerr << "latency_probe failed: " << e.what() << "\n";
        return 1;
    }
}
