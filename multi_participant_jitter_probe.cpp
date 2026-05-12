#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <iostream>
#include <map>
#include <string>
#include <thread>

#include <asio.hpp>
#include <asio/ip/udp.hpp>

#include "audio_packet.h"
#include "packet_builder.h"
#include "protocol.h"

using asio::ip::udp;
using clock_type = std::chrono::steady_clock;
using namespace std::chrono_literals;

namespace {

constexpr int SAMPLE_RATE = 48000;
constexpr int DEFAULT_FRAMES = 120;
constexpr int DEFAULT_PACKETS = 1200;
constexpr uint8_t STABLE_MARKER = 1;
constexpr uint8_t UNSTABLE_MARKER = 2;

struct Config {
    std::string host = "127.0.0.1";
    unsigned short port = 9999;
    int frames = DEFAULT_FRAMES;
    int packets = DEFAULT_PACKETS;
    int stable_target = 3;
    int unstable_target = 8;
};

struct Packet {
    int seq = 0;
    clock_type::time_point scheduled_send_time{};
};

struct ParticipantMetrics {
    int target = 0;
    int enqueued = 0;
    int played = 0;
    int underruns = 0;
    int max_queue = 0;
    long long queue_sum = 0;
    int queue_observations = 0;
    double age_ms_sum = 0.0;
    double age_ms_max = 0.0;
    int age_observations = 0;
    bool ready = false;
    std::deque<Packet> queue;
};

void send_join(udp::socket& socket, const udp::endpoint& server, const std::string& user) {
    JoinHdr hdr{};
    hdr.magic = CTRL_MAGIC;
    hdr.type = CtrlHdr::Cmd::JOIN;
    packet_builder::write_fixed(hdr.room_id, "multi-jitter-probe");
    packet_builder::write_fixed(hdr.room_handle, "multi-jitter-probe");
    packet_builder::write_fixed(hdr.profile_id, user);
    packet_builder::write_fixed(hdr.display_name, user);
    socket.send_to(asio::buffer(&hdr, sizeof(hdr)), server);
}

void send_leave(udp::socket& socket, const udp::endpoint& server) {
    CtrlHdr hdr{};
    hdr.magic = CTRL_MAGIC;
    hdr.type = CtrlHdr::Cmd::LEAVE;
    socket.send_to(asio::buffer(&hdr, sizeof(hdr)), server);
}

int delay_ms_for(uint8_t marker, int seq) {
    if (marker != UNSTABLE_MARKER) {
        return 0;
    }
    int delay = 0;
    if (seq % 11 == 0) {
        delay += 2;
    }
    if (seq % 41 >= 0 && seq % 41 <= 2) {
        delay += 5;
    }
    if (seq % 173 >= 0 && seq % 173 <= 5) {
        delay += 9;
    }
    return delay;
}

void sender_loop(udp::socket& socket, const udp::endpoint& server, const Config& config,
                 uint8_t marker, clock_type::time_point start_time) {
    const auto frame_duration = std::chrono::duration_cast<clock_type::duration>(
        std::chrono::duration<double>(static_cast<double>(config.frames) /
                                      static_cast<double>(SAMPLE_RATE)));
    for (int seq = 0; seq < config.packets; ++seq) {
        std::this_thread::sleep_until(start_time + frame_duration * seq +
                                      std::chrono::milliseconds(delay_ms_for(marker, seq)));
        std::array<unsigned char, 8> payload{};
        payload[0] = marker;
        std::memcpy(payload.data() + 1, &seq, sizeof(seq));
        auto packet = audio_packet::create_audio_packet_v2(
            AudioCodec::Opus, static_cast<uint32_t>(seq), SAMPLE_RATE,
            static_cast<uint16_t>(config.frames), 1, payload.data(),
            static_cast<uint16_t>(payload.size()));
        socket.send_to(asio::buffer(packet->data(), packet->size()), server);
    }
}

void drain_receiver(udp::socket& socket, std::map<uint8_t, ParticipantMetrics>& participants,
                    clock_type::time_point start_time, const Config& config) {
    std::array<unsigned char, 1024> buffer{};
    udp::endpoint sender;
    socket.non_blocking(true);
    for (;;) {
        std::error_code ec;
        const size_t bytes = socket.receive_from(asio::buffer(buffer), sender, 0, ec);
        if (ec == asio::error::would_block || ec == asio::error::try_again) {
            return;
        }
        if (ec || bytes < sizeof(AudioHdrV2) - AUDIO_BUF_SIZE + 5) {
            return;
        }

        MsgHdr msg{};
        std::memcpy(&msg, buffer.data(), sizeof(msg));
        if (msg.magic != AUDIO_V2_MAGIC) {
            continue;
        }

        AudioHdrV2 hdr{};
        std::memcpy(&hdr, buffer.data(), sizeof(AudioHdrV2) - AUDIO_BUF_SIZE);
        const auto* payload = buffer.data() + sizeof(AudioHdrV2) - AUDIO_BUF_SIZE;
        const uint8_t marker = payload[0];
        if (marker != STABLE_MARKER && marker != UNSTABLE_MARKER) {
            continue;
        }

        int seq = 0;
        std::memcpy(&seq, payload + 1, sizeof(seq));
        auto& participant = participants[marker];
        participant.queue.push_back(Packet{
            seq,
            start_time + std::chrono::duration_cast<clock_type::duration>(
                             std::chrono::duration<double>(
                                 static_cast<double>(seq * config.frames) /
                                 static_cast<double>(SAMPLE_RATE))),
        });
        participant.enqueued++;
        participant.max_queue =
            std::max(participant.max_queue, static_cast<int>(participant.queue.size()));
    }
}

void playout_tick(ParticipantMetrics& participant, clock_type::time_point now, int expected_packets) {
    if (participant.played >= expected_packets) {
        return;
    }

    const int queue_size = static_cast<int>(participant.queue.size());
    participant.max_queue = std::max(participant.max_queue, queue_size);
    if (!participant.ready && queue_size >= std::max(1, participant.target)) {
        participant.ready = true;
    }
    if (!participant.ready) {
        return;
    }

    participant.queue_observations++;
    participant.queue_sum += queue_size;
    if (participant.queue.empty()) {
        participant.underruns++;
        return;
    }

    Packet packet = participant.queue.front();
    participant.queue.pop_front();
    participant.played++;
    const double age_ms =
        static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(
                                now - packet.scheduled_send_time)
                                .count()) /
        1000.0;
    participant.age_ms_sum += age_ms;
    participant.age_ms_max = std::max(participant.age_ms_max, age_ms);
    participant.age_observations++;
}

double avg_queue(const ParticipantMetrics& metrics) {
    if (metrics.queue_observations == 0) {
        return 0.0;
    }
    return static_cast<double>(metrics.queue_sum) /
           static_cast<double>(metrics.queue_observations);
}

double avg_age_ms(const ParticipantMetrics& metrics) {
    if (metrics.age_observations == 0) {
        return 0.0;
    }
    return metrics.age_ms_sum / static_cast<double>(metrics.age_observations);
}

Config parse_args(int argc, char** argv) {
    Config config;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if ((arg == "--server" || arg == "--host") && i + 1 < argc) {
            config.host = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            config.port = static_cast<unsigned short>(std::stoi(argv[++i]));
        } else if (arg == "--frames" && i + 1 < argc) {
            config.frames = std::stoi(argv[++i]);
        } else if (arg == "--packets" && i + 1 < argc) {
            config.packets = std::stoi(argv[++i]);
        } else if (arg == "--stable-target" && i + 1 < argc) {
            config.stable_target = std::stoi(argv[++i]);
        } else if (arg == "--unstable-target" && i + 1 < argc) {
            config.unstable_target = std::stoi(argv[++i]);
        }
    }
    config.frames = std::max(1, config.frames);
    config.packets = std::max(100, config.packets);
    config.stable_target = std::max(0, config.stable_target);
    config.unstable_target = std::max(0, config.unstable_target);
    return config;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        Config config = parse_args(argc, argv);
        asio::io_context io;
        udp::resolver resolver(io);
        const udp::endpoint server =
            *resolver.resolve(udp::v4(), config.host, std::to_string(config.port)).begin();

        udp::socket receiver(io, udp::endpoint(udp::v4(), 0));
        udp::socket stable_sender(io, udp::endpoint(udp::v4(), 0));
        udp::socket unstable_sender(io, udp::endpoint(udp::v4(), 0));
        send_join(receiver, server, "multi-jitter-receiver");
        send_join(stable_sender, server, "multi-jitter-stable");
        send_join(unstable_sender, server, "multi-jitter-unstable");
        std::this_thread::sleep_for(100ms);

        std::map<uint8_t, ParticipantMetrics> participants;
        participants[STABLE_MARKER].target = config.stable_target;
        participants[UNSTABLE_MARKER].target = config.unstable_target;

        const auto frame_duration = std::chrono::duration_cast<clock_type::duration>(
            std::chrono::duration<double>(static_cast<double>(config.frames) /
                                          static_cast<double>(SAMPLE_RATE)));
        const auto start_time = clock_type::now() + 100ms;

        std::thread stable_thread(sender_loop, std::ref(stable_sender), std::cref(server),
                                  std::cref(config), STABLE_MARKER, start_time);
        std::thread unstable_thread(sender_loop, std::ref(unstable_sender), std::cref(server),
                                    std::cref(config), UNSTABLE_MARKER, start_time);

        for (int tick = 0; tick < config.packets + 120; ++tick) {
            const auto now = start_time + frame_duration * tick;
            std::this_thread::sleep_until(now);
            drain_receiver(receiver, participants, start_time, config);
            playout_tick(participants[STABLE_MARKER], now, config.packets);
            playout_tick(participants[UNSTABLE_MARKER], now, config.packets);
            if (participants[STABLE_MARKER].played >= config.packets &&
                participants[UNSTABLE_MARKER].played >= config.packets) {
                break;
            }
        }

        stable_thread.join();
        unstable_thread.join();
        drain_receiver(receiver, participants, start_time, config);

        send_leave(receiver, server);
        send_leave(stable_sender, server);
        send_leave(unstable_sender, server);

        const auto& stable = participants[STABLE_MARKER];
        const auto& unstable = participants[UNSTABLE_MARKER];
        std::cout << "source,target,enqueued,played,underruns,avg_queue,max_queue,avg_age_ms,max_age_ms\n";
        std::cout << "stable," << stable.target << ',' << stable.enqueued << ',' << stable.played
                  << ',' << stable.underruns << ',' << avg_queue(stable) << ','
                  << stable.max_queue << ',' << avg_age_ms(stable) << ',' << stable.age_ms_max
                  << "\n";
        std::cout << "unstable," << unstable.target << ',' << unstable.enqueued << ','
                  << unstable.played << ',' << unstable.underruns << ',' << avg_queue(unstable)
                  << ',' << unstable.max_queue << ',' << avg_age_ms(unstable) << ','
                  << unstable.age_ms_max << "\n";

        const bool stable_low_latency = avg_age_ms(stable) < avg_age_ms(unstable);
        const bool unstable_buffered =
            unstable.played > 0 && unstable.underruns <= stable.underruns;
        if (!stable_low_latency || !unstable_buffered) {
            std::cerr << "per-participant jitter isolation failed\n";
            return 2;
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "multi_participant_jitter_probe failed: " << e.what() << "\n";
        return 1;
    }
}
