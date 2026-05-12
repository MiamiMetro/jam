#include <algorithm>
#include <cmath>
#include <cstdint>
#include <deque>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr int SAMPLE_RATE = 48000;
constexpr int DEFAULT_FRAMES = 120;
constexpr int DEFAULT_PACKETS = 1200;
constexpr int IMPULSE_PACKET = 20;
constexpr int PCM_BUFFER_FRAMES = 1920;

struct Config {
    int frames = DEFAULT_FRAMES;
    int callback_frames = DEFAULT_FRAMES;
    bool callback_frames_set = false;
    int packets = DEFAULT_PACKETS;
    int jitter_target = 5;
    int queue_limit = 64;
    int age_limit_ms = 100;
    int trim_headroom = 2;
    int receiver_clock_ppm = 0;
    std::string scenario = "scheduler";
    std::string timeline_path;
    bool sweep = false;
    bool auto_jitter = false;
    bool adaptive_playout = false;
    bool self_test = false;
};

struct Packet {
    int seq = 0;
    int64_t send_us = 0;
    int64_t arrival_us = 0;
};

struct Metrics {
    int enqueued = 0;
    int played = 0;
    int decoded_packets = 0;
    int plc = 0;
    int underruns = 0;
    int full_rebuffers = 0;
    int target_trims = 0;
    int queue_limit_drops = 0;
    int age_limit_drops = 0;
    int sequence_gaps = 0;
    int late_packets = 0;
    int max_queue = 0;
    int min_queue_after_ready = std::numeric_limits<int>::max();
    int64_t queue_sum = 0;
    int queue_observations = 0;
    int64_t age_sum_us = 0;
    int64_t age_max_us = 0;
    int age_observations = 0;
    int latency_samples = -1;
    int final_jitter_target = 0;
    int auto_increases = 0;
    int auto_decreases = 0;
    double playout_ratio_last = 1.0;
    double playout_ratio_sum = 0.0;
    int playout_ratio_observations = 0;
};

int64_t packet_interval_us(int frames) {
    return (static_cast<int64_t>(frames) * 1'000'000LL) / SAMPLE_RATE;
}

int64_t receiver_callback_interval_us(const Config& config) {
    const int ppm = config.scenario == "clock_drift" && config.receiver_clock_ppm == 0
                        ? 180
                        : config.receiver_clock_ppm;
    const double scale = 1.0 + (static_cast<double>(ppm) / 1'000'000.0);
    return std::max<int64_t>(
        1, static_cast<int64_t>(
               (static_cast<double>(config.callback_frames) * 1'000'000.0 /
                static_cast<double>(SAMPLE_RATE)) *
               scale));
}

int ready_packets_for_target(int target) {
    return std::max(1, target);
}

int ready_packets(const Config& config) {
    return ready_packets_for_target(config.jitter_target);
}

int trim_target_packets(const Config& config, int target) {
    return std::min(config.queue_limit, ready_packets_for_target(target) + config.trim_headroom);
}

int rebuffer_threshold_for_target(int target) {
    return std::max(3, ready_packets_for_target(target));
}

int deterministic_delay_us(const Config& config, int seq) {
    if (config.scenario == "clean") {
        return 0;
    }
    if (config.scenario == "scheduler") {
        int delay = 0;
        if (seq % 10 == 0) {
            delay += 900;
        }
        if (seq % 37 == 0) {
            delay += 1800;
        }
        if (seq % 113 >= 0 && seq % 113 <= 2) {
            delay += 2600;
        }
        return delay;
    }
    if (config.scenario == "wifi") {
        int delay = 0;
        if (seq % 11 == 0) {
            delay += 1200;
        }
        if (seq % 41 >= 0 && seq % 41 <= 2) {
            delay += 3800;
        }
        if (seq % 173 >= 0 && seq % 173 <= 5) {
            delay += 7000;
        }
        return delay;
    }
    if (config.scenario == "tunnel") {
        int delay = 2200;
        if (seq % 17 == 0) {
            delay += 2500;
        }
        if (seq % 89 >= 0 && seq % 89 <= 4) {
            delay += 6500;
        }
        return delay;
    }
    if (config.scenario == "reorder") {
        int delay = 0;
        if (seq % 67 == 8) {
            delay += 7600;
        }
        if (seq % 149 >= 0 && seq % 149 <= 1) {
            delay += 4200;
        }
        return delay;
    }
    if (config.scenario == "callback_stall" || config.scenario == "clock_drift") {
        Config scheduler_config;
        scheduler_config.scenario = "scheduler";
        return deterministic_delay_us(scheduler_config, seq);
    }
    return 0;
}

bool packet_lost(const Config& config, int seq) {
    if (config.scenario == "loss") {
        return seq % 97 == 0;
    }
    if (config.scenario == "burst_loss") {
        return seq % 211 >= 0 && seq % 211 <= 2;
    }
    return false;
}

std::vector<Packet> make_packets(const Config& config) {
    if (!config.timeline_path.empty()) {
        std::ifstream file(config.timeline_path);
        if (!file) {
            throw std::runtime_error("could not open timeline: " + config.timeline_path);
        }

        std::vector<Packet> packets;
        std::string line;
        const int64_t interval_us = packet_interval_us(config.frames);
        while (std::getline(file, line)) {
            if (line.empty() || line[0] == '#') {
                continue;
            }

            std::replace(line.begin(), line.end(), ',', ' ');
            std::istringstream row(line);
            int seq = 0;
            int64_t arrival_us = 0;
            int64_t send_us = 0;
            if (!(row >> seq >> arrival_us)) {
                throw std::runtime_error("invalid timeline row: " + line);
            }
            if (!(row >> send_us)) {
                send_us = seq * interval_us;
            }
            packets.push_back(Packet{seq, send_us, arrival_us});
        }

        std::stable_sort(packets.begin(), packets.end(), [](const Packet& a, const Packet& b) {
            if (a.arrival_us == b.arrival_us) {
                return a.seq < b.seq;
            }
            return a.arrival_us < b.arrival_us;
        });
        return packets;
    }

    std::vector<Packet> packets;
    packets.reserve(static_cast<size_t>(config.packets));
    const int64_t interval_us = packet_interval_us(config.frames);
    for (int seq = 0; seq < config.packets; ++seq) {
        if (packet_lost(config, seq)) {
            continue;
        }
        const int64_t send_us = seq * interval_us;
        packets.push_back(Packet{
            seq,
            send_us,
            send_us + deterministic_delay_us(config, seq),
        });
    }
    std::stable_sort(packets.begin(), packets.end(), [](const Packet& a, const Packet& b) {
        if (a.arrival_us == b.arrival_us) {
            return a.seq < b.seq;
        }
        return a.arrival_us < b.arrival_us;
    });
    return packets;
}

void observe_queue(Metrics& metrics, int depth, bool ready) {
    metrics.max_queue = std::max(metrics.max_queue, depth);
    if (ready) {
        metrics.queue_sum += depth;
        metrics.queue_observations++;
        metrics.min_queue_after_ready = std::min(metrics.min_queue_after_ready, depth);
    }
}

void observe_age(Metrics& metrics, int64_t age_us) {
    metrics.age_sum_us += age_us;
    metrics.age_max_us = std::max(metrics.age_max_us, age_us);
    metrics.age_observations++;
}

void trim_queue(const Config& config, int jitter_target, std::deque<Packet>& queue,
                Metrics& metrics) {
    const int target = trim_target_packets(config, jitter_target);
    while (static_cast<int>(queue.size()) > target) {
        queue.pop_front();
        metrics.target_trims++;
    }
}

void raise_auto_jitter(const Config& config, Metrics& metrics, int& jitter_target,
                       int& instability_events, int& stable_callbacks, bool& ready,
                       int& consecutive_empty_callbacks) {
    if (!config.auto_jitter) {
        return;
    }
    stable_callbacks = 0;
    instability_events++;
    if (jitter_target < 32) {
        jitter_target = std::min(32, std::max(3, jitter_target + 1));
        metrics.auto_increases++;
        ready = false;
        consecutive_empty_callbacks = 0;
    }
}

void observe_auto_jitter_stable(const Config& config, Metrics& metrics, int& jitter_target,
                                int& instability_events, int& stable_callbacks) {
    if (!config.auto_jitter) {
        return;
    }
    instability_events = 0;
    stable_callbacks++;
    if (stable_callbacks < 2000) {
        return;
    }
    stable_callbacks = 0;
    if (jitter_target > config.jitter_target) {
        jitter_target--;
        metrics.auto_decreases++;
    }
}

double avg_playout_ratio(const Metrics& metrics) {
    if (metrics.playout_ratio_observations == 0) {
        return 1.0;
    }
    return metrics.playout_ratio_sum /
           static_cast<double>(metrics.playout_ratio_observations);
}

double adaptive_playout_ratio(const Config& config, const std::deque<Packet>& queue,
                              int pcm_buffered_frames, int jitter_target,
                              int queue_limit_drops, int& last_queue_limit_drops,
                              int& correction_callbacks, Metrics& metrics) {
    const double decoded_packets =
        static_cast<double>(pcm_buffered_frames) / static_cast<double>(config.frames);
    const double queued_packets = static_cast<double>(queue.size()) + decoded_packets;
    const double target_packets = static_cast<double>(std::max(1, jitter_target));
    const double queue_error = queued_packets - target_packets;
    const double gain = queue_error < 0.0 ? 0.01 : 0.005;
    double ratio = std::clamp(1.0 + (queue_error * gain), 0.95, 1.04);

    if (queue_limit_drops > last_queue_limit_drops) {
        last_queue_limit_drops = queue_limit_drops;
        correction_callbacks = 400;
    }
    if (correction_callbacks > 0) {
        correction_callbacks--;
        if (queued_packets >= target_packets * 0.5) {
            ratio = std::max(ratio, 1.04);
        }
    }

    metrics.playout_ratio_last = ratio;
    metrics.playout_ratio_sum += ratio;
    metrics.playout_ratio_observations++;
    return ratio;
}

int adaptive_required_input_frames(double phase, int callback_frames, double ratio) {
    if (callback_frames <= 0) {
        return 0;
    }
    const double last_source = phase + (static_cast<double>(callback_frames - 1) * ratio);
    return static_cast<int>(std::floor(last_source)) + 1;
}

int adaptive_consumed_frames(double& phase, int callback_frames, double ratio) {
    const double consumed_exact = phase + (static_cast<double>(callback_frames) * ratio);
    const int consumed_frames = static_cast<int>(std::floor(consumed_exact));
    phase = consumed_exact - static_cast<double>(consumed_frames);
    return consumed_frames;
}

Metrics run_simulation(const Config& config) {
    const std::vector<Packet> arrivals = make_packets(config);
    const int64_t interval_us = packet_interval_us(config.frames);
    const int64_t callback_interval = receiver_callback_interval_us(config);
    const int64_t max_age_us = static_cast<int64_t>(config.age_limit_ms) * 1000LL;
    const bool age_limit_enabled = config.age_limit_ms > 0;

    std::deque<Packet> queue;
    Metrics metrics;
    int jitter_target = config.jitter_target;
    bool ready = false;
    int consecutive_empty_callbacks = 0;
    int auto_instability_events = 0;
    int auto_stable_callbacks = 0;
    int next_expected_seq = 0;
    int pcm_buffered_frames = 0;
    double resample_phase = 0.0;
    int rate_last_queue_limit_drops = 0;
    int rate_correction_callbacks = 0;
    size_t next_arrival = 0;

    const int callback_count = config.packets + 160;
    int64_t now_us = 0;
    for (int callback = 0; callback < callback_count; ++callback) {
        if (callback > 0) {
            now_us += callback_interval;
        }
        if (config.scenario == "callback_stall" &&
            (callback % 173 == 80 || callback % 173 == 81)) {
            now_us += 7000;
        }

        while (next_arrival < arrivals.size() && arrivals[next_arrival].arrival_us <= now_us) {
            if (static_cast<int>(queue.size()) >= config.queue_limit) {
                queue.pop_front();
                metrics.queue_limit_drops++;
            }
            queue.push_back(arrivals[next_arrival]);
            metrics.enqueued++;
            if (!config.adaptive_playout) {
                trim_queue(config, jitter_target, queue, metrics);
            }
            next_arrival++;
        }

        if (!ready && static_cast<int>(queue.size()) >= ready_packets_for_target(jitter_target)) {
            ready = true;
            consecutive_empty_callbacks = 0;
        }

        observe_queue(metrics, static_cast<int>(queue.size()), ready);

        if (!ready) {
            continue;
        }

        while (!queue.empty() && age_limit_enabled && now_us - queue.front().arrival_us > max_age_us) {
            queue.pop_front();
            metrics.age_limit_drops++;
            raise_auto_jitter(config, metrics, jitter_target, auto_instability_events,
                              auto_stable_callbacks, ready, consecutive_empty_callbacks);
        }

        if (config.adaptive_playout) {
            const double ratio = adaptive_playout_ratio(
                config, queue, pcm_buffered_frames, jitter_target, metrics.queue_limit_drops,
                rate_last_queue_limit_drops, rate_correction_callbacks, metrics);
            int required_frames =
                adaptive_required_input_frames(resample_phase, config.callback_frames, ratio);
            while (pcm_buffered_frames < required_frames && !queue.empty()) {
                Packet packet = queue.front();
                queue.pop_front();
                metrics.decoded_packets++;

                if (packet.seq > next_expected_seq) {
                    metrics.sequence_gaps += packet.seq - next_expected_seq;
                } else if (packet.seq < next_expected_seq) {
                    metrics.late_packets++;
                }
                next_expected_seq = std::max(next_expected_seq, packet.seq + 1);
                observe_age(metrics, now_us - packet.arrival_us);

                if (pcm_buffered_frames + config.frames > PCM_BUFFER_FRAMES) {
                    pcm_buffered_frames = 0;
                    metrics.queue_limit_drops++;
                    rate_correction_callbacks = 400;
                    break;
                }

                pcm_buffered_frames += config.frames;
                required_frames =
                    adaptive_required_input_frames(resample_phase, config.callback_frames, ratio);

                if (packet.seq == IMPULSE_PACKET && metrics.latency_samples < 0) {
                    metrics.latency_samples = static_cast<int>(
                        ((now_us - packet.send_us) * static_cast<int64_t>(SAMPLE_RATE)) /
                        1'000'000LL);
                }
            }

            if (pcm_buffered_frames >= required_frames) {
                const int consumed =
                    adaptive_consumed_frames(resample_phase, config.callback_frames, ratio);
                pcm_buffered_frames = std::max(0, pcm_buffered_frames - consumed);
                metrics.played++;
                consecutive_empty_callbacks = 0;
                observe_auto_jitter_stable(config, metrics, jitter_target,
                                           auto_instability_events, auto_stable_callbacks);
                continue;
            }

            if (pcm_buffered_frames > 0) {
                pcm_buffered_frames = 0;
                resample_phase = 0.0;
                metrics.played++;
                consecutive_empty_callbacks = 0;
                continue;
            }

            if (next_arrival >= arrivals.size()) {
                break;
            }

            metrics.underruns++;
            metrics.plc++;
            consecutive_empty_callbacks++;
            raise_auto_jitter(config, metrics, jitter_target, auto_instability_events,
                              auto_stable_callbacks, ready, consecutive_empty_callbacks);
            if (consecutive_empty_callbacks >= rebuffer_threshold_for_target(jitter_target)) {
                metrics.full_rebuffers++;
                ready = false;
                consecutive_empty_callbacks = 0;
                pcm_buffered_frames = 0;
                resample_phase = 0.0;
            }
            continue;
        }

        if (!queue.empty()) {
            Packet packet = queue.front();
            queue.pop_front();
            metrics.played++;
            consecutive_empty_callbacks = 0;

            if (packet.seq > next_expected_seq) {
                metrics.sequence_gaps += packet.seq - next_expected_seq;
            } else if (packet.seq < next_expected_seq) {
                metrics.late_packets++;
            }
            next_expected_seq = std::max(next_expected_seq, packet.seq + 1);

            observe_age(metrics, now_us - packet.arrival_us);
            observe_auto_jitter_stable(config, metrics, jitter_target, auto_instability_events,
                                       auto_stable_callbacks);

            if (packet.seq == IMPULSE_PACKET && metrics.latency_samples < 0) {
                metrics.latency_samples = static_cast<int>(
                    ((now_us - packet.send_us) * static_cast<int64_t>(SAMPLE_RATE)) / 1'000'000LL);
            }
            continue;
        }

        if (next_arrival >= arrivals.size()) {
            break;
        }

        metrics.underruns++;
        metrics.plc++;
        consecutive_empty_callbacks++;
        raise_auto_jitter(config, metrics, jitter_target, auto_instability_events,
                          auto_stable_callbacks, ready, consecutive_empty_callbacks);
        if (consecutive_empty_callbacks >= rebuffer_threshold_for_target(jitter_target)) {
            metrics.full_rebuffers++;
            ready = false;
            consecutive_empty_callbacks = 0;
        }
    }

    metrics.final_jitter_target = jitter_target;
    return metrics;
}

double avg_queue(const Metrics& metrics) {
    if (metrics.queue_observations == 0) {
        return 0.0;
    }
    return static_cast<double>(metrics.queue_sum) / static_cast<double>(metrics.queue_observations);
}

double avg_age_ms(const Metrics& metrics) {
    if (metrics.age_observations == 0) {
        return 0.0;
    }
    return static_cast<double>(metrics.age_sum_us) / 1000.0 /
           static_cast<double>(metrics.age_observations);
}

double max_age_ms(const Metrics& metrics) {
    return static_cast<double>(metrics.age_max_us) / 1000.0;
}

double latency_ms(const Config& config, const Metrics& metrics) {
    if (metrics.latency_samples < 0) {
        return -1.0;
    }
    return static_cast<double>(metrics.latency_samples) * 1000.0 / SAMPLE_RATE;
}

bool stable(const Metrics& metrics) {
    return metrics.full_rebuffers == 0 && metrics.underruns == 0 && metrics.age_limit_drops == 0 &&
           metrics.queue_limit_drops == 0 && metrics.latency_samples >= 0;
}

std::string status_reason(const Metrics& metrics) {
    if (metrics.latency_samples < 0) {
        return "missing_impulse";
    }
    if (metrics.full_rebuffers > 0) {
        return "full_rebuffer";
    }
    if (metrics.underruns > 0) {
        return "underrun_plc";
    }
    if (metrics.age_limit_drops > 0) {
        return "age_drop";
    }
    if (metrics.queue_limit_drops > 0) {
        return "queue_drop";
    }
    return "ok";
}

void print_header() {
    std::cout
        << "scenario,frames,callback_frames,jitter_target,queue_limit,age_limit_ms,receiver_ppm,auto_jitter,adaptive_playout,final_jitter,auto_inc,auto_dec,played,decoded_packets,enqueued,latency_ms,"
           "avg_age_ms,max_age_ms,avg_queue,max_queue,min_queue,underruns,plc,full_rebuffers,"
           "target_trims,queue_drops,age_drops,seq_gaps,late,ratio_last,ratio_avg,status,reason\n";
}

void print_row(const Config& config, const Metrics& metrics) {
    const int min_queue =
        metrics.min_queue_after_ready == std::numeric_limits<int>::max()
            ? 0
            : metrics.min_queue_after_ready;
    std::cout << config.scenario << ',' << config.frames << ',' << config.callback_frames << ','
              << config.jitter_target << ',' << config.queue_limit << ',' << config.age_limit_ms
              << ',' << config.receiver_clock_ppm << ',' << (config.auto_jitter ? 1 : 0) << ','
              << (config.adaptive_playout ? 1 : 0) << ',' << metrics.final_jitter_target << ','
              << metrics.auto_increases << ',' << metrics.auto_decreases << ',' << metrics.played
              << ',' << metrics.decoded_packets << ',' << metrics.enqueued << ','
              << latency_ms(config, metrics) << ',' << avg_age_ms(metrics)
              << ',' << max_age_ms(metrics) << ',' << avg_queue(metrics) << ',' << metrics.max_queue
              << ',' << min_queue << ',' << metrics.underruns << ',' << metrics.plc << ','
              << metrics.full_rebuffers << ',' << metrics.target_trims << ','
              << metrics.queue_limit_drops << ',' << metrics.age_limit_drops << ','
              << metrics.sequence_gaps << ',' << metrics.late_packets << ','
              << metrics.playout_ratio_last << ',' << avg_playout_ratio(metrics) << ','
              << (stable(metrics) ? "ok" : "warn") << ',' << status_reason(metrics) << '\n';
}

Config parse_args(int argc, char** argv) {
    Config config;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--scenario" && i + 1 < argc) {
            config.scenario = argv[++i];
        } else if (arg == "--frames" && i + 1 < argc) {
            config.frames = std::stoi(argv[++i]);
        } else if (arg == "--callback-frames" && i + 1 < argc) {
            config.callback_frames = std::stoi(argv[++i]);
            config.callback_frames_set = true;
        } else if (arg == "--packets" && i + 1 < argc) {
            config.packets = std::stoi(argv[++i]);
        } else if (arg == "--jitter" && i + 1 < argc) {
            config.jitter_target = std::stoi(argv[++i]);
        } else if (arg == "--queue-limit" && i + 1 < argc) {
            config.queue_limit = std::stoi(argv[++i]);
        } else if (arg == "--age-limit-ms" && i + 1 < argc) {
            config.age_limit_ms = std::stoi(argv[++i]);
        } else if (arg == "--trim-headroom" && i + 1 < argc) {
            config.trim_headroom = std::stoi(argv[++i]);
        } else if (arg == "--receiver-ppm" && i + 1 < argc) {
            config.receiver_clock_ppm = std::stoi(argv[++i]);
        } else if (arg == "--timeline" && i + 1 < argc) {
            config.timeline_path = argv[++i];
            config.scenario = "timeline";
        } else if (arg == "--auto-jitter") {
            config.auto_jitter = true;
        } else if (arg == "--adaptive-playout") {
            config.adaptive_playout = true;
        } else if (arg == "--self-test") {
            config.self_test = true;
        } else if (arg == "--sweep") {
            config.sweep = true;
        }
    }
    config.frames = std::max(1, config.frames);
    if (!config.callback_frames_set) {
        config.callback_frames = config.frames;
    }
    config.callback_frames = std::max(1, config.callback_frames);
    config.packets = std::max(IMPULSE_PACKET + 1, config.packets);
    config.jitter_target = std::max(0, config.jitter_target);
    config.queue_limit = std::max(1, config.queue_limit);
    config.trim_headroom = std::max(0, config.trim_headroom);
    return config;
}

bool expect(bool condition, const std::string& name, const std::string& detail) {
    if (condition) {
        std::cerr << "PASS " << name << ": " << detail << '\n';
        return true;
    }
    std::cerr << "FAIL " << name << ": " << detail << '\n';
    return false;
}

int run_self_test() {
    bool ok = true;

    Config clean;
    clean.scenario = "clean";
    clean.jitter_target = 5;
    Metrics clean_metrics = run_simulation(clean);
    ok &= expect(stable(clean_metrics), "clean-jitter-5", "clean network stays stable");

    Config wifi_low;
    wifi_low.scenario = "wifi";
    wifi_low.jitter_target = 0;
    Metrics wifi_low_metrics = run_simulation(wifi_low);
    ok &= expect(!stable(wifi_low_metrics) && wifi_low_metrics.underruns > 0,
                 "wifi-low-target-fails", "low target reproduces PLC underruns");

    Config wifi_stable;
    wifi_stable.scenario = "wifi";
    wifi_stable.jitter_target = 3;
    Metrics wifi_stable_metrics = run_simulation(wifi_stable);
    ok &= expect(stable(wifi_stable_metrics), "wifi-target-3-stable",
                 "jitter target 3 stabilizes deterministic Wi-Fi");

    Config wifi_auto = wifi_low;
    wifi_auto.auto_jitter = true;
    wifi_auto.packets = 2400;
    wifi_low.packets = 2400;
    wifi_low_metrics = run_simulation(wifi_low);
    Metrics wifi_auto_metrics = run_simulation(wifi_auto);
    ok &= expect(wifi_auto_metrics.auto_increases > 0 &&
                     wifi_auto_metrics.final_jitter_target > wifi_auto.jitter_target &&
                     wifi_auto_metrics.underruns < wifi_low_metrics.underruns,
                 "auto-jitter-improves-wifi",
                 "auto raises target and reduces deterministic underruns");

    Config burst_loss;
    burst_loss.scenario = "burst_loss";
    burst_loss.jitter_target = 0;
    Metrics burst_loss_metrics = run_simulation(burst_loss);
    ok &= expect(!stable(burst_loss_metrics) && burst_loss_metrics.full_rebuffers > 0,
                 "burst-loss-rebuffers", "burst loss reproduces full rebuffer risk");

    Config drift;
    drift.scenario = "clock_drift";
    drift.receiver_clock_ppm = -1000;
    drift.packets = 24000;
    drift.jitter_target = 5;
    Metrics drift_metrics = run_simulation(drift);
    ok &= expect(!stable(drift_metrics) && drift_metrics.underruns > 0,
                 "clock-drift-underruns", "receiver clock skew is distinguishable");

    Config callback_mismatch;
    callback_mismatch.scenario = "clean";
    callback_mismatch.frames = 120;
    callback_mismatch.callback_frames = 128;
    callback_mismatch.callback_frames_set = true;
    callback_mismatch.packets = 24000;
    callback_mismatch.jitter_target = 5;
    callback_mismatch.queue_limit = 32;
    callback_mismatch.adaptive_playout = true;
    Metrics callback_mismatch_metrics = run_simulation(callback_mismatch);
    ok &= expect(stable(callback_mismatch_metrics) &&
                     callback_mismatch_metrics.decoded_packets > 23000,
                 "adaptive-callback-mismatch-stable",
                 "120-frame packets stay stable on 128-frame callbacks");

    Config receiver_slow = callback_mismatch;
    receiver_slow.receiver_clock_ppm = 25000;
    Metrics receiver_slow_metrics = run_simulation(receiver_slow);
    ok &= expect(stable(receiver_slow_metrics) && avg_playout_ratio(receiver_slow_metrics) > 1.0,
                 "adaptive-slow-receiver-stable",
                 "positive receiver clock skew drains backlog without hard drops");

    Config receiver_fast = callback_mismatch;
    receiver_fast.receiver_clock_ppm = -25000;
    Metrics receiver_fast_metrics = run_simulation(receiver_fast);
    ok &= expect(stable(receiver_fast_metrics) && avg_playout_ratio(receiver_fast_metrics) < 1.0,
                 "adaptive-fast-receiver-stable",
                 "negative receiver clock skew slows playout without underruns");

    return ok ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
    Config config = parse_args(argc, argv);
    if (config.self_test) {
        return run_self_test();
    }
    print_header();
    if (config.sweep) {
        const std::vector<int> targets{0, 1, 2, 3, 5, 8, 13, 32};
        for (int target: targets) {
            Config run = config;
            run.jitter_target = target;
            print_row(run, run_simulation(run));
        }
        return 0;
    }
    print_row(config, run_simulation(config));
    return 0;
}
