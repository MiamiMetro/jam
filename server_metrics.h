#pragma once

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace server_metrics {

struct TrafficCounters {
    uint64_t interval = 0;
    uint64_t total = 0;
    uint64_t sequence_gaps_interval = 0;
    uint64_t sequence_gaps_total = 0;
    uint64_t sequence_gap_recoveries_interval = 0;
    uint64_t sequence_gap_recoveries_total = 0;
    uint64_t sequence_unresolved_gaps = 0;
    uint64_t sequence_late_or_reordered_interval = 0;
    uint64_t sequence_late_or_reordered_total = 0;
};

struct DropCounters {
    uint64_t unknown_audio_interval = 0;
    uint64_t unknown_audio_total = 0;
    uint64_t invalid_audio_interval = 0;
    uint64_t invalid_audio_total = 0;
    uint64_t rate_limited_audio_interval = 0;
    uint64_t rate_limited_audio_total = 0;
};

struct IngressMetric {
    uint32_t sender_id = 0;
    std::string endpoint;
    TrafficCounters audio;
    uint16_t last_frame_count = 0;
};

struct ForwardMetric {
    uint32_t sender_id = 0;
    uint32_t target_id = 0;
    TrafficCounters audio;
};

struct PingMetric {
    uint32_t client_id = 0;
    std::string endpoint;
    uint64_t reply_queued_interval = 0;
    uint64_t reply_queued_total = 0;
    TrafficCounters ping;
};

struct Snapshot {
    std::string schema = "jam_server_metrics_v1";
    std::string server_id;
    int64_t timestamp_unix_ms = 0;
    int64_t uptime_ms = 0;
    uint64_t connected_clients = 0;
    uint64_t unknown_endpoint_count = 0;
    uint64_t token_nonce_count = 0;
    DropCounters drops;
    std::vector<IngressMetric> ingress;
    std::vector<ForwardMetric> forwards;
    std::vector<PingMetric> pings;
};

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

inline void append_counter_set(std::ostringstream& out, const TrafficCounters& counters,
                               std::string_view interval_name,
                               std::string_view total_name) {
    out << '{';
    append_json_string(out, interval_name);
    out << ':' << counters.interval << ',';
    append_json_string(out, total_name);
    out << ':' << counters.total
        << ",\"sequence_gaps_interval\":" << counters.sequence_gaps_interval
        << ",\"sequence_gaps_total\":" << counters.sequence_gaps_total
        << ",\"sequence_gap_recoveries_interval\":"
        << counters.sequence_gap_recoveries_interval
        << ",\"sequence_gap_recoveries_total\":" << counters.sequence_gap_recoveries_total
        << ",\"sequence_unresolved_gaps\":" << counters.sequence_unresolved_gaps
        << ",\"sequence_late_or_reordered_interval\":"
        << counters.sequence_late_or_reordered_interval
        << ",\"sequence_late_or_reordered_total\":"
        << counters.sequence_late_or_reordered_total << '}';
}

inline std::string to_json_line(const Snapshot& snapshot) {
    std::ostringstream out;
    out << '{';
    out << "\"schema\":";
    append_json_string(out, snapshot.schema);
    out << ",\"server_id\":";
    append_json_string(out, snapshot.server_id);
    out << ",\"timestamp_unix_ms\":" << snapshot.timestamp_unix_ms
        << ",\"uptime_ms\":" << snapshot.uptime_ms
        << ",\"connected_clients\":" << snapshot.connected_clients
        << ",\"unknown_endpoint_count\":" << snapshot.unknown_endpoint_count
        << ",\"token_nonce_count\":" << snapshot.token_nonce_count;

    out << ",\"drops\":{\"unknown_audio_interval\":"
        << snapshot.drops.unknown_audio_interval
        << ",\"unknown_audio_total\":" << snapshot.drops.unknown_audio_total
        << ",\"invalid_audio_interval\":" << snapshot.drops.invalid_audio_interval
        << ",\"invalid_audio_total\":" << snapshot.drops.invalid_audio_total
        << ",\"rate_limited_audio_interval\":"
        << snapshot.drops.rate_limited_audio_interval
        << ",\"rate_limited_audio_total\":"
        << snapshot.drops.rate_limited_audio_total << '}';

    out << ",\"ingress\":[";
    for (size_t i = 0; i < snapshot.ingress.size(); ++i) {
        const auto& metric = snapshot.ingress[i];
        if (i > 0) {
            out << ',';
        }
        out << "{\"sender_id\":" << metric.sender_id << ",\"endpoint\":";
        append_json_string(out, metric.endpoint);
        out << ",\"last_frame_count\":" << metric.last_frame_count << ",\"audio\":";
        append_counter_set(out, metric.audio, "received_interval", "received_total");
        out << '}';
    }
    out << ']';

    out << ",\"forwards\":[";
    for (size_t i = 0; i < snapshot.forwards.size(); ++i) {
        const auto& metric = snapshot.forwards[i];
        if (i > 0) {
            out << ',';
        }
        out << "{\"sender_id\":" << metric.sender_id
            << ",\"target_id\":" << metric.target_id << ",\"audio\":";
        append_counter_set(out, metric.audio, "forwarded_interval", "forwarded_total");
        out << '}';
    }
    out << ']';

    out << ",\"pings\":[";
    for (size_t i = 0; i < snapshot.pings.size(); ++i) {
        const auto& metric = snapshot.pings[i];
        if (i > 0) {
            out << ',';
        }
        out << "{\"client_id\":" << metric.client_id << ",\"endpoint\":";
        append_json_string(out, metric.endpoint);
        out << ",\"reply_queued_interval\":" << metric.reply_queued_interval
            << ",\"reply_queued_total\":" << metric.reply_queued_total
            << ",\"ping\":";
        append_counter_set(out, metric.ping, "received_interval", "received_total");
        out << '}';
    }
    out << "]}";
    out << '\n';
    return out.str();
}

class JsonlExporter {
public:
    JsonlExporter() = default;
    explicit JsonlExporter(std::filesystem::path path) : path_(std::move(path)) {}

    bool enabled() const {
        return !path_.empty();
    }

    const std::filesystem::path& path() const {
        return path_;
    }

    bool write(const Snapshot& snapshot, std::string* error = nullptr) const {
        if (!enabled()) {
            return true;
        }

        try {
            const auto parent = path_.parent_path();
            if (!parent.empty()) {
                std::filesystem::create_directories(parent);
            }

            std::ofstream out(path_, std::ios::app | std::ios::binary);
            if (!out) {
                if (error != nullptr) {
                    *error = "open failed";
                }
                return false;
            }
            out << to_json_line(snapshot);
            out.flush();
            if (!out) {
                if (error != nullptr) {
                    *error = "write failed";
                }
                return false;
            }
            return true;
        } catch (const std::exception& e) {
            if (error != nullptr) {
                *error = e.what();
            }
            return false;
        }
    }

private:
    std::filesystem::path path_;
};

}  // namespace server_metrics
