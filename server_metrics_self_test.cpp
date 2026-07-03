#include "server_metrics.h"

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
    server_metrics::Snapshot snapshot;
    snapshot.schema                 = "jam_server_metrics_v1";
    snapshot.server_id              = "server\"ops";
    snapshot.timestamp_unix_ms      = 123456789;
    snapshot.uptime_ms              = 2500;
    snapshot.connected_clients      = 2;
    snapshot.unknown_endpoint_count = 1;
    snapshot.token_nonce_count      = 1;
    snapshot.drops.unknown_audio_interval = 3;
    snapshot.drops.unknown_audio_total    = 5;
    snapshot.drops.invalid_audio_interval = 7;
    snapshot.drops.invalid_audio_total    = 11;
    snapshot.drops.rate_limited_audio_interval = 13;
    snapshot.drops.rate_limited_audio_total    = 17;
    snapshot.ingress.push_back(
        {1, "127.0.0.1:40000", {10, 20, 2, 4, 1, 3, 1, 0, 4}, 120});
    snapshot.forwards.push_back({1, 2, {9, 19, 1, 2, 0, 1, 0, 0, 3}});
    snapshot.pings.push_back(
        {2, "127.0.0.1:40001", 4, 8, {6, 12, 1, 1, 0, 1, 0, 0, 2}});

    const auto json = server_metrics::to_json_line(snapshot);
    require(json.ends_with('\n'), "metrics JSONL line must end in newline");
    require(json.find("\"schema\":\"jam_server_metrics_v1\"") != std::string::npos,
            "schema field missing");
    require(json.find("\"server_id\":\"server\\\"ops\"") != std::string::npos,
            "server_id was not escaped");
    require(json.find("\"connected_clients\":2") != std::string::npos,
            "connected client count missing");
    require(json.find("\"unknown_audio_interval\":3") != std::string::npos,
            "drop counters missing");
    require(json.find("\"ingress\"") != std::string::npos, "ingress array missing");
    require(json.find("\"forwards\"") != std::string::npos, "forward array missing");
    require(json.find("\"pings\"") != std::string::npos, "ping array missing");

    const auto dir = std::filesystem::temp_directory_path() / "jam_metrics_self_test";
    std::filesystem::remove_all(dir);
    server_metrics::JsonlExporter exporter(dir / "metrics.jsonl");
    std::string error;
    require(exporter.write(snapshot, &error), "first metrics write failed");
    require(exporter.write(snapshot, &error), "second metrics write failed");

    {
        std::ifstream in(dir / "metrics.jsonl", std::ios::binary);
        std::string body((std::istreambuf_iterator<char>(in)),
                         std::istreambuf_iterator<char>());
        require(body.find("\"server_id\":\"server\\\"ops\"") != std::string::npos,
                "metrics file did not contain snapshot");
        require(body.find('\n') != body.rfind('\n'),
                "metrics file should contain two JSONL rows");
    }
    std::filesystem::remove_all(dir);
    std::cout << "server metrics self-test passed\n";
}
