#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include <asio.hpp>
#include <asio/buffer.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <asio/steady_timer.hpp>

using asio::ip::udp;
using namespace std::chrono_literals;

namespace {

constexpr size_t MAX_PACKET_BYTES = 2048;

struct Config {
    std::string listen_host = "127.0.0.1";
    uint16_t listen_port = 9998;
    std::string server_host = "127.0.0.1";
    uint16_t server_port = 9999;
    int delay_ms = 0;
    int jitter_ms = 0;
    int loss_percent = 0;
    uint64_t burst_every = 0;
    uint64_t burst_count = 0;
    uint64_t reorder_every = 0;
    int reorder_delay_ms = 0;
    bool help = false;
};

std::string endpoint_key(const udp::endpoint& endpoint) {
    return endpoint.address().to_string() + ":" + std::to_string(endpoint.port());
}

int parse_int_arg(char** argv, int& index) {
    return std::stoi(argv[++index]);
}

Config parse_args(int argc, char** argv) {
    Config config;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            config.help = true;
        } else if (arg == "--listen-host" && i + 1 < argc) {
            config.listen_host = argv[++i];
        } else if (arg == "--listen-port" && i + 1 < argc) {
            config.listen_port = static_cast<uint16_t>(parse_int_arg(argv, i));
        } else if (arg == "--server" && i + 1 < argc) {
            config.server_host = argv[++i];
        } else if (arg == "--server-port" && i + 1 < argc) {
            config.server_port = static_cast<uint16_t>(parse_int_arg(argv, i));
        } else if (arg == "--delay-ms" && i + 1 < argc) {
            config.delay_ms = parse_int_arg(argv, i);
        } else if (arg == "--jitter-ms" && i + 1 < argc) {
            config.jitter_ms = parse_int_arg(argv, i);
        } else if (arg == "--loss-percent" && i + 1 < argc) {
            config.loss_percent = parse_int_arg(argv, i);
        } else if (arg == "--burst-every" && i + 1 < argc) {
            config.burst_every = static_cast<uint64_t>(parse_int_arg(argv, i));
        } else if (arg == "--burst-count" && i + 1 < argc) {
            config.burst_count = static_cast<uint64_t>(parse_int_arg(argv, i));
        } else if (arg == "--reorder-every" && i + 1 < argc) {
            config.reorder_every = static_cast<uint64_t>(parse_int_arg(argv, i));
        } else if (arg == "--reorder-delay-ms" && i + 1 < argc) {
            config.reorder_delay_ms = parse_int_arg(argv, i);
        } else {
            throw std::runtime_error("unknown or incomplete argument: " + arg);
        }
    }
    config.delay_ms = std::max(0, config.delay_ms);
    config.jitter_ms = std::max(0, config.jitter_ms);
    config.loss_percent = std::clamp(config.loss_percent, 0, 100);
    config.reorder_delay_ms = std::max(0, config.reorder_delay_ms);
    return config;
}

void print_usage() {
    std::cout
        << "Usage: udp_impair_proxy [options]\n"
        << "\n"
        << "Options:\n"
        << "  --listen-host <host>       Local bind host, default 127.0.0.1\n"
        << "  --listen-port <port>       Local bind UDP port, default 9998\n"
        << "  --server <host>            Real SFU host, default 127.0.0.1\n"
        << "  --server-port <port>       Real SFU UDP port, default 9999\n"
        << "  --delay-ms <ms>            Fixed one-way delay added both directions\n"
        << "  --jitter-ms <ms>           Deterministic additional one-way jitter range\n"
        << "  --loss-percent <0-100>     Deterministic packet drop percentage\n"
        << "  --burst-every <packets>    Start a drop burst every N packets\n"
        << "  --burst-count <packets>    Packets dropped at each burst start\n"
        << "  --reorder-every <packets>  Delay every Nth packet to force reordering\n"
        << "  --reorder-delay-ms <ms>    Extra delay for reordered packets\n";
}

class Proxy;

struct Session {
    Session(asio::io_context& io_context, Proxy& owner, udp::endpoint client)
        : owner(owner), client_endpoint(std::move(client)),
          upstream_socket(io_context, udp::endpoint(udp::v4(), 0)) {}

    Proxy& owner;
    udp::endpoint client_endpoint;
    udp::socket upstream_socket;
    udp::endpoint server_sender_endpoint;
    std::array<uint8_t, MAX_PACKET_BYTES> recv_buffer{};
};

class Proxy {
public:
    Proxy(asio::io_context& io_context, Config config)
        : io_context_(io_context), config_(std::move(config)),
          downstream_socket_(io_context),
          server_endpoint_(*udp::resolver(io_context)
                                .resolve(udp::v4(), config_.server_host,
                                         std::to_string(config_.server_port))
                                .begin()) {
        udp::endpoint listen_endpoint(
            asio::ip::make_address(config_.listen_host), config_.listen_port);
        downstream_socket_.open(udp::v4());
        downstream_socket_.bind(listen_endpoint);
    }

    void run() {
        std::cout << "UDP impairment proxy listening on " << config_.listen_host << ":"
                  << config_.listen_port << " -> " << server_endpoint_.address().to_string()
                  << ":" << server_endpoint_.port() << "\n";
        std::cout << "delay_ms=" << config_.delay_ms
                  << " jitter_ms=" << config_.jitter_ms
                  << " loss_percent=" << config_.loss_percent
                  << " burst_every=" << config_.burst_every
                  << " burst_count=" << config_.burst_count
                  << " reorder_every=" << config_.reorder_every
                  << " reorder_delay_ms=" << config_.reorder_delay_ms << "\n";
        receive_from_client();
    }

    void receive_from_server(const std::shared_ptr<Session>& session) {
        session->upstream_socket.async_receive_from(
            asio::buffer(session->recv_buffer), session->server_sender_endpoint,
            [this, session](std::error_code error, std::size_t bytes) {
                if (!error && bytes > 0) {
                    schedule_send_to_client(session, session->recv_buffer.data(), bytes);
                }
                receive_from_server(session);
            });
    }

private:
    void receive_from_client() {
        downstream_socket_.async_receive_from(
            asio::buffer(client_recv_buffer_), client_sender_endpoint_,
            [this](std::error_code error, std::size_t bytes) {
                if (!error && bytes > 0) {
                    auto session = session_for(client_sender_endpoint_);
                    schedule_send_to_server(session, client_recv_buffer_.data(), bytes);
                }
                receive_from_client();
            });
    }

    std::shared_ptr<Session> session_for(const udp::endpoint& client_endpoint) {
        const std::string key = endpoint_key(client_endpoint);
        auto existing = sessions_.find(key);
        if (existing != sessions_.end()) {
            return existing->second;
        }

        auto session = std::make_shared<Session>(io_context_, *this, client_endpoint);
        sessions_.emplace(key, session);
        std::cout << "new client session " << key << " upstream_port="
                  << session->upstream_socket.local_endpoint().port() << "\n";
        receive_from_server(session);
        return session;
    }

    bool should_drop(uint64_t counter) const {
        if (config_.loss_percent > 0 && (counter % 100) < static_cast<uint64_t>(config_.loss_percent)) {
            return true;
        }
        if (config_.burst_every > 0 && config_.burst_count > 0) {
            const uint64_t phase = (counter - 1) % config_.burst_every;
            if (phase < config_.burst_count) {
                return true;
            }
        }
        return false;
    }

    int delay_for(uint64_t counter) const {
        int delay = config_.delay_ms;
        if (config_.jitter_ms > 0) {
            delay += static_cast<int>((counter * 1103515245ULL + 12345ULL) %
                                      static_cast<uint64_t>(config_.jitter_ms + 1));
        }
        if (config_.reorder_every > 0 && counter % config_.reorder_every == 0) {
            delay += config_.reorder_delay_ms;
        }
        return delay;
    }

    void schedule_send_to_server(const std::shared_ptr<Session>& session, const uint8_t* data,
                                 std::size_t bytes) {
        const uint64_t counter = ++client_to_server_count_;
        if (should_drop(counter)) {
            return;
        }
        auto packet = std::make_shared<std::vector<uint8_t>>(data, data + bytes);
        schedule(delay_for(counter), [this, session, packet]() {
            session->upstream_socket.async_send_to(
                asio::buffer(*packet), server_endpoint_,
                [packet](std::error_code, std::size_t) {});
        });
    }

    void schedule_send_to_client(const std::shared_ptr<Session>& session, const uint8_t* data,
                                 std::size_t bytes) {
        const uint64_t counter = ++server_to_client_count_;
        if (should_drop(counter)) {
            return;
        }
        auto packet = std::make_shared<std::vector<uint8_t>>(data, data + bytes);
        schedule(delay_for(counter), [this, session, packet]() {
            downstream_socket_.async_send_to(
                asio::buffer(*packet), session->client_endpoint,
                [packet](std::error_code, std::size_t) {});
        });
    }

    template <typename Func>
    void schedule(int delay_ms, Func&& func) {
        if (delay_ms <= 0) {
            func();
            return;
        }
        auto timer = std::make_shared<asio::steady_timer>(io_context_, std::chrono::milliseconds(delay_ms));
        timer->async_wait([timer, fn = std::forward<Func>(func)](std::error_code error) mutable {
            if (!error) {
                fn();
            }
        });
    }

    asio::io_context& io_context_;
    Config config_;
    udp::socket downstream_socket_;
    udp::endpoint server_endpoint_;
    udp::endpoint client_sender_endpoint_;
    std::array<uint8_t, MAX_PACKET_BYTES> client_recv_buffer_{};
    std::unordered_map<std::string, std::shared_ptr<Session>> sessions_;
    uint64_t client_to_server_count_ = 0;
    uint64_t server_to_client_count_ = 0;
};

}  // namespace

int main(int argc, char** argv) {
    try {
        Config config = parse_args(argc, argv);
        if (config.help) {
            print_usage();
            return 0;
        }

        asio::io_context io_context;
        Proxy proxy(io_context, std::move(config));
        proxy.run();
        io_context.run();
    } catch (const std::exception& e) {
        std::cerr << "udp_impair_proxy error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
