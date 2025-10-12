#include <array>
#include <asio.hpp>
#include <cmath>
#include <concurrentqueue.h>
#include <iostream>
#include <opus.h>
#include <unordered_map>

#include "audio_codec.hpp"
#include "periodic_timer.hpp"
#include "protocol.hpp"

#define M_PI 3.14159265358979323846   // pi
#define M_PI_2 1.57079632679489661923 // pi/2

using asio::ip::udp;
using namespace std::chrono_literals;

class server {
  public:
    server(asio::io_context &io, short port)
        : _socket(io, udp::endpoint(udp::v4(), port)),
          _alive_check_timer(io, 5s, [this]() { _alive_check_timer_callback(); }),
          _broadcast_timer(io, 2500us, [this]() { _broadcast_timer_callback(); }) {

        do_receive();
        // Decoder receives mono from clients (1 ch), Encoder sends stereo to clients (2 ch)
        // Complexity 5 balances quality vs performance (saves ~40% CPU vs complexity 8)
        std::cout << "Creating server codec: decoder=1ch (mono), encoder=2ch (stereo), complexity=5\n";
        _audio_codec.create_codec(48000, 1, 2, OPUS_APPLICATION_AUDIO, 256000, 5);
    }

    ~server() { _socket.close(); }

    // Set pan position for a client: -1.0 = full left, 0.0 = center, +1.0 = full right
    void set_client_pan(const udp::endpoint& ep, float pan) {
        auto it = _clients.find(ep);
        if (it == _clients.end()) {
            return; // Client not found
        }
        it->second.pan = std::clamp(pan, -1.0f, 1.0f);
        std::cout << "Client " << ep.address().to_string() << ":" << ep.port() 
                  << " pan=" << it->second.pan << "\n";
    }

    // Set gain/volume for a client: 0.0 = mute, 1.0 = unity, >1.0 = boost
    void set_client_gain(const udp::endpoint& ep, float gain) {
        auto it = _clients.find(ep);
        if (it == _clients.end()) {
            return; // Client not found
        }
        it->second.gain = std::max(0.0f, gain); // Prevent negative gain
        std::cout << "Client " << ep.address().to_string() << ":" << ep.port() 
                  << " gain=" << it->second.gain << "\n";
    }

    void do_receive() {
        _socket.async_receive_from(asio::buffer(_recv_buf), _remote_endpoint,
                                   [this](std::error_code ec, std::size_t bytes) { on_receive(ec, bytes); });
    }

    void on_receive(std::error_code ec, std::size_t bytes) {
        if (ec) {
            std::cerr << "receive error: " << ec.message() << "\n";
            _clients.erase(_remote_endpoint);
            std::cout << "Client " << _remote_endpoint.address().to_string() << ":" << _remote_endpoint.port()
                      << " removed due to receive error\n";
            do_receive(); // keep listening
            return;
        }

        // std::cout << "Got " << bytes << " bytes from " << remote->address().to_string() << ":" <<
        // remote->port()
        //           << " -> " << std::string(buf->data(), bytes) << "\n";

        if (bytes >= sizeof(MsgHdr)) {
            MsgHdr hdr{};
            std::memcpy(&hdr, _recv_buf.data(), sizeof(MsgHdr));

            if (hdr.magic == PING_MAGIC && bytes >= sizeof(SyncHdr)) {
                if (_clients.find(_remote_endpoint) == _clients.end()) {
                    do_receive();
                    return;
                }
                SyncHdr shdr{};
                std::memcpy(&shdr, _recv_buf.data(), sizeof(SyncHdr));
                auto now = std::chrono::steady_clock::now();
                auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
                shdr.t2_server_recv = ns;
                shdr.t3_server_send = ns;
                std::memcpy(_recv_buf.data(), &shdr, sizeof(SyncHdr));

                send(_recv_buf.data(), sizeof(SyncHdr), _remote_endpoint);
            } else if (hdr.magic == CTRL_MAGIC && bytes >= sizeof(CtrlHdr)) {
                std::cout << "CTRL msg from " << _remote_endpoint.address().to_string() << ":"
                          << _remote_endpoint.port() << "\n";

                CtrlHdr chdr{};
                std::memcpy(&chdr, _recv_buf.data(), sizeof(CtrlHdr));

                auto now = std::chrono::steady_clock::now();

                switch (chdr.type) {
                case CtrlHdr::Cmd::JOIN:
                    std::cout << "  JOIN\n";
                    _clients[_remote_endpoint].last_alive = now;
                    break;
                case CtrlHdr::Cmd::LEAVE:
                    std::cout << "  LEAVE\n";
                    _clients.erase(_remote_endpoint);
                    break;
                case CtrlHdr::Cmd::ALIVE:
                    std::cout << "  ALIVE\n";
                    _clients[_remote_endpoint].last_alive = now;
                    break;
                default:
                    std::cout << "  Unknown CTRL cmd: " << static_cast<int>(chdr.type) << "\n";
                    break;
                }
            } else if (hdr.magic == ECHO_MAGIC && bytes >= sizeof(EchoHdr)) {
                if (_clients.find(_remote_endpoint) == _clients.end()) {
                    do_receive();
                    return;
                }
                // Echo back the received message
                send(_recv_buf.data(), bytes, _remote_endpoint);
            } else if (hdr.magic == AUDIO_MAGIC && bytes >= sizeof(MsgHdr) + sizeof(uint16_t)) {
                if (_clients.find(_remote_endpoint) == _clients.end()) {
                    do_receive();
                    return;
                }
                // Read only the header fields we need
                uint16_t encoded_bytes;
                std::memcpy(&encoded_bytes, _recv_buf.data() + sizeof(MsgHdr), sizeof(uint16_t));

                // Verify we received all the data
                size_t expected_size = sizeof(MsgHdr) + sizeof(uint16_t) + encoded_bytes;
                if (bytes < expected_size) {
                    std::cerr << "Incomplete audio packet: got " << bytes << ", expected " << expected_size << "\n";
                    do_receive();
                    return;
                }

                // Extract audio data (starts after magic + encoded_bytes field)
                const unsigned char *audio_data =
                    reinterpret_cast<const unsigned char *>(_recv_buf.data() + sizeof(MsgHdr) + sizeof(uint16_t));

                std::vector<unsigned char> audio_data_vec(audio_data, audio_data + encoded_bytes);

                _clients[_remote_endpoint]._audio_queue.enqueue(std::move(audio_data_vec));
            }
        }

        do_receive(); // start next receive immediately
    }

    void send(void *data, std::size_t len, const udp::endpoint &target) {
        _socket.async_send_to(asio::buffer(data, len), target, [](std::error_code ec, std::size_t) {
            if (ec)
                std::cerr << "send error: " << ec.message() << "\n";
        });
    }

  private:
    udp::socket _socket;

    struct endpoint_hash {
        size_t operator()(const udp::endpoint &ep) const {
            // Avoid string allocations - hash IP bytes + port directly
            size_t h1 = 0;
            if (ep.address().is_v4()) {
                h1 = std::hash<uint32_t>{}(ep.address().to_v4().to_uint());
            } else {
                auto bytes = ep.address().to_v6().to_bytes();
                h1 = std::hash<std::string_view>{}(
                    std::string_view(reinterpret_cast<const char *>(bytes.data()), bytes.size()));
            }
            size_t h2 = std::hash<unsigned short>{}(ep.port());
            return h1 ^ (h2 << 1); // Combine hashes
        }
    };

    struct client_info {
        std::chrono::steady_clock::time_point last_alive;
        moodycamel::ConcurrentQueue<std::vector<unsigned char>> _audio_queue;
        
        // Per-client audio state for proper mixing
        std::vector<float> stereo_contribution; // This client's stereo output (after panning)
        float pan = 0.0f;  // Pan position: -1.0 = full left, 0.0 = center, +1.0 = full right
        float gain = 1.0f; // Client gain/volume
        
        client_info() : stereo_contribution(240, 0.0f) {} // Pre-allocate 120 frames × 2 channels
    };

    std::unordered_map<udp::endpoint, client_info, endpoint_hash> _clients;

    periodic_timer _alive_check_timer;
    periodic_timer _broadcast_timer;

    void _alive_check_timer_callback() {
        auto now = std::chrono::steady_clock::now();
        for (auto it = _clients.begin(); it != _clients.end();) {
            if (now - it->second.last_alive > 15s) {
                std::cout << "Client " << it->first.address().to_string() << ":" << it->first.port() << " timed out\n";
                it = _clients.erase(it);
            } else {
                ++it;
            }
        }
    }

    void _broadcast_timer_callback() {
        auto t_start = std::chrono::high_resolution_clock::now();

        if (_clients.empty())
            return; // No clients to process

        // Reusable buffers - allocated ONCE, reused forever
        static std::vector<unsigned char> compressed_audio;
        static std::vector<float> mono_decoded(120);
        static std::vector<float> global_mix(240, 0.0f); // Global stereo mix of ALL clients
        static std::vector<float> custom_mix(240, 0.0f); // Custom mix per client
        static std::vector<unsigned char> encoded_output;

        const size_t frame_size = 120; // TODO: Get from _audio_codec.frame_size() eventually
        const float M_PI_2f = static_cast<float>(M_PI_2);

        // Step 1: Decode all clients and build their stereo contributions with panning
        std::fill(global_mix.begin(), global_mix.end(), 0.0f);
        int active_sources = 0;

        for (auto &[ep, info] : _clients) {
            if (info._audio_queue.try_dequeue(compressed_audio)) {
                // Decode mono audio from this client
                _audio_codec.decode_opus(compressed_audio.data(), compressed_audio.size(), frame_size, 1,
                                         mono_decoded);

                // Apply panning to create stereo contribution
                // Equal-power panning: maintains perceived loudness
                float pan_angle = (info.pan + 1.0f) * 0.5f * M_PI_2f; // Map -1..1 to 0..π/2
                float pan_left = std::cos(pan_angle) * info.gain;
                float pan_right = std::sin(pan_angle) * info.gain;

                // Build this client's stereo contribution and add to global mix
                for (size_t i = 0; i < frame_size; ++i) {
                    float mono_sample = mono_decoded[i];
                    info.stereo_contribution[i * 2 + 0] = mono_sample * pan_left;  // Left
                    info.stereo_contribution[i * 2 + 1] = mono_sample * pan_right; // Right

                    global_mix[i * 2 + 0] += info.stereo_contribution[i * 2 + 0];
                    global_mix[i * 2 + 1] += info.stereo_contribution[i * 2 + 1];
                }
                active_sources++;
            } else {
                // Client didn't send audio - fill with silence
                std::fill(info.stereo_contribution.begin(), info.stereo_contribution.end(), 0.0f);
            }
        }

        if (active_sources == 0)
            return; // No audio to process

        // Step 2: For each client, create custom mix by subtracting their own stereo contribution
        for (auto &[target_ep, target_info] : _clients) {
            // Start with global mix
            std::copy(global_mix.begin(), global_mix.end(), custom_mix.begin());

            // Subtract this client's stereo contribution (not raw mono!)
            for (size_t i = 0; i < frame_size * 2; ++i) {
                custom_mix[i] -= target_info.stereo_contribution[i];
            }

            // Check if this client contributed audio
            bool client_was_active = !std::all_of(target_info.stereo_contribution.begin(),
                                                   target_info.stereo_contribution.end(),
                                                   [](float s) { return s == 0.0f; });
            
            int other_sources = active_sources;
            if (client_was_active) {
                other_sources--;
            }

            if (other_sources == 0)
                continue; // No other audio to send

            // Equal-power normalization: 1/sqrt(N) maintains perceived loudness better than 1/N
            if (active_sources > 1) {
                float scale = 1.0f / std::sqrt(static_cast<float>(active_sources));
                for (auto &sample : custom_mix) {
                    sample *= scale;
                }
            }

            // Encode the custom mix
            _audio_codec.encode_opus(custom_mix.data(), frame_size, encoded_output);

            if (encoded_output.empty())
                continue;

            // Send to this specific client
            AudioHdr ahdr{};
            ahdr.magic = AUDIO_MAGIC;
            ahdr.encoded_bytes = static_cast<uint16_t>(encoded_output.size());
            std::memcpy(ahdr.buf, encoded_output.data(), std::min(encoded_output.size(), sizeof(ahdr.buf)));
            size_t packet_size = sizeof(MsgHdr) + sizeof(uint16_t) + ahdr.encoded_bytes;

            send(&ahdr, packet_size, target_ep);
        }

        // Performance monitoring (optional - can comment out for production)
        auto t_end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(t_end - t_start).count();

        static int tick_count = 0;
        static long long total_time = 0;
        static long long max_time = 0;

        total_time += duration;
        max_time = std::max(max_time, duration);
        tick_count++;

        // Report every 400 ticks (1 second at 2.5ms rate)
        if (tick_count >= 400) {
            long long avg_time = total_time / tick_count;
            std::cout << "Broadcast stats [" << active_sources << " active / " << _clients.size()
                      << " total clients]: "
                      << "avg=" << avg_time << "μs, max=" << max_time << "μs, "
                      << "budget=" << (avg_time * 100 / 2500) << "%\n";

            // Reset for next interval
            tick_count = 0;
            total_time = 0;
            max_time = 0;
        }
    }

    std::array<char, 1024> _recv_buf;
    std::array<char, 1024> _audio_tx_buf;
    udp::endpoint _remote_endpoint;

    audio_codec _audio_codec;
};

int main() {
    try {
        asio::io_context io;
        server srv(io, 9999);
        std::cout << "Echo server listening on 127.0.0.1:9999\n";
        std::cout << "Broadcast timer running at 2.5ms intervals (48kHz, 120 frames)\n";

        // Just run the io_context - timers handle everything!
        io.run();
    } catch (std::exception &e) {
        std::cerr << "ERR: " << e.what() << "\n";
    }
}
