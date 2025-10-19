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

                _clients[_remote_endpoint].push_audio_packet(std::move(audio_data_vec));
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
        moodycamel::ConcurrentQueue<std::vector<unsigned char>> audio_queue;

        void push_audio_packet(const std::vector<unsigned char> &packet) {
            if (audio_queue.size_approx() >= 16) {
                std::vector<unsigned char> discarded;
                audio_queue.try_dequeue(discarded); // discard oldest
            }
            audio_queue.enqueue(packet);
        }
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
        if (_clients.empty())
            return;

        static constexpr int FRAME_SIZE = 120;              // 2.5ms at 48kHz
        static constexpr int STEREO_CHANNELS = 2;
        static constexpr int MONO_CHANNELS = 1;
        static constexpr float SOFT_LIMIT_THRESHOLD = 0.9f; // Start compressing above 0.9
        static constexpr float SOFT_LIMIT_KNEE = 0.1f;      // Smooth knee width

        // Reusable buffers (avoid allocations every 2.5ms!)
        static std::vector<float> decoded_mono(FRAME_SIZE);                     // Temp for one client's decoded audio
        static std::vector<float> mixed_mono(FRAME_SIZE, 0.0f);                 // Accumulated mix
        static std::vector<float> mixed_stereo(FRAME_SIZE * STEREO_CHANNELS);   // Final stereo output
        static std::vector<unsigned char> encoded_packet;                        // Opus-encoded result
        static std::vector<unsigned char> client_packet;                         // Temp for dequeued packet

        // For each client, we need to send a mix of all OTHER clients
        for (auto &[target_endpoint, target_client] : _clients) {
            // Reset mix accumulator
            std::fill(mixed_mono.begin(), mixed_mono.end(), 0.0f);
            int sources_mixed = 0;

            // Decode and mix all clients EXCEPT the target
            for (auto &[source_endpoint, source_client] : _clients) {
                if (source_endpoint == target_endpoint)
                    continue; // Don't send client their own audio back

                // Try to get one packet from this client's queue
                if (source_client.audio_queue.try_dequeue(client_packet)) {
                    // Decode Opus mono → PCM float
                    _audio_codec.decode_opus(client_packet.data(), client_packet.size(), 
                                            FRAME_SIZE, MONO_CHANNELS, decoded_mono);
                    
                    if (decoded_mono.size() == FRAME_SIZE) {
                        // Mix: add this client's samples to the accumulator
                        for (int i = 0; i < FRAME_SIZE; ++i) {
                            mixed_mono[i] += decoded_mono[i];
                        }
                        sources_mixed++;
                    }
                }
            }

            // If we have audio to send (at least one source mixed)
            if (sources_mixed > 0) {
                // Apply soft limiting to prevent clipping
                // Soft limiter: gradually compress peaks above threshold
                for (int i = 0; i < FRAME_SIZE; ++i) {
                    float sample = mixed_mono[i];
                    float abs_sample = std::fabs(sample);
                    
                    if (abs_sample > SOFT_LIMIT_THRESHOLD) {
                        // Smooth compression above threshold
                        float excess = abs_sample - SOFT_LIMIT_THRESHOLD;
                        float compressed = SOFT_LIMIT_THRESHOLD + std::tanh(excess / SOFT_LIMIT_KNEE) * SOFT_LIMIT_KNEE;
                        sample = std::copysign(compressed, sample);
                    }
                    
                    // Hard clamp as safety (should rarely trigger with soft limiter)
                    sample = std::clamp(sample, -1.0f, 1.0f);
                    
                    // Convert mono → stereo (duplicate to both channels)
                    mixed_stereo[i * STEREO_CHANNELS + 0] = sample; // Left
                    mixed_stereo[i * STEREO_CHANNELS + 1] = sample; // Right
                }

                // Encode mixed stereo PCM → Opus
                _audio_codec.encode_opus(mixed_stereo.data(), FRAME_SIZE, encoded_packet);

                if (!encoded_packet.empty()) {
                    // Build audio packet header
                    AudioHdr ahdr{};
                    ahdr.magic = AUDIO_MAGIC;
                    ahdr.encoded_bytes = static_cast<uint16_t>(encoded_packet.size());
                    std::memcpy(ahdr.buf, encoded_packet.data(), std::min(encoded_packet.size(), sizeof(ahdr.buf)));
                    
                    size_t packet_size = sizeof(MsgHdr) + sizeof(uint16_t) + ahdr.encoded_bytes;
                    
                    // Send to this client
                    send(&ahdr, packet_size, target_endpoint);
                }
            }
            // If sources_mixed == 0, send nothing (silence) - client will handle it
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
