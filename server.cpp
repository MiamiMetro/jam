#include <array>
#include <asio.hpp>
#include <cmath>
#include <concurrentqueue.h>
#include <iostream>
#include <opus.h>
#include <unordered_map>

#include "opus_decoder.hpp"
#include "opus_encoder.hpp"
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
        // Server encoder: sends stereo to clients (2 ch)
        // Complexity 5 balances quality vs performance (saves ~40% CPU vs complexity 8)
        std::cout << "Creating server encoder: 2ch (stereo), 48kHz, complexity=5\n";
        _encoder.create(48000, 2, OPUS_APPLICATION_AUDIO, 256000, 5);
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
        opus_decoder_wrapper decoder;  // Per-client decoder (maintains state)

        client_info() {
            // Each client sends mono audio at 48kHz
            decoder.create(48000, 1);
        }

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
        static constexpr float SOFT_LIMIT_THRESHOLD = 0.95f; // Start compressing above 0.95
        static constexpr float SOFT_LIMIT_KNEE = 0.05f;      // Smooth knee width

        // Reusable buffers (avoid allocations every 2.5ms!)
        static std::vector<float> decoded_mono(FRAME_SIZE);                     // Temp for one client's decoded audio
        static std::vector<float> mixed_mono(FRAME_SIZE, 0.0f);                 // Accumulated mix
        static std::vector<float> mixed_stereo(FRAME_SIZE * STEREO_CHANNELS);   // Final stereo output
        static std::vector<unsigned char> encoded_packet;                        // Opus-encoded result
        static std::vector<unsigned char> client_packet;                         // Temp for dequeued packet
        
        // Diagnostics
        static int callback_count = 0;
        static int total_packets_sent = 0;
        if (++callback_count % 400 == 0) {  // Every second (400 × 2.5ms)
            // Check queue depths
            std::cout << "Server: " << callback_count << " callbacks, " << _clients.size() 
                      << " clients, " << total_packets_sent << " packets sent";
            for (const auto& [ep, client] : _clients) {
                std::cout << " | Q:" << client.audio_queue.size_approx();
            }
            std::cout << "\n";
        }

        // For each client, we need to send a mix of all OTHER clients
        for (auto &[target_endpoint, target_client] : _clients) {
            // Reset mix accumulator
            std::fill(mixed_mono.begin(), mixed_mono.end(), 0.0f);
            int sources_mixed = 0;

            // First pass: Decode all available packets and collect them
            std::vector<std::vector<float>> decoded_sources;
            decoded_sources.reserve(_clients.size() - 1);

            // Decode and collect all clients EXCEPT the target
            for (auto &[source_endpoint, source_client] : _clients) {
                if (source_endpoint == target_endpoint)
                    continue; // Don't send client their own audio back

                // Check queue depth
                size_t queue_depth = source_client.audio_queue.size_approx();
                
                if (queue_depth >= 1 && source_client.audio_queue.try_dequeue(client_packet)) {
                    // Decode Opus mono → PCM float using this client's decoder
                    decoded_mono.clear();
                    bool decode_ok = source_client.decoder.decode(client_packet.data(), client_packet.size(), 
                                                                   FRAME_SIZE, decoded_mono);
                    
                    if (decode_ok && decoded_mono.size() == FRAME_SIZE) {
                        decoded_sources.push_back(decoded_mono);
                        sources_mixed++;
                    } else if (decode_ok) {
                        // Decoded size mismatch - log warning
                        static int mismatch_count = 0;
                        if (++mismatch_count % 100 == 0) {
                            std::cerr << "Server: Decoded " << decoded_mono.size() 
                                     << " samples, expected " << FRAME_SIZE << "\n";
                        }
                    }
                }
                // else: queue_depth == 0 → Client is silent, don't mix anything
            }

            // Second pass: Mix with proper gain based on ACTUAL sources
            if (sources_mixed > 0) {
                // Calculate gain based on actual number of sources (not total clients)
                float mix_gain = 1.0f / std::sqrt(static_cast<float>(sources_mixed));
                
                // Diagnostic: Log mixing stats periodically
                static int mix_count = 0;
                static int total_sources_mixed = 0;
                static int mix_with_2_sources = 0;
                static int mix_with_1_source = 0;
                static int empty_mixes = 0;
                total_sources_mixed += sources_mixed;
                mix_count++;
                if (sources_mixed == 2) mix_with_2_sources++;
                if (sources_mixed == 1) mix_with_1_source++;
                if (mix_count % 400 == 0) {
                    std::cout << "Mix stats: 2src=" << mix_with_2_sources 
                              << " (1src=" << mix_with_1_source << ", 0src=" << empty_mixes 
                              << "), gain=" << mix_gain << "\n";
                }
                
                // Mix all sources with gain
                for (const auto& source : decoded_sources) {
                    for (int i = 0; i < FRAME_SIZE; ++i) {
                        mixed_mono[i] += source[i] * mix_gain;
                    }
                }
            } else {
                static int empty_count = 0;
                empty_count++;
            }

            // If we have audio to send (at least one source mixed)
            if (sources_mixed > 0) {
                // Convert mono → stereo and apply final limiting
                for (int i = 0; i < FRAME_SIZE; ++i) {
                    float sample = mixed_mono[i];
                    
                    // Check for NaN or Inf (corrupted audio)
                    if (!std::isfinite(sample)) {
                        sample = 0.0f;
                        static int nan_count = 0;
                        if (++nan_count % 100 == 0) {
                            std::cerr << "Warning: NaN/Inf detected in mix, zeroing\n";
                        }
                    }
                    
                    float abs_sample = std::fabs(sample);
                    
                    // Soft limiting only if needed
                    if (abs_sample > SOFT_LIMIT_THRESHOLD) {
                        float excess = abs_sample - SOFT_LIMIT_THRESHOLD;
                        float compressed = SOFT_LIMIT_THRESHOLD + std::tanh(excess / SOFT_LIMIT_KNEE) * SOFT_LIMIT_KNEE;
                        sample = std::copysign(compressed, sample);
                    }
                    
                    // Hard clamp as final safety
                    sample = std::clamp(sample, -1.0f, 1.0f);
                    
                    // Duplicate to both stereo channels
                    mixed_stereo[i * STEREO_CHANNELS + 0] = sample; // Left
                    mixed_stereo[i * STEREO_CHANNELS + 1] = sample; // Right
                }

                // Encode mixed stereo PCM → Opus (using shared encoder)
                bool encode_ok = _encoder.encode(mixed_stereo.data(), FRAME_SIZE, encoded_packet);

                if (encode_ok && !encoded_packet.empty()) {
                    // Verify packet size is reasonable
                    if (encoded_packet.size() > sizeof(AudioHdr::buf)) {
                        std::cerr << "Warning: Encoded packet too large (" << encoded_packet.size() 
                                 << " bytes), truncating\n";
                        encoded_packet.resize(sizeof(AudioHdr::buf));
                    }
                    
                    // Build audio packet header
                    AudioHdr ahdr{};
                    ahdr.magic = AUDIO_MAGIC;
                    ahdr.encoded_bytes = static_cast<uint16_t>(encoded_packet.size());
                    std::memcpy(ahdr.buf, encoded_packet.data(), encoded_packet.size());
                    
                    size_t packet_size = sizeof(MsgHdr) + sizeof(uint16_t) + ahdr.encoded_bytes;
                    
                    // Send to this client
                    send(&ahdr, packet_size, target_endpoint);
                    total_packets_sent++;
                } else {
                    static int encode_fail_count = 0;
                    if (++encode_fail_count % 100 == 0) {
                        std::cerr << "Warning: Encoding failed " << encode_fail_count << " times\n";
                    }
                }
            }
            // If sources_mixed == 0, send nothing (silence) - client will handle it
        }
    }

    std::array<char, 1024> _recv_buf;
    std::array<char, 1024> _audio_tx_buf;
    udp::endpoint _remote_endpoint;

    opus_encoder_wrapper _encoder;  // Shared encoder for all clients
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
