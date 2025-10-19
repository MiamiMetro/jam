#include <array>
#include <asio.hpp>
#include <concurrentqueue.h>
#include <iostream>
#include <opus.h>
#include <unordered_map>

#include "opus_decoder.hpp"
#include "opus_encoder.hpp"
#include "periodic_timer.hpp"
#include "protocol.hpp"

using asio::ip::udp;
using namespace std::chrono_literals;

class server {
  public:
    server(asio::io_context &io_context, short port)
        : _socket(io_context, udp::endpoint(udp::v4(), port)),
          _alive_check_timer(io_context, 5s, [this]() { _alive_check_timer_callback(); }),
          _broadcast_timer(io_context, 2500us, [this]() { _broadcast_timer_callback(); }) {

        do_receive();
        // Server encoder: sends stereo to clients (2 ch)
        // Complexity 5 balances quality vs performance (saves ~40% CPU vs complexity 8)
        std::cout << "Creating server encoder: 2ch (stereo), 48kHz, complexity=5\n";
        _encoder.create(48000, 2, OPUS_APPLICATION_AUDIO, 256000, 5);
    }

    ~server() { _socket.close(); }

    void do_receive() {
        _socket.async_receive_from(
            asio::buffer(_recv_buf), _remote_endpoint,
            [this](std::error_code error_code, std::size_t bytes) { on_receive(error_code, bytes); });
    }

    void on_receive(std::error_code error_code, std::size_t bytes) {
        if (error_code) {
            _handle_receive_error(error_code);
            return;
        }

        if (bytes < sizeof(MsgHdr)) {
            do_receive();
            return;
        }

        MsgHdr hdr{};
        std::memcpy(&hdr, _recv_buf.data(), sizeof(MsgHdr));

        if (hdr.magic == PING_MAGIC) {
            _handle_ping_message(bytes);
        } else if (hdr.magic == CTRL_MAGIC) {
            _handle_ctrl_message(bytes);
        } else if (hdr.magic == ECHO_MAGIC) {
            _handle_echo_message(bytes);
        } else if (hdr.magic == AUDIO_MAGIC) {
            _handle_audio_message(bytes);
        }

        do_receive(); // start next receive immediately
    }

    void send(void *data, std::size_t len, const udp::endpoint &target) {
        _socket.async_send_to(asio::buffer(data, len), target, [](std::error_code error_code, std::size_t) {
            if (error_code) {
                std::cerr << "send error: " << error_code.message() << "\n";
            }
        });
    }

  private:
    void _handle_receive_error(std::error_code error_code) {
        std::cerr << "receive error: " << error_code.message() << "\n";
        _clients.erase(_remote_endpoint);
        std::cout << "Client " << _remote_endpoint.address().to_string() << ":" << _remote_endpoint.port()
                  << " removed due to receive error\n";
        do_receive(); // keep listening
    }

    void _handle_ping_message(std::size_t bytes) {
        if (bytes < sizeof(SyncHdr) || _clients.find(_remote_endpoint) == _clients.end()) {
            do_receive();
            return;
        }

        SyncHdr shdr{};
        std::memcpy(&shdr, _recv_buf.data(), sizeof(SyncHdr));
        auto now = std::chrono::steady_clock::now();
        auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        shdr.t2_server_recv = nanoseconds;
        shdr.t3_server_send = nanoseconds;
        std::memcpy(_recv_buf.data(), &shdr, sizeof(SyncHdr));

        send(_recv_buf.data(), sizeof(SyncHdr), _remote_endpoint);
    }

    void _handle_ctrl_message(std::size_t bytes) {
        if (bytes < sizeof(CtrlHdr)) {
            do_receive();
            return;
        }

        std::cout << "CTRL msg from " << _remote_endpoint.address().to_string() << ":" << _remote_endpoint.port()
                  << "\n";

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
    }

    void _handle_echo_message(std::size_t bytes) {
        if (bytes < sizeof(EchoHdr) || _clients.find(_remote_endpoint) == _clients.end()) {
            do_receive();
            return;
        }
        // Echo back the received message
        send(_recv_buf.data(), bytes, _remote_endpoint);
    }

    void _handle_audio_message(std::size_t bytes) {
        if (bytes < sizeof(MsgHdr) + sizeof(uint16_t) || _clients.find(_remote_endpoint) == _clients.end()) {
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

        _clients[_remote_endpoint].push_audio_packet(audio_data_vec);
    }

    udp::socket _socket;

    struct endpoint_hash {
        size_t operator()(const udp::endpoint &endpoint) const {
            // Avoid string allocations - hash IP bytes + port directly
            size_t address_hash = 0;
            if (endpoint.address().is_v4()) {
                address_hash = std::hash<uint32_t>{}(endpoint.address().to_v4().to_uint());
            } else {
                auto bytes = endpoint.address().to_v6().to_bytes();
                address_hash = std::hash<std::string_view>{}(
                    std::string_view(reinterpret_cast<const char *>(bytes.data()), bytes.size()));
            }
            size_t port_hash = std::hash<unsigned short>{}(endpoint.port());
            return address_hash ^ (port_hash << 1); // Combine hashes
        }
    };

    struct client_info {
        std::chrono::steady_clock::time_point last_alive;
        moodycamel::ConcurrentQueue<std::vector<unsigned char>> audio_queue;
        opus_decoder_wrapper decoder; // Per-client decoder (maintains state)

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

    void _send_audio_to_client(const udp::endpoint& endpoint, const std::vector<unsigned char>& encoded_audio) {
        if (encoded_audio.empty()) {
            return;
        }

        // Create audio packet header
        AudioHdr ahdr{};
        ahdr.magic = AUDIO_MAGIC;
        ahdr.encoded_bytes = static_cast<uint16_t>(encoded_audio.size());
        
        // Copy encoded audio data to the header buffer
        size_t copy_size = std::min(encoded_audio.size(), sizeof(ahdr.buf));
        std::memcpy(ahdr.buf, encoded_audio.data(), copy_size);
        
        // Send the packet
        size_t packet_size = sizeof(MsgHdr) + sizeof(uint16_t) + ahdr.encoded_bytes;
        send(&ahdr, packet_size, endpoint);
    }

    void _broadcast_timer_callback() {
        // Only broadcast if we have clients
        if (_clients.empty()) {
            return;
        }

        // Constants for audio processing
        constexpr int FRAME_SIZE = 120;        // 2.5ms at 48kHz
        constexpr int SAMPLE_RATE = 48000;
        constexpr int INPUT_CHANNELS = 1;      // Clients send mono
        constexpr int OUTPUT_CHANNELS = 2;     // Server sends stereo
        constexpr int SAMPLES_PER_FRAME = FRAME_SIZE * OUTPUT_CHANNELS;

        // Create stereo mix buffer (initialized to silence)
        std::vector<float> stereo_mix(SAMPLES_PER_FRAME, 0.0F);
        int active_clients = 0;

        // Process each client's audio
        for (auto& [endpoint, client_info] : _clients) {
            std::vector<unsigned char> audio_packet;
            
            // Try to get the latest audio packet from this client
            if (client_info.audio_queue.try_dequeue(audio_packet)) {
                // Decode the client's mono audio
                std::vector<float> mono_audio;
                if (client_info.decoder.decode(audio_packet.data(), audio_packet.size(), FRAME_SIZE, mono_audio)) {
                    // Upmix mono to stereo and add to mix
                    if (mono_audio.size() == FRAME_SIZE) {
                        for (int i = 0; i < FRAME_SIZE; ++i) {
                            float sample = mono_audio[i];
                            // Simple upmix: duplicate mono to both stereo channels
                            stereo_mix[(i * 2)] += sample;     // Left channel
                            stereo_mix[(i * 2) + 1] += sample; // Right channel
                        }
                        active_clients++;
                    }
                }
            } else {
                // No audio packet available - use packet loss concealment
                std::vector<float> plc_audio;
                if (client_info.decoder.decode_plc(FRAME_SIZE, plc_audio)) {
                    if (plc_audio.size() == FRAME_SIZE) {
                        for (int i = 0; i < FRAME_SIZE; ++i) {
                            float sample = plc_audio[i];
                            stereo_mix[(i * 2)] += sample;     // Left channel
                            stereo_mix[(i * 2) + 1] += sample; // Right channel
                        }
                    }
                }
            }
        }

        // Apply gain control to prevent clipping (simple normalization)
        if (active_clients > 0) {
            float gain = 1.0F / static_cast<float>(active_clients);
            for (float& sample : stereo_mix) {
                sample *= gain;
            }
        }

        // Encode the stereo mix
        std::vector<unsigned char> encoded_mix;
        if (_encoder.encode(stereo_mix.data(), FRAME_SIZE, encoded_mix)) {
            // Broadcast to all clients
            for (const auto& [endpoint, client_info] : _clients) {
                _send_audio_to_client(endpoint, encoded_mix);
            }
        }

        // Optional: Print stats periodically
        static int callback_count = 0;
        if (++callback_count % 400 == 0) { // Every second (400 * 2.5ms = 1000ms)
            std::cout << "Broadcast: " << _clients.size() << " clients, " 
                      << active_clients << " active, mix size: " << encoded_mix.size() << " bytes\n";
        }
    }

    std::array<char, 1024> _recv_buf;
    std::array<char, 1024> _audio_tx_buf;
    udp::endpoint _remote_endpoint;

    opus_encoder_wrapper _encoder; // Shared encoder for all clients
};

int main() {
    try {
        asio::io_context io_context;
        server srv(io_context, 9999);
        std::cout << "Echo server listening on 127.0.0.1:9999\n";
        std::cout << "Broadcast timer running at 2.5ms intervals (48kHz, 120 frames)\n";

        // Just run the io_context - timers handle everything!
        io_context.run();
    } catch (std::exception &e) {
        std::cerr << "ERR: " << e.what() << "\n";
    }
}
