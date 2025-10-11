#include <array>
#include <asio.hpp>
#include <concurrentqueue.h>
#include <iostream>
#include <opus.h>
#include <unordered_map>

#include "periodic_timer.hpp"
#include "protocol.hpp"

using asio::ip::udp;
using namespace std::chrono_literals;

// class for both opus encode and decode
class audio_codec {
  private:
    OpusEncoder *_encoder = nullptr;
    OpusDecoder *_decoder = nullptr;
    int _application;
    int _bitrate;
    int _complexity;
    int _frame_size; // in samples
    int _max_data_bytes;

  public:
    audio_codec(int sample_rate = 48000, int channels = 2, int application = OPUS_APPLICATION_AUDIO,
                int bitrate = 96000, int complexity = 5, int frame_size = 120, int max_data_bytes = 128)
        : _application(application), _bitrate(bitrate), _complexity(complexity), _frame_size(frame_size),
          _max_data_bytes(max_data_bytes) {
        int err;
        _encoder = opus_encoder_create(sample_rate, channels, application, &err);
        if (err != OPUS_OK) {
            std::cerr << "Failed to create Opus encoder: " << opus_strerror(err) << "\n";
            _encoder = nullptr;
        } else {
            // Set encoder options for low-latency music streaming
            opus_encoder_ctl(_encoder, OPUS_SET_COMPLEXITY(complexity));
            opus_encoder_ctl(_encoder, OPUS_SET_BITRATE(bitrate));
            opus_encoder_ctl(_encoder, OPUS_SET_SIGNAL(OPUS_SIGNAL_MUSIC));
            opus_encoder_ctl(_encoder, OPUS_SET_VBR(1));              // Variable bitrate for better quality
            opus_encoder_ctl(_encoder, OPUS_SET_VBR_CONSTRAINT(0));   // Unconstrained VBR for music
            opus_encoder_ctl(_encoder, OPUS_SET_INBAND_FEC(1));       // Forward error correction for UDP
            opus_encoder_ctl(_encoder, OPUS_SET_PACKET_LOSS_PERC(5)); // Expect some packet loss
            opus_encoder_ctl(_encoder, OPUS_SET_DTX(0));              // Disable DTX for music (no silence detection)
        }

        _decoder = opus_decoder_create(sample_rate, channels, &err);
        if (err != OPUS_OK) {
            std::cerr << "Failed to create Opus decoder: " << opus_strerror(err) << "\n";
            opus_encoder_destroy(_encoder);
            _encoder = nullptr;
            _decoder = nullptr;
        }
    }

    ~audio_codec() {
        if (_encoder)
            opus_encoder_destroy(_encoder);
        if (_decoder)
            opus_decoder_destroy(_decoder);
    }

    // Encode raw PCM samples to Opus
    // in: pointer to input PCM samples (int16_t)
    // frame_count: number of samples per channel
    // sample_rate: sample rate of input PCM (e.g., 48000)
    // out: vector to store encoded Opus data
    // Returns: number of bytes written to out, or -1 on error
    int encode_opus(const int16_t *in, int frame_count, int sample_rate, std::vector<uint8_t> &out) {
        if (!_encoder)
            return -1;

        out.resize(_max_data_bytes);
        int bytes_encoded = opus_encode(_encoder, in, frame_count, out.data(), static_cast<opus_int32>(out.size()));
        if (bytes_encoded < 0) {
            std::cerr << "Opus encoding failed: " << opus_strerror(bytes_encoded) << "\n";
            out.clear();
            return -1;
        }
        out.resize(bytes_encoded);
        return bytes_encoded;
    }
    // Decode Opus data to raw PCM samples
    // in: pointer to input Opus data
    // in_bytes: size of input Opus data in bytes
    // out: vector to store decoded PCM samples (int16_t)
    // Returns: number of samples decoded per channel, or -1 on error
    int decode_opus(const uint8_t *in, int in_bytes, std::vector<int16_t> &out) {
        if (!_decoder)
            return -1;

        out.resize(_frame_size * 2); // Allocate enough space for stereo
        int samples_decoded =
            opus_decode(_decoder, in, in_bytes, out.data(), static_cast<opus_int32>(out.size() / sizeof(int16_t)), 0);
        if (samples_decoded < 0) {
            std::cerr << "Opus decoding failed: " << opus_strerror(samples_decoded) << "\n";
            out.clear();
            return -1;
        }
        out.resize(samples_decoded); // Resize to actual number of samples decoded
        return samples_decoded;
    }
};

class server {
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
    };

    std::unordered_map<udp::endpoint, client_info, endpoint_hash> _clients;
    periodic_timer _alive_check_timer;

    std::array<char, 1024> _recv_buf;
    udp::endpoint _remote_endpoint;

    audio_codec _audio_codec;

  public:
    server(asio::io_context &io, short port)
        : _socket(io, udp::endpoint(udp::v4(), port)), _alive_check_timer(io, 5s, [this]() {
              auto now = std::chrono::steady_clock::now();
              for (auto it = _clients.begin(); it != _clients.end();) {
                  if (now - it->second.last_alive > 15s) {
                      std::cout << "Client " << it->first.address().to_string() << ":" << it->first.port()
                                << " timed out\n";
                      it = _clients.erase(it);
                  } else {
                      ++it;
                  }
              }
          }) {

        do_receive();
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
            } else if (hdr.magic == AUDIO_MAGIC && bytes >= sizeof(MsgHdr) + sizeof(uint8_t)) {
                if (_clients.find(_remote_endpoint) == _clients.end()) {
                    do_receive();
                    return;
                }
                // Read only the header fields we need
                uint8_t encoded_bytes;
                std::memcpy(&encoded_bytes, _recv_buf.data() + sizeof(MsgHdr), sizeof(uint8_t));

                // Verify we received all the data
                size_t expected_size = sizeof(MsgHdr) + sizeof(uint8_t) + encoded_bytes;
                if (bytes < expected_size) {
                    std::cerr << "Incomplete audio packet: got " << bytes << ", expected " << expected_size << "\n";
                    do_receive();
                    return;
                }

                // Extract audio data (starts after magic + encoded_bytes field)
                const unsigned char *audio_data =
                    reinterpret_cast<const unsigned char *>(_recv_buf.data() + sizeof(MsgHdr) + sizeof(uint8_t));

                send(_recv_buf.data(), bytes, _remote_endpoint);
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
};

int main() {
    try {
        asio::io_context io;
        server srv(io, 9999);

        std::cout << "Echo server listening on 127.0.0.1:9999\n";
        io.run();
    } catch (std::exception &e) {
        std::cerr << "ERR: " << e.what() << "\n";
    }
}
