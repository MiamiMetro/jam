#include <array>
#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <concurrentqueue.h>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <opus.h>
#include <portaudio.h>
#include <unordered_map>

#include "opus_decoder.hpp"
#include "opus_encoder.hpp"
#include "periodic_timer.hpp"
#include "protocol.hpp"

using asio::ip::udp;
using namespace std::chrono_literals;

class audio_stream {
  public:
    audio_stream() { Pa_Initialize(); }

    ~audio_stream() {
        if (_stream) {
            Pa_StopStream(_stream);
            Pa_CloseStream(_stream);
        }

        Pa_Terminate();
    }

    void list_devices() {
        int numDevices = Pa_GetDeviceCount();
        if (numDevices < 0) {
            std::cerr << "ERROR: Pa_GetDeviceCount returned " << numDevices << "\n";
            return;
        }

        for (int i = 0; i < numDevices; ++i) {
            const PaDeviceInfo *deviceInfo = Pa_GetDeviceInfo(i);
            if (!deviceInfo)
                continue;
            const PaHostApiInfo *hostApiInfo = Pa_GetHostApiInfo(deviceInfo->hostApi);
            // device index: api - name (in: maxInputChannels, out: maxOutputChannels, defaultSR)
            std::cout << i << ": " << (hostApiInfo ? hostApiInfo->name : "Unknown API") << " - " << deviceInfo->name
                      << " (in: " << deviceInfo->maxInputChannels << ", out: " << deviceInfo->maxOutputChannels
                      << ", defaultSR: " << deviceInfo->defaultSampleRate << ")\n";
        }
    }

    const PaDeviceInfo *get_device_info(int deviceIndex) {
        const PaDeviceInfo *deviceInfo = Pa_GetDeviceInfo(deviceIndex);
        if (!deviceInfo) {
            std::cerr << "Invalid device index: " << deviceIndex << "\n";
            return nullptr;
        }
        return deviceInfo;
    }

    void print_device_info(const PaDeviceInfo *inputInfo, const PaDeviceInfo *outputInfo) const {
        std::cout << "Input Device: " << inputInfo->name << " | API: "
                  << (Pa_GetHostApiInfo(inputInfo->hostApi) ? Pa_GetHostApiInfo(inputInfo->hostApi)->name : "Unknown")
                  << " | Max Input Channels: " << inputInfo->maxInputChannels
                  << " | Default Sample Rate: " << inputInfo->defaultSampleRate << "\n";
        std::cout << "Output Device: " << outputInfo->name << " | API: "
                  << (Pa_GetHostApiInfo(outputInfo->hostApi) ? Pa_GetHostApiInfo(outputInfo->hostApi)->name : "Unknown")
                  << " | Max Output Channels: " << outputInfo->maxOutputChannels
                  << " | Default Sample Rate: " << outputInfo->defaultSampleRate << "\n";
    }

    void start_audio_stream(PaDeviceIndex inputDevice, PaDeviceIndex outputDevice, int framesPerBuffer = 120,
                            PaStreamCallback *callback = nullptr, void *userData = nullptr) {
        // Opus requires specific frame sizes: 120, 240, 480, 960, 1920, or 2880 frames
        auto inputInfo = get_device_info(inputDevice);
        auto outputInfo = get_device_info(outputDevice);
        if (!inputInfo || !outputInfo) {
            std::cerr << "Invalid input or output device.\n";
            return;
        }

        PaStreamParameters inputParameters = {inputDevice, std::min(inputInfo->maxInputChannels, 1), paFloat32,
                                              inputInfo->defaultLowInputLatency, nullptr};

        PaStreamParameters outputParameters = {outputDevice, std::min(outputInfo->maxOutputChannels, 2), paFloat32,
                                               outputInfo->defaultLowOutputLatency, nullptr};

        _input_channel_count = inputParameters.channelCount;
        _output_channel_count = outputParameters.channelCount;

        print_device_info(inputInfo, outputInfo);
        std::cout << "Frames per buffer: " << framesPerBuffer << "\n";

        PaError err = Pa_OpenStream(&_stream, &inputParameters, &outputParameters, inputInfo->defaultSampleRate,
                                    framesPerBuffer, paNoFlag, callback, userData);
        if (err != paNoError) {
            std::cerr << "Pa_OpenStream failed: " << Pa_GetErrorText(err) << "\n";
            _stream = nullptr;
            return;
        }
        err = Pa_StartStream(_stream);
        if (err != paNoError) {
            std::cerr << "Pa_StartStream failed: " << Pa_GetErrorText(err) << "\n";
        }

        std::cout << _input_channel_count << " input channel(s), " << _output_channel_count << " output channel(s) at "
                  << inputInfo->defaultSampleRate << " Hz\n";

        // Decoder receives stereo from server, Encoder sends mono to server
        // Use 256 kbps for near-transparent music quality (mono: ~80 bytes per 2.5ms packet)
        // Complexity 5 balances quality vs performance
        std::cout << "Creating client encoder (mono) and decoder (stereo) with 256kbps bitrate, complexity 5\n";
        _encoder.create(static_cast<int>(inputInfo->defaultSampleRate), _input_channel_count, OPUS_APPLICATION_AUDIO,
                        256000, 5);
        _decoder.create(static_cast<int>(inputInfo->defaultSampleRate), _output_channel_count);
    }

    void stop_audio_stream() {
        if (_stream) {
            Pa_StopStream(_stream);
            Pa_CloseStream(_stream);
            _stream = nullptr;
        }
        _encoder.destroy();
        _decoder.destroy();
    }

    void print_latency_info() {
        const PaStreamInfo *streamInfo = Pa_GetStreamInfo(_stream);
        if (streamInfo) {
            printf("Input latency:  %.3f ms\n", streamInfo->inputLatency * 1000.0);
            printf("Output latency: %.3f ms\n", streamInfo->outputLatency * 1000.0);
            printf("Sample rate:    %.1f Hz\n", streamInfo->sampleRate);
        }
    }

    void encode_opus(const float *input, int frameSize, std::vector<unsigned char> &output) {
        _encoder.encode(input, frameSize, output);
    }

    void decode_opus(const unsigned char *input, int inputSize, int frameSize, int channelCount,
                     std::vector<float> &output) {
        _decoder.decode(input, inputSize, frameSize, output);
    }

    int get_input_channel_count() const { return _input_channel_count; }
    int get_output_channel_count() const { return _output_channel_count; }

  private:
    PaStream *_stream = nullptr;
    opus_encoder_wrapper _encoder;
    opus_decoder_wrapper _decoder;

    int _input_channel_count;
    int _output_channel_count;
};

class client {

  public:
    client(asio::io_context &io, const std::string &server_address, short server_port)
        : _socket(io, udp::endpoint(udp::v4(), 0)), _ping_timer(io, 100ms, [this]() { _ping_timer_callback(); }),
          _alive_timer(io, 5s, [this]() { _alive_timer_callback(); }), _jitter_buffer_ready(false),
          _jitter_buffer_min_packets(4), _jitter_buffer_target_packets(6), _jitter_buffer_max_packets(12) {

        std::cout << "Client local port: " << _socket.local_endpoint().port() << "\n";

        // Resolve hostname or IP address
        udp::resolver resolver(io);
        udp::resolver::results_type endpoints =
            resolver.resolve(udp::v4(), server_address, std::to_string(server_port));
        _server_endpoint = *endpoints.begin();

        std::cout << "Connecting to: " << _server_endpoint.address().to_string() << ":" << _server_endpoint.port()
                  << "\n";

        CtrlHdr chdr{};
        chdr.magic = CTRL_MAGIC;
        chdr.type = CtrlHdr::Cmd::JOIN;
        std::memcpy(_ctrl_tx_buf.data(), &chdr, sizeof(CtrlHdr));
        send(_ctrl_tx_buf.data(), sizeof(CtrlHdr));

        std::cout << "\n=== Available Audio Devices ===\n";
        _audio.list_devices();

        _audio.start_audio_stream(18, 15, 120, audio_callback, this);
        _audio.print_latency_info();

        do_receive();
    }

    void on_receive(std::error_code ec, std::size_t bytes) {
        if (ec) {
            // std::cerr << "receive error: " << ec.message() << "\n";
            do_receive(); // keep listening
            return;
        }

        if (bytes >= sizeof(MsgHdr)) {
            MsgHdr hdr{};
            std::memcpy(&hdr, _recv_buf.data(), sizeof(MsgHdr));

            if (hdr.magic == PING_MAGIC && bytes >= sizeof(SyncHdr)) {
                SyncHdr hdr{};
                std::memcpy(&hdr, _recv_buf.data(), sizeof(SyncHdr));

                auto now = std::chrono::steady_clock::now();
                auto t4 = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
                auto rtt = (t4 - hdr.t1_client_send) - (hdr.t3_server_send - hdr.t2_server_recv);
                auto offset = ((hdr.t2_server_recv - hdr.t1_client_send) + (hdr.t3_server_send - t4)) / 2;

                double rtt_ms = rtt / 1e6;
                double offset_ms = offset / 1e6;

                // print live stats
                std::cout << "seq " << hdr.seq << " RTT " << rtt_ms << " ms"
                          << " | offset " << offset_ms << " ms" << std::string(20, ' ') << "\r" << std::flush;
            } else if (hdr.magic == ECHO_MAGIC && bytes >= sizeof(EchoHdr)) {
                EchoHdr ehdr{};
                std::memcpy(&ehdr, _recv_buf.data(), sizeof(EchoHdr));
                static int echo_count = 0;
                std::cout << "Echo " << ++echo_count << " from server: " << std::string(ehdr.data) << "\n";
            } else if (hdr.magic == AUDIO_MAGIC && bytes >= sizeof(MsgHdr) + sizeof(uint16_t)) {
                uint16_t encoded_bytes;
                std::memcpy(&encoded_bytes, _recv_buf.data() + sizeof(MsgHdr), sizeof(uint16_t));
                size_t expected_size = sizeof(MsgHdr) + sizeof(uint16_t) + encoded_bytes;
                if (bytes < expected_size) {
                    std::cerr << "Incomplete audio packet: got " << bytes << ", expected " << expected_size << "\n";
                    do_receive();
                    return;
                }
                const unsigned char *audio_data =
                    reinterpret_cast<const unsigned char *>(_recv_buf.data() + sizeof(MsgHdr) + sizeof(uint16_t));

                std::vector<float> decodedData;
                if (encoded_bytes > 0) {
                    // Decode the received Opus data
                    _audio.decode_opus(audio_data, encoded_bytes, 120, _audio.get_output_channel_count(), decodedData);

                    // Diagnostic: Check decoded size periodically
                    static int decode_count = 0;
                    static int size_errors = 0;
                    if (++decode_count % 400 == 0) {
                        std::cout << "Client decoded " << decode_count << " packets, " << decodedData.size()
                                  << " samples (expected " << (120 * _audio.get_output_channel_count()) << "), "
                                  << size_errors << " size errors\n";
                    }
                    if (decodedData.size() != 120 * _audio.get_output_channel_count()) {
                        size_errors++;
                    }
                }
                if (!decodedData.empty()) {
                    // Add to jitter buffer queue
                    size_t queue_size = _audio_recv_queue.size_approx();

                    // Drop packet if queue is too full (prevent unbounded latency)
                    if (queue_size < 16) {
                        _audio_recv_queue.enqueue(std::move(decodedData));

                        // Mark buffer as ready once we have enough packets
                        if (!_jitter_buffer_ready && queue_size >= _jitter_buffer_min_packets) {
                            _jitter_buffer_ready = true;
                            std::cout << "\nJitter buffer ready (" << queue_size << " packets buffered)\n";
                        }
                    } else {
                        // Buffer overflow - drop oldest packet
                        std::vector<float> discarded;
                        _audio_recv_queue.try_dequeue(discarded);
                        _audio_recv_queue.enqueue(std::move(decodedData));
                    }
                }

            } else {
                std::cout << "Unknown message: " << std::string(_recv_buf.data(), bytes) << "\n";
            }
        }

        do_receive(); // keep listening
    }

    void do_receive() {
        _socket.async_receive_from(asio::buffer(_recv_buf), _server_endpoint,
                                   [this](std::error_code ec, std::size_t bytes) { on_receive(ec, bytes); });
    }

    void send(void *data, std::size_t len) {
        _socket.async_send_to(asio::buffer(data, len), _server_endpoint, [](std::error_code ec, std::size_t) {
            if (ec)
                std::cerr << "send error: " << ec.message() << "\n";
        });
    }

    static int audio_callback(const void *input, void *output, unsigned long frame_count,
                              const PaStreamCallbackTimeInfo *, PaStreamCallbackFlags, void *user_data) {

        const float *in = static_cast<const float *>(input);
        float *out = static_cast<float *>(output);
        if (!out)
            return paContinue;

        client *cl = static_cast<client *>(user_data);

        // Use static buffers to avoid allocations (reused across calls)
        static std::vector<float> decoded_data;
        static std::vector<unsigned char> encoded_data;
        static int underrun_count = 0;
        static int playback_count = 0;
        static int consecutive_low_buffer = 0;
        static int consecutive_high_buffer = 0;
        static auto last_adaptation = std::chrono::steady_clock::now();

        size_t out_channels = cl->_audio.get_output_channel_count(); // 2
        size_t bytes_to_copy = frame_count * out_channels * sizeof(float);

        // 1. Play received audio from server (with adaptive jitter buffer)
        size_t queue_size = cl->_audio_recv_queue.size_approx();
        size_t current_min = cl->_jitter_buffer_min_packets.load();
        size_t current_target = cl->_jitter_buffer_target_packets.load();

        // Jitter buffer logic: only play if buffer is ready
        if (cl->_jitter_buffer_ready && cl->_audio_recv_queue.try_dequeue(decoded_data)) {
            // Validate decoded data size matches expected output
            size_t expected_samples = frame_count * out_channels;
            if (decoded_data.size() == expected_samples) {
                std::memcpy(out, decoded_data.data(), bytes_to_copy);
            } else {
                // Size mismatch - zero output and log warning
                std::memset(out, 0, bytes_to_copy);
                static int mismatch_count = 0;
                if (++mismatch_count % 100 == 0) {
                    std::cerr << "Client: Decoded size mismatch: got " << decoded_data.size() << " samples, expected "
                              << expected_samples << "\n";
                }
            }
            playback_count++;

            // === ADAPTIVE BUFFER SIZE ADJUSTMENT ===
            auto now = std::chrono::steady_clock::now();
            auto time_since_adapt = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_adaptation);

            // Only adapt every 1 second to avoid oscillation
            if (time_since_adapt.count() >= 1000) {
                // Track buffer health
                if (queue_size < current_min) {
                    consecutive_low_buffer++;
                    consecutive_high_buffer = 0;
                } else if (queue_size > current_target + 2) {
                    consecutive_high_buffer++;
                    consecutive_low_buffer = 0;
                } else {
                    // Buffer in healthy range - decay counters slowly
                    consecutive_low_buffer = std::max(0, consecutive_low_buffer - 1);
                    consecutive_high_buffer = std::max(0, consecutive_high_buffer - 1);
                }

                // Increase buffer if consistently low (network jitter detected)
                if (consecutive_low_buffer >= 3 && current_min < cl->_jitter_buffer_max_packets - 2) {
                    size_t new_min = std::min(current_min + 2, cl->_jitter_buffer_max_packets - 2);
                    size_t new_target = std::min(current_target + 2, cl->_jitter_buffer_max_packets);
                    cl->_jitter_buffer_min_packets.store(new_min);
                    cl->_jitter_buffer_target_packets.store(new_target);
                    std::cout << "\n📈 Adaptive: Increasing buffer to min=" << new_min << ", target=" << new_target
                              << " (high jitter detected)\n";
                    consecutive_low_buffer = 0;
                    last_adaptation = now;
                }
                // Decrease buffer if consistently high (stable network, reduce latency)
                else if (consecutive_high_buffer >= 5 && current_min > 3) {
                    size_t new_min = std::max(current_min - 1, size_t(3));
                    size_t new_target = std::max(current_target - 1, size_t(5));
                    cl->_jitter_buffer_min_packets.store(new_min);
                    cl->_jitter_buffer_target_packets.store(new_target);
                    std::cout << "\n📉 Adaptive: Decreasing buffer to min=" << new_min << ", target=" << new_target
                              << " (stable network)\n";
                    consecutive_high_buffer = 0;
                    last_adaptation = now;
                }
            }

            // Warn if buffer is critically low
            if (queue_size < current_min - 1) {
                underrun_count++;
                if (underrun_count % 200 == 0) {
                    std::cout << "\n⚠️  Jitter buffer low (" << queue_size << "/" << current_min << " packets)\n";
                }
            } else {
                underrun_count = 0;
            }
        } else {
            // Buffer not ready or underrun - play silence
            std::memset(out, 0, bytes_to_copy);
            underrun_count++;

            // Print underrun stats periodically
            if (!cl->_jitter_buffer_ready && underrun_count % 100 == 0) {
                std::cout << "\nBuffering... (" << queue_size << "/" << current_min << " packets)\n";
            }

            // Reset buffer ready flag if we've drained completely
            if (cl->_jitter_buffer_ready && queue_size == 0) {
                cl->_jitter_buffer_ready = false;
                std::cout << "\n❌ Jitter buffer underrun! Rebuffering...\n";
                consecutive_low_buffer = 0;
                consecutive_high_buffer = 0;
            }
        }

        // 2. Mix in your own live instrument (local monitor)
        // float self_gain = 1.0f; // Adjust to taste (0.0–1.0)
        // if (in) {
        //     for (size_t i = 0; i < frame_count; ++i) {
        //         float sample = in[i] * self_gain;
        //         out[i * out_channels + 0] += sample; // Left
        //         out[i * out_channels + 1] += sample; // Right
        //     }
        // }

        // 3. Encode and send to server
        if (in) {
            // Silence detection: Check if input has significant audio
            static constexpr float SILENCE_THRESHOLD = 0.001f; // -60dB
            float max_sample = 0.0f;
            for (unsigned long i = 0; i < frame_count; ++i) {
                float abs_sample = std::fabs(in[i]);
                if (abs_sample > max_sample) {
                    max_sample = abs_sample;
                }
            }
            
            // Only encode and send if there's actual audio (not silence)
            if (max_sample > SILENCE_THRESHOLD) {
                cl->_audio.encode_opus(in, frame_count, encoded_data);

                // Diagnostic: Check encoding success
                static int encode_count = 0;
                static int encode_failures = 0;
                encode_count++;
                if (encoded_data.empty()) {
                    encode_failures++;
                }
                if (encode_count % 400 == 0) {
                    std::cout << "Client encoded " << encode_count << " packets, "
                              << encode_failures << " failures, last size: " << encoded_data.size() 
                              << " bytes, peak: " << max_sample << "\n";
                }

                if (!encoded_data.empty()) {
                    AudioHdr ahdr{};
                    ahdr.magic = AUDIO_MAGIC;
                    ahdr.encoded_bytes = static_cast<uint16_t>(encoded_data.size());
                    std::memcpy(ahdr.buf, encoded_data.data(), std::min(encoded_data.size(), sizeof(ahdr.buf)));
                    size_t packetSize = sizeof(MsgHdr) + sizeof(uint16_t) + ahdr.encoded_bytes;
                    cl->send(&ahdr, packetSize);
                }
            } else {
                // Silence detected - don't send packet (save bandwidth and prevent glitches)
                static int silence_count = 0;
                if (++silence_count % 400 == 0) {
                    std::cout << "Client: " << silence_count << " silent frames skipped\n";
                }
            }
        } else {
            // No input - send silence packet periodically to keep connection alive
            static int no_input_count = 0;
            if (++no_input_count % 100 == 0) {
                std::cerr << "Warning: No input audio (in == nullptr)\n";
            }
        }

        return paContinue;
    }

  private:
    udp::socket _socket;
    udp::endpoint _server_endpoint;

    std::array<char, 1024> _recv_buf;
    std::array<unsigned char, 128> _sync_tx_buf;
    std::array<unsigned char, 128> _ctrl_tx_buf;

    audio_stream _audio;
    std::vector<float> _stereo_buffer;
    moodycamel::ConcurrentQueue<std::vector<float>> _audio_recv_queue;

    // Jitter buffer state
    std::atomic<bool> _jitter_buffer_ready;
    std::atomic<size_t> _jitter_buffer_min_packets;    // Adaptive minimum (starts at 4)
    std::atomic<size_t> _jitter_buffer_target_packets; // Adaptive target (starts at 6)
    const size_t _jitter_buffer_max_packets;           // Hard max (12 packets = 30ms)

    periodic_timer _ping_timer;
    void _ping_timer_callback() {
        static uint32_t seq = 0;
        SyncHdr shdr{};
        shdr.magic = PING_MAGIC;
        shdr.seq = seq++;
        auto now = std::chrono::steady_clock::now();
        shdr.t1_client_send = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        std::memcpy(_sync_tx_buf.data(), &shdr, sizeof(SyncHdr));
        send(_sync_tx_buf.data(), sizeof(SyncHdr));
    }
    periodic_timer _alive_timer;
    void _alive_timer_callback() {
        CtrlHdr chdr{};
        chdr.magic = CTRL_MAGIC;
        chdr.type = CtrlHdr::Cmd::ALIVE;
        std::memcpy(_ctrl_tx_buf.data(), &chdr, sizeof(CtrlHdr));
        send(_ctrl_tx_buf.data(), sizeof(CtrlHdr));
    }
};

int main() {
    try {
        asio::io_context io;
        client cl(io, "127.0.0.1", 9999);
        io.run();
    } catch (std::exception &e) {
        std::cerr << "ERR: " << e.what() << "\n";
    }
}