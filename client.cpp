#include <algorithm>
#include <array>
#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <concurrentqueue.h>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <opus.h>
#include <portaudio.h>
#include <thread>

#include "opus_decoder.hpp"
#include "opus_encoder.hpp"
#include "periodic_timer.hpp"
#include "protocol.hpp"
#include "tcp_control_server.hpp"

using asio::ip::udp;
using namespace std::chrono_literals;

class audio_stream {
  public:
    audio_stream() { Pa_Initialize(); }

    ~audio_stream() {
        if (_stream != nullptr) {
            Pa_StopStream(_stream);
            Pa_CloseStream(_stream);
        }

        Pa_Terminate();
    }

    static void list_devices() {
        int numDevices = Pa_GetDeviceCount();
        if (numDevices < 0) {
            std::cerr << "ERROR: Pa_GetDeviceCount returned " << numDevices << "\n";
            return;
        }

        for (int i = 0; i < numDevices; ++i) {
            const PaDeviceInfo *deviceInfo = Pa_GetDeviceInfo(i);
            if (deviceInfo == nullptr) {
                continue;
            }
            const PaHostApiInfo *hostApiInfo = Pa_GetHostApiInfo(deviceInfo->hostApi);
            // device index: api - name (in: maxInputChannels, out: maxOutputChannels, defaultSR)
            std::cout << i << ": " << ((hostApiInfo != nullptr) ? hostApiInfo->name : "Unknown API") << " - "
                      << deviceInfo->name << " (in: " << deviceInfo->maxInputChannels
                      << ", out: " << deviceInfo->maxOutputChannels << ", defaultSR: " << deviceInfo->defaultSampleRate
                      << ")\n";
        }
    }

    static std::string get_devices_json(const std::string &hostApiName = "") {
        std::string json = "[";
        int numDevices = Pa_GetDeviceCount();
        bool first = true;
        for (int i = 0; i < numDevices; ++i) {
            const PaDeviceInfo *deviceInfo = Pa_GetDeviceInfo(i);
            if (deviceInfo == nullptr) {
                continue;
            }
            const PaHostApiInfo *hostApiInfo = Pa_GetHostApiInfo(deviceInfo->hostApi);
            std::string apiName = (hostApiInfo != nullptr) ? hostApiInfo->name : "Unknown API";
            if (!hostApiName.empty() && apiName != hostApiName) {
                continue;
            }
            if (!first) {
                json += ",";
            }
            first = false;
            json += R"({"index": )" + std::to_string(i) + R"(, "name": ")" + deviceInfo->name +
                    R"(", "maxInputChannels": )" + std::to_string(deviceInfo->maxInputChannels) +
                    R"(, "maxOutputChannels": )" + std::to_string(deviceInfo->maxOutputChannels) +
                    R"(, "defaultSampleRate": )" + std::to_string(deviceInfo->defaultSampleRate) + R"(, "hostApi": ")" +
                    apiName + R"("})";
        }
        json += "]";
        return json;
    }

    static const PaDeviceInfo *get_device_info(int deviceIndex) {
        const PaDeviceInfo *deviceInfo = Pa_GetDeviceInfo(deviceIndex);
        if (deviceInfo == nullptr) {
            std::cerr << "Invalid device index: " << deviceIndex << "\n";
            return nullptr;
        }
        return deviceInfo;
    }

    static void print_device_info(const PaDeviceInfo *inputInfo, const PaDeviceInfo *outputInfo) {
        std::cout << "Input Device: " << inputInfo->name << " | API: "
                  << ((Pa_GetHostApiInfo(inputInfo->hostApi) != nullptr) ? Pa_GetHostApiInfo(inputInfo->hostApi)->name
                                                                         : "Unknown")
                  << " | Max Input Channels: " << inputInfo->maxInputChannels
                  << " | Default Sample Rate: " << inputInfo->defaultSampleRate << "\n";
        std::cout << "Output Device: " << outputInfo->name << " | API: "
                  << ((Pa_GetHostApiInfo(outputInfo->hostApi) != nullptr) ? Pa_GetHostApiInfo(outputInfo->hostApi)->name
                                                                          : "Unknown")
                  << " | Max Output Channels: " << outputInfo->maxOutputChannels
                  << " | Default Sample Rate: " << outputInfo->defaultSampleRate << "\n";
    }

    void start_audio_stream(PaDeviceIndex inputDevice, PaDeviceIndex outputDevice, int framesPerBuffer = 120,
                            PaStreamCallback *callback = nullptr, void *userData = nullptr) {
        // Opus requires specific frame sizes: 120, 240, 480, 960, 1920, or 2880 frames
        const auto *inputInfo = get_device_info(inputDevice);
        const auto *outputInfo = get_device_info(outputDevice);
        if (inputInfo == nullptr || outputInfo == nullptr) {
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
        } else {
            _stream_active.store(true, std::memory_order_relaxed);
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
        _stream_active.store(false, std::memory_order_relaxed);
        if (_stream != nullptr) {
            Pa_StopStream(_stream);
            Pa_CloseStream(_stream);
            _stream = nullptr;
        }
        _encoder.destroy();
        _decoder.destroy();
    }

    void print_latency_info() {
        const PaStreamInfo *streamInfo = Pa_GetStreamInfo(_stream);
        if (streamInfo != nullptr) {
            static constexpr double SECONDS_TO_MILLISECONDS = 1000.0;
            printf("Input latency:  %.3f ms\n", streamInfo->inputLatency * SECONDS_TO_MILLISECONDS);
            printf("Output latency: %.3f ms\n", streamInfo->outputLatency * SECONDS_TO_MILLISECONDS);
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
    bool is_stream_active() const { return _stream_active.load(std::memory_order_relaxed); }

  private:
    PaStream *_stream = nullptr;
    opus_encoder_wrapper _encoder;
    opus_decoder_wrapper _decoder;
    std::atomic<bool> _stream_active{false};

    int _input_channel_count;
    int _output_channel_count;
};

class client {

  public:
    client(asio::io_context &io_context, const std::string &server_address, short server_port)
        : _io_context(io_context), _socket(io_context, udp::endpoint(udp::v4(), 0)),
          _ping_timer(io_context, 100ms, [this]() { _ping_timer_callback(); }),
          _alive_timer(io_context, 5s, [this]() { _alive_timer_callback(); }), _jitter_buffer_ready(false),
          _jitter_buffer_min_packets(4), _jitter_buffer_target_packets(6), _jitter_buffer_max_packets(12),
          _is_connected(false), _echo_enabled(false) {

        std::cout << "Client local port: " << _socket.local_endpoint().port() << "\n";

        std::cout << "\n=== Available Audio Devices ===\n";
        audio_stream::list_devices();

        // Start audio stream
        start_audio_stream(17, 15, 120);
        // Connect to server
        start_connection(server_address, server_port);
    }

    // Start connection to server (or switch to new server)
    void start_connection(const std::string &server_address, short server_port) {
        std::cout << "\nConnecting to " << server_address << ":" << server_port << "...\n";

        // Resolve hostname or IP address
        udp::resolver resolver(_io_context);
        udp::resolver::results_type endpoints =
            resolver.resolve(udp::v4(), server_address, std::to_string(server_port));
        _server_endpoint = *endpoints.begin();

        std::cout << "Resolved to: " << _server_endpoint.address().to_string() << ":" << _server_endpoint.port()
                  << "\n";

        _is_connected.store(true, std::memory_order_relaxed);
        do_receive();

        std::cout << "Connected and receiving!\n";

        // Send JOIN message
        CtrlHdr chdr{};
        chdr.magic = CTRL_MAGIC;
        chdr.type = CtrlHdr::Cmd::JOIN;
        std::memcpy(_ctrl_tx_buf.data(), &chdr, sizeof(CtrlHdr));
        send(_ctrl_tx_buf.data(), sizeof(CtrlHdr));
    }

    // Stop connection (stops sending/receiving UDP packets)
    void stop_connection() {
        std::cout << "\nDisconnecting from server...\n";

        _is_connected.store(false, std::memory_order_relaxed);

        // Cancel pending async operations
        _socket.cancel();

        // Clear audio receive queue
        std::vector<float> temp;
        while (_audio_recv_queue.try_dequeue(temp)) {
        }
        _jitter_buffer_ready = false;

        std::cout << "Disconnected (no longer sending/receiving)\n";
    }

    // Check if connected to server
    bool is_connected() const { return _is_connected.load(std::memory_order_relaxed); }

    void start_audio_stream(PaDeviceIndex inputDevice, PaDeviceIndex outputDevice, int framesPerBuffer = 120) {
        std::cout << "Starting audio stream...\n";
        _audio.start_audio_stream(inputDevice, outputDevice, framesPerBuffer, audio_callback, this);
        _audio.print_latency_info();
    }

    void stop_audio_stream() { _audio.stop_audio_stream(); }

    void enable_echo(bool enable) { _echo_enabled.store(enable, std::memory_order_relaxed); }

    bool is_echo_enabled() const { return _echo_enabled.load(std::memory_order_relaxed); }

    void on_receive(std::error_code error_code, std::size_t bytes) {
        if (error_code) {
            // std::cerr << "receive error: " << error_code.message() << "\n";
            do_receive(); // keep listening
            return;
        }

        if (bytes < sizeof(MsgHdr)) {
            do_receive();
            return;
        }

        MsgHdr hdr{};
        std::memcpy(&hdr, _recv_buf.data(), sizeof(MsgHdr));

        if (hdr.magic == PING_MAGIC && bytes >= sizeof(SyncHdr)) {
            _handle_ping_message(bytes);
        } else if (hdr.magic == ECHO_MAGIC && bytes >= sizeof(EchoHdr)) {
            _handle_echo_message(bytes);
        } else if (hdr.magic == AUDIO_MAGIC && bytes >= sizeof(MsgHdr) + sizeof(uint16_t)) {
            _handle_audio_message(bytes);
        } else {
            std::cout << "Unknown message: " << std::string(_recv_buf.data(), bytes) << "\n";
        }

        do_receive(); // keep listening
    }

    void do_receive() {
        // Only receive if connected
        if (!_is_connected.load(std::memory_order_relaxed)) {
            return;
        }

        _socket.async_receive_from(
            asio::buffer(_recv_buf), _server_endpoint,
            [this](std::error_code error_code, std::size_t bytes) { on_receive(error_code, bytes); });
    }

    void send(void *data, std::size_t len) {
        // Only send if connected
        if (!_is_connected.load(std::memory_order_relaxed)) {
            return;
        }

        _socket.async_send_to(asio::buffer(data, len), _server_endpoint, [](std::error_code error_code, std::size_t) {
            if (error_code) {
                std::cerr << "send error: " << error_code.message() << "\n";
            }
        });
    }

  private:
    asio::io_context &_io_context;
    udp::socket _socket;
    udp::endpoint _server_endpoint;

    std::array<char, 1024> _recv_buf;
    std::array<unsigned char, 128> _sync_tx_buf;
    std::array<unsigned char, 128> _ctrl_tx_buf;

    audio_stream _audio;
    std::vector<float> _stereo_buffer;
    moodycamel::ConcurrentQueue<std::vector<float>> _audio_recv_queue;

    // Connection state (atomic for thread-safe access from audio callback)
    std::atomic<bool> _is_connected;

    std::atomic<bool> _echo_enabled;

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

    void _handle_ping_message(std::size_t bytes) {
        SyncHdr hdr{};
        std::memcpy(&hdr, _recv_buf.data(), sizeof(SyncHdr));

        auto now = std::chrono::steady_clock::now();
        auto current_time = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        auto rtt = (current_time - hdr.t1_client_send) - (hdr.t3_server_send - hdr.t2_server_recv);
        auto offset = ((hdr.t2_server_recv - hdr.t1_client_send) + (hdr.t3_server_send - current_time)) / 2;

        double rtt_ms = rtt / 1e6;
        double offset_ms = offset / 1e6;

        // print live stats
        std::cout << "seq " << hdr.seq << " RTT " << rtt_ms << " ms"
                  << " | offset " << offset_ms << " ms" << std::string(20, ' ') << "\r" << std::flush;
    }

    void _handle_echo_message(std::size_t bytes) {
        EchoHdr ehdr{};
        std::memcpy(&ehdr, _recv_buf.data(), sizeof(EchoHdr));
        static int echo_count = 0;
        std::cout << "Echo " << ++echo_count << " from server: " << std::string(ehdr.data) << "\n";
    }

    void _handle_audio_message(std::size_t bytes) {
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
            _decode_audio_data(audio_data, encoded_bytes, decodedData);
        }

        if (!decodedData.empty()) {
            _process_decoded_audio(std::move(decodedData));
        }
    }

    void _decode_audio_data(const unsigned char *audio_data, uint16_t encoded_bytes, std::vector<float> &decodedData) {
        // Decode the received Opus data
        _audio.decode_opus(audio_data, encoded_bytes, 120, _audio.get_output_channel_count(), decodedData);

        // Diagnostic: Check decoded size periodically
        static int decode_count = 0;
        static int size_errors = 0;
        if (++decode_count % 400 == 0) {
            std::cout << "Client decoded " << decode_count << " packets, " << decodedData.size()
                      << " samples (expected " << (120 * _audio.get_output_channel_count()) << "), " << size_errors
                      << " size errors\n";
        }
        if (decodedData.size() != 120 * _audio.get_output_channel_count()) {
            size_errors++;
        }
    }

    void _process_decoded_audio(std::vector<float> decodedData) {
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

    // Helper methods for audio callback to reduce cognitive complexity
    struct AudioCallbackState {
        std::vector<float> decoded_data;
        std::vector<unsigned char> encoded_data;
        int underrun_count = 0;
        int playback_count = 0;
        int consecutive_low_buffer = 0;
        int consecutive_high_buffer = 0;
        std::chrono::steady_clock::time_point last_adaptation = std::chrono::steady_clock::now();
    };

    static void handle_audio_playback(client *client_ptr, float *output_buffer, unsigned long frame_count,
                                      size_t out_channels, size_t bytes_to_copy, AudioCallbackState &state) {
        size_t queue_size = client_ptr->_audio_recv_queue.size_approx();
        size_t current_min = client_ptr->_jitter_buffer_min_packets.load();
        size_t current_target = client_ptr->_jitter_buffer_target_packets.load();

        // Jitter buffer logic: only play if buffer is ready
        if (client_ptr->_jitter_buffer_ready && client_ptr->_audio_recv_queue.try_dequeue(state.decoded_data)) {
            // Validate decoded data size matches expected output
            size_t expected_samples = frame_count * out_channels;
            if (state.decoded_data.size() == expected_samples) {
                std::memcpy(output_buffer, state.decoded_data.data(), bytes_to_copy);
            } else {
                // Size mismatch - zero output and log warning
                std::memset(output_buffer, 0, bytes_to_copy);
                static int mismatch_count = 0;
                if (++mismatch_count % 100 == 0) {
                    std::cerr << "Client: Decoded size mismatch: got " << state.decoded_data.size()
                              << " samples, expected " << expected_samples << "\n";
                }
            }
            state.playback_count++;

            // Adaptive buffer management
            adapt_jitter_buffer(client_ptr, queue_size, current_min, current_target, state);

            // Warn if buffer is critically low
            if (queue_size < current_min - 1) {
                state.underrun_count++;
                if (state.underrun_count % 200 == 0) {
                    std::cout << "\nJitter buffer low (" << queue_size << "/" << current_min << " packets)\n";
                }
            } else {
                state.underrun_count = 0;
            }
        } else {
            // Buffer not ready or underrun - play silence
            std::memset(output_buffer, 0, bytes_to_copy);
            state.underrun_count++;

            // Print underrun stats periodically
            if (!client_ptr->_jitter_buffer_ready && state.underrun_count % 100 == 0) {
                // std::cout << "\nBuffering... (" << queue_size << "/" << current_min << " packets)\n";
            }

            // Reset buffer ready flag if we've drained completely
            if (client_ptr->_jitter_buffer_ready && queue_size == 0) {
                client_ptr->_jitter_buffer_ready = false;
                std::cout << "\nJitter buffer underrun! Rebuffering...\n";
                state.consecutive_low_buffer = 0;
                state.consecutive_high_buffer = 0;
            }
        }
    }

    static void adapt_jitter_buffer(client *client_ptr, size_t queue_size, size_t current_min, size_t current_target,
                                    AudioCallbackState &state) {
        auto now = std::chrono::steady_clock::now();
        auto time_since_adapt = std::chrono::duration_cast<std::chrono::milliseconds>(now - state.last_adaptation);

        // Only adapt every 1 second to avoid oscillation
        if (time_since_adapt.count() >= 1000) {
            // Track buffer health
            if (queue_size < current_min) {
                state.consecutive_low_buffer++;
                state.consecutive_high_buffer = 0;
            } else if (queue_size > current_target + 2) {
                state.consecutive_high_buffer++;
                state.consecutive_low_buffer = 0;
            } else {
                // Buffer in healthy range - decay counters slowly
                state.consecutive_low_buffer = std::max(0, state.consecutive_low_buffer - 1);
                state.consecutive_high_buffer = std::max(0, state.consecutive_high_buffer - 1);
            }

            // Increase buffer if consistently low (network jitter detected)
            if (state.consecutive_low_buffer >= 3 && current_min < client_ptr->_jitter_buffer_max_packets - 2) {
                size_t new_min = std::min(current_min + 2, client_ptr->_jitter_buffer_max_packets - 2);
                size_t new_target = std::min(current_target + 2, client_ptr->_jitter_buffer_max_packets);
                client_ptr->_jitter_buffer_min_packets.store(new_min);
                client_ptr->_jitter_buffer_target_packets.store(new_target);
                std::cout << "\nAdaptive: Increasing buffer to min=" << new_min << ", target=" << new_target
                          << " (high jitter detected)\n";
                state.consecutive_low_buffer = 0;
                state.last_adaptation = now;
            }
            // Decrease buffer if consistently high (stable network, reduce latency)
            else if (state.consecutive_high_buffer >= 5 && current_min > 3) {
                size_t new_min = std::max(current_min - 1, size_t(3));
                size_t new_target = std::max(current_target - 1, size_t(5));
                client_ptr->_jitter_buffer_min_packets.store(new_min);
                client_ptr->_jitter_buffer_target_packets.store(new_target);
                std::cout << "\nAdaptive: Decreasing buffer to min=" << new_min << ", target=" << new_target
                          << " (stable network)\n";
                state.consecutive_high_buffer = 0;
                state.last_adaptation = now;
            }
        }
    }

    static void handle_echo_monitoring(const float *input_buffer, float *output_buffer, unsigned long frame_count,
                                       size_t out_channels, bool echo_enabled) {
        if (echo_enabled && (input_buffer != nullptr)) {
            float self_gain = 1.0F; // Adjust to taste (0.0–1.0)
            for (size_t i = 0; i < frame_count; ++i) {
                float sample = input_buffer[i] * self_gain;
                output_buffer[(i * out_channels) + 0] += sample; // Left
                output_buffer[(i * out_channels) + 1] += sample; // Right
            }
        }
    }

    static void handle_audio_encoding(client *client_ptr, const float *input_buffer, unsigned long frame_count,
                                      AudioCallbackState &state) {
        if (input_buffer == nullptr) {
            // No input - send silence packet periodically to keep connection alive
            static int no_input_count = 0;
            if (++no_input_count % 100 == 0) {
                std::cerr << "Warning: No input audio (in == nullptr)\n";
            }
            return;
        }

        // Silence detection: Check if input has significant audio
        static constexpr float SILENCE_THRESHOLD = 0.001F; // -60dB
        float max_sample = 0.0F;
        for (unsigned long i = 0; i < frame_count; ++i) {
            float abs_sample = std::fabs(input_buffer[i]);
            max_sample = std::max(abs_sample, max_sample);
        }

        // Only encode and send if there's actual audio (not silence) and stream is active
        if (max_sample > SILENCE_THRESHOLD && client_ptr->_audio.is_stream_active()) {
            client_ptr->_audio.encode_opus(input_buffer, frame_count, state.encoded_data);

            // Diagnostic: Check encoding success
            static int encode_count = 0;
            static int encode_failures = 0;
            encode_count++;
            if (state.encoded_data.empty()) {
                encode_failures++;
            }
            if (encode_count % 400 == 0) {
                std::cout << "Client encoded " << encode_count << " packets, " << encode_failures
                          << " failures, last size: " << state.encoded_data.size() << " bytes, peak: " << max_sample
                          << "\n";
            }

            if (!state.encoded_data.empty()) {
                AudioHdr ahdr{};
                ahdr.magic = AUDIO_MAGIC;
                ahdr.encoded_bytes = static_cast<uint16_t>(state.encoded_data.size());
                std::memcpy(ahdr.buf, state.encoded_data.data(), std::min(state.encoded_data.size(), sizeof(ahdr.buf)));
                size_t packetSize = sizeof(MsgHdr) + sizeof(uint16_t) + ahdr.encoded_bytes;
                client_ptr->send(&ahdr, packetSize);
            }
        } else {
            // Silence detected - don't send packet (save bandwidth and prevent glitches)
            static int silence_count = 0;
            if (++silence_count % 400 == 0) {
                // std::cout << "Client: " << silence_count << " silent frames skipped\n";
            }
        }
    }

    static int audio_callback(const void *input, void *output, unsigned long frame_count,
                              const PaStreamCallbackTimeInfo * /*unused*/, PaStreamCallbackFlags /*unused*/,
                              void *user_data) {
        const auto *input_buffer = static_cast<const float *>(input);
        auto *output_buffer = static_cast<float *>(output);
        if (output_buffer == nullptr) {
            return paContinue;
        }

        auto *client_ptr = static_cast<client *>(user_data);

        // Use static state to avoid allocations (reused across calls)
        static AudioCallbackState state;

        size_t out_channels = client_ptr->_audio.get_output_channel_count(); // 2
        size_t bytes_to_copy = frame_count * out_channels * sizeof(float);

        // 1. Play received audio from server (with adaptive jitter buffer)
        client::handle_audio_playback(client_ptr, output_buffer, frame_count, out_channels, bytes_to_copy, state);

        // 2. Mix in your own live instrument (local monitor)
        client::handle_echo_monitoring(input_buffer, output_buffer, frame_count, out_channels,
                                       client_ptr->is_echo_enabled());

        // 3. Encode and send to server
        client::handle_audio_encoding(client_ptr, input_buffer, frame_count, state);

        return paContinue;
    }
};

int main() {
    try {
        asio::io_context io_context;
        client client_instance(io_context, "127.0.0.1", 9999);
        // client_instance.start_connection("127.0.0.1", 9999);
        // client_instance.start_audio_stream(15, 17, 120);

        // Create TCP server on a separate thread with its own io_context
        std::thread tcp_server_thread([&]() {
            try {
                asio::io_context tcp_io_context;
                tcp_control_server server(tcp_io_context, 9969);
                server.add_endpoint("GET", "/join",
                                    [&client_instance, &io_context](const std::string &method, const std::string &path,
                                                                    const std::string &body) {
                                        // Post audio operations to the main thread's io_context
                                        asio::post(io_context, [&client_instance]() {
                                            client_instance.start_connection("127.0.0.1", 9999);
                                            client_instance.start_audio_stream(17, 15, 120);
                                            client_instance.enable_echo(true);
                                        });

                                        return tcp_control_server::http_response(
                                            tcp_control_server::HTTP_OK, "OK",
                                            "Audio connection started. Echo enabled. Try speaking!");
                                    });

                server.add_endpoint("GET", "/exit",
                                    [&client_instance, &io_context](const std::string &method, const std::string &path,
                                                                    const std::string &body) {
                                        // Post audio operations to the main thread's io_context
                                        asio::post(io_context, [&client_instance]() {
                                            client_instance.stop_connection();
                                            client_instance.stop_audio_stream();
                                            client_instance.enable_echo(false);
                                        });

                                        return tcp_control_server::http_response(tcp_control_server::HTTP_OK, "OK",
                                                                                 "Audio connection stopped.");
                                    });
                server.add_endpoint(
                    "GET", "/devices", [](const std::string &method, const std::string &path, const std::string &body) {
                        return tcp_control_server::http_response(tcp_control_server::HTTP_OK, "OK",
                                                                 audio_stream::get_devices_json(), "application/json");
                    });
                server.add_endpoint("GET", "/devices/mme",
                                    [](const std::string &method, const std::string &path, const std::string &body) {
                                        return tcp_control_server::http_response(tcp_control_server::HTTP_OK, "OK",
                                                                                 audio_stream::get_devices_json("MME"),
                                                                                 "application/json");
                                    });
                server.add_endpoint("GET", "/devices/wasapi",
                                    [](const std::string &method, const std::string &path, const std::string &body) {
                                        return tcp_control_server::http_response(
                                            tcp_control_server::HTTP_OK, "OK",
                                            audio_stream::get_devices_json("Windows WASAPI"), "application/json");
                                    });
                server.add_endpoint("GET", "/devices/directsound",
                                    [](const std::string &method, const std::string &path, const std::string &body) {
                                        return tcp_control_server::http_response(
                                            tcp_control_server::HTTP_OK, "OK",
                                            audio_stream::get_devices_json("Windows DirectSound"), "application/json");
                                    });
                tcp_io_context.run();
            } catch (std::exception &e) {
                std::cerr << "TCP Server ERR: " << e.what() << "\n";
            }
        });

        // Run the main UDP client on the main thread
        io_context.run();

        // Wait for TCP server thread to finish
        if (tcp_server_thread.joinable()) {
            tcp_server_thread.join();
        }
    } catch (std::exception &e) {
        std::cerr << "ERR: " << e.what() << "\n";
    }
}