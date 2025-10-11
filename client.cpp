#include <array>
#include <asio.hpp>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <opus.h>
#include <portaudio.h>
#include <unordered_map>

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
        if (opus_encoder) {
            opus_encoder_destroy(opus_encoder);
            opus_encoder = nullptr;
        }
        if (opus_decoder) {
            opus_decoder_destroy(opus_decoder);
            opus_decoder = nullptr;
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

        PaStreamParameters inputParameters = {inputDevice, std::min(inputInfo->maxInputChannels, 2), paFloat32,
                                              inputInfo->defaultLowInputLatency, nullptr};

        PaStreamParameters outputParameters = {outputDevice, std::min(outputInfo->maxOutputChannels, 2), paFloat32,
                                               outputInfo->defaultLowOutputLatency, nullptr};

        _input_channel_count = inputParameters.channelCount;
        _output_channel_count = outputParameters.channelCount;
        _channel_count = 2;

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

        init_opus(static_cast<int>(inputInfo->defaultSampleRate), _channel_count);
    }

    void encode_opus(const float *input, int frameSize, int sampleRate, std::vector<unsigned char> &output) {
        if (!opus_encoder) {
            std::cerr << "Opus encoder not initialized.\n";
            output.clear();
            return;
        }
        output.resize(256); // Allocate enough space for encoded data
        int encodedBytes = opus_encode_float(opus_encoder, input, frameSize, output.data(), output.size());
        if (encodedBytes < 0) {
            std::cerr << "Opus encoding failed: " << opus_strerror(encodedBytes) << "\n";
            output.clear();
        } else {
            output.resize(encodedBytes); // Resize to actual encoded size
        }
    }

    void decode_opus(const unsigned char *input, int inputSize, int frameSize, int channelCount,
                     std::vector<float> &output) {
        if (!opus_decoder) {
            std::cerr << "Opus decoder not initialized.\n";
            output.clear();
            return;
        }
        output.resize(frameSize * channelCount); // Allocate space for decoded PCM (frameSize is samples per channel)
        // opus_decode_float returns samples per channel decoded
        int decodedSamplesPerChannel = opus_decode_float(opus_decoder, input, inputSize, output.data(), frameSize, 0);
        if (decodedSamplesPerChannel < 0) {
            std::cerr << "Opus decoding failed: " << opus_strerror(decodedSamplesPerChannel) << "\n";
            output.clear();
        } else {
            // The output buffer now contains decodedSamplesPerChannel * channelCount total samples
            output.resize(decodedSamplesPerChannel * channelCount);
        }
    }

    void init_opus(int sampleRate = 48000, int channels = 2, int application = OPUS_APPLICATION_AUDIO,
                   int complexity = 5, int bitrate = 96000) {
        if (opus_encoder) {
            opus_encoder_destroy(opus_encoder);
            opus_encoder = nullptr;
        }
        if (opus_decoder) {
            opus_decoder_destroy(opus_decoder);
            opus_decoder = nullptr;
        }

        std::cout << "Initializing Opus encoder/decoder...\n";

        int err;
        opus_encoder = opus_encoder_create(sampleRate, channels, application, &err);
        if (err != OPUS_OK) {
            std::cerr << "Failed to create Opus encoder: " << opus_strerror(err) << "\n";
            opus_encoder = nullptr;
            return;
        }
        opus_decoder = opus_decoder_create(sampleRate, channels, &err);
        if (err != OPUS_OK) {
            std::cerr << "Failed to create Opus decoder: " << opus_strerror(err) << "\n";
            opus_decoder = nullptr;
            return;
        }

        // Set encoder options for low-latency music streaming
        opus_encoder_ctl(opus_encoder, OPUS_SET_COMPLEXITY(complexity));
        opus_encoder_ctl(opus_encoder, OPUS_SET_BITRATE(bitrate));
        opus_encoder_ctl(opus_encoder, OPUS_SET_SIGNAL(OPUS_SIGNAL_MUSIC));
        opus_encoder_ctl(opus_encoder, OPUS_SET_VBR(1));              // Variable bitrate for better quality
        opus_encoder_ctl(opus_encoder, OPUS_SET_VBR_CONSTRAINT(0));   // Unconstrained VBR for music
        opus_encoder_ctl(opus_encoder, OPUS_SET_INBAND_FEC(1));       // Forward error correction for UDP
        opus_encoder_ctl(opus_encoder, OPUS_SET_PACKET_LOSS_PERC(5)); // Expect some packet loss
        opus_encoder_ctl(opus_encoder, OPUS_SET_DTX(0));              // Disable DTX for music (no silence detection)
    }

    void destroy_opus() {
        if (opus_encoder) {
            opus_encoder_destroy(opus_encoder);
            opus_encoder = nullptr;
        }
        if (opus_decoder) {
            opus_decoder_destroy(opus_decoder);
            opus_decoder = nullptr;
        }
    }

    int get_channel_count() const { return _channel_count; }
    int get_input_channel_count() const { return _input_channel_count; }
    int get_output_channel_count() const { return _output_channel_count; }

    std::vector<float> stereo_buffer;

  private:
    PaStream *_stream = nullptr;
    OpusEncoder *opus_encoder = nullptr;
    OpusDecoder *opus_decoder = nullptr;
    int _channel_count;
    int _input_channel_count;
    int _output_channel_count;
};

class client {

  public:
    client(asio::io_context &io, const std::string &server_ip, short server_port)
        : _socket(io, udp::endpoint(udp::v4(), 0)), _ping_timer(io, 100ms, [this]() { _ping_timer_callback(); }),
          _alive_timer(io, 5s, [this]() { _alive_timer_callback(); }) {

        std::cout << "Client local port: " << _socket.local_endpoint().port() << "\n";
        _server_endpoint = udp::endpoint(asio::ip::make_address(server_ip), server_port);

        CtrlHdr chdr{};
        chdr.magic = CTRL_MAGIC;
        chdr.type = CtrlHdr::Cmd::JOIN;
        std::memcpy(_ctrl_tx_buf.data(), &chdr, sizeof(CtrlHdr));
        send(_ctrl_tx_buf.data(), sizeof(CtrlHdr));

        _audio.start_audio_stream(17, 14, 120, audio_callback, this);

        do_receive();
    }

    void on_receive(std::error_code ec, std::size_t bytes) {
        if (ec) {
            std::cerr << "receive error: " << ec.message() << "\n";
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
                // std::cout << "seq " << hdr.seq << " RTT " << rtt_ms << " ms"
                //           << " | offset " << offset_ms << " ms" << std::string(20, ' ') << "\r" << std::flush;
            } else if (hdr.magic == ECHO_MAGIC && bytes >= sizeof(EchoHdr)) {
                EchoHdr ehdr{};
                std::memcpy(&ehdr, _recv_buf.data(), sizeof(EchoHdr));
                std::cout << "Echo from server: " << std::string(ehdr.data) << "\n";
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

    static int audio_callback(const void *input, void *output, unsigned long frameCount,
                              const PaStreamCallbackTimeInfo *, PaStreamCallbackFlags, void *userData) {

        const float *in = static_cast<const float *>(input);
        float *out = static_cast<float *>(output);

        client *cl = static_cast<client *>(userData);
        if (!cl)
            return paContinue;

        if (!out)
            return paContinue;

        if (cl->_audio.get_input_channel_count() < 2) {
            // duplicate mono to stereo
            cl->_audio.stereo_buffer.resize(frameCount * 2);
            if (in) {
                for (unsigned long i = 0; i < frameCount; ++i) {
                    cl->_audio.stereo_buffer[i * 2] = in[i];
                    cl->_audio.stereo_buffer[i * 2 + 1] = in[i];
                }
                in = cl->_audio.stereo_buffer.data();
            }
        }

        size_t bytesToCopy = frameCount * cl->_audio.get_channel_count() * sizeof(float);


        std::vector<unsigned char> encodedData;
        cl->_audio.encode_opus(in, frameCount, 48000, encodedData);

        std::vector<float> decodedData;
        if (!encodedData.empty()) {
            cl->_audio.decode_opus(encodedData.data(), encodedData.size(), frameCount, cl->_audio.get_channel_count(),
                                   decodedData);
        }

        if (!decodedData.empty()) {
            std::memcpy(out, decodedData.data(), bytesToCopy);
        } else {
            std::memset(out, 0, bytesToCopy);
        }

        AudioHdr ahdr{};
        ahdr.magic = AUDIO_MAGIC;
        ahdr.encoded_bytes = static_cast<uint8_t>(encodedData.size());
        std::memcpy(ahdr.buf, encodedData.data(), std::min(encodedData.size(), sizeof(ahdr.buf)));
        // cl->send(&ahdr, sizeof(MsgHdr) + 1 + ahdr.encoded_bytes);
        cl->send(&ahdr, sizeof(AudioHdr));

        // if (!in)
        //     std::memset(out, 0, bytesToCopy);
        // else
        //     std::memcpy(out, in, bytesToCopy);

        // static size_t totalKB = 0;
        // totalKB += bytesToCopy / 1024;
        // std::cout << bytesToCopy << " bytes (" << totalKB << " KB)\r" << std::flush;

        return paContinue;
    }

  private:
    udp::socket _socket;
    udp::endpoint _server_endpoint;

    std::array<char, 1024> _recv_buf;
    std::array<unsigned char, 128> _sync_tx_buf;
    std::array<unsigned char, 128> _ctrl_tx_buf;

    audio_stream _audio;

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