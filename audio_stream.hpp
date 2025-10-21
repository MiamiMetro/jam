#pragma once

#include "logger.hpp"
#include "opus_decoder.hpp"
#include "opus_encoder.hpp"
#include <atomic>
#include <nlohmann/json.hpp>
#include <portaudio.h>


class audio_stream {
  public:
    struct AudioConfig {
        int sample_rate{};
        int bitrate{};
        int complexity{};
        int frames_per_buffer{};
        float input_gain{};
        float output_gain{};

        AudioConfig()
            : sample_rate(48000), bitrate(64000), complexity(2), frames_per_buffer(240), input_gain(1.0F),
              output_gain(1.0F) {}
    };

    audio_stream() { Pa_Initialize(); }

    ~audio_stream() {
        if (_stream != nullptr) {
            Pa_StopStream(_stream);
            Pa_CloseStream(_stream);
        }

        Pa_Terminate();
    }

    static nlohmann::json get_devices_json(const std::string &hostApiName = "") {
        nlohmann::json devices = nlohmann::json::array();
        int numDevices = Pa_GetDeviceCount();

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

            // Much cleaner and faster - no string concatenation!
            nlohmann::json device;
            device["index"] = i;
            device["name"] = deviceInfo->name;
            device["maxInputChannels"] = deviceInfo->maxInputChannels;
            device["maxOutputChannels"] = deviceInfo->maxOutputChannels;
            device["defaultSampleRate"] = deviceInfo->defaultSampleRate;
            device["hostApi"] = apiName;

            devices.push_back(device);
        }

        return devices;
    }

    static nlohmann::json get_host_apis_json() {
        nlohmann::json hostApis = nlohmann::json::array();
        int numHostApis = Pa_GetHostApiCount();

        for (int i = 0; i < numHostApis; ++i) {
            const PaHostApiInfo *hostApiInfo = Pa_GetHostApiInfo(i);
            if (hostApiInfo == nullptr) {
                continue;
            }

            nlohmann::json api;
            api["index"] = i;
            api["name"] = hostApiInfo->name;
            api["type"] = static_cast<int>(hostApiInfo->type);
            api["deviceCount"] = hostApiInfo->deviceCount;
            api["defaultInputDevice"] = hostApiInfo->defaultInputDevice;
            api["defaultOutputDevice"] = hostApiInfo->defaultOutputDevice;

            hostApis.push_back(api);
        }

        return hostApis;
    }

    static const PaDeviceInfo *get_device_info(int deviceIndex) {
        const PaDeviceInfo *deviceInfo = Pa_GetDeviceInfo(deviceIndex);
        if (deviceInfo == nullptr) {
            Log::error("Invalid device index: {}", deviceIndex);
            return nullptr;
        }
        return deviceInfo;
    }

    static bool is_device_valid(int deviceIndex) {
        return deviceIndex >= 0 && deviceIndex < Pa_GetDeviceCount() && Pa_GetDeviceInfo(deviceIndex) != nullptr;
    }

    static void print_device_info(const PaDeviceInfo *inputInfo, const PaDeviceInfo *outputInfo) {
        Log::info("Input Device: {} | API: {} | Max Input Channels: {} | Default Sample Rate: {}", inputInfo->name,
                  (Pa_GetHostApiInfo(inputInfo->hostApi) != nullptr) ? Pa_GetHostApiInfo(inputInfo->hostApi)->name
                                                                     : "Unknown",
                  inputInfo->maxInputChannels, inputInfo->defaultSampleRate);
        Log::info("Output Device: {} | API: {} | Max Output Channels: {} | Default Sample Rate: {}", outputInfo->name,
                  (Pa_GetHostApiInfo(outputInfo->hostApi) != nullptr) ? Pa_GetHostApiInfo(outputInfo->hostApi)->name
                                                                      : "Unknown",
                  outputInfo->maxOutputChannels, outputInfo->defaultSampleRate);
    }

    bool start_audio_stream(PaDeviceIndex inputDevice, PaDeviceIndex outputDevice,
                            const AudioConfig &config = AudioConfig{}, PaStreamCallback *callback = nullptr,
                            void *userData = nullptr) {
        // Validate devices
        if (!is_device_valid(inputDevice) || !is_device_valid(outputDevice)) {
            Log::error("Invalid input or output device.");
            return false;
        }

        const auto *inputInfo = get_device_info(inputDevice);
        const auto *outputInfo = get_device_info(outputDevice);

        PaStreamParameters inputParameters = {inputDevice, std::min(inputInfo->maxInputChannels, 1), paFloat32,
                                              inputInfo->defaultLowInputLatency, nullptr};

        PaStreamParameters outputParameters = {outputDevice, std::min(outputInfo->maxOutputChannels, 2), paFloat32,
                                               outputInfo->defaultLowOutputLatency, nullptr};

        _input_channel_count = inputParameters.channelCount;
        _output_channel_count = outputParameters.channelCount;
        _current_config = config;

        print_device_info(inputInfo, outputInfo);
        Log::info("Frames per buffer: {}", config.frames_per_buffer);
        Log::info("Sample rate: {} Hz", config.sample_rate);
        Log::info("Bitrate: {} bps", config.bitrate);

        PaError err = Pa_OpenStream(&_stream, &inputParameters, &outputParameters, config.sample_rate,
                                    config.frames_per_buffer, paNoFlag, callback, userData);
        if (err != paNoError) {
            Log::error("Pa_OpenStream failed: {}", Pa_GetErrorText(err));
            _stream = nullptr;
            return false;
        }
        err = Pa_StartStream(_stream);
        if (err != paNoError) {
            Log::error("Pa_StartStream failed: {}", Pa_GetErrorText(err));
            Pa_CloseStream(_stream);
            _stream = nullptr;
            return false;
        }
        _stream_active.store(true, std::memory_order_relaxed);

        Log::info("{} input channel(s), {} output channel(s) at {} Hz", _input_channel_count, _output_channel_count,
                  config.sample_rate);

        // Create encoder and decoder with config
        Log::info("Creating client encoder (mono) and decoder (stereo) with {} bps bitrate, complexity {}",
                  config.bitrate, config.complexity);
        _encoder.create(config.sample_rate, _input_channel_count, OPUS_APPLICATION_AUDIO, config.bitrate,
                        config.complexity);
        _decoder.create(config.sample_rate, _output_channel_count);

        return true;
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
            Log::info("Input latency:  {:.3f} ms", streamInfo->inputLatency * SECONDS_TO_MILLISECONDS);
            Log::info("Output latency: {:.3f} ms", streamInfo->outputLatency * SECONDS_TO_MILLISECONDS);
            Log::info("Sample rate:    {:.1f} Hz", streamInfo->sampleRate);
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

    // Simple configuration getter
    AudioConfig get_config() const { return _current_config; }

  private:
    PaStream *_stream = nullptr;
    opus_encoder_wrapper _encoder;
    opus_decoder_wrapper _decoder;
    std::atomic<bool> _stream_active{false};
    AudioConfig _current_config;

    int _input_channel_count;
    int _output_channel_count;
};