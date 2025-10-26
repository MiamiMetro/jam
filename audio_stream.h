#pragma once

#include <atomic>
#include <nlohmann/json.hpp>
#include <portaudio.h>
#include "logger.h"
#include "opus_decoder.h"
#include "opus_encoder.h"

class AudioStream {
public:
    struct AudioConfig {
        int   sample_rate{};
        int   bitrate{};
        int   complexity{};
        int   frames_per_buffer{};
        float input_gain{};
        float output_gain{};

        AudioConfig()
            : sample_rate(48000),
              bitrate(64000),
              complexity(2),
              frames_per_buffer(240),
              input_gain(1.0F),
              output_gain(1.0F) {}
    };

    AudioStream() {
        Pa_Initialize();
    }

    ~AudioStream() {
        if (stream_ != nullptr) {
            Pa_StopStream(stream_);
            Pa_CloseStream(stream_);
        }

        Pa_Terminate();
    }

    static nlohmann::json get_devices_json(const std::string& host_api_name = "") {
        nlohmann::json devices    = nlohmann::json::array();
        int            numDevices = Pa_GetDeviceCount();

        for (int i = 0; i < numDevices; ++i) {
            const PaDeviceInfo* device_info = Pa_GetDeviceInfo(i);
            if (device_info == nullptr) {
                continue;
            }

            const PaHostApiInfo* hostApiInfo = Pa_GetHostApiInfo(device_info->hostApi);
            std::string api_name = (hostApiInfo != nullptr) ? hostApiInfo->name : "Unknown API";

            if (!host_api_name.empty() && api_name != host_api_name) {
                continue;
            }

            // Much cleaner and faster - no string concatenation!
            nlohmann::json device;
            device["index"]             = i;
            device["name"]              = device_info->name;
            device["maxInputChannels"]  = device_info->maxInputChannels;
            device["maxOutputChannels"] = device_info->maxOutputChannels;
            device["defaultSampleRate"] = device_info->defaultSampleRate;
            device["hostApi"]           = api_name;

            devices.push_back(device);
        }

        return devices;
    }

    static nlohmann::json get_host_apis_json() {
        nlohmann::json hostApis    = nlohmann::json::array();
        int            numHostApis = Pa_GetHostApiCount();

        for (int i = 0; i < numHostApis; ++i) {
            const PaHostApiInfo* hostApiInfo = Pa_GetHostApiInfo(i);
            if (hostApiInfo == nullptr) {
                continue;
            }

            nlohmann::json api;
            api["index"]               = i;
            api["name"]                = hostApiInfo->name;
            api["type"]                = static_cast<int>(hostApiInfo->type);
            api["deviceCount"]         = hostApiInfo->deviceCount;
            api["defaultInputDevice"]  = hostApiInfo->defaultInputDevice;
            api["defaultOutputDevice"] = hostApiInfo->defaultOutputDevice;

            hostApis.push_back(api);
        }

        return hostApis;
    }

    static const PaDeviceInfo* get_device_info(int device_index) {
        const PaDeviceInfo* device_info = Pa_GetDeviceInfo(device_index);
        if (device_info == nullptr) {
            Log::error("Invalid device index: {}", device_index);
            return nullptr;
        }
        return device_info;
    }

    static bool is_device_valid(int device_index) {
        return device_index >= 0 && device_index < Pa_GetDeviceCount() &&
               Pa_GetDeviceInfo(device_index) != nullptr;
    }

    static void print_device_info(const PaDeviceInfo* input_info, const PaDeviceInfo* output_info) {
        Log::info("Input Device: {} | API: {} | Max Input Channels: {} | Default Sample Rate: {}",
                  input_info->name,
                  (Pa_GetHostApiInfo(input_info->hostApi) != nullptr)
                      ? Pa_GetHostApiInfo(input_info->hostApi)->name
                      : "Unknown",
                  input_info->maxInputChannels, input_info->defaultSampleRate);
        Log::info("Output Device: {} | API: {} | Max Output Channels: {} | Default Sample Rate: {}",
                  output_info->name,
                  (Pa_GetHostApiInfo(output_info->hostApi) != nullptr)
                      ? Pa_GetHostApiInfo(output_info->hostApi)->name
                      : "Unknown",
                  output_info->maxOutputChannels, output_info->defaultSampleRate);
    }

    bool start_audio_stream(PaDeviceIndex input_device, PaDeviceIndex output_device,
                            const AudioConfig& config  = AudioConfig{},
                            PaStreamCallback* callback = nullptr, void* user_data = nullptr) {
        // Validate devices
        if (!is_device_valid(input_device) || !is_device_valid(output_device)) {
            Log::error("Invalid input or output device.");
            return false;
        }

        const auto* input_info  = get_device_info(input_device);
        const auto* output_info = get_device_info(output_device);

        PaStreamParameters input_parameters = {input_device,
                                               std::min(input_info->maxInputChannels, 1), paFloat32,
                                               input_info->defaultLowInputLatency, nullptr};

        PaStreamParameters output_parameters = {
            output_device, std::min(output_info->maxOutputChannels, 2), paFloat32,
            output_info->defaultLowOutputLatency, nullptr};

        input_channel_count_  = input_parameters.channelCount;
        output_channel_count_ = output_parameters.channelCount;
        current_config_       = config;

        print_device_info(input_info, output_info);
        Log::info("Frames per buffer: {}", config.frames_per_buffer);
        Log::info("Sample rate: {} Hz", config.sample_rate);
        Log::info("Bitrate: {} bps", config.bitrate);

        PaError err =
            Pa_OpenStream(&stream_, &input_parameters, &output_parameters, config.sample_rate,
                          config.frames_per_buffer, paNoFlag, callback, user_data);
        if (err != paNoError) {
            Log::error("Pa_OpenStream failed: {}", Pa_GetErrorText(err));
            stream_ = nullptr;
            return false;
        }
        err = Pa_StartStream(stream_);
        if (err != paNoError) {
            Log::error("Pa_StartStream failed: {}", Pa_GetErrorText(err));
            Pa_CloseStream(stream_);
            stream_ = nullptr;
            return false;
        }
        stream_active_.store(true, std::memory_order_relaxed);

        Log::info("{} input channel(s), {} output channel(s) at {} Hz", input_channel_count_,
                  output_channel_count_, config.sample_rate);

        // Create encoder and decoder with config
        Log::info(
            "Creating client encoder (mono) and decoder (stereo) with {} bps bitrate, complexity "
            "{}",
            config.bitrate, config.complexity);
        encoder_.create(config.sample_rate, input_channel_count_, OPUS_APPLICATION_AUDIO,
                        config.bitrate, config.complexity);
        decoder_.create(config.sample_rate, output_channel_count_);

        return true;
    }

    void stop_audio_stream() {
        stream_active_.store(false, std::memory_order_relaxed);
        if (stream_ != nullptr) {
            Pa_StopStream(stream_);
            Pa_CloseStream(stream_);
            stream_ = nullptr;
        }
        encoder_.destroy();
        decoder_.destroy();
    }

    void print_latency_info() {
        const PaStreamInfo* stream_info = Pa_GetStreamInfo(stream_);
        if (stream_info != nullptr) {
            static constexpr double SECONDS_TO_MILLISECONDS = 1000.0;
            Log::info("Input latency:  {:.3f} ms",
                      stream_info->inputLatency * SECONDS_TO_MILLISECONDS);
            Log::info("Output latency: {:.3f} ms",
                      stream_info->outputLatency * SECONDS_TO_MILLISECONDS);
            Log::info("Sample rate:    {:.1f} Hz", stream_info->sampleRate);
        }
    }

    void encode_opus(const float* input, int frame_size, std::vector<unsigned char>& output) {
        encoder_.encode(input, frame_size, output);
    }

    void decode_opus(const unsigned char* input, int input_size, int frame_size, int channel_count,
                     std::vector<float>& output) {
        decoder_.decode(input, input_size, frame_size, output);
    }

    int get_input_channel_count() const {
        return input_channel_count_;
    }
    int get_output_channel_count() const {
        return output_channel_count_;
    }
    bool is_stream_active() const {
        return stream_active_.load(std::memory_order_relaxed);
    }

    AudioConfig get_config() const {
        return current_config_;
    }

private:
    PaStream*          stream_ = nullptr;
    OpusEncoderWrapper encoder_;
    OpusDecoderWrapper decoder_;
    std::atomic<bool>  stream_active_{false};
    AudioConfig        current_config_;

    int input_channel_count_;
    int output_channel_count_;
};