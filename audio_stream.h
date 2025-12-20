#pragma once

#include <algorithm>
#include <atomic>
#include <string>
#include <vector>

#include <opus_defines.h>
#include <portaudio.h>

#include "logger.h"
#include "opus_decoder.h"
#include "opus_encoder.h"

class AudioStream {
public:
    struct AudioConfig {
        static constexpr int   DEFAULT_SAMPLE_RATE       = 48000;
        static constexpr int   DEFAULT_BITRATE           = 64000;
        static constexpr int   DEFAULT_COMPLEXITY        = 2;
        static constexpr int   DEFAULT_FRAMES_PER_BUFFER = 240;
        static constexpr float DEFAULT_INPUT_GAIN        = 1.0F;
        static constexpr float DEFAULT_OUTPUT_GAIN       = 1.0F;

        int   sample_rate{};
        int   bitrate{};
        int   complexity{};
        int   frames_per_buffer{};
        float input_gain{};
        float output_gain{};

        AudioConfig()
            : sample_rate(DEFAULT_SAMPLE_RATE),
              bitrate(DEFAULT_BITRATE),
              complexity(DEFAULT_COMPLEXITY),
              frames_per_buffer(DEFAULT_FRAMES_PER_BUFFER),
              input_gain(DEFAULT_INPUT_GAIN),
              output_gain(DEFAULT_OUTPUT_GAIN) {}
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
            output_device, std::min(output_info->maxOutputChannels, 1), paFloat32,
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

        return true;
    }

    void stop_audio_stream() {
        stream_active_.store(false, std::memory_order_relaxed);
        if (stream_ != nullptr) {
            Pa_StopStream(stream_);
            Pa_CloseStream(stream_);
            stream_ = nullptr;
        }
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
    PaStream*         stream_ = nullptr;
    std::atomic<bool> stream_active_{false};
    AudioConfig       current_config_;

    int input_channel_count_;
    int output_channel_count_;
};