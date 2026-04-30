#pragma once

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include <RtAudio.h>
#include <opus_defines.h>

#include "logger.h"
#include "opus_decoder.h"
#include "opus_encoder.h"

class AudioStream {
public:
    using DeviceIndex = unsigned int;
    using AudioCallback =
        int (*)(const void* input, void* output, unsigned long frame_count, void* user_data);

    static constexpr DeviceIndex NO_DEVICE = 0;

    // Static error storage for UI display
    static inline std::string last_error_;

    static const std::string& get_last_error() { return last_error_; }
    static void               clear_last_error() { last_error_.clear(); }

    struct AudioConfig {
        static constexpr int   DEFAULT_SAMPLE_RATE       = 48000;
        static constexpr int   DEFAULT_BITRATE           = 96000;
        static constexpr int   DEFAULT_COMPLEXITY        = 5;
        static constexpr int   DEFAULT_FRAMES_PER_BUFFER = 240;  // 5ms (optimal for stability)
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

    struct DeviceInfo {
        DeviceIndex index = NO_DEVICE;
        std::string name;
        std::string api_name;
        int         api_index = -1;
        int         max_input_channels = 0;
        int         max_output_channels = 0;
        double      default_sample_rate = 0.0;
        bool        is_default_input = false;
        bool        is_default_output = false;
    };

    struct ApiInfo {
        int         index = -1;
        std::string name;
        DeviceIndex default_input_device = NO_DEVICE;
        DeviceIndex default_output_device = NO_DEVICE;
    };

    AudioStream() : input_channel_count_(0), output_channel_count_(0) {}

    ~AudioStream() {
        stop_audio_stream();
    }

    static void print_all_devices() {
        Log::info("Available audio devices:");
        for (const auto& device_info: get_all_devices()) {
            Log::info(
                "Device {}: {} | API: {} | Max Input Channels: {} | Max Output Channels: {} | "
                "Default Sample Rate: {}",
                device_info.index, device_info.name, device_info.api_name,
                device_info.max_input_channels, device_info.max_output_channels,
                device_info.default_sample_rate);
        }
    }

    static const DeviceInfo* get_device_info(DeviceIndex device_index) {
        static thread_local std::vector<DeviceInfo> cached_devices;
        cached_devices = get_all_devices();
        auto it = std::find_if(cached_devices.begin(), cached_devices.end(), [&](const DeviceInfo& device) {
            return device.index == device_index;
        });
        if (it == cached_devices.end()) {
            Log::error("Invalid device index: {}", device_index);
            return nullptr;
        }

        return &(*it);
    }

    static bool is_device_valid(DeviceIndex device_index) {
        if (device_index == NO_DEVICE) {
            return false;
        }

        auto devices = get_all_devices();
        return std::any_of(devices.begin(), devices.end(), [&](const DeviceInfo& device) {
            return device.index == device_index;
        });
    }

    static std::vector<DeviceInfo> get_input_devices() {
        std::vector<DeviceInfo> result;
        for (const auto& device: get_all_devices()) {
            if (device.max_input_channels > 0) {
                result.push_back(device);
            }
        }
        return result;
    }

    static std::vector<DeviceInfo> get_output_devices() {
        std::vector<DeviceInfo> result;
        for (const auto& device: get_all_devices()) {
            if (device.max_output_channels > 0) {
                result.push_back(device);
            }
        }
        return result;
    }

    static std::vector<ApiInfo> get_apis() {
        std::vector<ApiInfo> apis;
        std::vector<RtAudio::Api> compiled_apis;
        RtAudio::getCompiledApi(compiled_apis);

        for (const auto api: compiled_apis) {
            if (api == RtAudio::UNSPECIFIED) {
                continue;
            }

            try {
                RtAudio audio(api);
                ApiInfo info;
                info.index = static_cast<int>(apis.size());
                info.name = RtAudio::getApiDisplayName(api);
                info.default_input_device = audio.getDefaultInputDevice();
                info.default_output_device = audio.getDefaultOutputDevice();
                apis.push_back(info);
            } catch (const std::exception& e) {
                Log::debug("Skipping RtAudio API {}: {}", RtAudio::getApiDisplayName(api),
                           e.what());
            }
        }

        return apis;
    }

    static DeviceIndex get_default_input_device() {
        auto devices = get_all_devices();
        auto asio_it = std::find_if(devices.begin(), devices.end(), [](const DeviceInfo& device) {
            return device.api_name == "ASIO" && device.is_default_input &&
                   device.max_input_channels > 0;
        });
        if (asio_it != devices.end()) {
            return asio_it->index;
        }

        asio_it = std::find_if(devices.begin(), devices.end(), [](const DeviceInfo& device) {
            return device.api_name == "ASIO" && device.max_input_channels > 0;
        });
        if (asio_it != devices.end()) {
            return asio_it->index;
        }

        auto it = std::find_if(devices.begin(), devices.end(), [](const DeviceInfo& device) {
            return device.is_default_input && device.max_input_channels > 0;
        });
        if (it != devices.end()) {
            return it->index;
        }

        it = std::find_if(devices.begin(), devices.end(), [](const DeviceInfo& device) {
            return device.max_input_channels > 0;
        });
        return it != devices.end() ? it->index : NO_DEVICE;
    }

    static DeviceIndex get_default_output_device() {
        auto devices = get_all_devices();
        auto asio_it = std::find_if(devices.begin(), devices.end(), [](const DeviceInfo& device) {
            return device.api_name == "ASIO" && device.is_default_output &&
                   device.max_output_channels > 0;
        });
        if (asio_it != devices.end()) {
            return asio_it->index;
        }

        asio_it = std::find_if(devices.begin(), devices.end(), [](const DeviceInfo& device) {
            return device.api_name == "ASIO" && device.max_output_channels > 0;
        });
        if (asio_it != devices.end()) {
            return asio_it->index;
        }

        auto it = std::find_if(devices.begin(), devices.end(), [](const DeviceInfo& device) {
            return device.is_default_output && device.max_output_channels > 0;
        });
        if (it != devices.end()) {
            return it->index;
        }

        it = std::find_if(devices.begin(), devices.end(), [](const DeviceInfo& device) {
            return device.max_output_channels > 0;
        });
        return it != devices.end() ? it->index : NO_DEVICE;
    }

    static void print_device_info(const DeviceInfo* input_info, const DeviceInfo* output_info) {
        Log::info("Input Device: {} | API: {} | Max Input Channels: {} | Default Sample Rate: {}",
                  input_info->name, input_info->api_name, input_info->max_input_channels,
                  input_info->default_sample_rate);
        Log::info("Output Device: {} | API: {} | Max Output Channels: {} | Default Sample Rate: {}",
                  output_info->name, output_info->api_name, output_info->max_output_channels,
                  output_info->default_sample_rate);
    }

    bool start_audio_stream(DeviceIndex input_device, DeviceIndex output_device,
                            const AudioConfig& config = AudioConfig{},
                            AudioCallback callback = nullptr, void* user_data = nullptr) {
        if (!is_device_valid(input_device) || !is_device_valid(output_device)) {
            last_error_ = "Invalid input or output device";
            Log::error("Invalid input or output device.");
            return false;
        }

        const auto* input_info_ptr = get_device_info(input_device);
        if (input_info_ptr == nullptr) {
            last_error_ = "Invalid input or output device";
            return false;
        }
        auto input_info = *input_info_ptr;

        const auto* output_info_ptr = get_device_info(output_device);
        if (output_info_ptr == nullptr) {
            last_error_ = "Invalid input or output device";
            return false;
        }
        auto output_info = *output_info_ptr;

        input_channel_count_  = std::min(input_info.max_input_channels, 1);
        output_channel_count_ = output_info.max_output_channels >= 2 ? 2 : 1;
        current_config_       = config;
        callback_             = callback;
        callback_user_data_   = user_data;

        RtAudio::StreamParameters input_parameters;
        input_parameters.deviceId = input_device;
        input_parameters.nChannels = input_channel_count_;
        input_parameters.firstChannel = 0;

        RtAudio::StreamParameters output_parameters;
        output_parameters.deviceId = output_device;
        output_parameters.nChannels = output_channel_count_;
        output_parameters.firstChannel = 0;

        RtAudio::StreamOptions options;
        options.flags = RTAUDIO_SCHEDULE_REALTIME | RTAUDIO_MINIMIZE_LATENCY;

        unsigned int buffer_frames = static_cast<unsigned int>(config.frames_per_buffer);

        print_device_info(&input_info, &output_info);
        Log::info("Frames per buffer requested: {}", config.frames_per_buffer);
        Log::info("Sample rate: {} Hz", config.sample_rate);
        Log::info("Bitrate: {} bps", config.bitrate);

        RtAudioErrorType open_result = stream_.openStream(
            &output_parameters, &input_parameters, RTAUDIO_FLOAT32,
            static_cast<unsigned int>(config.sample_rate), &buffer_frames,
            &AudioStream::rt_audio_callback, this, &options);
        if (open_result != RTAUDIO_NO_ERROR) {
            last_error_ = std::string("RtAudio open failed: ") + stream_.getErrorText();
            Log::error("RtAudio open failed: {}", stream_.getErrorText());
            if (stream_.isStreamOpen()) {
                stream_.closeStream();
            }
            return false;
        }

        RtAudioErrorType start_result = stream_.startStream();
        if (start_result != RTAUDIO_NO_ERROR) {
            last_error_ = std::string("RtAudio start failed: ") + stream_.getErrorText();
            Log::error("RtAudio start failed: {}", stream_.getErrorText());
            if (stream_.isStreamOpen()) {
                stream_.closeStream();
            }
            return false;
        }

        actual_buffer_frames_ = buffer_frames;
        last_error_.clear();
        stream_active_.store(true, std::memory_order_relaxed);

        Log::info("{} input channel(s), {} output channel(s) at {} Hz", input_channel_count_,
                  output_channel_count_, config.sample_rate);
        if (static_cast<int>(buffer_frames) != config.frames_per_buffer) {
            Log::warn("RtAudio adjusted buffer size from {} to {}", config.frames_per_buffer,
                      buffer_frames);
        }

        return true;
    }

    void stop_audio_stream() {
        stream_active_.store(false, std::memory_order_relaxed);
        if (stream_.isStreamRunning()) {
            RtAudioErrorType result = stream_.stopStream();
            if (result != RTAUDIO_NO_ERROR) {
                Log::warn("RtAudio stop failed: {}", stream_.getErrorText());
            }
        }
        if (stream_.isStreamOpen()) {
            stream_.closeStream();
        }
    }

    struct LatencyInfo {
        double input_latency_ms  = 0.0;
        double output_latency_ms = 0.0;
        double sample_rate       = 0.0;
        int requested_buffer_frames = 0;
        int actual_buffer_frames = 0;
        double buffer_duration_ms = 0.0;
        bool backend_latency_available = false;
        uint64_t input_overflows = 0;
        uint64_t output_underflows = 0;
    };

    void print_latency_info() {
        auto info = get_latency_info();
        Log::info("Input latency:  {:.3f} ms", info.input_latency_ms);
        Log::info("Output latency: {:.3f} ms", info.output_latency_ms);
        Log::info("Sample rate:    {:.1f} Hz", info.sample_rate);
        Log::info("Requested buffer: {} frames", info.requested_buffer_frames);
        Log::info("Actual buffer:    {} frames ({:.3f} ms)", info.actual_buffer_frames,
                  info.buffer_duration_ms);
        if (!info.backend_latency_available) {
            Log::warn("RtAudio backend latency is unavailable or reported as zero");
        }
    }

    LatencyInfo get_latency_info() const {
        LatencyInfo info{};
        info.sample_rate = current_config_.sample_rate;
        info.requested_buffer_frames = current_config_.frames_per_buffer;
        info.actual_buffer_frames = static_cast<int>(actual_buffer_frames_);
        if (current_config_.sample_rate > 0 && actual_buffer_frames_ > 0) {
            info.buffer_duration_ms =
                static_cast<double>(actual_buffer_frames_) * 1000.0 /
                static_cast<double>(current_config_.sample_rate);
        }

        if (stream_.isStreamOpen() && current_config_.sample_rate > 0) {
            unsigned int latency_frames = const_cast<RtAudio&>(stream_).getStreamLatency();
            double total_latency_ms = static_cast<double>(latency_frames) * 1000.0 /
                                      static_cast<double>(current_config_.sample_rate);
            info.input_latency_ms  = total_latency_ms * 0.5;
            info.output_latency_ms = total_latency_ms * 0.5;
            info.backend_latency_available = latency_frames > 0;
        }
        info.input_overflows = input_overflows_.load(std::memory_order_relaxed);
        info.output_underflows = output_underflows_.load(std::memory_order_relaxed);
        return info;
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
    static std::vector<DeviceInfo> get_all_devices() {
        std::vector<DeviceInfo> devices;
        auto apis = get_apis_without_defaults();

        for (const auto& api: apis) {
            try {
                RtAudio audio(api.rt_api);
                auto ids = audio.getDeviceIds();
                for (const auto id: ids) {
                    auto rt_info = audio.getDeviceInfo(id);
                    DeviceInfo info;
                    info.index = id;
                    info.name = rt_info.name;
                    info.api_name = api.name;
                    info.api_index = api.index;
                    info.max_input_channels = static_cast<int>(rt_info.inputChannels);
                    info.max_output_channels = static_cast<int>(rt_info.outputChannels);
                    info.default_sample_rate = rt_info.preferredSampleRate;
                    info.is_default_input = rt_info.isDefaultInput;
                    info.is_default_output = rt_info.isDefaultOutput;
                    devices.push_back(info);
                }
            } catch (const std::exception& e) {
                Log::debug("RtAudio device scan failed for {}: {}", api.name, e.what());
            }
        }

        return devices;
    }

    struct ApiScanInfo {
        int          index = -1;
        std::string  name;
        RtAudio::Api rt_api = RtAudio::UNSPECIFIED;
    };

    static std::vector<ApiScanInfo> get_apis_without_defaults() {
        std::vector<ApiScanInfo> apis;
        std::vector<RtAudio::Api> compiled_apis;
        RtAudio::getCompiledApi(compiled_apis);

        for (const auto api: compiled_apis) {
            if (api == RtAudio::UNSPECIFIED) {
                continue;
            }
            ApiScanInfo info;
            info.index = static_cast<int>(apis.size());
            info.name = RtAudio::getApiDisplayName(api);
            info.rt_api = api;
            apis.push_back(info);
        }
        return apis;
    }

    static int rt_audio_callback(void* output_buffer, void* input_buffer, unsigned int n_frames,
                                 double /*stream_time*/, RtAudioStreamStatus status,
                                 void* user_data) {
        auto* self = static_cast<AudioStream*>(user_data);
        if (self == nullptr || self->callback_ == nullptr) {
            return 0;
        }
        if ((status & RTAUDIO_INPUT_OVERFLOW) != 0) {
            self->input_overflows_.fetch_add(1, std::memory_order_relaxed);
        }
        if ((status & RTAUDIO_OUTPUT_UNDERFLOW) != 0) {
            self->output_underflows_.fetch_add(1, std::memory_order_relaxed);
        }
        return self->callback_(input_buffer, output_buffer, n_frames, self->callback_user_data_);
    }

    RtAudio           stream_;
    std::atomic<bool> stream_active_{false};
    AudioConfig       current_config_;
    AudioCallback     callback_ = nullptr;
    void*             callback_user_data_ = nullptr;
    unsigned int      actual_buffer_frames_ = 0;
    std::atomic<uint64_t> input_overflows_{0};
    std::atomic<uint64_t> output_underflows_{0};

    int input_channel_count_;
    int output_channel_count_;
};
