#pragma once

#include "audio_backend.h"

#include <memory>
#include <string>
#include <vector>

class JuceAudioBackend;

class AudioStream {
public:
    using DeviceIndex = AudioDeviceId;
    using AudioCallback = ::AudioCallback;
    using AudioConfig = ::AudioConfig;
    using LatencyInfo = ::AudioLatencyInfo;

    static constexpr DeviceIndex NO_DEVICE = AUDIO_NO_DEVICE;

    struct DeviceInfo : AudioDeviceInfo {
        DeviceIndex index = AUDIO_NO_DEVICE;
    };

    struct ApiInfo : AudioApiInfo {};

    AudioStream();
    ~AudioStream();

    static const std::string& get_last_error();
    static void clear_last_error();
    static void print_all_devices();
    static const DeviceInfo* get_device_info(DeviceIndex device_index);
    static bool is_device_valid(DeviceIndex device_index);
    static std::vector<DeviceInfo> get_input_devices();
    static std::vector<DeviceInfo> get_output_devices();
    static std::vector<DeviceInfo> get_input_device_stubs();
    static std::vector<DeviceInfo> get_output_device_stubs();
    static std::vector<ApiInfo> get_apis();
    static DeviceIndex get_default_input_device();
    static DeviceIndex get_default_output_device();
    static void print_device_info(const DeviceInfo* input_info, const DeviceInfo* output_info);

    bool start_audio_stream(DeviceIndex input_device, DeviceIndex output_device,
                            const AudioConfig& config = AudioConfig{},
                            AudioCallback callback = nullptr, void* user_data = nullptr);
    void stop_audio_stream();
    void print_latency_info();
    LatencyInfo get_latency_info() const;
    int get_input_channel_count() const;
    int get_output_channel_count() const;
    bool is_stream_active() const;
    AudioConfig get_config() const;

private:
    static JuceAudioBackend& shared_backend();
    static DeviceInfo to_stream_device_info(const AudioDeviceInfo& info);
    static std::vector<DeviceInfo> to_stream_device_infos(
        const std::vector<AudioDeviceInfo>& infos);
    static std::vector<ApiInfo> to_stream_api_infos(const std::vector<AudioApiInfo>& infos);

    std::unique_ptr<JuceAudioBackend> backend_;
};
