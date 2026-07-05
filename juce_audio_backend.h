#pragma once

#include "audio_backend.h"

#include <juce_audio_devices/juce_audio_devices.h>
#include <juce_events/juce_events.h>

#include <atomic>
#include <cstddef>
#include <string>
#include <vector>

class JuceAudioBackend final : private juce::AudioIODeviceCallback {
public:
    JuceAudioBackend();
    ~JuceAudioBackend() override;

    std::vector<AudioApiInfo> get_apis();
    std::vector<AudioDeviceInfo> get_input_devices();
    std::vector<AudioDeviceInfo> get_output_devices();
    std::vector<AudioDeviceInfo> get_input_device_stubs();
    std::vector<AudioDeviceInfo> get_output_device_stubs();
    std::vector<AudioDeviceInfo> get_all_devices();
    AudioDeviceId get_default_input_device();
    AudioDeviceId get_default_output_device();
    bool is_device_valid(AudioDeviceId device_id);
    bool get_device_info(AudioDeviceId device_id, AudioDeviceInfo& out);
    bool start_audio_stream(AudioDeviceId input_device, AudioDeviceId output_device,
                            const AudioConfig& config, AudioCallback callback, void* user_data);
    void stop_audio_stream();
    bool is_stream_active() const;
    int get_input_channel_count() const;
    int get_output_channel_count() const;
    AudioConfig get_config() const;
    AudioLatencyInfo get_latency_info() const;
    const std::string& get_last_error() const;
    void clear_last_error();
    void set_last_error(std::string error);

private:
    struct DeviceCapabilities {
        int channel_count = 0;
        std::vector<double> sample_rates;
    };

    struct JuceRuntime {
        JuceRuntime();
    };

    void audioDeviceIOCallbackWithContext(
        const float* const* input_channel_data, int num_input_channels,
        float* const* output_channel_data, int num_output_channels, int num_samples,
        const juce::AudioIODeviceCallbackContext& context) override;
    void audioDeviceAboutToStart(juce::AudioIODevice* device) override;
    void audioDeviceStopped() override;

    static AudioDeviceId make_device_id(int api_index, int device_index, bool input);
    static int decode_api_index(AudioDeviceId id);
    static int decode_device_index(AudioDeviceId id);
    static bool decode_is_input(AudioDeviceId id);

    std::vector<AudioDeviceInfo> scan_devices(bool input);
    std::vector<AudioDeviceInfo> scan_device_stubs(bool input);
    juce::AudioIODeviceType* find_type(int api_index);
    juce::String device_name_for_id(AudioDeviceId id);
    DeviceCapabilities query_device_capabilities(juce::AudioIODeviceType& type,
                                                 const juce::String& device_name,
                                                 bool input);
    void prepare_callback_buffers(int frame_count);

    JuceRuntime juce_runtime_;
    juce::AudioDeviceManager device_manager_;
    juce::OwnedArray<juce::AudioIODeviceType> device_types_;
    std::atomic<bool> stream_active_{false};
    AudioConfig current_config_;
    std::atomic<AudioCallback> callback_{nullptr};
    std::atomic<void*> callback_user_data_{nullptr};
    std::vector<float> interleaved_input_;
    std::vector<float> interleaved_output_;
    std::atomic<int> input_channel_count_{0};
    std::atomic<int> opened_input_channel_count_{0};
    std::atomic<int> selected_input_channel_{0};
    std::atomic<int> output_channel_count_{0};
    std::atomic<int> actual_buffer_frames_{0};
    std::size_t callback_frame_capacity_ = 0;
    std::string last_error_;
};
