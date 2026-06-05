#pragma once

#include <cstdint>
#include <string>

using AudioDeviceId = std::uint32_t;

inline constexpr AudioDeviceId AUDIO_NO_DEVICE = 0;

using AudioCallback = int (*)(const void* input,
                              void* output,
                              unsigned long frame_count,
                              void* user_data);

struct AudioConfig {
    int sample_rate = 48000;
    int bitrate = 96000;
    int complexity = 5;
    unsigned long frames_per_buffer = 240;
    float input_gain = 1.0F;
    float output_gain = 1.0F;
};

struct AudioDeviceInfo {
    AudioDeviceId id = AUDIO_NO_DEVICE;
    std::string name;
    std::string api_name;
    unsigned int api_index = 0;
    unsigned int max_input_channels = 0;
    unsigned int max_output_channels = 0;
    double default_sample_rate = 0.0;
    bool is_default_input = false;
    bool is_default_output = false;
};

struct AudioApiInfo {
    unsigned int index = 0;
    std::string name;
    AudioDeviceId default_input_device = AUDIO_NO_DEVICE;
    AudioDeviceId default_output_device = AUDIO_NO_DEVICE;
};

struct AudioLatencyInfo {
    double input_latency_ms = 0.0;
    double output_latency_ms = 0.0;
    int sample_rate = 0;
    unsigned long requested_buffer_frames = 0;
    unsigned long actual_buffer_frames = 0;
    double buffer_duration_ms = 0.0;
    bool backend_latency_available = false;
};
