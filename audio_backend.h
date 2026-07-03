#pragma once

#include <cstdint>
#include <string>
#include <vector>

using AudioDeviceId = std::uint32_t;

inline constexpr AudioDeviceId AUDIO_NO_DEVICE = 0;

using AudioCallback = int (*)(const void* input,
                              void* output,
                              unsigned long frame_count,
                              void* user_data);

struct AudioConfig {
    static constexpr int DEFAULT_SAMPLE_RATE = 48000;
    static constexpr int DEFAULT_BITRATE = 96000;
    static constexpr int DEFAULT_COMPLEXITY = 5;
    static constexpr int DEFAULT_FRAMES_PER_BUFFER = 240;
    static constexpr float DEFAULT_INPUT_GAIN = 1.0F;
    static constexpr float DEFAULT_OUTPUT_GAIN = 1.0F;

    int sample_rate = DEFAULT_SAMPLE_RATE;
    int bitrate = DEFAULT_BITRATE;
    int complexity = DEFAULT_COMPLEXITY;
    int frames_per_buffer = DEFAULT_FRAMES_PER_BUFFER;
    int input_channel_index = 0;
    float input_gain = DEFAULT_INPUT_GAIN;
    float output_gain = DEFAULT_OUTPUT_GAIN;
};

struct AudioDeviceInfo {
    AudioDeviceId id = AUDIO_NO_DEVICE;
    std::string name;
    std::string api_name;
    int api_index = -1;
    int max_input_channels = 0;
    int max_output_channels = 0;
    double default_sample_rate = 0.0;
    std::vector<double> sample_rates;
    bool is_default_input = false;
    bool is_default_output = false;
};

struct AudioApiInfo {
    int index = -1;
    std::string name;
    AudioDeviceId default_input_device = AUDIO_NO_DEVICE;
    AudioDeviceId default_output_device = AUDIO_NO_DEVICE;
};

struct AudioLatencyInfo {
    double input_latency_ms = 0.0;
    double output_latency_ms = 0.0;
    double sample_rate = 0.0;
    int requested_buffer_frames = 0;
    int actual_buffer_frames = 0;
    double buffer_duration_ms = 0.0;
    bool backend_latency_available = false;
};
