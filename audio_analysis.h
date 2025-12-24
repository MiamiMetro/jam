#pragma once

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <vector>

// Audio analysis utilities
namespace audio_analysis {

// Calculate RMS (Root Mean Square) audio level
inline float calculate_rms(const float* samples, size_t count) {
    if (count == 0) {
        return 0.0F;
    }

    float sum_squares = 0.0F;
    for (size_t i = 0; i < count; ++i) {
        sum_squares += samples[i] * samples[i];
    }
    return std::sqrt(sum_squares / static_cast<float>(count));
}

// Find maximum absolute sample value
inline float find_peak(const float* samples, size_t count) {
    float max_sample = 0.0F;
    for (size_t i = 0; i < count; ++i) {
        float abs_sample = std::fabs(samples[i]);
        max_sample       = std::max(abs_sample, max_sample);
    }
    return max_sample;
}

// Voice Activity Detection - simple threshold-based
inline bool detect_voice_activity(float rms_level, float threshold = 0.01F) {
    return rms_level > threshold;
}

// Silence detection - checks if audio is below threshold
inline bool is_silence(const float* samples, size_t count, float threshold = 0.001F) {
    float peak = find_peak(samples, count);
    return peak <= threshold;
}

// Mix audio samples with gain (mono)
inline void mix_with_gain(float* output, const float* input, size_t count, float gain) {
    for (size_t i = 0; i < count; ++i) {
        output[i] += input[i] * gain;
    }
}

// Mix mono input to stereo output with gain
inline void mix_mono_to_stereo(float* output, const float* input, size_t frame_count,
                               size_t out_channels, float gain) {
    for (size_t i = 0; i < frame_count; ++i) {
        float sample = input[i] * gain;
        output[(i * out_channels) + 0] += sample;  // Left
        if (out_channels > 1) {
            output[(i * out_channels) + 1] += sample;  // Right
        }
    }
}

}  // namespace audio_analysis
