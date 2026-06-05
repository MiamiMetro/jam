#pragma once

#include <algorithm>
#include <cstddef>
#include <vector>

namespace juce_audio_adapter {

inline void copy_first_input_to_interleaved(const float* const* input_channels,
                                            int input_channel_count,
                                            int frame_count,
                                            int interleaved_channel_count,
                                            float* interleaved,
                                            std::size_t interleaved_size)
{
    const auto safe_frame_count = std::max(frame_count, 0);
    const auto safe_channel_count = std::max(interleaved_channel_count, 1);
    const auto required_size = static_cast<std::size_t>(safe_frame_count) *
                               static_cast<std::size_t>(safe_channel_count);
    const auto writable_size = std::min(required_size, interleaved_size);

    if (interleaved == nullptr || writable_size == 0) {
        return;
    }

    std::fill_n(interleaved, writable_size, 0.0F);

    if (input_channels == nullptr || input_channel_count <= 0 || input_channels[0] == nullptr) {
        return;
    }

    for (int frame = 0; frame < safe_frame_count; ++frame) {
        const auto index =
            static_cast<std::size_t>(frame) * static_cast<std::size_t>(safe_channel_count);
        if (index >= writable_size) {
            break;
        }
        interleaved[index] = input_channels[0][frame];
    }
}

inline void copy_first_input_to_interleaved(const float* const* input_channels,
                                            int input_channel_count,
                                            int frame_count,
                                            int interleaved_channel_count,
                                            std::vector<float>& interleaved)
{
    const auto safe_frame_count = std::max(frame_count, 0);
    const auto safe_channel_count = std::max(interleaved_channel_count, 1);
    interleaved.resize(static_cast<std::size_t>(safe_frame_count) *
                       static_cast<std::size_t>(safe_channel_count));
    copy_first_input_to_interleaved(input_channels, input_channel_count, frame_count,
                                    interleaved_channel_count, interleaved.data(),
                                    interleaved.size());
}

inline void copy_interleaved_to_outputs(const std::vector<float>& interleaved,
                                        int frame_count,
                                        int interleaved_channel_count,
                                        float* const* output_channels,
                                        int output_channel_count)
{
    if (output_channels == nullptr || output_channel_count <= 0) {
        return;
    }

    const auto safe_frame_count = std::max(frame_count, 0);
    const auto safe_interleaved_channel_count = std::max(interleaved_channel_count, 0);

    for (int output_channel = 0; output_channel < output_channel_count; ++output_channel) {
        if (output_channels[output_channel] == nullptr) {
            continue;
        }

        if (safe_interleaved_channel_count == 0) {
            for (int frame = 0; frame < safe_frame_count; ++frame) {
                output_channels[output_channel][frame] = 0.0F;
            }
            continue;
        }

        const auto source_channel =
            std::min(output_channel, safe_interleaved_channel_count - 1);

        for (int frame = 0; frame < safe_frame_count; ++frame) {
            const auto source_index =
                static_cast<std::size_t>(frame) *
                    static_cast<std::size_t>(safe_interleaved_channel_count) +
                static_cast<std::size_t>(source_channel);
            output_channels[output_channel][frame] =
                source_index < interleaved.size() ? interleaved[source_index] : 0.0F;
        }
    }
}

} // namespace juce_audio_adapter
