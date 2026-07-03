#pragma once

#include <algorithm>
#include <cstddef>
#include <vector>

namespace juce_audio_adapter {

inline void copy_inputs_to_interleaved(const float* const* input_channels,
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

    if (input_channels == nullptr || input_channel_count <= 0) {
        return;
    }

    for (int frame = 0; frame < safe_frame_count; ++frame) {
        const auto frame_index =
            static_cast<std::size_t>(frame) * static_cast<std::size_t>(safe_channel_count);
        if (frame_index >= writable_size) {
            break;
        }

        if (safe_channel_count == 1) {
            float mixed = 0.0F;
            int mixed_channels = 0;
            for (int input_channel = 0; input_channel < input_channel_count; ++input_channel) {
                if (input_channels[input_channel] == nullptr) {
                    continue;
                }
                mixed += input_channels[input_channel][frame];
                ++mixed_channels;
            }
            interleaved[frame_index] =
                mixed_channels > 0 ? mixed / static_cast<float>(mixed_channels) : 0.0F;
            continue;
        }

        for (int output_channel = 0; output_channel < safe_channel_count; ++output_channel) {
            const auto index = frame_index + static_cast<std::size_t>(output_channel);
            if (index >= writable_size) {
                break;
            }
            if (output_channel < input_channel_count && input_channels[output_channel] != nullptr) {
                interleaved[index] = input_channels[output_channel][frame];
            }
        }
    }
}

inline void copy_inputs_to_interleaved(const float* const* input_channels,
                                       int input_channel_count,
                                       int frame_count,
                                       int interleaved_channel_count,
                                       std::vector<float>& interleaved)
{
    const auto safe_frame_count = std::max(frame_count, 0);
    const auto safe_channel_count = std::max(interleaved_channel_count, 1);
    interleaved.resize(static_cast<std::size_t>(safe_frame_count) *
                       static_cast<std::size_t>(safe_channel_count));
    copy_inputs_to_interleaved(input_channels, input_channel_count, frame_count,
                               interleaved_channel_count, interleaved.data(), interleaved.size());
}

inline void copy_selected_input_channel_to_interleaved(const float* const* input_channels,
                                                       int input_channel_count,
                                                       int requested_input_channel,
                                                       int frame_count,
                                                       int interleaved_channel_count,
                                                       float* interleaved,
                                                       std::size_t interleaved_size)
{
    const auto safe_frame_count = std::max(frame_count, 0);
    const auto safe_interleaved_channel_count = std::max(interleaved_channel_count, 1);
    const auto required_size = static_cast<std::size_t>(safe_frame_count) *
                               static_cast<std::size_t>(safe_interleaved_channel_count);
    const auto writable_size = std::min(required_size, interleaved_size);

    if (interleaved == nullptr || writable_size == 0) {
        return;
    }

    std::fill_n(interleaved, writable_size, 0.0F);

    if (input_channels == nullptr || input_channel_count <= 0) {
        return;
    }

    int source_channel = -1;
    if (requested_input_channel >= 0 && requested_input_channel < input_channel_count &&
        input_channels[requested_input_channel] != nullptr) {
        source_channel = requested_input_channel;
    } else {
        for (int input_channel = 0; input_channel < input_channel_count; ++input_channel) {
            if (input_channels[input_channel] != nullptr) {
                source_channel = input_channel;
                break;
            }
        }
    }

    if (source_channel < 0) {
        return;
    }

    for (int frame = 0; frame < safe_frame_count; ++frame) {
        const auto frame_index =
            static_cast<std::size_t>(frame) *
            static_cast<std::size_t>(safe_interleaved_channel_count);
        if (frame_index >= writable_size) {
            break;
        }

        const auto sample = input_channels[source_channel][frame];
        for (int output_channel = 0; output_channel < safe_interleaved_channel_count;
             ++output_channel) {
            const auto index = frame_index + static_cast<std::size_t>(output_channel);
            if (index >= writable_size) {
                break;
            }
            interleaved[index] = sample;
        }
    }
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
