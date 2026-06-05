#pragma once

#include "audio_backend.h"

#include <limits>
#include <string>
#include <vector>

namespace audio_backend {

inline int rank_api_for_platform(const std::string& api_name) {
#if defined(_WIN32)
    if (api_name == "ASIO") {
        return 0;
    }
    if (api_name.find("WASAPI") != std::string::npos) {
        return 1;
    }
    return 100;
#elif defined(__APPLE__)
    if (api_name == "CoreAudio") {
        return 0;
    }
    return 100;
#else
    if (api_name == "JACK") {
        return 0;
    }
    if (api_name == "ALSA") {
        return 1;
    }
    return 100;
#endif
}

inline AudioDeviceId choose_default_input_device(const std::vector<AudioDeviceInfo>& devices) {
    AudioDeviceId best_device = AUDIO_NO_DEVICE;
    int best_rank = std::numeric_limits<int>::max();
    bool best_is_default = false;

    for (const auto& device : devices) {
        if (device.max_input_channels == 0) {
            continue;
        }

        const int rank = rank_api_for_platform(device.api_name);
        if (rank < best_rank || (rank == best_rank && device.is_default_input && !best_is_default)) {
            best_device = device.id;
            best_rank = rank;
            best_is_default = device.is_default_input;
        }
    }

    return best_device;
}

inline AudioDeviceId choose_default_output_device(const std::vector<AudioDeviceInfo>& devices) {
    AudioDeviceId best_device = AUDIO_NO_DEVICE;
    int best_rank = std::numeric_limits<int>::max();
    bool best_is_default = false;

    for (const auto& device : devices) {
        if (device.max_output_channels == 0) {
            continue;
        }

        const int rank = rank_api_for_platform(device.api_name);
        if (rank < best_rank || (rank == best_rank && device.is_default_output && !best_is_default)) {
            best_device = device.id;
            best_rank = rank;
            best_is_default = device.is_default_output;
        }
    }

    return best_device;
}

}  // namespace audio_backend
