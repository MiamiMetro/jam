#pragma once

#include "audio_backend.h"

#include <limits>
#include <string>
#include <vector>

namespace audio_backend {

enum class Platform {
    windows,
    macos,
    linux,
};

inline int rank_api_for_platform(Platform platform, const std::string& api_name) {
    switch (platform) {
    case Platform::windows:
        if (api_name == "ASIO") {
            return 0;
        }
        if (api_name == "Windows Audio (Low Latency Mode)") {
            return 1;
        }
        if (api_name == "Windows Audio (Exclusive Mode)") {
            return 2;
        }
        if (api_name == "Windows Audio" ||
            api_name.find("WASAPI") != std::string::npos) {
            return 3;
        }
        return 100;
    case Platform::macos:
        if (api_name == "CoreAudio") {
            return 0;
        }
        return 100;
    case Platform::linux:
        if (api_name == "JACK") {
            return 0;
        }
        if (api_name == "ALSA") {
            return 1;
        }
        return 100;
    }

    return 100;
}

inline int rank_api_for_platform(const std::string& api_name) {
#if defined(_WIN32)
    return rank_api_for_platform(Platform::windows, api_name);
#elif defined(__APPLE__)
    return rank_api_for_platform(Platform::macos, api_name);
#else
    return rank_api_for_platform(Platform::linux, api_name);
#endif
}

inline AudioDeviceId choose_default_input_device_for_platform(const std::vector<AudioDeviceInfo>& devices,
                                                              Platform platform) {
    AudioDeviceId best_device = AUDIO_NO_DEVICE;
    int best_rank = std::numeric_limits<int>::max();
    bool best_is_default = false;

    for (const auto& device : devices) {
        if (device.max_input_channels <= 0) {
            continue;
        }

        const int rank = rank_api_for_platform(platform, device.api_name);
        if (rank < best_rank || (rank == best_rank && device.is_default_input && !best_is_default)) {
            best_device = device.id;
            best_rank = rank;
            best_is_default = device.is_default_input;
        }
    }

    return best_device;
}

inline AudioDeviceId choose_default_input_device(const std::vector<AudioDeviceInfo>& devices) {
#if defined(_WIN32)
    return choose_default_input_device_for_platform(devices, Platform::windows);
#elif defined(__APPLE__)
    return choose_default_input_device_for_platform(devices, Platform::macos);
#else
    return choose_default_input_device_for_platform(devices, Platform::linux);
#endif
}

inline AudioDeviceId choose_default_output_device_for_platform(const std::vector<AudioDeviceInfo>& devices,
                                                               Platform platform) {
    AudioDeviceId best_device = AUDIO_NO_DEVICE;
    int best_rank = std::numeric_limits<int>::max();
    bool best_is_default = false;

    for (const auto& device : devices) {
        if (device.max_output_channels <= 0) {
            continue;
        }

        const int rank = rank_api_for_platform(platform, device.api_name);
        if (rank < best_rank || (rank == best_rank && device.is_default_output && !best_is_default)) {
            best_device = device.id;
            best_rank = rank;
            best_is_default = device.is_default_output;
        }
    }

    return best_device;
}

inline AudioDeviceId choose_default_output_device(const std::vector<AudioDeviceInfo>& devices) {
#if defined(_WIN32)
    return choose_default_output_device_for_platform(devices, Platform::windows);
#elif defined(__APPLE__)
    return choose_default_output_device_for_platform(devices, Platform::macos);
#else
    return choose_default_output_device_for_platform(devices, Platform::linux);
#endif
}

}  // namespace audio_backend
