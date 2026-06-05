#include "audio_backend_policy.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {
void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}

AudioDeviceInfo device(AudioDeviceId id, std::string api, bool input, bool output,
                       bool default_input = false, bool default_output = false) {
    AudioDeviceInfo info;
    info.id = id;
    info.name = api + " device";
    info.api_name = std::move(api);
    info.max_input_channels = input ? 1 : 0;
    info.max_output_channels = output ? 2 : 0;
    info.default_sample_rate = 48000.0;
    info.is_default_input = default_input;
    info.is_default_output = default_output;
    return info;
}
}

int main() {
    std::vector<AudioDeviceInfo> windows_devices{
        device(1, "WASAPI", true, false, true, false),
        device(2, "WASAPI", false, true, false, true),
        device(3, "ASIO", true, true, false, false),
    };

    require(audio_backend::rank_api_for_platform("ASIO") <= audio_backend::rank_api_for_platform("WASAPI"),
            "ASIO must rank no worse than WASAPI on Windows builds");
    require(audio_backend::choose_default_input_device(windows_devices) != AUDIO_NO_DEVICE,
            "input selection must find a valid device");
    require(audio_backend::choose_default_output_device(windows_devices) != AUDIO_NO_DEVICE,
            "output selection must find a valid device");

    std::vector<AudioDeviceInfo> single_api_devices{
        device(10, "WASAPI", true, false, true, false),
        device(11, "WASAPI", false, true, false, true),
    };

    require(audio_backend::choose_default_input_device(single_api_devices) == 10,
            "input should use default input when only one API is present");
    require(audio_backend::choose_default_output_device(single_api_devices) == 11,
            "output should use default output when only one API is present");

    std::cout << "audio backend policy self-test passed\n";
    return 0;
}
