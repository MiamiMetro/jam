#include "audio_backend_policy.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <type_traits>
#include <utility>
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
    require(AudioConfig::DEFAULT_SAMPLE_RATE == 48000,
            "AudioConfig must expose DEFAULT_SAMPLE_RATE");
    require(AudioConfig::DEFAULT_BITRATE == 96000,
            "AudioConfig must expose DEFAULT_BITRATE");
    require(AudioConfig::DEFAULT_COMPLEXITY == 5,
            "AudioConfig must expose DEFAULT_COMPLEXITY");
    require(AudioConfig::DEFAULT_FRAMES_PER_BUFFER == 240,
            "AudioConfig must expose DEFAULT_FRAMES_PER_BUFFER");
    require(AudioConfig::DEFAULT_INPUT_GAIN == 1.0F,
            "AudioConfig must expose DEFAULT_INPUT_GAIN");
    require(AudioConfig::DEFAULT_OUTPUT_GAIN == 1.0F,
            "AudioConfig must expose DEFAULT_OUTPUT_GAIN");
    require(std::is_same_v<decltype(AudioDeviceInfo{}.api_index), int>,
            "AudioDeviceInfo::api_index must be int");
    require(AudioDeviceInfo{}.api_index == -1,
            "AudioDeviceInfo::api_index must default to -1");
    require(std::is_same_v<decltype(AudioApiInfo{}.index), int>,
            "AudioApiInfo::index must be int");
    require(AudioApiInfo{}.index == -1,
            "AudioApiInfo::index must default to -1");
    require(std::is_same_v<decltype(AudioLatencyInfo{}.sample_rate), double>,
            "AudioLatencyInfo::sample_rate must be double");
    require(std::is_same_v<decltype(AudioLatencyInfo{}.requested_buffer_frames), int>,
            "AudioLatencyInfo::requested_buffer_frames must be int");
    require(std::is_same_v<decltype(AudioLatencyInfo{}.actual_buffer_frames), int>,
            "AudioLatencyInfo::actual_buffer_frames must be int");
    require(std::is_same_v<decltype(AudioConfig{}.frames_per_buffer), int>,
            "AudioConfig::frames_per_buffer must be int");
    require(std::is_same_v<decltype(AudioConfig{}.input_channel_index), int>,
            "AudioConfig::input_channel_index must be int");
    require(AudioConfig{}.input_channel_index == 0,
            "AudioConfig::input_channel_index must default to channel 0");
    require(std::is_same_v<decltype(AudioDeviceInfo{}.max_input_channels), int>,
            "AudioDeviceInfo::max_input_channels must be int");
    require(std::is_same_v<decltype(AudioDeviceInfo{}.max_output_channels), int>,
            "AudioDeviceInfo::max_output_channels must be int");
    require(std::is_same_v<decltype(AudioDeviceInfo{}.sample_rates), std::vector<double>>,
            "AudioDeviceInfo::sample_rates must be vector<double>");

    require(audio_backend::rank_api_for_platform(audio_backend::Platform::windows, "ASIO")
                <= audio_backend::rank_api_for_platform(audio_backend::Platform::windows,
                                                        "Windows Audio (Low Latency Mode)"),
            "ASIO must rank no worse than Windows Audio on Windows");
    require(audio_backend::rank_api_for_platform(audio_backend::Platform::windows, "ASIO") == 0,
            "ASIO must be preferred on Windows");
    require(audio_backend::rank_api_for_platform(
                audio_backend::Platform::windows,
                "Windows Audio (Low Latency Mode)") == 1,
            "JUCE low-latency Windows Audio must be second on Windows");
    require(audio_backend::rank_api_for_platform(
                audio_backend::Platform::windows,
                "Windows Audio (Exclusive Mode)") == 2,
            "JUCE exclusive Windows Audio must outrank shared Windows Audio");
    require(audio_backend::rank_api_for_platform(
                audio_backend::Platform::windows, "Windows Audio") == 3,
            "JUCE shared Windows Audio must be ranked as a usable fallback");
    require(audio_backend::rank_api_for_platform(audio_backend::Platform::windows,
                                                 "Windows WASAPI") == 3,
            "legacy WASAPI-containing names must remain usable on Windows");
    require(audio_backend::rank_api_for_platform(audio_backend::Platform::macos, "CoreAudio") == 0,
            "CoreAudio must be preferred on macOS");
    require(audio_backend::rank_api_for_platform(audio_backend::Platform::macos, "ASIO") == 100,
            "non-CoreAudio APIs must be fallback-ranked on macOS");
    require(audio_backend::rank_api_for_platform(audio_backend::Platform::linux, "JACK") == 0,
            "JACK must be preferred on Linux");
    require(audio_backend::rank_api_for_platform(audio_backend::Platform::linux, "ALSA") == 1,
            "ALSA must be second on Linux");
    require(audio_backend::rank_api_for_platform(audio_backend::Platform::linux, "PulseAudio") == 100,
            "other APIs must be fallback-ranked on Linux");

    std::vector<AudioDeviceInfo> windows_devices{
        device(1, "Windows Audio", true, false, true, false),
        device(2, "Windows Audio", false, true, false, true),
        device(3, "ASIO", true, true, false, false),
    };

    require(audio_backend::rank_api_for_platform("ASIO") <=
                audio_backend::rank_api_for_platform("Windows Audio"),
            "ASIO must rank no worse than Windows Audio on Windows builds");
    require(audio_backend::choose_default_input_device_for_platform(windows_devices, audio_backend::Platform::windows) == 3,
            "Windows input selection must prefer ASIO over WASAPI");
    require(audio_backend::choose_default_output_device_for_platform(windows_devices, audio_backend::Platform::windows) == 3,
            "Windows output selection must prefer ASIO over WASAPI");

    auto invalid_channels_devices = windows_devices;
    invalid_channels_devices[2].max_input_channels = -1;
    invalid_channels_devices[2].max_output_channels = -1;
    require(audio_backend::choose_default_input_device_for_platform(invalid_channels_devices,
                                                                    audio_backend::Platform::windows) == 1,
            "input selection must skip devices with negative input channels");
    require(audio_backend::choose_default_output_device_for_platform(invalid_channels_devices,
                                                                     audio_backend::Platform::windows) == 2,
            "output selection must skip devices with negative output channels");

    std::vector<AudioDeviceInfo> single_api_devices{
        device(10, "Windows Audio", true, false, true, false),
        device(11, "Windows Audio", false, true, false, true),
    };

    require(audio_backend::choose_default_input_device(single_api_devices) == 10,
            "input should use default input when only one API is present");
    require(audio_backend::choose_default_output_device(single_api_devices) == 11,
            "output should use default output when only one API is present");

    std::vector<AudioDeviceInfo> juce_windows_devices{
        device(20, "Windows Audio", true, true, true, true),
        device(21, "Windows Audio (Exclusive Mode)", true, true, false, false),
        device(22, "Windows Audio (Low Latency Mode)", true, true, false, false),
    };
    require(audio_backend::choose_default_input_device_for_platform(
                juce_windows_devices, audio_backend::Platform::windows) == 22,
            "Windows input selection must prefer JUCE low-latency mode");
    require(audio_backend::choose_default_output_device_for_platform(
                juce_windows_devices, audio_backend::Platform::windows) == 22,
            "Windows output selection must prefer JUCE low-latency mode");

    std::cout << "audio backend policy self-test passed\n";
    return 0;
}
