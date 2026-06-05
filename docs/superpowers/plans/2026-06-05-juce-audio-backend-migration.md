# JUCE Audio Backend Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fully replace the client audio backend with JUCE and remove the legacy RtAudio dependency from the client build.

**Architecture:** Keep `AudioStream` as the compatibility facade used by `client.cpp`, but make its implementation JUCE-only. Add small backend-neutral types and pure adapter helpers so device policy and JUCE channel-buffer conversion are testable without opening real audio hardware.

**Tech Stack:** C++23, CMake FetchContent, JUCE `juce_audio_devices`/`juce_audio_basics`/`juce_core`/`juce_events`, ImGui/GLFW client UI, Opus.

---

## Scope Check

This plan changes one subsystem: client audio device integration. It does not change GUI framework, codec behavior, UDP room routing, jitter buffer policy, recording, or broadcast/listener behavior except where regression checks verify they still work.

## File Structure

- Create `LICENSE`: AGPLv3 license text for the public open-source repository.
- Create `THIRD_PARTY_NOTICES.md`: notices for JUCE, ASIO, Opus, ImGui, GLFW, and other linked libraries.
- Create `audio_backend.h`: backend-neutral audio IDs, device/API/config/latency structs, and callback type.
- Create `audio_backend_policy.h`: deterministic API/device preference helpers.
- Create `audio_backend_policy_self_test.cpp`: tests ASIO/WASAPI/CoreAudio/JACK/ALSA preference logic.
- Create `juce_audio_adapter.h`: pure helpers for JUCE channel buffers to/from the current interleaved callback contract.
- Create `juce_audio_adapter_self_test.cpp`: tests mono input interleaving and stereo output deinterleaving.
- Create `juce_audio_backend.h`: JUCE backend class declaration.
- Create `juce_audio_backend.cpp`: JUCE device inventory, stream open/close, callback adapter, latency reporting.
- Create `audio_stream.cpp`: `AudioStream` facade implementation backed only by `JuceAudioBackend`.
- Modify `audio_stream.h`: remove direct RtAudio dependency and keep the existing public `AudioStream` shape.
- Modify `cmake/client.cmake`: remove RtAudio FetchContent/linking, add JUCE FetchContent/linking, add new audio source files.
- Modify `CMakeLists.txt`: add backend policy and adapter self-test executables.
- Modify `client.cpp`: change backend wording from RtAudio-specific to backend-neutral.

## Task 1: License And Notices

**Files:**
- Create: `LICENSE`
- Create: `THIRD_PARTY_NOTICES.md`

- [ ] **Step 1: Add AGPLv3 license text**

Run:

```powershell
Invoke-WebRequest -Uri "https://www.gnu.org/licenses/agpl-3.0.txt" -OutFile LICENSE
```

Expected: `LICENSE` exists and starts with `GNU AFFERO GENERAL PUBLIC LICENSE`.

- [ ] **Step 2: Add third-party notices**

Create `THIRD_PARTY_NOTICES.md`:

```markdown
# Third-Party Notices

This project uses third-party open-source components.

## JUCE

JUCE is used for cross-platform audio device access.

- Project: https://juce.com/
- Source: https://github.com/juce-framework/JUCE
- License: AGPLv3 or commercial JUCE license, depending on distribution terms.

This project uses JUCE under AGPLv3-compatible public open-source terms.

## ASIO

ASIO is a Steinberg audio driver technology. JUCE can expose ASIO devices when ASIO support and user-installed ASIO drivers are available.

- Steinberg developer information: https://www.steinberg.net/developers/
- ASIO open-source information: https://www.steinberg.net/developers/asiosdk-open/

ASIO is a trademark and software technology of Steinberg Media Technologies GmbH.

## Opus

Opus is used for compressed audio mode.

- Project: https://opus-codec.org/

## Dear ImGui

Dear ImGui is used for the native client UI.

- Source: https://github.com/ocornut/imgui
- License: MIT.

## GLFW

GLFW is used for window and OpenGL context management.

- Source: https://github.com/glfw/glfw
- License: zlib/libpng.

## spdlog

spdlog is used for logging.

- Source: https://github.com/gabime/spdlog
- License: MIT.
```

- [ ] **Step 3: Verify and commit**

Run:

```powershell
Get-Content LICENSE -TotalCount 2
Get-Content THIRD_PARTY_NOTICES.md -TotalCount 12
git diff --check
git add LICENSE THIRD_PARTY_NOTICES.md
git commit -m "Add open source license notices"
```

Expected: the two files are committed and `git diff --check` exits `0`.

## Task 2: Backend-Neutral Types And Device Policy

**Files:**
- Create: `audio_backend.h`
- Create: `audio_backend_policy.h`
- Create: `audio_backend_policy_self_test.cpp`
- Modify: `CMakeLists.txt`

- [ ] **Step 1: Write backend-neutral types**

Create `audio_backend.h`:

```cpp
#pragma once

#include <cstdint>
#include <string>
#include <vector>

using AudioDeviceId = uint32_t;
inline constexpr AudioDeviceId AUDIO_NO_DEVICE = 0;

using AudioCallback =
    int (*)(const void* input, void* output, unsigned long frame_count, void* user_data);

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
```

- [ ] **Step 2: Write policy helpers**

Create `audio_backend_policy.h`:

```cpp
#pragma once

#include "audio_backend.h"

#include <limits>
#include <string>
#include <vector>

namespace audio_backend {

inline int rank_api_for_platform(const std::string& api_name) {
#ifdef _WIN32
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
    const AudioDeviceInfo* best = nullptr;
    int best_rank = std::numeric_limits<int>::max();
    for (const auto& device: devices) {
        if (device.max_input_channels <= 0) {
            continue;
        }
        const int rank = rank_api_for_platform(device.api_name);
        if (best == nullptr || rank < best_rank ||
            (rank == best_rank && device.is_default_input && !best->is_default_input)) {
            best = &device;
            best_rank = rank;
        }
    }
    return best == nullptr ? AUDIO_NO_DEVICE : best->id;
}

inline AudioDeviceId choose_default_output_device(const std::vector<AudioDeviceInfo>& devices) {
    const AudioDeviceInfo* best = nullptr;
    int best_rank = std::numeric_limits<int>::max();
    for (const auto& device: devices) {
        if (device.max_output_channels <= 0) {
            continue;
        }
        const int rank = rank_api_for_platform(device.api_name);
        if (best == nullptr || rank < best_rank ||
            (rank == best_rank && device.is_default_output && !best->is_default_output)) {
            best = &device;
            best_rank = rank;
        }
    }
    return best == nullptr ? AUDIO_NO_DEVICE : best->id;
}

}  // namespace audio_backend
```

- [ ] **Step 3: Write policy self-test**

Create `audio_backend_policy_self_test.cpp`:

```cpp
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

}  // namespace

int main() {
    std::vector<AudioDeviceInfo> windows_devices{
        device(1, "WASAPI", true, false, true, false),
        device(2, "WASAPI", false, true, false, true),
        device(3, "ASIO", true, true, false, false),
    };

    require(audio_backend::rank_api_for_platform("ASIO") <=
                audio_backend::rank_api_for_platform("WASAPI"),
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
```

- [ ] **Step 4: Add test target**

Append to `CMakeLists.txt`:

```cmake
add_executable(audio_backend_policy_self_test audio_backend_policy_self_test.cpp)
```

- [ ] **Step 5: Verify and commit**

Run:

```powershell
cmake --build build --config Release --target audio_backend_policy_self_test
.\build\Release\audio_backend_policy_self_test.exe
git diff --check
git add audio_backend.h audio_backend_policy.h audio_backend_policy_self_test.cpp CMakeLists.txt
git commit -m "Add audio backend policy types"
```

Expected: the self-test prints `audio backend policy self-test passed`.

## Task 3: JUCE Buffer Adapter Helpers

**Files:**
- Create: `juce_audio_adapter.h`
- Create: `juce_audio_adapter_self_test.cpp`
- Modify: `CMakeLists.txt`

- [ ] **Step 1: Add adapter helpers**

Create `juce_audio_adapter.h`:

```cpp
#pragma once

#include <algorithm>
#include <cstddef>
#include <vector>

namespace juce_audio_adapter {

inline void copy_first_input_to_interleaved(const float* const* input_channels,
                                            int input_channel_count, int frame_count,
                                            int interleaved_channel_count,
                                            std::vector<float>& interleaved) {
    const size_t frames = static_cast<size_t>(std::max(frame_count, 0));
    const size_t channels = static_cast<size_t>(std::max(interleaved_channel_count, 1));
    interleaved.assign(frames * channels, 0.0F);
    if (input_channels == nullptr || input_channel_count <= 0 || input_channels[0] == nullptr) {
        return;
    }
    for (size_t frame = 0; frame < frames; ++frame) {
        interleaved[frame * channels] = input_channels[0][frame];
    }
}

inline void copy_interleaved_to_outputs(const std::vector<float>& interleaved,
                                        int frame_count, int interleaved_channel_count,
                                        float* const* output_channels,
                                        int output_channel_count) {
    if (output_channels == nullptr || output_channel_count <= 0) {
        return;
    }
    const size_t frames = static_cast<size_t>(std::max(frame_count, 0));
    const size_t source_channels = static_cast<size_t>(std::max(interleaved_channel_count, 1));
    for (int channel = 0; channel < output_channel_count; ++channel) {
        if (output_channels[channel] == nullptr) {
            continue;
        }
        const size_t source_channel = static_cast<size_t>(std::min(channel, interleaved_channel_count - 1));
        for (size_t frame = 0; frame < frames; ++frame) {
            const size_t source_index = frame * source_channels + source_channel;
            output_channels[channel][frame] =
                source_index < interleaved.size() ? interleaved[source_index] : 0.0F;
        }
    }
}

}  // namespace juce_audio_adapter
```

- [ ] **Step 2: Add adapter self-test**

Create `juce_audio_adapter_self_test.cpp`:

```cpp
#include "juce_audio_adapter.h"

#include <cstdlib>
#include <iostream>
#include <vector>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}

}  // namespace

int main() {
    float mono_input[] = {0.25F, -0.5F, 0.75F};
    const float* inputs[] = {mono_input};
    std::vector<float> interleaved;

    juce_audio_adapter::copy_first_input_to_interleaved(inputs, 1, 3, 1, interleaved);
    require(interleaved.size() == 3, "mono interleaved size");
    require(interleaved[0] == 0.25F && interleaved[1] == -0.5F && interleaved[2] == 0.75F,
            "mono input copy");

    std::vector<float> stereo_interleaved{0.1F, 0.2F, 0.3F, 0.4F, 0.5F, 0.6F};
    float left[3] = {};
    float right[3] = {};
    float* outputs[] = {left, right};
    juce_audio_adapter::copy_interleaved_to_outputs(stereo_interleaved, 3, 2, outputs, 2);
    require(left[0] == 0.1F && left[1] == 0.3F && left[2] == 0.5F, "left output copy");
    require(right[0] == 0.2F && right[1] == 0.4F && right[2] == 0.6F, "right output copy");

    std::cout << "juce audio adapter self-test passed\n";
    return 0;
}
```

- [ ] **Step 3: Add test target**

Append to `CMakeLists.txt`:

```cmake
add_executable(juce_audio_adapter_self_test juce_audio_adapter_self_test.cpp)
```

- [ ] **Step 4: Verify and commit**

Run:

```powershell
cmake --build build --config Release --target juce_audio_adapter_self_test
.\build\Release\juce_audio_adapter_self_test.exe
git diff --check
git add juce_audio_adapter.h juce_audio_adapter_self_test.cpp CMakeLists.txt
git commit -m "Add JUCE audio buffer adapter tests"
```

Expected: the self-test prints `juce audio adapter self-test passed`.

## Task 4: Replace Client Audio Build With JUCE

**Files:**
- Modify: `cmake/client.cmake`
- Create: `juce_audio_backend.h`
- Create: `juce_audio_backend.cpp`
- Create: `audio_stream.cpp`
- Modify: `audio_stream.h`

- [ ] **Step 1: Replace audio dependencies in CMake**

In `cmake/client.cmake`, delete the `FetchContent_Declare(rtaudio ...)` block and delete `set(RTAUDIO_API_ASIO ...)`.

Add this JUCE declaration before ImGui/GLFW declarations:

```cmake
FetchContent_Declare(
    juce
    GIT_REPOSITORY https://github.com/juce-framework/JUCE.git
    GIT_TAG        8.0.10
    GIT_SHALLOW    TRUE
    GIT_PROGRESS   TRUE
)
```

Before `FetchContent_MakeAvailable`, add:

```cmake
set(JUCE_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(JUCE_BUILD_EXTRAS OFF CACHE BOOL "" FORCE)
set(JUCE_ENABLE_MODULE_SOURCE_GROUPS ON CACHE BOOL "" FORCE)
```

Change:

```cmake
FetchContent_MakeAvailable(rtaudio imgui glfw)
```

to:

```cmake
FetchContent_MakeAvailable(juce imgui glfw)
```

Change the client target block to:

```cmake
add_executable(client
    client.cpp
    gui.cpp
    audio_stream.cpp
    juce_audio_backend.cpp
)

target_compile_definitions(client PRIVATE
    JUCE_GLOBAL_MODULE_SETTINGS_INCLUDED=1
    JUCE_ASIO=1
    JUCE_WASAPI=1
    JUCE_DIRECTSOUND=0
    JUCE_JACK=1
    JUCE_ALSA=1
    JUCE_USE_ANDROID_OBOE=1
    JUCE_WEB_BROWSER=0
    JUCE_USE_CURL=0
)

target_link_libraries(client PRIVATE
    asio
    concurrentqueue
    spdlog::spdlog
    opus
    imgui_lib
    juce::juce_audio_devices
    juce::juce_audio_basics
    juce::juce_core
    juce::juce_events
)
```

- [ ] **Step 2: Replace `audio_stream.h` with facade declarations**

Replace `audio_stream.h` with:

```cpp
#pragma once

#include "audio_backend.h"

#include <memory>
#include <string>
#include <vector>

class JuceAudioBackend;

class AudioStream {
public:
    using DeviceIndex = AudioDeviceId;
    using AudioCallback = ::AudioCallback;
    using AudioConfig = ::AudioConfig;
    using LatencyInfo = ::AudioLatencyInfo;

    static constexpr DeviceIndex NO_DEVICE = AUDIO_NO_DEVICE;

    struct DeviceInfo : AudioDeviceInfo {
        DeviceIndex index = AUDIO_NO_DEVICE;
    };

    struct ApiInfo : AudioApiInfo {};

    AudioStream();
    ~AudioStream();

    static const std::string& get_last_error();
    static void clear_last_error();
    static void print_all_devices();
    static const DeviceInfo* get_device_info(DeviceIndex device_index);
    static bool is_device_valid(DeviceIndex device_index);
    static std::vector<DeviceInfo> get_input_devices();
    static std::vector<DeviceInfo> get_output_devices();
    static std::vector<ApiInfo> get_apis();
    static DeviceIndex get_default_input_device();
    static DeviceIndex get_default_output_device();
    static void print_device_info(const DeviceInfo* input_info, const DeviceInfo* output_info);

    bool start_audio_stream(DeviceIndex input_device, DeviceIndex output_device,
                            const AudioConfig& config = AudioConfig{},
                            AudioCallback callback = nullptr, void* user_data = nullptr);
    void stop_audio_stream();
    void print_latency_info();
    LatencyInfo get_latency_info() const;
    int get_input_channel_count() const;
    int get_output_channel_count() const;
    bool is_stream_active() const;
    AudioConfig get_config() const;

private:
    static JuceAudioBackend& shared_backend();
    static DeviceInfo to_stream_device_info(const AudioDeviceInfo& info);
    static std::vector<DeviceInfo> to_stream_device_infos(const std::vector<AudioDeviceInfo>& infos);
    static std::vector<ApiInfo> to_stream_api_infos(const std::vector<AudioApiInfo>& infos);

    std::unique_ptr<JuceAudioBackend> backend_;
};
```

- [ ] **Step 3: Create JUCE backend header**

Create `juce_audio_backend.h`:

```cpp
#pragma once

#include "audio_backend.h"

#include <juce_audio_devices/juce_audio_devices.h>

#include <atomic>
#include <memory>
#include <string>
#include <vector>

class JuceAudioBackend final : private juce::AudioIODeviceCallback {
public:
    JuceAudioBackend();
    ~JuceAudioBackend() override;

    std::vector<AudioApiInfo> get_apis();
    std::vector<AudioDeviceInfo> get_input_devices();
    std::vector<AudioDeviceInfo> get_output_devices();
    std::vector<AudioDeviceInfo> get_all_devices();
    AudioDeviceId get_default_input_device();
    AudioDeviceId get_default_output_device();
    bool is_device_valid(AudioDeviceId device_id);
    bool get_device_info(AudioDeviceId device_id, AudioDeviceInfo& out);
    bool start_audio_stream(AudioDeviceId input_device, AudioDeviceId output_device,
                            const AudioConfig& config, AudioCallback callback,
                            void* user_data);
    void stop_audio_stream();
    bool is_stream_active() const;
    int get_input_channel_count() const;
    int get_output_channel_count() const;
    AudioConfig get_config() const;
    AudioLatencyInfo get_latency_info() const;
    const std::string& get_last_error() const;
    void clear_last_error();

private:
    void audioDeviceIOCallbackWithContext(const float* const* input_channel_data,
                                          int num_input_channels,
                                          float* const* output_channel_data,
                                          int num_output_channels,
                                          int num_samples,
                                          const juce::AudioIODeviceCallbackContext& context) override;
    void audioDeviceAboutToStart(juce::AudioIODevice* device) override;
    void audioDeviceStopped() override;

    static AudioDeviceId make_device_id(int api_index, int device_index, bool input);
    static int decode_api_index(AudioDeviceId id);
    static int decode_device_index(AudioDeviceId id);
    static bool decode_is_input(AudioDeviceId id);
    std::vector<AudioDeviceInfo> scan_devices(bool input);
    juce::AudioIODeviceType* find_type(int api_index);
    juce::String device_name_for_id(AudioDeviceId id);

    juce::AudioDeviceManager device_manager_;
    juce::OwnedArray<juce::AudioIODeviceType> device_types_;
    std::atomic<bool> stream_active_{false};
    AudioConfig current_config_;
    AudioCallback callback_ = nullptr;
    void* callback_user_data_ = nullptr;
    std::vector<float> interleaved_input_;
    std::vector<float> interleaved_output_;
    int input_channel_count_ = 0;
    int output_channel_count_ = 0;
    int actual_buffer_frames_ = 0;
    std::string last_error_;
};
```

- [ ] **Step 4: Implement JUCE backend**

Create `juce_audio_backend.cpp` with device inventory, stream open, callback adapter, and latency reporting. Use `AudioDeviceManager::createAudioDeviceTypes`, call `scanForDevices()` before reading device names, call `setAudioDeviceSetup()`, and route callbacks through `juce_audio_adapter` helpers.

The implementation must satisfy these details:

```text
Device IDs encode API index, device index, and input/output direction.
get_input_devices() returns devices with max_input_channels = 1.
get_output_devices() returns devices with max_output_channels = 2.
get_default_input_device() uses audio_backend::choose_default_input_device().
get_default_output_device() uses audio_backend::choose_default_output_device().
start_audio_stream() rejects invalid devices, devices with no required channels, and API mismatches.
start_audio_stream() sets sampleRate and bufferSize from AudioConfig.
audioDeviceIOCallbackWithContext() converts JUCE channel buffers to the current interleaved callback contract.
get_latency_info() reports current sample rate, requested frames, actual frames, and JUCE device input/output latency samples when available.
```

Use this callback body:

```cpp
void JuceAudioBackend::audioDeviceIOCallbackWithContext(
    const float* const* input_channel_data, int num_input_channels,
    float* const* output_channel_data, int num_output_channels, int num_samples,
    const juce::AudioIODeviceCallbackContext&) {
    juce_audio_adapter::copy_first_input_to_interleaved(
        input_channel_data, num_input_channels, num_samples,
        std::max(input_channel_count_, 1), interleaved_input_);

    interleaved_output_.assign(static_cast<size_t>(num_samples) *
                                   static_cast<size_t>(std::max(output_channel_count_, 1)),
                               0.0F);

    if (callback_ != nullptr) {
        callback_(interleaved_input_.data(), interleaved_output_.data(),
                  static_cast<unsigned long>(num_samples), callback_user_data_);
    }

    juce_audio_adapter::copy_interleaved_to_outputs(
        interleaved_output_, num_samples, std::max(output_channel_count_, 1),
        output_channel_data, num_output_channels);
}
```

- [ ] **Step 5: Implement `AudioStream` facade**

Create `audio_stream.cpp` so every static and instance method delegates to `JuceAudioBackend`. The facade must copy `AudioDeviceInfo::id` into `AudioStream::DeviceInfo::index` because `client.cpp` currently reads `dev.index`.

Include these methods exactly:

```cpp
AudioStream::AudioStream() : backend_(std::make_unique<JuceAudioBackend>()) {}

AudioStream::~AudioStream() {
    stop_audio_stream();
}

AudioStream::DeviceInfo AudioStream::to_stream_device_info(const AudioDeviceInfo& info) {
    DeviceInfo out;
    static_cast<AudioDeviceInfo&>(out) = info;
    out.index = info.id;
    return out;
}

bool AudioStream::start_audio_stream(DeviceIndex input_device, DeviceIndex output_device,
                                     const AudioConfig& config, AudioCallback callback,
                                     void* user_data) {
    return backend_->start_audio_stream(input_device, output_device, config, callback, user_data);
}

void AudioStream::stop_audio_stream() {
    if (backend_) {
        backend_->stop_audio_stream();
    }
}
```

Also preserve:

```text
get_last_error()
clear_last_error()
print_all_devices()
get_device_info()
is_device_valid()
get_input_devices()
get_output_devices()
get_apis()
get_default_input_device()
get_default_output_device()
print_device_info()
print_latency_info()
get_latency_info()
get_input_channel_count()
get_output_channel_count()
is_stream_active()
get_config()
```

- [ ] **Step 6: Configure and build JUCE-only client**

Run:

```powershell
cmake -S . -B build
cmake --build build --config Release --target client audio_backend_policy_self_test juce_audio_adapter_self_test audio_analysis_self_test
```

Expected: build succeeds without linking `rtaudio`.

- [ ] **Step 7: Run local smoke checks**

Run:

```powershell
.\build\Release\audio_backend_policy_self_test.exe
.\build\Release\juce_audio_adapter_self_test.exe
.\build\Release\audio_analysis_self_test.exe
.\build\Release\client.exe --list-audio-devices
.\build\Release\client.exe --audio-open-smoke --frames 240
.\build\Release\client.exe --audio-open-smoke --frames 120
git diff --check
```

Expected: tests pass, JUCE device inventory prints, and audio open smoke succeeds on the current default device path.

- [ ] **Step 8: Verify RtAudio is gone from active client code**

Run:

```powershell
rg -n "RtAudio|rtaudio|RTAUDIO" audio_stream.h audio_stream.cpp juce_audio_backend.h juce_audio_backend.cpp cmake\client.cmake client.cpp
```

Expected: no matches in active client audio build files. Historical docs and `.cache` may still contain matches.

- [ ] **Step 9: Commit**

```powershell
git add cmake/client.cmake audio_stream.h audio_stream.cpp juce_audio_backend.h juce_audio_backend.cpp client.cpp
git commit -m "Replace client audio backend with JUCE"
```

Expected: commit succeeds.

## Task 5: Backend-Neutral Diagnostics

**Files:**
- Modify: `client.cpp`
- Modify: `audio_stream.cpp`

- [ ] **Step 1: Remove RtAudio-specific diagnostic wording**

In `client.cpp`, change:

```cpp
Log::info("Compiled/available RtAudio APIs:");
```

to:

```cpp
Log::info("Available audio APIs:");
```

Search active client files:

```powershell
rg -n "RtAudio|rtaudio|RTAUDIO" client.cpp audio_stream.h audio_stream.cpp juce_audio_backend.h juce_audio_backend.cpp cmake\client.cmake
```

Expected: no active diagnostic text refers to RtAudio.

- [ ] **Step 2: Build and commit**

Run:

```powershell
cmake --build build --config Release --target client
.\build\Release\client.exe --list-audio-devices
git diff --check
git add client.cpp audio_stream.cpp
git commit -m "Use backend-neutral audio diagnostics"
```

Expected: build succeeds, device inventory prints, and commit succeeds.

## Task 6: Validation Matrix

**Files:**
- Modify: `archive/md-artifacts/root/LOW_LATENCY_AUDIO_AUDIT.md` if validation results are recorded.

- [ ] **Step 1: Run local automated checks**

Run:

```powershell
cmake --build build --config Release --target client audio_backend_policy_self_test juce_audio_adapter_self_test audio_analysis_self_test client_manager_self_test recording_writer_self_test
.\build\Release\audio_backend_policy_self_test.exe
.\build\Release\juce_audio_adapter_self_test.exe
.\build\Release\audio_analysis_self_test.exe
.\build\Release\client_manager_self_test.exe
.\build\Release\recording_writer_self_test.exe
.\build\Release\client.exe --list-audio-devices
.\build\Release\client.exe --audio-open-smoke --frames 240
.\build\Release\client.exe --audio-open-smoke --frames 120
git diff --check
```

Expected: all commands pass.

- [ ] **Step 2: Run Windows real-driver checks**

On Windows with a real ASIO driver:

```powershell
.\build\Release\client.exe --list-audio-devices
.\build\Release\client.exe --backend-check --require-api ASIO --frames 120
```

Expected: ASIO appears, the stream opens, actual buffer frames are logged, and latency is reported when the driver exposes it.

On Windows without ASIO:

```powershell
.\build\Release\client.exe --list-audio-devices
.\build\Release\client.exe --audio-open-smoke --frames 120
```

Expected: WASAPI appears through JUCE and opens for compatibility.

- [ ] **Step 3: Run macOS CoreAudio checks**

On macOS:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target client
./build/client --list-audio-devices
./build/client --audio-open-smoke --frames 120
```

Expected: CoreAudio devices appear and the open smoke succeeds.

- [ ] **Step 4: Manual GUI regression**

Run the GUI and verify:

```text
1. API dropdown lists JUCE APIs.
2. Input dropdown changes selected input.
3. Output dropdown changes selected output.
4. APPLY restarts an active stream.
5. START opens the selected devices.
6. STOP closes the stream.
7. Monitor checkbox routes local mic to local output.
8. MUTE prevents monitor and send.
9. PCM and Opus modes still send and receive.
10. Listener/broadcast tap does not include local monitor.
```

Expected: all checks pass.

- [ ] **Step 5: Record validation notes if needed**

If validation is recorded in the audit file, append a dated section to `archive/md-artifacts/root/LOW_LATENCY_AUDIO_AUDIT.md` with:

```markdown
### 2026-06-05 JUCE Audio Backend Validation

- JUCE is now the only active client audio backend.
- Local Windows smoke:
  - `client --list-audio-devices`: result recorded here.
  - `client --audio-open-smoke --frames 120`: result recorded here.
- Real ASIO hardware:
  - Result recorded here after hardware validation.
- macOS CoreAudio:
  - Result recorded here after hardware validation.
```

Then run:

```powershell
git add archive\md-artifacts\root\LOW_LATENCY_AUDIO_AUDIT.md
git commit -m "Record JUCE audio backend validation"
```

Expected: commit only if the audit file changed.

## Final Verification

Run:

```powershell
rg -n "RtAudio|rtaudio|RTAUDIO" audio_stream.h audio_stream.cpp juce_audio_backend.h juce_audio_backend.cpp cmake\client.cmake client.cpp
cmake --build build --config Release --target client
.\build\Release\client.exe --list-audio-devices
git status --short
git log --oneline -8
```

Expected: no RtAudio matches in active client files, client builds, device inventory prints, and the working tree is clean.
