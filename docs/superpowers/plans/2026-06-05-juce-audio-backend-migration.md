# JUCE Audio Backend Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the production RtAudio client path with JUCE while preserving the current client callback, GUI, CLI diagnostics, and rollback path.

**Architecture:** Introduce a small backend-neutral audio layer, move the existing RtAudio code behind that interface, then add a JUCE backend and make it the default. `AudioStream` remains the compatibility facade used by `client.cpp` until the JUCE path is validated.

**Tech Stack:** C++23, CMake FetchContent, JUCE `juce_audio_devices`/`juce_audio_basics`/`juce_core`, temporary RtAudio fallback, ImGui/GLFW client UI.

---

## Scope Check

The approved spec covers one subsystem: client audio backend migration. Codec, network, jitter, broadcast, recording, and GUI framework changes remain outside this plan except for regression verification.

## File Structure

- Create `LICENSE`: AGPLv3 license text for the public open-source repository.
- Create `THIRD_PARTY_NOTICES.md`: JUCE, RtAudio transition note, Opus, ImGui, GLFW, ASIO notice.
- Create `audio_backend.h`: backend-neutral audio types and `AudioBackend` interface.
- Create `audio_backend_policy.h`: API ranking and default selection helpers, independent of real devices.
- Create `audio_backend_policy_self_test.cpp`: deterministic test for ASIO/WASAPI/CoreAudio/JACK/ALSA preference rules.
- Create `rtaudio_audio_backend.h`.
- Create `rtaudio_audio_backend.cpp`: current RtAudio behavior moved out of `audio_stream.h`.
- Create `juce_audio_backend.h`.
- Create `juce_audio_backend.cpp`: JUCE device inventory, open/close, and callback adapter.
- Modify `audio_stream.h`: keep the existing public facade and delegate to a selected backend.
- Modify `cmake/client.cmake`: add backend options, JUCE dependency, backend sources, and compile definitions.
- Modify `CMakeLists.txt`: add the policy self-test executable.
- Modify `client.cpp`: update backend inventory wording from RtAudio-specific to backend-neutral, keep CLI names unchanged.

## Task 1: License And Third-Party Notices

**Files:**
- Create: `LICENSE`
- Create: `THIRD_PARTY_NOTICES.md`

- [ ] **Step 1: Add the AGPLv3 license text**

Run:

```powershell
Invoke-WebRequest -Uri "https://www.gnu.org/licenses/agpl-3.0.txt" -OutFile LICENSE
```

Expected: `LICENSE` exists and starts with `GNU AFFERO GENERAL PUBLIC LICENSE`.

- [ ] **Step 2: Add third-party notices**

Create `THIRD_PARTY_NOTICES.md` with this content:

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

ASIO is a Steinberg audio driver technology. JUCE can expose ASIO devices when the ASIO SDK and user-installed ASIO drivers are available.

- Steinberg developer information: https://www.steinberg.net/developers/
- ASIO open-source information: https://www.steinberg.net/developers/asiosdk-open/

ASIO is a trademark and software technology of Steinberg Media Technologies GmbH.

## RtAudio

RtAudio remains as a temporary transition backend until the JUCE backend passes validation.

- Source: https://github.com/thestk/rtaudio
- License: RtAudio license in the upstream repository.

## Opus

Opus is used for compressed audio mode.

- Source: https://opus-codec.org/
- License: Opus license in the upstream repository.

## Dear ImGui

Dear ImGui is used for the native client UI.

- Source: https://github.com/ocornut/imgui
- License: MIT.

## GLFW

GLFW is used for window and OpenGL context management.

- Source: https://github.com/glfw/glfw
- License: zlib/libpng.
```

- [ ] **Step 3: Verify files**

Run:

```powershell
Get-Content LICENSE -TotalCount 2
Get-Content THIRD_PARTY_NOTICES.md -TotalCount 12
git diff --check
```

Expected: license header prints, notices header prints, and `git diff --check` exits `0`.

- [ ] **Step 4: Commit**

```powershell
git add LICENSE THIRD_PARTY_NOTICES.md
git commit -m "Add open source license notices"
```

Expected: commit succeeds.

## Task 2: Backend-Neutral Types And Selection Policy

**Files:**
- Create: `audio_backend.h`
- Create: `audio_backend_policy.h`
- Create: `audio_backend_policy_self_test.cpp`
- Modify: `CMakeLists.txt`

- [ ] **Step 1: Write the failing policy test**

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
    std::vector<AudioDeviceInfo> devices{
        device(1, "WASAPI", true, false, true, false),
        device(2, "WASAPI", false, true, false, true),
        device(3, "ASIO", true, true, false, false),
    };

    require(audio_backend::rank_api_for_platform("ASIO") <
                audio_backend::rank_api_for_platform("WASAPI"),
            "ASIO must rank before WASAPI on Windows builds");

    auto input = audio_backend::choose_default_input_device(devices);
    auto output = audio_backend::choose_default_output_device(devices);
    require(input == 3, "input should prefer ASIO over WASAPI default");
    require(output == 3, "output should prefer ASIO over WASAPI default");

    std::vector<AudioDeviceInfo> fallback{
        device(10, "WASAPI", true, false, true, false),
        device(11, "WASAPI", false, true, false, true),
    };
    require(audio_backend::choose_default_input_device(fallback) == 10,
            "input should use default input when preferred API is absent");
    require(audio_backend::choose_default_output_device(fallback) == 11,
            "output should use default output when preferred API is absent");

    std::cout << "audio backend policy self-test passed\n";
    return 0;
}
```

- [ ] **Step 2: Add the self-test target and verify it fails**

Add to the end of `CMakeLists.txt`:

```cmake
add_executable(audio_backend_policy_self_test audio_backend_policy_self_test.cpp)
```

Run:

```powershell
cmake --build build --config Release --target audio_backend_policy_self_test
```

Expected: build fails because `audio_backend_policy.h` does not exist.

- [ ] **Step 3: Add backend-neutral types**

Create `audio_backend.h`:

```cpp
#pragma once

#include <cstdint>
#include <functional>
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

class AudioBackend {
public:
    virtual ~AudioBackend() = default;

    virtual const char* backend_name() const = 0;
    virtual std::vector<AudioApiInfo> get_apis() = 0;
    virtual std::vector<AudioDeviceInfo> get_input_devices() = 0;
    virtual std::vector<AudioDeviceInfo> get_output_devices() = 0;
    virtual std::vector<AudioDeviceInfo> get_all_devices() = 0;
    virtual AudioDeviceId get_default_input_device() = 0;
    virtual AudioDeviceId get_default_output_device() = 0;
    virtual bool is_device_valid(AudioDeviceId device_id) = 0;
    virtual bool get_device_info(AudioDeviceId device_id, AudioDeviceInfo& out) = 0;
    virtual bool start_audio_stream(AudioDeviceId input_device, AudioDeviceId output_device,
                                    const AudioConfig& config, AudioCallback callback,
                                    void* user_data) = 0;
    virtual void stop_audio_stream() = 0;
    virtual bool is_stream_active() const = 0;
    virtual int get_input_channel_count() const = 0;
    virtual int get_output_channel_count() const = 0;
    virtual AudioConfig get_config() const = 0;
    virtual AudioLatencyInfo get_latency_info() const = 0;
    virtual const std::string& get_last_error() const = 0;
    virtual void clear_last_error() = 0;
};
```

- [ ] **Step 4: Add platform ranking helpers**

Create `audio_backend_policy.h`:

```cpp
#pragma once

#include "audio_backend.h"

#include <algorithm>
#include <limits>
#include <string>
#include <vector>

namespace audio_backend {

inline int rank_api_for_platform(const std::string& api_name) {
#ifdef _WIN32
    if (api_name == "ASIO") {
        return 0;
    }
    if (api_name == "WASAPI") {
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

- [ ] **Step 5: Run the policy test**

Run:

```powershell
cmake --build build --config Release --target audio_backend_policy_self_test
.\build\Release\audio_backend_policy_self_test.exe
```

Expected: executable prints `audio backend policy self-test passed`.

- [ ] **Step 6: Commit**

```powershell
git add audio_backend.h audio_backend_policy.h audio_backend_policy_self_test.cpp CMakeLists.txt
git commit -m "Add audio backend interface policy"
```

Expected: commit succeeds.

## Task 3: CMake Backend Switch And JUCE Dependency

**Files:**
- Modify: `cmake/client.cmake`

- [ ] **Step 1: Add backend options**

In `cmake/client.cmake`, after `include(cmake/common.cmake)`, add:

```cmake
set(JAM_AUDIO_BACKEND "JUCE" CACHE STRING "Audio backend: JUCE or RTAUDIO")
set_property(CACHE JAM_AUDIO_BACKEND PROPERTY STRINGS JUCE RTAUDIO)
option(JAM_ENABLE_RTAUDIO_BACKEND "Build temporary RtAudio fallback backend" ON)
```

- [ ] **Step 2: Add JUCE FetchContent**

After the RtAudio `FetchContent_Declare` block, add:

```cmake
FetchContent_Declare(
    juce
    GIT_REPOSITORY https://github.com/juce-framework/JUCE.git
    GIT_TAG        8.0.10
    GIT_SHALLOW    TRUE
    GIT_PROGRESS   TRUE
)
```

Before `FetchContent_MakeAvailable(...)`, add:

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
FetchContent_MakeAvailable(rtaudio juce imgui glfw)
```

- [ ] **Step 3: Link JUCE modules without changing sources yet**

Replace the current client target block:

```cmake
add_executable(client client.cpp gui.cpp)
target_link_libraries(client PRIVATE asio concurrentqueue spdlog::spdlog rtaudio opus imgui_lib)
```

with:

```cmake
add_executable(client client.cpp gui.cpp)

target_compile_definitions(client PRIVATE
    JAM_AUDIO_BACKEND_${JAM_AUDIO_BACKEND}=1
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
    rtaudio
    opus
    imgui_lib
    juce::juce_audio_devices
    juce::juce_audio_basics
    juce::juce_core
    juce::juce_events
)
```

The backend source files are added in later tasks after those files exist.

- [ ] **Step 4: Verify configure and current client build**

Run:

```powershell
cmake -S . -B build
cmake --build build --config Release --target client
```

Expected: configure and build succeed with the current RtAudio implementation still inside `audio_stream.h`.

- [ ] **Step 5: Commit CMake dependency change**

```powershell
git add cmake/client.cmake
git commit -m "Add JUCE audio backend build switch"
```

Expected: commit succeeds.

## Task 4: Extract RtAudio Behind AudioBackend

**Files:**
- Create: `rtaudio_audio_backend.h`
- Create: `rtaudio_audio_backend.cpp`
- Create: `audio_stream.cpp`
- Modify: `audio_stream.h`
- Modify: `cmake/client.cmake`

- [ ] **Step 1: Create the RtAudio backend header**

Create `rtaudio_audio_backend.h`:

```cpp
#pragma once

#include "audio_backend.h"

#include <RtAudio.h>

#include <atomic>
#include <memory>
#include <string>
#include <vector>

class RtAudioBackend final : public AudioBackend {
public:
    RtAudioBackend();
    ~RtAudioBackend() override;

    const char* backend_name() const override;
    std::vector<AudioApiInfo> get_apis() override;
    std::vector<AudioDeviceInfo> get_input_devices() override;
    std::vector<AudioDeviceInfo> get_output_devices() override;
    std::vector<AudioDeviceInfo> get_all_devices() override;
    AudioDeviceId get_default_input_device() override;
    AudioDeviceId get_default_output_device() override;
    bool is_device_valid(AudioDeviceId device_id) override;
    bool get_device_info(AudioDeviceId device_id, AudioDeviceInfo& out) override;
    bool start_audio_stream(AudioDeviceId input_device, AudioDeviceId output_device,
                            const AudioConfig& config, AudioCallback callback,
                            void* user_data) override;
    void stop_audio_stream() override;
    bool is_stream_active() const override;
    int get_input_channel_count() const override;
    int get_output_channel_count() const override;
    AudioConfig get_config() const override;
    AudioLatencyInfo get_latency_info() const override;
    const std::string& get_last_error() const override;
    void clear_last_error() override;

private:
    struct ApiScanInfo {
        int index = -1;
        std::string name;
        RtAudio::Api rt_api = RtAudio::UNSPECIFIED;
    };

    static std::vector<ApiScanInfo> get_apis_without_defaults();
    static int rt_audio_callback(void* output_buffer, void* input_buffer, unsigned int n_frames,
                                 double stream_time, RtAudioStreamStatus status,
                                 void* user_data);

    std::unique_ptr<RtAudio> stream_;
    std::atomic<bool> stream_active_{false};
    AudioConfig current_config_;
    AudioCallback callback_ = nullptr;
    void* callback_user_data_ = nullptr;
    unsigned int actual_buffer_frames_ = 0;
    int input_channel_count_ = 0;
    int output_channel_count_ = 0;
    std::string last_error_;
};
```

- [ ] **Step 2: Move current RtAudio implementation**

Create `rtaudio_audio_backend.cpp` by moving the current RtAudio logic from `audio_stream.h` into `RtAudioBackend`.

Use these exact mapping rules:

```text
AudioStream::get_apis -> RtAudioBackend::get_apis
AudioStream::get_all_devices -> RtAudioBackend::get_all_devices
AudioStream::get_default_input_device -> RtAudioBackend::get_default_input_device
AudioStream::get_default_output_device -> RtAudioBackend::get_default_output_device
AudioStream::get_device_info -> RtAudioBackend::get_device_info
AudioStream::is_device_valid -> RtAudioBackend::is_device_valid
AudioStream::start_audio_stream -> RtAudioBackend::start_audio_stream
AudioStream::stop_audio_stream -> RtAudioBackend::stop_audio_stream
AudioStream::get_latency_info -> RtAudioBackend::get_latency_info
AudioStream::rt_audio_callback -> RtAudioBackend::rt_audio_callback
```

Add these method bodies directly:

```cpp
const char* RtAudioBackend::backend_name() const {
    return "RtAudio";
}

RtAudioBackend::RtAudioBackend() = default;

RtAudioBackend::~RtAudioBackend() {
    stop_audio_stream();
}

const std::string& RtAudioBackend::get_last_error() const {
    return last_error_;
}

void RtAudioBackend::clear_last_error() {
    last_error_.clear();
}

bool RtAudioBackend::is_stream_active() const {
    return stream_active_.load(std::memory_order_relaxed);
}

int RtAudioBackend::get_input_channel_count() const {
    return input_channel_count_;
}

int RtAudioBackend::get_output_channel_count() const {
    return output_channel_count_;
}

AudioConfig RtAudioBackend::get_config() const {
    return current_config_;
}
```

When moving code, replace every write to `AudioStream::last_error_` with `last_error_`.

- [ ] **Step 3: Refactor AudioStream into a facade**

Replace the contents of `audio_stream.h` with declarations only:

```cpp
#pragma once

#include "audio_backend.h"

#include <memory>
#include <string>
#include <vector>

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
    static AudioBackend& default_backend();
    static DeviceInfo to_stream_device_info(const AudioDeviceInfo& info);
    static std::vector<DeviceInfo> to_stream_device_infos(const std::vector<AudioDeviceInfo>& infos);
    static std::vector<ApiInfo> to_stream_api_infos(const std::vector<AudioApiInfo>& infos);

    std::unique_ptr<AudioBackend> backend_;
};
```

- [ ] **Step 4: Add AudioStream implementation**

Create `audio_stream.cpp` with facade methods. The backend factory should select RtAudio for this task so behavior stays unchanged:

```cpp
#include "audio_stream.h"

#include "logger.h"
#include "rtaudio_audio_backend.h"

#include <algorithm>
#include <mutex>

namespace {

std::string global_audio_error;

std::unique_ptr<AudioBackend> make_audio_backend() {
    return std::make_unique<RtAudioBackend>();
}

}  // namespace

AudioStream::AudioStream() : backend_(make_audio_backend()) {}

AudioStream::~AudioStream() {
    stop_audio_stream();
}

AudioBackend& AudioStream::default_backend() {
    static std::unique_ptr<AudioBackend> backend = make_audio_backend();
    return *backend;
}

AudioStream::DeviceInfo AudioStream::to_stream_device_info(const AudioDeviceInfo& info) {
    DeviceInfo out;
    static_cast<AudioDeviceInfo&>(out) = info;
    out.index = info.id;
    return out;
}

std::vector<AudioStream::DeviceInfo>
AudioStream::to_stream_device_infos(const std::vector<AudioDeviceInfo>& infos) {
    std::vector<DeviceInfo> result;
    result.reserve(infos.size());
    for (const auto& info: infos) {
        result.push_back(to_stream_device_info(info));
    }
    return result;
}

std::vector<AudioStream::ApiInfo>
AudioStream::to_stream_api_infos(const std::vector<AudioApiInfo>& infos) {
    std::vector<ApiInfo> result;
    result.reserve(infos.size());
    for (const auto& info: infos) {
        ApiInfo out;
        static_cast<AudioApiInfo&>(out) = info;
        result.push_back(out);
    }
    return result;
}

const std::string& AudioStream::get_last_error() {
    global_audio_error = default_backend().get_last_error();
    return global_audio_error;
}

void AudioStream::clear_last_error() {
    default_backend().clear_last_error();
    global_audio_error.clear();
}

void AudioStream::print_all_devices() {
    Log::info("Available audio devices:");
    for (const auto& device_info: get_input_devices()) {
        Log::info("Input Device {}: {} | API: {} | Max Input Channels: {} | Default Sample Rate: {}",
                  device_info.index, device_info.name, device_info.api_name,
                  device_info.max_input_channels, device_info.default_sample_rate);
    }
    for (const auto& device_info: get_output_devices()) {
        Log::info("Output Device {}: {} | API: {} | Max Output Channels: {} | Default Sample Rate: {}",
                  device_info.index, device_info.name, device_info.api_name,
                  device_info.max_output_channels, device_info.default_sample_rate);
    }
}

const AudioStream::DeviceInfo* AudioStream::get_device_info(DeviceIndex device_index) {
    static thread_local DeviceInfo cached;
    AudioDeviceInfo info;
    if (!default_backend().get_device_info(device_index, info)) {
        Log::error("Invalid device index: {}", device_index);
        return nullptr;
    }
    cached = to_stream_device_info(info);
    return &cached;
}

bool AudioStream::is_device_valid(DeviceIndex device_index) {
    return default_backend().is_device_valid(device_index);
}

std::vector<AudioStream::DeviceInfo> AudioStream::get_input_devices() {
    return to_stream_device_infos(default_backend().get_input_devices());
}

std::vector<AudioStream::DeviceInfo> AudioStream::get_output_devices() {
    return to_stream_device_infos(default_backend().get_output_devices());
}

std::vector<AudioStream::ApiInfo> AudioStream::get_apis() {
    return to_stream_api_infos(default_backend().get_apis());
}

AudioStream::DeviceIndex AudioStream::get_default_input_device() {
    return default_backend().get_default_input_device();
}

AudioStream::DeviceIndex AudioStream::get_default_output_device() {
    return default_backend().get_default_output_device();
}

void AudioStream::print_device_info(const DeviceInfo* input_info, const DeviceInfo* output_info) {
    Log::info("Input Device: {} | API: {} | Max Input Channels: {} | Default Sample Rate: {}",
              input_info->name, input_info->api_name, input_info->max_input_channels,
              input_info->default_sample_rate);
    Log::info("Output Device: {} | API: {} | Max Output Channels: {} | Default Sample Rate: {}",
              output_info->name, output_info->api_name, output_info->max_output_channels,
              output_info->default_sample_rate);
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

void AudioStream::print_latency_info() {
    auto info = get_latency_info();
    Log::info("Input latency:  {:.3f} ms", info.input_latency_ms);
    Log::info("Output latency: {:.3f} ms", info.output_latency_ms);
    Log::info("Sample rate:    {:.1f} Hz", info.sample_rate);
    Log::info("Requested buffer: {} frames", info.requested_buffer_frames);
    Log::info("Actual buffer:    {} frames ({:.3f} ms)", info.actual_buffer_frames,
              info.buffer_duration_ms);
    if (!info.backend_latency_available) {
        Log::info("Backend latency is unavailable or reported as zero");
    }
}

AudioStream::LatencyInfo AudioStream::get_latency_info() const {
    return backend_->get_latency_info();
}

int AudioStream::get_input_channel_count() const {
    return backend_->get_input_channel_count();
}

int AudioStream::get_output_channel_count() const {
    return backend_->get_output_channel_count();
}

bool AudioStream::is_stream_active() const {
    return backend_->is_stream_active();
}

AudioStream::AudioConfig AudioStream::get_config() const {
    return backend_->get_config();
}
```

- [ ] **Step 5: Add extracted backend sources to the client target**

In `cmake/client.cmake`, change:

```cmake
add_executable(client client.cpp gui.cpp)
```

to:

```cmake
add_executable(client
    client.cpp
    gui.cpp
    audio_stream.cpp
    rtaudio_audio_backend.cpp
)
```

- [ ] **Step 6: Build and run current RtAudio diagnostics**

Run:

```powershell
cmake -S . -B build
cmake --build build --config Release --target client audio_backend_policy_self_test audio_analysis_self_test
.\build\Release\audio_backend_policy_self_test.exe
.\build\Release\audio_analysis_self_test.exe
.\build\Release\client.exe --list-audio-devices
.\build\Release\client.exe --audio-open-smoke --require-api WASAPI --frames 120
```

Expected: both self-tests pass, device inventory prints, and WASAPI smoke succeeds on the current Windows machine.

- [ ] **Step 7: Commit**

```powershell
git add audio_stream.h audio_stream.cpp rtaudio_audio_backend.h rtaudio_audio_backend.cpp cmake/client.cmake
git commit -m "Move RtAudio behind audio backend interface"
```

Expected: commit succeeds.

## Task 5: JUCE Device Inventory Backend

**Files:**
- Create: `juce_audio_backend.h`
- Create: `juce_audio_backend.cpp`
- Modify: `audio_stream.cpp`
- Modify: `cmake/client.cmake`

- [ ] **Step 1: Create JUCE backend header**

Create `juce_audio_backend.h`:

```cpp
#pragma once

#include "audio_backend.h"

#include <juce_audio_devices/juce_audio_devices.h>

#include <atomic>
#include <memory>
#include <string>
#include <vector>

class JuceAudioBackend final : public AudioBackend,
                               private juce::AudioIODeviceCallback {
public:
    JuceAudioBackend();
    ~JuceAudioBackend() override;

    const char* backend_name() const override;
    std::vector<AudioApiInfo> get_apis() override;
    std::vector<AudioDeviceInfo> get_input_devices() override;
    std::vector<AudioDeviceInfo> get_output_devices() override;
    std::vector<AudioDeviceInfo> get_all_devices() override;
    AudioDeviceId get_default_input_device() override;
    AudioDeviceId get_default_output_device() override;
    bool is_device_valid(AudioDeviceId device_id) override;
    bool get_device_info(AudioDeviceId device_id, AudioDeviceInfo& out) override;
    bool start_audio_stream(AudioDeviceId input_device, AudioDeviceId output_device,
                            const AudioConfig& config, AudioCallback callback,
                            void* user_data) override;
    void stop_audio_stream() override;
    bool is_stream_active() const override;
    int get_input_channel_count() const override;
    int get_output_channel_count() const override;
    AudioConfig get_config() const override;
    AudioLatencyInfo get_latency_info() const override;
    const std::string& get_last_error() const override;
    void clear_last_error() override;

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

- [ ] **Step 2: Add JUCE inventory implementation**

Create `juce_audio_backend.cpp` with these inventory methods:

```cpp
#include "juce_audio_backend.h"

#include "audio_backend_policy.h"
#include "logger.h"

#include <algorithm>
#include <cstring>

JuceAudioBackend::JuceAudioBackend() {
    device_manager_.createAudioDeviceTypes(device_types_);
}

JuceAudioBackend::~JuceAudioBackend() {
    stop_audio_stream();
}

const char* JuceAudioBackend::backend_name() const {
    return "JUCE";
}

AudioDeviceId JuceAudioBackend::make_device_id(int api_index, int device_index, bool input) {
    return static_cast<AudioDeviceId>(((api_index + 1) << 17) |
                                      ((device_index + 1) << 1) |
                                      (input ? 1 : 0));
}

int JuceAudioBackend::decode_api_index(AudioDeviceId id) {
    return (static_cast<int>(id >> 17) - 1);
}

int JuceAudioBackend::decode_device_index(AudioDeviceId id) {
    return (static_cast<int>((id >> 1) & 0xFFFF) - 1);
}

bool JuceAudioBackend::decode_is_input(AudioDeviceId id) {
    return (id & 1U) != 0U;
}

std::vector<AudioApiInfo> JuceAudioBackend::get_apis() {
    std::vector<AudioApiInfo> apis;
    for (int api_index = 0; api_index < device_types_.size(); ++api_index) {
        auto* type = device_types_[api_index];
        if (type == nullptr) {
            continue;
        }
        type->scanForDevices();
        AudioApiInfo info;
        info.index = api_index;
        info.name = type->getTypeName().toStdString();
        apis.push_back(info);
    }
    return apis;
}

std::vector<AudioDeviceInfo> JuceAudioBackend::scan_devices(bool input) {
    std::vector<AudioDeviceInfo> devices;
    for (int api_index = 0; api_index < device_types_.size(); ++api_index) {
        auto* type = device_types_[api_index];
        if (type == nullptr) {
            continue;
        }

        type->scanForDevices();
        const auto names = type->getDeviceNames(input);
        const auto default_name = type->getDefaultDeviceName(input);
        for (int device_index = 0; device_index < names.size(); ++device_index) {
            AudioDeviceInfo info;
            info.id = make_device_id(api_index, device_index, input);
            info.name = names[device_index].toStdString();
            info.api_name = type->getTypeName().toStdString();
            info.api_index = api_index;
            info.max_input_channels = input ? 1 : 0;
            info.max_output_channels = input ? 0 : 2;
            info.default_sample_rate = 48000.0;
            info.is_default_input = input && names[device_index] == default_name;
            info.is_default_output = !input && names[device_index] == default_name;
            devices.push_back(info);
        }
    }
    return devices;
}

std::vector<AudioDeviceInfo> JuceAudioBackend::get_input_devices() {
    return scan_devices(true);
}

std::vector<AudioDeviceInfo> JuceAudioBackend::get_output_devices() {
    return scan_devices(false);
}

std::vector<AudioDeviceInfo> JuceAudioBackend::get_all_devices() {
    auto input = get_input_devices();
    auto output = get_output_devices();
    input.insert(input.end(), output.begin(), output.end());
    return input;
}

AudioDeviceId JuceAudioBackend::get_default_input_device() {
    return audio_backend::choose_default_input_device(get_input_devices());
}

AudioDeviceId JuceAudioBackend::get_default_output_device() {
    return audio_backend::choose_default_output_device(get_output_devices());
}

bool JuceAudioBackend::is_device_valid(AudioDeviceId device_id) {
    AudioDeviceInfo ignored;
    return get_device_info(device_id, ignored);
}

bool JuceAudioBackend::get_device_info(AudioDeviceId device_id, AudioDeviceInfo& out) {
    for (const auto& device: get_all_devices()) {
        if (device.id == device_id) {
            out = device;
            return true;
        }
    }
    last_error_ = "Invalid JUCE audio device";
    return false;
}

juce::AudioIODeviceType* JuceAudioBackend::find_type(int api_index) {
    if (api_index < 0 || api_index >= device_types_.size()) {
        return nullptr;
    }
    return device_types_[api_index];
}

juce::String JuceAudioBackend::device_name_for_id(AudioDeviceId id) {
    auto* type = find_type(decode_api_index(id));
    if (type == nullptr) {
        return {};
    }
    type->scanForDevices();
    const auto names = type->getDeviceNames(decode_is_input(id));
    const int device_index = decode_device_index(id);
    if (device_index < 0 || device_index >= names.size()) {
        return {};
    }
    return names[device_index];
}

const std::string& JuceAudioBackend::get_last_error() const {
    return last_error_;
}

void JuceAudioBackend::clear_last_error() {
    last_error_.clear();
}
```

- [ ] **Step 3: Add stub stream methods so the project links**

Append these methods to `juce_audio_backend.cpp`:

```cpp
bool JuceAudioBackend::start_audio_stream(AudioDeviceId, AudioDeviceId,
                                          const AudioConfig& config,
                                          AudioCallback callback, void* user_data) {
    current_config_ = config;
    callback_ = callback;
    callback_user_data_ = user_data;
    last_error_ = "JUCE stream open is not wired yet";
    return false;
}

void JuceAudioBackend::stop_audio_stream() {
    stream_active_.store(false, std::memory_order_relaxed);
    device_manager_.removeAudioCallback(this);
    device_manager_.closeAudioDevice();
}

bool JuceAudioBackend::is_stream_active() const {
    return stream_active_.load(std::memory_order_relaxed);
}

int JuceAudioBackend::get_input_channel_count() const {
    return input_channel_count_;
}

int JuceAudioBackend::get_output_channel_count() const {
    return output_channel_count_;
}

AudioConfig JuceAudioBackend::get_config() const {
    return current_config_;
}

AudioLatencyInfo JuceAudioBackend::get_latency_info() const {
    AudioLatencyInfo info;
    info.sample_rate = current_config_.sample_rate;
    info.requested_buffer_frames = current_config_.frames_per_buffer;
    info.actual_buffer_frames = actual_buffer_frames_;
    if (current_config_.sample_rate > 0 && actual_buffer_frames_ > 0) {
        info.buffer_duration_ms = static_cast<double>(actual_buffer_frames_) * 1000.0 /
                                  static_cast<double>(current_config_.sample_rate);
    }
    return info;
}

void JuceAudioBackend::audioDeviceIOCallbackWithContext(
    const float* const*, int, float* const* output_channel_data, int num_output_channels,
    int num_samples, const juce::AudioIODeviceCallbackContext&) {
    for (int channel = 0; channel < num_output_channels; ++channel) {
        if (output_channel_data[channel] != nullptr) {
            std::fill(output_channel_data[channel],
                      output_channel_data[channel] + num_samples, 0.0F);
        }
    }
}

void JuceAudioBackend::audioDeviceAboutToStart(juce::AudioIODevice* device) {
    if (device != nullptr) {
        actual_buffer_frames_ = device->getCurrentBufferSizeSamples();
    }
}

void JuceAudioBackend::audioDeviceStopped() {
    stream_active_.store(false, std::memory_order_relaxed);
}
```

- [ ] **Step 4: Add JUCE backend source to the client target**

In `cmake/client.cmake`, change:

```cmake
add_executable(client
    client.cpp
    gui.cpp
    audio_stream.cpp
    rtaudio_audio_backend.cpp
)
```

to:

```cmake
add_executable(client
    client.cpp
    gui.cpp
    audio_stream.cpp
    rtaudio_audio_backend.cpp
    juce_audio_backend.cpp
)
```

- [ ] **Step 5: Select JUCE backend in AudioStream factory**

In `audio_stream.cpp`, include the JUCE header:

```cpp
#include "juce_audio_backend.h"
```

Change `make_audio_backend()`:

```cpp
std::unique_ptr<AudioBackend> make_audio_backend() {
#if defined(JAM_AUDIO_BACKEND_JUCE)
    return std::make_unique<JuceAudioBackend>();
#else
    return std::make_unique<RtAudioBackend>();
#endif
}
```

- [ ] **Step 6: Build and list devices**

Run:

```powershell
cmake -S . -B build -DJAM_AUDIO_BACKEND=JUCE
cmake --build build --config Release --target client
.\build\Release\client.exe --list-audio-devices
```

Expected: build succeeds and device inventory prints JUCE APIs/devices. `--audio-open-smoke` may fail with `JUCE stream open is not wired yet`.

- [ ] **Step 7: Commit**

```powershell
git add juce_audio_backend.h juce_audio_backend.cpp audio_stream.cpp cmake/client.cmake
git commit -m "Add JUCE audio device inventory backend"
```

Expected: commit succeeds.

## Task 6: JUCE Stream Open And Callback Adapter

**Files:**
- Modify: `juce_audio_backend.cpp`

- [ ] **Step 1: Replace JUCE stream open stub**

Replace `JuceAudioBackend::start_audio_stream` with:

```cpp
bool JuceAudioBackend::start_audio_stream(AudioDeviceId input_device, AudioDeviceId output_device,
                                          const AudioConfig& config,
                                          AudioCallback callback, void* user_data) {
    stop_audio_stream();

    AudioDeviceInfo input_info;
    AudioDeviceInfo output_info;
    if (!get_device_info(input_device, input_info) || !get_device_info(output_device, output_info)) {
        last_error_ = "Invalid input or output device";
        return false;
    }
    if (input_info.max_input_channels <= 0) {
        last_error_ = "Selected input device has no input channels";
        return false;
    }
    if (output_info.max_output_channels <= 0) {
        last_error_ = "Selected output device has no output channels";
        return false;
    }
    if (input_info.api_index != output_info.api_index) {
        last_error_ = "Input and output devices must use the same audio API";
        return false;
    }

    current_config_ = config;
    callback_ = callback;
    callback_user_data_ = user_data;
    input_channel_count_ = 1;
    output_channel_count_ = output_info.max_output_channels >= 2 ? 2 : 1;
    actual_buffer_frames_ = config.frames_per_buffer;
    interleaved_input_.assign(static_cast<size_t>(config.frames_per_buffer) *
                                  static_cast<size_t>(input_channel_count_),
                              0.0F);
    interleaved_output_.assign(static_cast<size_t>(config.frames_per_buffer) *
                                   static_cast<size_t>(output_channel_count_),
                               0.0F);

    juce::AudioDeviceManager::AudioDeviceSetup setup;
    setup.inputDeviceName = device_name_for_id(input_device);
    setup.outputDeviceName = device_name_for_id(output_device);
    setup.sampleRate = static_cast<double>(config.sample_rate);
    setup.bufferSize = config.frames_per_buffer;
    setup.useDefaultInputChannels = false;
    setup.inputChannels.clear();
    setup.inputChannels.setBit(0);
    setup.useDefaultOutputChannels = false;
    setup.outputChannels.clear();
    for (int channel = 0; channel < output_channel_count_; ++channel) {
        setup.outputChannels.setBit(channel);
    }

    const auto init_error = device_manager_.initialise(
        input_channel_count_, output_channel_count_, nullptr, false);
    if (init_error.isNotEmpty()) {
        last_error_ = init_error.toStdString();
        return false;
    }

    const auto setup_error = device_manager_.setAudioDeviceSetup(setup, true);
    if (setup_error.isNotEmpty()) {
        last_error_ = setup_error.toStdString();
        device_manager_.closeAudioDevice();
        return false;
    }

    device_manager_.addAudioCallback(this);
    stream_active_.store(true, std::memory_order_relaxed);
    last_error_.clear();

    if (auto* device = device_manager_.getCurrentAudioDevice()) {
        actual_buffer_frames_ = device->getCurrentBufferSizeSamples();
        Log::info("JUCE opened {} input channel(s), {} output channel(s) at {:.1f} Hz",
                  input_channel_count_, output_channel_count_, device->getCurrentSampleRate());
        Log::info("JUCE requested {} frames, actual {} frames", config.frames_per_buffer,
                  actual_buffer_frames_);
    }
    return true;
}
```

- [ ] **Step 2: Replace JUCE callback stub**

Replace `audioDeviceIOCallbackWithContext` with:

```cpp
void JuceAudioBackend::audioDeviceIOCallbackWithContext(
    const float* const* input_channel_data, int num_input_channels,
    float* const* output_channel_data, int num_output_channels, int num_samples,
    const juce::AudioIODeviceCallbackContext&) {
    const size_t frames = static_cast<size_t>(num_samples);
    const size_t input_channels = static_cast<size_t>(std::max(input_channel_count_, 1));
    const size_t output_channels = static_cast<size_t>(std::max(output_channel_count_, 1));

    interleaved_input_.assign(frames * input_channels, 0.0F);
    interleaved_output_.assign(frames * output_channels, 0.0F);

    if (input_channel_data != nullptr && num_input_channels > 0 &&
        input_channel_data[0] != nullptr) {
        for (size_t frame = 0; frame < frames; ++frame) {
            interleaved_input_[frame * input_channels] = input_channel_data[0][frame];
        }
    }

    if (callback_ != nullptr) {
        callback_(interleaved_input_.data(), interleaved_output_.data(),
                  static_cast<unsigned long>(num_samples), callback_user_data_);
    }

    for (int channel = 0; channel < num_output_channels; ++channel) {
        if (output_channel_data[channel] == nullptr) {
            continue;
        }
        const size_t source_channel =
            static_cast<size_t>(std::min(channel, output_channel_count_ - 1));
        for (size_t frame = 0; frame < frames; ++frame) {
            output_channel_data[channel][frame] =
                interleaved_output_[frame * output_channels + source_channel];
        }
    }
}
```

- [ ] **Step 3: Replace latency reporting with JUCE device values**

Replace `JuceAudioBackend::get_latency_info` with:

```cpp
AudioLatencyInfo JuceAudioBackend::get_latency_info() const {
    AudioLatencyInfo info;
    info.sample_rate = current_config_.sample_rate;
    info.requested_buffer_frames = current_config_.frames_per_buffer;
    info.actual_buffer_frames = actual_buffer_frames_;
    if (current_config_.sample_rate > 0 && actual_buffer_frames_ > 0) {
        info.buffer_duration_ms = static_cast<double>(actual_buffer_frames_) * 1000.0 /
                                  static_cast<double>(current_config_.sample_rate);
    }

    if (auto* device = device_manager_.getCurrentAudioDevice()) {
        const double rate = device->getCurrentSampleRate();
        if (rate > 0.0) {
            info.sample_rate = rate;
            info.input_latency_ms = static_cast<double>(device->getInputLatencyInSamples()) *
                                    1000.0 / rate;
            info.output_latency_ms = static_cast<double>(device->getOutputLatencyInSamples()) *
                                     1000.0 / rate;
            info.backend_latency_available =
                device->getInputLatencyInSamples() > 0 || device->getOutputLatencyInSamples() > 0;
        }
    }
    return info;
}
```

- [ ] **Step 4: Build and smoke open JUCE**

Run:

```powershell
cmake -S . -B build -DJAM_AUDIO_BACKEND=JUCE
cmake --build build --config Release --target client audio_analysis_self_test
.\build\Release\audio_analysis_self_test.exe
.\build\Release\client.exe --list-audio-devices
.\build\Release\client.exe --audio-open-smoke --frames 240
.\build\Release\client.exe --audio-open-smoke --frames 120
```

Expected: build succeeds, analysis self-test passes, device inventory prints, and both open smoke commands succeed on the current default device path.

- [ ] **Step 5: Commit**

```powershell
git add juce_audio_backend.cpp
git commit -m "Open JUCE audio streams through client callback"
```

Expected: commit succeeds.

## Task 7: Backend-Neutral Diagnostics And Default Switch

**Files:**
- Modify: `client.cpp`
- Modify: `audio_stream.cpp`
- Modify: `cmake/client.cmake`

- [ ] **Step 1: Update inventory wording**

In `client.cpp`, change:

```cpp
Log::info("Compiled/available RtAudio APIs:");
```

to:

```cpp
Log::info("Available audio APIs:");
```

Change any user-visible `RtAudio` wording in backend inventory and latency diagnostics to `audio backend`, except RtAudio-specific messages inside `rtaudio_audio_backend.cpp`.

- [ ] **Step 2: Keep JUCE as default**

In `cmake/client.cmake`, verify this line remains:

```cmake
set(JAM_AUDIO_BACKEND "JUCE" CACHE STRING "Audio backend: JUCE or RTAUDIO")
```

Run:

```powershell
cmake -S . -B build
cmake --build build --config Release --target client
.\build\Release\client.exe --list-audio-devices
```

Expected: configure uses JUCE by default and device inventory still prints.

- [ ] **Step 3: Verify RtAudio fallback still builds**

Run:

```powershell
cmake -S . -B build-rtaudio -DJAM_AUDIO_BACKEND=RTAUDIO
cmake --build build-rtaudio --config Release --target client
.\build-rtaudio\Release\client.exe --list-audio-devices
```

Expected: fallback build succeeds and lists RtAudio devices.

- [ ] **Step 4: Commit**

```powershell
git add client.cpp audio_stream.cpp cmake/client.cmake
git commit -m "Make JUCE the default audio backend"
```

Expected: commit succeeds.

## Task 8: Regression And Hardware Validation

**Files:**
- Modify: `docs/superpowers/specs/2026-06-05-juce-audio-backend-migration-design.md` only if validation findings change the design.
- Modify: `archive/md-artifacts/root/LOW_LATENCY_AUDIO_AUDIT.md` if this repo still uses that audit log for active validation notes.

- [ ] **Step 1: Run local automated verification**

Run:

```powershell
cmake --build build --config Release --target client audio_backend_policy_self_test audio_analysis_self_test client_manager_self_test recording_writer_self_test
.\build\Release\audio_backend_policy_self_test.exe
.\build\Release\audio_analysis_self_test.exe
.\build\Release\client_manager_self_test.exe
.\build\Release\recording_writer_self_test.exe
.\build\Release\client.exe --list-audio-devices
.\build\Release\client.exe --audio-open-smoke --frames 240
.\build\Release\client.exe --audio-open-smoke --frames 120
.\build\Release\client.exe --backend-check --require-api WASAPI --frames 120
git diff --check
```

Expected: all build and self-test commands pass. WASAPI backend check passes on Windows machines with WASAPI devices.

- [ ] **Step 2: Run Windows ASIO hardware validation**

On a Windows machine with a real ASIO driver, run:

```powershell
.\build\Release\client.exe --list-audio-devices
.\build\Release\client.exe --backend-check --require-api ASIO --frames 120
```

Expected: ASIO appears in the inventory, ASIO backend check opens successfully, and the log prints actual buffer frames and backend latency if the driver reports it.

- [ ] **Step 3: Run macOS CoreAudio validation**

On macOS, run:

```bash
cmake -S . -B build -DJAM_AUDIO_BACKEND=JUCE -DCMAKE_BUILD_TYPE=Release
cmake --build build --target client
./build/client --list-audio-devices
./build/client --audio-open-smoke --frames 120
```

Expected: CoreAudio devices appear and the open smoke succeeds without the previous RtAudio CoreAudio error.

- [ ] **Step 4: Manual GUI regression**

Run the client GUI and verify:

```text
1. Device API dropdown refreshes.
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

Expected: all ten checks pass.

- [ ] **Step 5: Commit validation notes**

If validation updates an audit file, commit it:

```powershell
git add archive\md-artifacts\root\LOW_LATENCY_AUDIO_AUDIT.md
git commit -m "Record JUCE audio backend validation"
```

Expected: commit succeeds if the audit file changed. If no validation notes were added, leave the tree clean.

## Task 9: Remove RtAudio Default Dependency After Validation

**Files:**
- Modify: `cmake/client.cmake`
- Modify: `audio_stream.cpp`
- Keep: `rtaudio_audio_backend.*` if one more release needs fallback builds.

- [ ] **Step 1: Disable RtAudio fallback by default**

In `cmake/client.cmake`, change:

```cmake
option(JAM_ENABLE_RTAUDIO_BACKEND "Build temporary RtAudio fallback backend" ON)
```

to:

```cmake
option(JAM_ENABLE_RTAUDIO_BACKEND "Build temporary RtAudio fallback backend" OFF)
```

Guard RtAudio FetchContent and source linking with:

```cmake
if(JAM_ENABLE_RTAUDIO_BACKEND OR JAM_AUDIO_BACKEND STREQUAL "RTAUDIO")
    FetchContent_MakeAvailable(rtaudio)
endif()
```

Keep the exact final `FetchContent_MakeAvailable` calls separated by dependency:

```cmake
FetchContent_MakeAvailable(juce imgui glfw)
if(JAM_ENABLE_RTAUDIO_BACKEND OR JAM_AUDIO_BACKEND STREQUAL "RTAUDIO")
    FetchContent_MakeAvailable(rtaudio)
endif()
```

- [ ] **Step 2: Build JUCE-only default**

Run:

```powershell
cmake -S . -B build -DJAM_AUDIO_BACKEND=JUCE -DJAM_ENABLE_RTAUDIO_BACKEND=OFF
cmake --build build --config Release --target client
.\build\Release\client.exe --list-audio-devices
```

Expected: JUCE-only build succeeds and lists devices.

- [ ] **Step 3: Build explicit RtAudio fallback**

Run:

```powershell
cmake -S . -B build-rtaudio -DJAM_AUDIO_BACKEND=RTAUDIO -DJAM_ENABLE_RTAUDIO_BACKEND=ON
cmake --build build-rtaudio --config Release --target client
.\build-rtaudio\Release\client.exe --list-audio-devices
```

Expected: explicit fallback build succeeds.

- [ ] **Step 4: Commit**

```powershell
git add cmake/client.cmake audio_stream.cpp
git commit -m "Disable RtAudio fallback by default"
```

Expected: commit succeeds.

## Final Verification

Run:

```powershell
git status --short
git log --oneline -8
```

Expected: working tree is clean and the recent commits show each migration task separately.
