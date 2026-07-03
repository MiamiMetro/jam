# Phase 5 Track E Devices Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace fabricated JUCE device capabilities with real channel/sample-rate enumeration and let the user select which physical input channel is captured.

**Architecture:** Keep the app's capture pipeline mono and keep the Opus network clock at 48 kHz. Enumerate real JUCE device channel counts and supported sample rates when scanning devices, then open only the selected physical input channel and compact it to the existing mono callback buffer. Store input-channel selection in `AudioConfig` so UI, CLI, preferences, stream restart, and backend setup all share one contract.

**Tech Stack:** C++20, JUCE audio devices, ImGui, CMake/CTest, existing `AudioStream`/`JuceAudioBackend` abstraction.

## Global Constraints

- Execute exactly Phase 5 Track E; do not start another Phase 5 track in this session.
- Current citations verified against `main` at `9e895bb`: `juce_audio_backend.cpp:363-388` still fabricates `2/2/48000`, and `juce_audio_backend.cpp:154-163` still opens the first one or two input channels while delivering one mono channel to the pipeline.
- Keep `opus_network_clock::SAMPLE_RATE == 48000`; do not silently run 44.1 kHz hardware as a room participant.
- If JUCE reports non-empty sample-rate lists and either selected device lacks the configured sample rate, fail stream start with a clear error.
- Follow tracker rules: one branch for the track, one commit per task, and Release build plus full `ctest` after each task.
- Preserve existing callback real-time constraints: no heap allocation added inside `audioDeviceIOCallbackWithContext`.

---

## File Structure

- Modify `audio_backend.h`: add `AudioConfig::input_channel_index` and `AudioDeviceInfo::sample_rates`.
- Modify `juce_audio_adapter.h`: add a pure helper that selects one physical input channel, with fallback to the first enabled channel.
- Modify `juce_audio_adapter_self_test.cpp`: cover selected-channel copy, compact JUCE channel arrays, and null selected-channel fallback.
- Modify `juce_audio_backend.h/.cpp`: enumerate JUCE channel counts/sample rates from created devices; open exactly the selected input channel; expose the clamped channel in `get_config()`.
- Modify `audio_stream.cpp`: print supported sample rates in device inventory.
- Modify `audio_backend_policy_self_test.cpp`: pin the new struct fields and defaults.
- Modify `client.cpp`: persist/input-channel config, CLI override, bottom-bar channel selector, stream restart on channel change, and startup-config smoke output.
- Modify `LOW_LATENCY_ACTION_PLAN.md`: mark Track E complete only after validation commands have passed.

## Task 1: Backend Capabilities and Adapter Contract

**Files:**
- Modify: `audio_backend.h`
- Modify: `juce_audio_adapter.h`
- Modify: `juce_audio_adapter_self_test.cpp`
- Modify: `juce_audio_backend.h`
- Modify: `juce_audio_backend.cpp`
- Modify: `audio_stream.cpp`
- Modify: `audio_backend_policy_self_test.cpp`

**Interfaces:**
- Consumes: existing `AudioConfig`, `AudioDeviceInfo`, `JuceAudioBackend::scan_devices(bool)`, and `juce_audio_adapter::copy_inputs_to_interleaved(...)`.
- Produces:
  - `AudioConfig::input_channel_index` as a zero-based requested physical input channel.
  - `AudioDeviceInfo::sample_rates` as a sorted list of positive rates reported by JUCE.
  - `juce_audio_adapter::copy_selected_input_channel_to_interleaved(const float* const*, int, int, int, int, float*, std::size_t)`.
  - `JuceAudioBackend` opens `setup.inputChannels` with exactly the selected input bit.

- [x] **Step 1: Write the failing adapter and type tests**

Add these assertions to `juce_audio_adapter_self_test.cpp`:

```cpp
void test_selected_input_channel_copy()
{
    const std::array<float, 3> first{0.1F, 0.2F, 0.3F};
    const std::array<float, 3> second{0.4F, 0.5F, 0.6F};
    const std::array<float, 3> third{0.7F, 0.8F, 0.9F};
    const float* inputs[] = {first.data(), second.data(), third.data()};
    std::array<float, 3> interleaved{};

    juce_audio_adapter::copy_selected_input_channel_to_interleaved(
        inputs, 3, 2, 3, 1, interleaved.data(), interleaved.size());

    expect_array(interleaved, {0.7F, 0.8F, 0.9F});
}

void test_selected_input_channel_falls_back_to_enabled_channel()
{
    const std::array<float, 3> enabled{0.25F, 0.5F, 0.75F};
    const float* inputs[] = {enabled.data()};
    std::array<float, 3> interleaved{};

    juce_audio_adapter::copy_selected_input_channel_to_interleaved(
        inputs, 1, 4, 3, 1, interleaved.data(), interleaved.size());

    expect_array(interleaved, {0.25F, 0.5F, 0.75F});
}
```

Add these assertions to `audio_backend_policy_self_test.cpp`:

```cpp
require(std::is_same_v<decltype(AudioConfig{}.input_channel_index), int>,
        "AudioConfig::input_channel_index must be int");
require(AudioConfig{}.input_channel_index == 0,
        "AudioConfig::input_channel_index must default to channel 0");
require(std::is_same_v<decltype(AudioDeviceInfo{}.sample_rates), std::vector<double>>,
        "AudioDeviceInfo::sample_rates must be vector<double>");
```

- [x] **Step 2: Run tests to verify they fail**

Run: `cmake --build build --config Release --target juce_audio_adapter_self_test audio_backend_policy_self_test`

Expected: compile fails because `copy_selected_input_channel_to_interleaved`, `AudioConfig::input_channel_index`, and `AudioDeviceInfo::sample_rates` do not exist.

- [x] **Step 3: Implement the backend contract**

Implement these exact behaviors:

```cpp
struct AudioConfig {
    ...
    int input_channel_index = 0;
};

struct AudioDeviceInfo {
    ...
    double default_sample_rate = 0.0;
    std::vector<double> sample_rates;
    ...
};
```

In `juce_audio_adapter.h`, add a helper that zeros the destination, selects `requested_input_channel` only when that pointer is available, otherwise falls back to the first non-null channel, and writes the selected mono source into the interleaved destination.

In `juce_audio_backend.cpp`, replace hardcoded caps in `scan_devices()` with JUCE queries:

```cpp
const auto caps = query_device_capabilities(*type, names[device_index], input);
info.max_input_channels = input ? caps.channel_count : 0;
info.max_output_channels = input ? 0 : caps.channel_count;
info.sample_rates = caps.sample_rates;
info.default_sample_rate = choose_default_sample_rate(caps.sample_rates);
```

In `start_audio_stream()`, clamp `config.input_channel_index` to `[0, input_info.max_input_channels - 1]`, store the clamped value in `current_config_`, reject non-empty sample-rate lists that do not contain `current_config_.sample_rate`, and set exactly one JUCE input bit:

```cpp
setup.inputChannels.clear();
setup.inputChannels.setBit(clamped_input_channel);
```

- [x] **Step 4: Run Task 1 validation**

Run: `cmake --build build --config Release --parallel 8`

Expected: build succeeds.

Run: `ctest --test-dir build -C Release --output-on-failure`

Expected: all tests pass.

- [x] **Step 5: Commit Task 1**

```bash
git add audio_backend.h juce_audio_adapter.h juce_audio_adapter_self_test.cpp juce_audio_backend.h juce_audio_backend.cpp audio_stream.cpp audio_backend_policy_self_test.cpp
git commit -m "feat: enumerate JUCE device capabilities"
```

## Task 2: Client Input-Channel Selection and Tracker Closure

**Files:**
- Modify: `client.cpp`
- Modify: `LOW_LATENCY_ACTION_PLAN.md`

**Interfaces:**
- Consumes: `AudioConfig::input_channel_index`, real `AudioDeviceInfo::max_input_channels`, and backend clamping from Task 1.
- Produces:
  - Persisted `input_channel=<zero-based-index>` in `jam_client.ini`.
  - CLI `--input-channel <one-based-channel>` / `--input-channel-index <zero-based-index>`.
  - Bottom-bar input channel combo that restarts the stream when the selected channel changes.
  - Startup-config smoke output includes `input_channel=`.

- [x] **Step 1: Write the failing startup-config smoke expectation**

Add `startup_input_channel_index` to `ClientStartupOptions` and include `input_channel={}` in the existing startup-config smoke log. The expected command after implementation is:

```powershell
build\Release\client.exe --startup-config-smoke --input-channel 2 --log-file validation_logs/phase5-track-e/startup-config-smoke.log
```

Expected log line on the two-channel default input used for this session includes `input_channel=1`.

- [x] **Step 2: Implement client config, preferences, CLI, and UI**

Implement these exact behaviors:

```cpp
struct AudioDevicePreferences {
    ...
    std::optional<int> input_channel_index;
};

struct ClientStartupOptions {
    ...
    std::optional<int> startup_input_channel_index;
};
```

Parsing:

```cpp
} else if (arg == "--input-channel" && i + 1 < argc) {
    options.startup_input_channel_index = std::max(0, std::stoi(argv[++i]) - 1);
} else if (arg == "--input-channel-index" && i + 1 < argc) {
    options.startup_input_channel_index = std::max(0, std::stoi(argv[++i]));
}
```

Client API:

```cpp
int get_input_channel_index() const;
void set_input_channel_index(int channel_index);
int max_input_channel_count_for_device(AudioStream::DeviceIndex device_index) const;
```

Bottom bar:
- Keep the label compact: `Ch:`.
- Show channels as `1`, `2`, `3`, up to `max_input_channels`.
- Include channel changes in `stream_restart_needed`.
- Save preferences before restart/start.

Preferences:

```cpp
output << "input_channel=" << get_audio_config().input_channel_index << '\n';
```

- [x] **Step 3: Update tracker after validation**

After validation passes, update Track E in `LOW_LATENCY_ACTION_PLAN.md` from `not started` to Done and record the build/ctest results plus the accepted behavior: real JUCE caps, sample-rate reporting, clear 48 kHz rejection for unsupported devices, persisted/UI/CLI input-channel selection.

- [x] **Step 4: Run Task 2 validation**

Run: `cmake --build build --config Release --parallel 8`

Expected: build succeeds.

Run: `ctest --test-dir build -C Release --output-on-failure`

Expected: all tests pass.

Run: `rg -n "max_input_channels = input \\? 2|max_output_channels = input \\? 0 : 2|default_sample_rate = FALLBACK_SAMPLE_RATE" juce_audio_backend.cpp`

Expected: no matches.

- [x] **Step 5: Commit Task 2**

```bash
git add client.cpp LOW_LATENCY_ACTION_PLAN.md
git commit -m "feat: add input channel selection"
```

## Self-Review

- Spec coverage: Track E asks for real JUCE device-capability enumeration and input-channel selection. Task 1 covers channel/sample-rate enumeration and selected-channel backend opening. Task 2 covers user selection through UI, CLI, persistence, and tracker closure.
- Placeholder scan: no `TBD`, `TODO`, `implement later`, or "write tests for the above" placeholders remain.
- Type consistency: `input_channel_index` is zero-based in config/preferences/backend and one-based only for the `--input-channel` user-facing CLI alias and ImGui labels.
