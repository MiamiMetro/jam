#include "juce_audio_backend.h"

#include "audio_backend_policy.h"
#include "juce_audio_adapter.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <memory>
#include <string>
#include <utility>

namespace {
constexpr AudioDeviceId API_SHIFT = 16;
constexpr AudioDeviceId INDEX_SHIFT = 1;
constexpr AudioDeviceId ENCODED_FIELD_MASK = 0x7FFF;
constexpr double FALLBACK_SAMPLE_RATE = 48000.0;

std::string to_std_string(const juce::String& value) {
    return value.toStdString();
}

bool juce_error(const juce::String& error) {
    return error.isNotEmpty();
}

std::vector<double> positive_sorted_sample_rates(const juce::Array<double>& rates) {
    std::vector<double> out;
    out.reserve(static_cast<std::size_t>(rates.size()));
    for (int index = 0; index < rates.size(); ++index) {
        const auto rate = rates[index];
        if (rate > 0.0) {
            out.push_back(rate);
        }
    }

    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end(), [](double lhs, double rhs) {
                  return std::abs(lhs - rhs) < 0.5;
              }),
              out.end());
    return out;
}

bool sample_rate_list_contains(const std::vector<double>& rates, int sample_rate) {
    if (sample_rate <= 0) {
        return false;
    }

    return std::any_of(rates.begin(), rates.end(), [&](double rate) {
        return std::abs(rate - static_cast<double>(sample_rate)) < 0.5;
    });
}

bool sample_rate_is_supported_or_unknown(const std::vector<double>& rates, int sample_rate) {
    return rates.empty() || sample_rate_list_contains(rates, sample_rate);
}

double choose_default_sample_rate(const std::vector<double>& rates) {
    if (sample_rate_list_contains(rates, static_cast<int>(FALLBACK_SAMPLE_RATE))) {
        return FALLBACK_SAMPLE_RATE;
    }
    if (!rates.empty()) {
        return rates.front();
    }
    return FALLBACK_SAMPLE_RATE;
}

void ensure_juce_runtime() {
    // JUCE shutdown is unsafe from our static backend destruction path on macOS. Keep the
    // process-wide initializer alive until the OS reclaims it at process exit.
    static const auto* const initializer = new juce::ScopedJuceInitialiser_GUI();
    (void)initializer;
}
}  // namespace

JuceAudioBackend::JuceRuntime::JuceRuntime() {
    ensure_juce_runtime();
}

JuceAudioBackend::JuceAudioBackend() {
    device_manager_.createAudioDeviceTypes(device_types_);
}

JuceAudioBackend::~JuceAudioBackend() {
    stop_audio_stream();
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
        info.name = to_std_string(type->getTypeName());

        const int input_index = type->getDefaultDeviceIndex(true);
        if (input_index >= 0 && input_index < type->getDeviceNames(true).size()) {
            info.default_input_device = make_device_id(api_index, input_index, true);
        }

        const int output_index = type->getDefaultDeviceIndex(false);
        if (output_index >= 0 && output_index < type->getDeviceNames(false).size()) {
            info.default_output_device = make_device_id(api_index, output_index, false);
        }

        apis.push_back(info);
    }
    return apis;
}

std::vector<AudioDeviceInfo> JuceAudioBackend::get_input_devices() {
    return scan_devices(true);
}

std::vector<AudioDeviceInfo> JuceAudioBackend::get_output_devices() {
    return scan_devices(false);
}

std::vector<AudioDeviceInfo> JuceAudioBackend::get_input_device_stubs() {
    return scan_device_stubs(true);
}

std::vector<AudioDeviceInfo> JuceAudioBackend::get_output_device_stubs() {
    return scan_device_stubs(false);
}

std::vector<AudioDeviceInfo> JuceAudioBackend::get_all_devices() {
    auto devices = get_input_devices();
    auto outputs = get_output_devices();
    devices.insert(devices.end(), outputs.begin(), outputs.end());
    return devices;
}

AudioDeviceId JuceAudioBackend::get_default_input_device() {
    auto devices = scan_device_stubs(true);
    return audio_backend::choose_default_input_device(devices);
}

AudioDeviceId JuceAudioBackend::get_default_output_device() {
    auto devices = scan_device_stubs(false);
    return audio_backend::choose_default_output_device(devices);
}

bool JuceAudioBackend::is_device_valid(AudioDeviceId device_id) {
    AudioDeviceInfo info;
    return get_device_info(device_id, info);
}

bool JuceAudioBackend::get_device_info(AudioDeviceId device_id, AudioDeviceInfo& out) {
    if (device_id == AUDIO_NO_DEVICE) {
        return false;
    }

    auto* type = find_type(decode_api_index(device_id));
    if (type == nullptr) {
        return false;
    }

    const bool input = decode_is_input(device_id);
    type->scanForDevices();
    const auto names = type->getDeviceNames(input);
    const auto device_index = decode_device_index(device_id);
    if (device_index < 0 || device_index >= names.size()) {
        return false;
    }

    const auto caps = query_device_capabilities(*type, names[device_index], input);
    out = {};
    out.id = device_id;
    out.name = to_std_string(names[device_index]);
    out.api_name = to_std_string(type->getTypeName());
    out.api_index = decode_api_index(device_id);
    out.max_input_channels = input ? caps.channel_count : 0;
    out.max_output_channels = input ? 0 : caps.channel_count;
    out.sample_rates = caps.sample_rates;
    out.default_sample_rate = choose_default_sample_rate(caps.sample_rates);
    out.is_default_input =
        input && device_index == type->getDefaultDeviceIndex(true);
    out.is_default_output =
        !input && device_index == type->getDefaultDeviceIndex(false);
    return true;
}

bool JuceAudioBackend::start_audio_stream(AudioDeviceId input_device, AudioDeviceId output_device,
                                          const AudioConfig& config, AudioCallback callback,
                                          void* user_data) {
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

    auto* type = find_type(input_info.api_index);
    if (type == nullptr) {
        last_error_ = "Selected audio API is unavailable";
        return false;
    }

    stop_audio_stream();

    AudioConfig runtime_config = config;
    runtime_config.input_channel_index =
        std::clamp(runtime_config.input_channel_index, 0, input_info.max_input_channels - 1);
    if (!sample_rate_is_supported_or_unknown(input_info.sample_rates,
                                             runtime_config.sample_rate)) {
        last_error_ = "Selected input device does not report support for required 48000 Hz";
        return false;
    }
    if (!sample_rate_is_supported_or_unknown(output_info.sample_rates,
                                             runtime_config.sample_rate)) {
        last_error_ = "Selected output device does not report support for required 48000 Hz";
        return false;
    }

    current_config_ = runtime_config;
    callback_.store(callback, std::memory_order_release);
    callback_user_data_.store(user_data, std::memory_order_release);
    const auto input_device_name = device_name_for_id(input_device);
    const auto output_device_name = device_name_for_id(output_device);
    const auto clamped_input_channel = runtime_config.input_channel_index;

    input_channel_count_.store(1, std::memory_order_release);
    opened_input_channel_count_.store(1, std::memory_order_release);
    selected_input_channel_.store(clamped_input_channel, std::memory_order_release);
    output_channel_count_.store(output_info.max_output_channels >= 2 ? 2 : 1,
                                std::memory_order_release);
    actual_buffer_frames_.store(std::max(runtime_config.frames_per_buffer, 0),
                                std::memory_order_release);
    prepare_callback_buffers(std::max(runtime_config.frames_per_buffer, 0));

    juce::AudioDeviceManager::AudioDeviceSetup setup;
    setup.inputDeviceName = input_device_name;
    setup.outputDeviceName = output_device_name;
    setup.sampleRate = static_cast<double>(runtime_config.sample_rate);
    setup.bufferSize = runtime_config.frames_per_buffer;
    setup.useDefaultInputChannels = false;
    setup.useDefaultOutputChannels = false;
    setup.inputChannels.clear();
    setup.outputChannels.clear();
    setup.inputChannels.setBit(clamped_input_channel);
    setup.outputChannels.setRange(0, output_channel_count_.load(std::memory_order_acquire), true);

    device_manager_.setCurrentAudioDeviceType(type->getTypeName(), true);

    auto error =
        device_manager_.initialise(opened_input_channel_count_.load(std::memory_order_acquire),
                                   output_channel_count_.load(std::memory_order_acquire), nullptr,
                                   false, {}, &setup);
    if (juce_error(error)) {
        last_error_ = "JUCE audio initialise failed: " + to_std_string(error);
        device_manager_.closeAudioDevice();
        return false;
    }

    error = device_manager_.setAudioDeviceSetup(setup, true);
    if (juce_error(error)) {
        last_error_ = "JUCE audio setup failed: " + to_std_string(error);
        device_manager_.closeAudioDevice();
        return false;
    }

    if (auto* current_device = device_manager_.getCurrentAudioDevice()) {
        const auto current_buffer_size = current_device->getCurrentBufferSizeSamples();
        actual_buffer_frames_.store(current_buffer_size, std::memory_order_release);
        prepare_callback_buffers(current_buffer_size);
    }

    device_manager_.addAudioCallback(this);

    stream_active_.store(true, std::memory_order_relaxed);
    last_error_.clear();
    return true;
}

void JuceAudioBackend::stop_audio_stream() {
    stream_active_.store(false, std::memory_order_relaxed);
    device_manager_.removeAudioCallback(this);
    device_manager_.closeAudioDevice();
    callback_.store(nullptr, std::memory_order_release);
    callback_user_data_.store(nullptr, std::memory_order_release);
    opened_input_channel_count_.store(0, std::memory_order_release);
}

bool JuceAudioBackend::is_stream_active() const {
    return stream_active_.load(std::memory_order_relaxed);
}

int JuceAudioBackend::get_input_channel_count() const {
    return input_channel_count_.load(std::memory_order_acquire);
}

int JuceAudioBackend::get_output_channel_count() const {
    return output_channel_count_.load(std::memory_order_acquire);
}

AudioConfig JuceAudioBackend::get_config() const {
    return current_config_;
}

AudioLatencyInfo JuceAudioBackend::get_latency_info() const {
    AudioLatencyInfo info;
    info.sample_rate = current_config_.sample_rate;
    info.requested_buffer_frames = current_config_.frames_per_buffer;
    info.actual_buffer_frames = actual_buffer_frames_.load(std::memory_order_acquire);
    if (info.sample_rate > 0.0 && info.actual_buffer_frames > 0) {
        info.buffer_duration_ms =
            static_cast<double>(info.actual_buffer_frames) * 1000.0 / info.sample_rate;
    }

    if (auto* device = device_manager_.getCurrentAudioDevice()) {
        const auto sample_rate = device->getCurrentSampleRate();
        if (sample_rate > 0.0) {
            info.sample_rate = sample_rate;
        }

        const auto input_latency = device->getInputLatencyInSamples();
        const auto output_latency = device->getOutputLatencyInSamples();
        if (info.sample_rate > 0.0) {
            info.input_latency_ms =
                static_cast<double>(input_latency) * 1000.0 / info.sample_rate;
            info.output_latency_ms =
                static_cast<double>(output_latency) * 1000.0 / info.sample_rate;
        }
        info.backend_latency_available = input_latency > 0 || output_latency > 0;
    }

    return info;
}

const std::string& JuceAudioBackend::get_last_error() const {
    return last_error_;
}

void JuceAudioBackend::clear_last_error() {
    last_error_.clear();
}

void JuceAudioBackend::set_last_error(std::string error) {
    last_error_ = std::move(error);
}

void JuceAudioBackend::audioDeviceIOCallbackWithContext(
    const float* const* input_channel_data, int num_input_channels,
    float* const* output_channel_data, int num_output_channels, int num_samples,
    const juce::AudioIODeviceCallbackContext&) {
    const auto input_channels = std::max(input_channel_count_.load(std::memory_order_acquire), 1);
    const auto output_channels = std::max(output_channel_count_.load(std::memory_order_acquire), 1);
    const auto safe_num_samples = std::max(num_samples, 0);
    const auto frames_to_process =
        std::min<std::size_t>(static_cast<std::size_t>(safe_num_samples),
                              callback_frame_capacity_);

    for (int channel = 0; channel < num_output_channels; ++channel) {
        if (output_channel_data != nullptr && output_channel_data[channel] != nullptr) {
            std::fill_n(output_channel_data[channel], static_cast<std::size_t>(safe_num_samples),
                        0.0F);
        }
    }

    if (frames_to_process == 0) {
        return;
    }

    juce_audio_adapter::copy_selected_input_channel_to_interleaved(
        input_channel_data, num_input_channels,
        selected_input_channel_.load(std::memory_order_acquire),
        static_cast<int>(frames_to_process), input_channels, interleaved_input_.data(),
        interleaved_input_.size());

    std::fill_n(interleaved_output_.data(),
                frames_to_process * static_cast<std::size_t>(output_channels), 0.0F);

    const auto callback = callback_.load(std::memory_order_acquire);
    if (callback != nullptr) {
        callback(interleaved_input_.data(), interleaved_output_.data(),
                 static_cast<unsigned long>(frames_to_process),
                 callback_user_data_.load(std::memory_order_acquire));
    }

    juce_audio_adapter::copy_interleaved_to_outputs(
        interleaved_output_, static_cast<int>(frames_to_process), output_channels,
        output_channel_data, num_output_channels);
}

void JuceAudioBackend::audioDeviceAboutToStart(juce::AudioIODevice* device) {
    if (device != nullptr) {
        const auto current_buffer_size = device->getCurrentBufferSizeSamples();
        actual_buffer_frames_.store(current_buffer_size, std::memory_order_release);
        prepare_callback_buffers(current_buffer_size);
    }
}

void JuceAudioBackend::audioDeviceStopped() {
    actual_buffer_frames_.store(0, std::memory_order_release);
    stream_active_.store(false, std::memory_order_relaxed);
}

AudioDeviceId JuceAudioBackend::make_device_id(int api_index, int device_index, bool input) {
    if (api_index < 0 || device_index < 0) {
        return AUDIO_NO_DEVICE;
    }

    const auto encoded_api =
        (static_cast<AudioDeviceId>(api_index + 1) & ENCODED_FIELD_MASK) << API_SHIFT;
    const auto encoded_device =
        (static_cast<AudioDeviceId>(device_index + 1) & ENCODED_FIELD_MASK) << INDEX_SHIFT;
    return encoded_api | encoded_device | (input ? 1U : 0U);
}

int JuceAudioBackend::decode_api_index(AudioDeviceId id) {
    if (id == AUDIO_NO_DEVICE) {
        return -1;
    }
    return static_cast<int>((id >> API_SHIFT) & ENCODED_FIELD_MASK) - 1;
}

int JuceAudioBackend::decode_device_index(AudioDeviceId id) {
    if (id == AUDIO_NO_DEVICE) {
        return -1;
    }
    return static_cast<int>((id >> INDEX_SHIFT) & ENCODED_FIELD_MASK) - 1;
}

bool JuceAudioBackend::decode_is_input(AudioDeviceId id) {
    return (id & 1U) != 0U;
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
        const auto default_index = type->getDefaultDeviceIndex(input);

        for (int device_index = 0; device_index < names.size(); ++device_index) {
            const auto caps = query_device_capabilities(*type, names[device_index], input);
            AudioDeviceInfo info;
            info.id = make_device_id(api_index, device_index, input);
            info.name = to_std_string(names[device_index]);
            info.api_name = to_std_string(type->getTypeName());
            info.api_index = api_index;
            info.max_input_channels = input ? caps.channel_count : 0;
            info.max_output_channels = input ? 0 : caps.channel_count;
            info.sample_rates = caps.sample_rates;
            info.default_sample_rate = choose_default_sample_rate(caps.sample_rates);
            info.is_default_input = input && device_index == default_index;
            info.is_default_output = !input && device_index == default_index;
            devices.push_back(info);
        }
    }

    return devices;
}

std::vector<AudioDeviceInfo> JuceAudioBackend::scan_device_stubs(bool input) {
    std::vector<AudioDeviceInfo> devices;

    for (int api_index = 0; api_index < device_types_.size(); ++api_index) {
        auto* type = device_types_[api_index];
        if (type == nullptr) {
            continue;
        }

        type->scanForDevices();
        const auto names = type->getDeviceNames(input);
        const auto default_index = type->getDefaultDeviceIndex(input);

        for (int device_index = 0; device_index < names.size(); ++device_index) {
            AudioDeviceInfo info;
            info.id = make_device_id(api_index, device_index, input);
            info.name = to_std_string(names[device_index]);
            info.api_name = to_std_string(type->getTypeName());
            info.api_index = api_index;
            info.max_input_channels = input ? 1 : 0;
            info.max_output_channels = input ? 0 : 1;
            info.default_sample_rate = static_cast<double>(AudioConfig::DEFAULT_SAMPLE_RATE);
            info.is_default_input = input && device_index == default_index;
            info.is_default_output = !input && device_index == default_index;
            devices.push_back(info);
        }
    }

    return devices;
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
    const auto device_index = decode_device_index(id);
    if (device_index < 0 || device_index >= names.size()) {
        return {};
    }

    return names[device_index];
}

JuceAudioBackend::DeviceCapabilities JuceAudioBackend::query_device_capabilities(
    juce::AudioIODeviceType& type, const juce::String& device_name, bool input) {
    DeviceCapabilities caps;
    std::unique_ptr<juce::AudioIODevice> device(
        input ? type.createDevice({}, device_name) : type.createDevice(device_name, {}));
    if (device == nullptr) {
        caps.channel_count = input ? 1 : 2;
        return caps;
    }

    const auto channels =
        input ? device->getInputChannelNames().size() : device->getOutputChannelNames().size();
    caps.channel_count = std::max(channels, 0);
    caps.sample_rates = positive_sorted_sample_rates(device->getAvailableSampleRates());
    return caps;
}

void JuceAudioBackend::prepare_callback_buffers(int frame_count) {
    const auto frames = static_cast<std::size_t>(std::max(frame_count, 0));
    callback_frame_capacity_ = frames;
    interleaved_input_.resize(frames *
                              static_cast<std::size_t>(
                                  std::max(input_channel_count_.load(std::memory_order_acquire), 1)));
    interleaved_output_.resize(frames *
                               static_cast<std::size_t>(
                                   std::max(output_channel_count_.load(std::memory_order_acquire), 1)));
}
