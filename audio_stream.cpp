#include "audio_stream.h"

#include "juce_audio_backend.h"

#include <algorithm>
#include <cmath>
#include <memory>
#include <sstream>
#include <spdlog/spdlog.h>

namespace {
std::string format_sample_rates(const std::vector<double>& sample_rates) {
    if (sample_rates.empty()) {
        return "unknown";
    }

    std::ostringstream out;
    for (std::size_t index = 0; index < sample_rates.size(); ++index) {
        if (index > 0) {
            out << ',';
        }
        out << static_cast<int>(std::lround(sample_rates[index]));
    }
    return out.str();
}
}  // namespace

AudioStream::AudioStream() : backend_(std::make_unique<JuceAudioBackend>()) {}

AudioStream::~AudioStream() {
    stop_audio_stream();
}

const std::string& AudioStream::get_last_error() {
    return shared_backend().get_last_error();
}

void AudioStream::clear_last_error() {
    shared_backend().clear_last_error();
}

void AudioStream::print_all_devices() {
    spdlog::info("Available audio devices:");
    for (const auto& device_info: to_stream_device_infos(shared_backend().get_all_devices())) {
        spdlog::info(
            "Device {}: {} | API: {} | Max Input Channels: {} | Max Output Channels: {} | "
            "Default Sample Rate: {} | Sample Rates: {}",
            device_info.index, device_info.name, device_info.api_name,
            device_info.max_input_channels, device_info.max_output_channels,
            device_info.default_sample_rate, format_sample_rates(device_info.sample_rates));
    }
}

const AudioStream::DeviceInfo* AudioStream::get_device_info(DeviceIndex device_index) {
    static thread_local DeviceInfo cached_device;
    AudioDeviceInfo backend_device;
    if (!shared_backend().get_device_info(device_index, backend_device)) {
        shared_backend().set_last_error("Invalid device index");
        spdlog::error("Invalid device index: {}", device_index);
        return nullptr;
    }

    cached_device = to_stream_device_info(backend_device);
    return &cached_device;
}

bool AudioStream::is_device_valid(DeviceIndex device_index) {
    return shared_backend().is_device_valid(device_index);
}

std::vector<AudioStream::DeviceInfo> AudioStream::get_input_devices() {
    return to_stream_device_infos(shared_backend().get_input_devices());
}

std::vector<AudioStream::DeviceInfo> AudioStream::get_output_devices() {
    return to_stream_device_infos(shared_backend().get_output_devices());
}

std::vector<AudioStream::DeviceInfo> AudioStream::get_input_device_stubs() {
    return to_stream_device_infos(shared_backend().get_input_device_stubs());
}

std::vector<AudioStream::DeviceInfo> AudioStream::get_output_device_stubs() {
    return to_stream_device_infos(shared_backend().get_output_device_stubs());
}

std::vector<AudioStream::ApiInfo> AudioStream::get_apis() {
    return to_stream_api_infos(shared_backend().get_apis());
}

AudioStream::DeviceIndex AudioStream::get_default_input_device() {
    return shared_backend().get_default_input_device();
}

AudioStream::DeviceIndex AudioStream::get_default_output_device() {
    return shared_backend().get_default_output_device();
}

void AudioStream::print_device_info(const DeviceInfo* input_info, const DeviceInfo* output_info) {
    if (input_info == nullptr || output_info == nullptr) {
        spdlog::error("Cannot print audio device info for null device");
        return;
    }

    spdlog::info(
        "Input Device: {} | API: {} | Max Input Channels: {} | Default Sample Rate: {} | "
        "Sample Rates: {}",
                 input_info->name, input_info->api_name, input_info->max_input_channels,
        input_info->default_sample_rate, format_sample_rates(input_info->sample_rates));
    spdlog::info(
        "Output Device: {} | API: {} | Max Output Channels: {} | Default Sample Rate: {} | "
        "Sample Rates: {}",
                 output_info->name, output_info->api_name, output_info->max_output_channels,
        output_info->default_sample_rate, format_sample_rates(output_info->sample_rates));
}

bool AudioStream::start_audio_stream(DeviceIndex input_device, DeviceIndex output_device,
                                     const AudioConfig& config, AudioCallback callback,
                                     void* user_data) {
    shared_backend().clear_last_error();

    const bool started =
        backend_->start_audio_stream(input_device, output_device, config, callback, user_data);
    if (!started) {
        shared_backend().set_last_error(backend_->get_last_error());
        spdlog::error("Audio stream start failed: {}", backend_->get_last_error());
        return false;
    }

    shared_backend().clear_last_error();
    return true;
}

void AudioStream::stop_audio_stream() {
    if (backend_) {
        backend_->stop_audio_stream();
    }
}

void AudioStream::print_latency_info() {
    auto info = get_latency_info();
    spdlog::info("Input latency:  {:.3f} ms", info.input_latency_ms);
    spdlog::info("Output latency: {:.3f} ms", info.output_latency_ms);
    spdlog::info("Sample rate:    {:.1f} Hz", info.sample_rate);
    spdlog::info("Requested buffer: {} frames", info.requested_buffer_frames);
    spdlog::info("Actual buffer:    {} frames ({:.3f} ms)", info.actual_buffer_frames,
                 info.buffer_duration_ms);
    if (!info.backend_latency_available) {
        spdlog::info("Backend latency is unavailable or reported as zero");
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

JuceAudioBackend& AudioStream::shared_backend() {
    static JuceAudioBackend backend;
    return backend;
}

AudioStream::DeviceInfo AudioStream::to_stream_device_info(const AudioDeviceInfo& info) {
    DeviceInfo out;
    static_cast<AudioDeviceInfo&>(out) = info;
    out.index = info.id;
    return out;
}

std::vector<AudioStream::DeviceInfo> AudioStream::to_stream_device_infos(
    const std::vector<AudioDeviceInfo>& infos) {
    std::vector<DeviceInfo> result;
    result.reserve(infos.size());
    for (const auto& info: infos) {
        result.push_back(to_stream_device_info(info));
    }
    return result;
}

std::vector<AudioStream::ApiInfo> AudioStream::to_stream_api_infos(
    const std::vector<AudioApiInfo>& infos) {
    std::vector<ApiInfo> result;
    result.reserve(infos.size());
    for (const auto& info: infos) {
        ApiInfo out;
        static_cast<AudioApiInfo&>(out) = info;
        result.push_back(out);
    }
    return result;
}
