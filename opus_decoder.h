#pragma once

#include "logger.hpp"
#include <opus.h>
#include <vector>

class opus_decoder_wrapper {
  private:
    OpusDecoder *_decoder = nullptr;
    int _channels = 0;
    int _sample_rate = 0;

  public:
    opus_decoder_wrapper() = default;

    ~opus_decoder_wrapper() { destroy(); }

    // Prevent copying (Opus decoder maintains state)
    opus_decoder_wrapper(const opus_decoder_wrapper &) = delete;
    opus_decoder_wrapper &operator=(const opus_decoder_wrapper &) = delete;

    // Allow moving
    opus_decoder_wrapper(opus_decoder_wrapper &&other) noexcept
        : _decoder(other._decoder), _channels(other._channels), _sample_rate(other._sample_rate) {
        other._decoder = nullptr;
    }

    opus_decoder_wrapper &operator=(opus_decoder_wrapper &&other) noexcept {
        if (this != &other) {
            destroy();
            _decoder = other._decoder;
            _channels = other._channels;
            _sample_rate = other._sample_rate;
            other._decoder = nullptr;
        }
        return *this;
    }

    bool create(int sample_rate, int channels) {
        destroy(); // Clean up any existing decoder

        int err;
        _decoder = opus_decoder_create(sample_rate, channels, &err);
        if (err != OPUS_OK) {
            Log::error("Failed to create Opus decoder: {}", opus_strerror(err));
            return false;
        }

        _channels = channels;
        _sample_rate = sample_rate;

        Log::info("Opus decoder created: {}ch, {}Hz", channels, sample_rate);
        return true;
    }

    void destroy() {
        if (_decoder != nullptr) {
            opus_decoder_destroy(_decoder);
            _decoder = nullptr;
        }
        _channels = 0;
        _sample_rate = 0;
    }

    bool decode(const unsigned char *input, int input_size, int frame_size, std::vector<float> &output) {
        if (_decoder == nullptr) {
            Log::error("Opus decoder not initialized.");
            output.clear();
            return false;
        }

        output.resize(frame_size * _channels);
        int decoded_samples_per_channel = opus_decode_float(_decoder, input, input_size, output.data(), frame_size, 0);

        if (decoded_samples_per_channel < 0) {
            Log::error("Opus decoding failed: {}", opus_strerror(decoded_samples_per_channel));
            output.clear();
            return false;
        }

        output.resize(decoded_samples_per_channel * _channels);
        return true;
    }

    // Decode with Packet Loss Concealment (when packet is lost)
    bool decode_plc(int frame_size, std::vector<float> &output) {
        if (_decoder == nullptr) {
            Log::error("Opus decoder not initialized.");
            output.clear();
            return false;
        }

        output.resize(frame_size * _channels);
        // Pass nullptr to trigger PLC (packet loss concealment)
        int decoded_samples_per_channel = opus_decode_float(_decoder, nullptr, 0, output.data(), frame_size, 0);

        if (decoded_samples_per_channel < 0) {
            Log::error("Opus PLC decoding failed: {}", opus_strerror(decoded_samples_per_channel));
            output.clear();
            return false;
        }

        output.resize(decoded_samples_per_channel * _channels);
        return true;
    }

    bool is_initialized() const { return _decoder != nullptr; }
    int get_channels() const { return _channels; }
    int get_sample_rate() const { return _sample_rate; }
};
