#pragma once

#include <vector>

#include <opus.h>
#include <opus_defines.h>

#include "logger.h"

class OpusDecoderWrapper {
public:
    OpusDecoderWrapper() = default;

    ~OpusDecoderWrapper() {
        destroy();
    }

    // Prevent copying (Opus decoder maintains state)
    OpusDecoderWrapper(const OpusDecoderWrapper&)            = delete;
    OpusDecoderWrapper& operator=(const OpusDecoderWrapper&) = delete;

    // Allow moving
    OpusDecoderWrapper(OpusDecoderWrapper&& other) noexcept
        : decoder_(other.decoder_), channels_(other.channels_), sample_rate_(other.sample_rate_) {
        other.decoder_ = nullptr;
    }

    OpusDecoderWrapper& operator=(OpusDecoderWrapper&& other) noexcept {
        if (this != &other) {
            destroy();
            decoder_       = other.decoder_;
            channels_      = other.channels_;
            sample_rate_   = other.sample_rate_;
            other.decoder_ = nullptr;
        }
        return *this;
    }

    bool create(int sample_rate, int channels) {
        destroy();  // Clean up any existing decoder

        int err;
        decoder_ = opus_decoder_create(sample_rate, channels, &err);
        if (err != OPUS_OK) {
            Log::error("Failed to create Opus decoder: {}", opus_strerror(err));
            return false;
        }

        channels_    = channels;
        sample_rate_ = sample_rate;

        Log::info("Opus decoder created: {}ch, {}Hz", channels, sample_rate);
        return true;
    }

    void destroy() {
        if (decoder_ != nullptr) {
            opus_decoder_destroy(decoder_);
            decoder_ = nullptr;
        }
        channels_    = 0;
        sample_rate_ = 0;
    }

    bool decode(const unsigned char* input, int input_size, int frame_size,
                std::vector<float>& output) {
        if (decoder_ == nullptr) {
            Log::error("Opus decoder not initialized.");
            output.clear();
            return false;
        }

        output.resize(static_cast<long long>(frame_size) * channels_);
        int decoded_samples_per_channel =
            opus_decode_float(decoder_, input, input_size, output.data(), frame_size, 0);

        if (decoded_samples_per_channel < 0) {
            Log::error("Opus decoding failed: {}", opus_strerror(decoded_samples_per_channel));
            output.clear();
            return false;
        }

        output.resize(static_cast<long long>(decoded_samples_per_channel) * channels_);
        return true;
    }

    // Decode with Packet Loss Concealment (when packet is lost)
    bool decode_plc(int frame_size, std::vector<float>& output) {
        if (decoder_ == nullptr) {
            Log::error("Opus decoder not initialized.");
            output.clear();
            return false;
        }

        output.resize(static_cast<long long>(frame_size) * channels_);
        // Pass nullptr to trigger PLC (packet loss concealment)
        int decoded_samples_per_channel =
            opus_decode_float(decoder_, nullptr, 0, output.data(), frame_size, 0);

        if (decoded_samples_per_channel < 0) {
            Log::error("Opus PLC decoding failed: {}", opus_strerror(decoded_samples_per_channel));
            output.clear();
            return false;
        }

        output.resize(static_cast<long long>(decoded_samples_per_channel) * channels_);
        return true;
    }

    bool is_initialized() const {
        return decoder_ != nullptr;
    }
    int get_channels() const {
        return channels_;
    }
    int get_sample_rate() const {
        return sample_rate_;
    }

private:
    OpusDecoder* decoder_     = nullptr;
    int          channels_    = 0;
    int          sample_rate_ = 0;
};
