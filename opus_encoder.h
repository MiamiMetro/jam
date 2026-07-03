#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

#include <opus.h>
#include <opus_defines.h>
#include <opus_types.h>

#include "logger.h"

class OpusEncoderWrapper {
public:
    using SampleRate = int;
    using Channels   = int;
    using Bitrate    = int;
    using Complexity = int;

    static constexpr size_t ENCODE_BUFFER_SIZE = 512;

    OpusEncoderWrapper() = default;

    ~OpusEncoderWrapper() {
        destroy();
    }

    // Prevent copying (Opus encoder is a resource)
    OpusEncoderWrapper(const OpusEncoderWrapper&)            = delete;
    OpusEncoderWrapper& operator=(const OpusEncoderWrapper&) = delete;

    // Allow moving
    OpusEncoderWrapper(OpusEncoderWrapper&& other) noexcept
        : encoder_(other.encoder_), channels_(other.channels_), sample_rate_(other.sample_rate_) {
        other.encoder_ = nullptr;
    }

    OpusEncoderWrapper& operator=(OpusEncoderWrapper&& other) noexcept {
        if (this != &other) {
            destroy();
            encoder_       = other.encoder_;
            channels_      = other.channels_;
            sample_rate_   = other.sample_rate_;
            other.encoder_ = nullptr;
        }
        return *this;
    }

    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters) - Parameters are semantically distinct
    bool create(SampleRate sample_rate, Channels channels, opus_int32 application, Bitrate bitrate,
                Complexity complexity) {
        destroy();  // Clean up any existing encoder

        int err;
        encoder_ = opus_encoder_create(sample_rate, channels, application, &err);
        if (err != OPUS_OK) {
            Log::error("Failed to create Opus encoder: {}", opus_strerror(err));
            return false;
        }

        channels_    = channels;
        sample_rate_ = sample_rate;

        // Set encoder options for ultra-low-latency music streaming
        opus_encoder_ctl(encoder_, OPUS_SET_COMPLEXITY(complexity));
        opus_encoder_ctl(encoder_, OPUS_SET_BITRATE(bitrate));
        opus_encoder_ctl(encoder_, OPUS_SET_SIGNAL(OPUS_SIGNAL_MUSIC));
        opus_encoder_ctl(encoder_, OPUS_SET_APPLICATION(OPUS_APPLICATION_RESTRICTED_LOWDELAY));
        opus_encoder_ctl(encoder_, OPUS_SET_VBR(0));  // CBR-style pacing for jamming
        opus_encoder_ctl(encoder_, OPUS_SET_VBR_CONSTRAINT(1));
        opus_encoder_ctl(encoder_, OPUS_SET_INBAND_FEC(0));  // Avoid extra FEC delay/bit use
        opus_encoder_ctl(encoder_, OPUS_SET_PACKET_LOSS_PERC(0));
        opus_encoder_ctl(encoder_,
                         OPUS_SET_DTX(0));  // Disable DTX for music (no silence detection)

        // Verify settings
        int32_t actual_bitrate;
        opus_encoder_ctl(encoder_, OPUS_GET_BITRATE(&actual_bitrate));
        Log::info("Opus encoder created: {}ch, {}Hz, target={}bps, actual={}bps, complexity={}",
                  channels, sample_rate, bitrate, actual_bitrate, complexity);

        return true;
    }

    void destroy() {
        if (encoder_ != nullptr) {
            opus_encoder_destroy(encoder_);
            encoder_ = nullptr;
        }
        channels_    = 0;
        sample_rate_ = 0;
    }

    bool encode(const float* input, int frame_size, unsigned char* output,
                size_t output_capacity, uint16_t& encoded_bytes) {
        encoded_bytes = 0;
        if (encoder_ == nullptr) {
            Log::error("Opus encoder not initialized.");
            return false;
        }
        if (output == nullptr || output_capacity == 0 ||
            output_capacity > static_cast<size_t>(std::numeric_limits<opus_int32>::max())) {
            Log::error("Invalid Opus output buffer.");
            return false;
        }
        if (!is_legal_frame_size(sample_rate_, frame_size)) {
            Log::error("Illegal Opus frame size: {} samples at {} Hz", frame_size, sample_rate_);
            return false;
        }

        const int result = opus_encode_float(
            encoder_, input, frame_size, output,
            static_cast<opus_int32>(output_capacity));
        if (result < 0) {
            Log::error("Opus encoding failed: {}", opus_strerror(result));
            return false;
        }
        encoded_bytes = static_cast<uint16_t>(result);
        return true;
    }

    bool encode(const float* input, int frame_size, std::vector<unsigned char>& output) {
        output.resize(ENCODE_BUFFER_SIZE);
        uint16_t encoded_bytes = 0;
        if (!encode(input, frame_size, output.data(), output.size(), encoded_bytes)) {
            output.clear();
            return false;
        }
        output.resize(encoded_bytes);
        return true;
    }

    bool is_initialized() const {
        return encoder_ != nullptr;
    }
    int get_channels() const {
        return channels_;
    }
    int get_sample_rate() const {
        return sample_rate_;
    }
    int get_actual_bitrate() const {
        if (encoder_ == nullptr) {
            return 0;
        }
        int32_t actual_bitrate;
        opus_encoder_ctl(encoder_, OPUS_GET_BITRATE(&actual_bitrate));
        return actual_bitrate;
    }

    static bool is_legal_frame_size(int sample_rate, int frame_size) {
        // Opus accepts 2.5, 5, 10, 20, 40, or 60 ms frames.
        constexpr int durations_per_400_ms[] = {1, 2, 4, 8, 16, 24};
        for (int duration: durations_per_400_ms) {
            if ((sample_rate * duration) / 400 == frame_size &&
                (sample_rate * duration) % 400 == 0) {
                return true;
            }
        }
        return false;
    }

private:
    OpusEncoder* encoder_     = nullptr;
    int          channels_    = 0;
    int          sample_rate_ = 0;
};
