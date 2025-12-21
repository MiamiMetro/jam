#pragma once

#include <cstddef>
#include <cstdint>
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

        // Set encoder options for low-latency music streaming
        opus_encoder_ctl(encoder_, OPUS_SET_COMPLEXITY(complexity));
        opus_encoder_ctl(encoder_, OPUS_SET_BITRATE(bitrate));
        opus_encoder_ctl(encoder_, OPUS_SET_SIGNAL(OPUS_SIGNAL_MUSIC));
        opus_encoder_ctl(encoder_, OPUS_SET_VBR(1));  // Variable bitrate for better quality
        opus_encoder_ctl(encoder_, OPUS_SET_VBR_CONSTRAINT(0));  // Unconstrained VBR for music
        opus_encoder_ctl(encoder_, OPUS_SET_INBAND_FEC(1));      // Forward error correction for UDP
        opus_encoder_ctl(encoder_, OPUS_SET_PACKET_LOSS_PERC(5));  // Expect some packet loss
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

    bool encode(const float* input, int frame_size, std::vector<unsigned char>& output) {
        if (encoder_ == nullptr) {
            Log::error("Opus encoder not initialized.");
            output.clear();
            return false;
        }

        output.resize(ENCODE_BUFFER_SIZE);
        int encoded_bytes = opus_encode_float(encoder_, input, frame_size, output.data(),
                                              static_cast<opus_int32>(output.size()));

        if (encoded_bytes < 0) {
            Log::error("Opus encoding failed: {}", opus_strerror(encoded_bytes));
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

private:
    OpusEncoder* encoder_     = nullptr;
    int          channels_    = 0;
    int          sample_rate_ = 0;
};
