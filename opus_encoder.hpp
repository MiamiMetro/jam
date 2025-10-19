#pragma once

#include <iostream>
#include <opus.h>
#include <vector>

class opus_encoder_wrapper {
  private:
    OpusEncoder *_encoder = nullptr;
    int _channels = 0;
    int _sample_rate = 0;

  public:
    opus_encoder_wrapper() = default;

    ~opus_encoder_wrapper() {
        destroy();
    }

    // Prevent copying (Opus encoder is a resource)
    opus_encoder_wrapper(const opus_encoder_wrapper &) = delete;
    opus_encoder_wrapper &operator=(const opus_encoder_wrapper &) = delete;

    // Allow moving
    opus_encoder_wrapper(opus_encoder_wrapper &&other) noexcept
        : _encoder(other._encoder), _channels(other._channels), _sample_rate(other._sample_rate) {
        other._encoder = nullptr;
    }

    opus_encoder_wrapper &operator=(opus_encoder_wrapper &&other) noexcept {
        if (this != &other) {
            destroy();
            _encoder = other._encoder;
            _channels = other._channels;
            _sample_rate = other._sample_rate;
            other._encoder = nullptr;
        }
        return *this;
    }

    bool create(int sample_rate, int channels, int application = OPUS_APPLICATION_AUDIO, int bitrate = 256000,
                int complexity = 5) {
        destroy(); // Clean up any existing encoder

        int err;
        _encoder = opus_encoder_create(sample_rate, channels, application, &err);
        if (err != OPUS_OK) {
            std::cerr << "Failed to create Opus encoder: " << opus_strerror(err) << "\n";
            return false;
        }

        _channels = channels;
        _sample_rate = sample_rate;

        // Set encoder options for low-latency music streaming
        opus_encoder_ctl(_encoder, OPUS_SET_COMPLEXITY(complexity));
        opus_encoder_ctl(_encoder, OPUS_SET_BITRATE(bitrate));
        opus_encoder_ctl(_encoder, OPUS_SET_SIGNAL(OPUS_SIGNAL_MUSIC));
        opus_encoder_ctl(_encoder, OPUS_SET_VBR(1));              // Variable bitrate for better quality
        opus_encoder_ctl(_encoder, OPUS_SET_VBR_CONSTRAINT(0));   // Unconstrained VBR for music
        opus_encoder_ctl(_encoder, OPUS_SET_INBAND_FEC(1));       // Forward error correction for UDP
        opus_encoder_ctl(_encoder, OPUS_SET_PACKET_LOSS_PERC(5)); // Expect some packet loss
        opus_encoder_ctl(_encoder, OPUS_SET_DTX(0));              // Disable DTX for music (no silence detection)

        // Verify settings
        int32_t actual_bitrate;
        opus_encoder_ctl(_encoder, OPUS_GET_BITRATE(&actual_bitrate));
        std::cout << "Opus encoder created: " << channels << "ch, " << sample_rate << "Hz, target=" << bitrate
                  << "bps, actual=" << actual_bitrate << "bps, complexity=" << complexity << "\n";

        return true;
    }

    void destroy() {
        if (_encoder) {
            opus_encoder_destroy(_encoder);
            _encoder = nullptr;
        }
        _channels = 0;
        _sample_rate = 0;
    }

    bool encode(const float *input, int frame_size, std::vector<unsigned char> &output) {
        if (!_encoder) {
            std::cerr << "Opus encoder not initialized.\n";
            output.clear();
            return false;
        }

        output.resize(512); // Buffer for high-quality music
        int encoded_bytes = opus_encode_float(_encoder, input, frame_size, output.data(), output.size());
        
        if (encoded_bytes < 0) {
            std::cerr << "Opus encoding failed: " << opus_strerror(encoded_bytes) << "\n";
            output.clear();
            return false;
        }

        output.resize(encoded_bytes);
        return true;
    }

    bool is_initialized() const { return _encoder != nullptr; }
    int get_channels() const { return _channels; }
    int get_sample_rate() const { return _sample_rate; }
};
