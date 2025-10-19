#pragma once

#include <iostream>
#include <opus.h>
#include <vector>

class audio_codec {
  private:
    OpusEncoder *_encoder = nullptr;
    OpusDecoder *_decoder = nullptr;

  public:
    audio_codec() = default;

    ~audio_codec() {
        if (_encoder) {
            opus_encoder_destroy(_encoder);
            _encoder = nullptr;
        }
        if (_decoder) {
            opus_decoder_destroy(_decoder);
            _decoder = nullptr;
        }
    }

    void create_codec(int sample_rate, int decoder_channels, int encoder_channels,
                      int application = OPUS_APPLICATION_AUDIO, int bitrate = 256000, int complexity = 8) {
        if (_encoder) {
            opus_encoder_destroy(_encoder);
            _encoder = nullptr;
        }
        if (_decoder) {
            opus_decoder_destroy(_decoder);
            _decoder = nullptr;
        }

        std::cout << "Initializing Opus encoder/decoder...\n";

        int err;
        _encoder = opus_encoder_create(sample_rate, encoder_channels, application, &err);
        if (err != OPUS_OK) {
            std::cerr << "Failed to create Opus encoder: " << opus_strerror(err) << "\n";
            _encoder = nullptr;
            return;
        }
        _decoder = opus_decoder_create(sample_rate, decoder_channels, &err);
        if (err != OPUS_OK) {
            std::cerr << "Failed to create Opus decoder: " << opus_strerror(err) << "\n";
            opus_encoder_destroy(_encoder);
            _encoder = nullptr;
            _decoder = nullptr;
            return;
        }

        // Set encoder options for low-latency music streaming
        opus_encoder_ctl(_encoder, OPUS_SET_COMPLEXITY(complexity));
        opus_encoder_ctl(_encoder, OPUS_SET_BITRATE(bitrate));
        opus_encoder_ctl(_encoder, OPUS_SET_SIGNAL(OPUS_SIGNAL_MUSIC));
        opus_encoder_ctl(_encoder, OPUS_SET_VBR(1));              // Variable bitrate for better quality
        opus_encoder_ctl(_encoder, OPUS_SET_VBR_CONSTRAINT(0));   // Unconstrained VBR for music
        opus_encoder_ctl(_encoder, OPUS_SET_INBAND_FEC(1));       // Forward error correction for UDP
        opus_encoder_ctl(_encoder, OPUS_SET_PACKET_LOSS_PERC(5)); // Expect some packet loss
        opus_encoder_ctl(_encoder, OPUS_SET_DTX(0));              // Disable DTX for music (no silence detection)

        // Verify settings were applied
        int32_t actual_bitrate;
        opus_encoder_ctl(_encoder, OPUS_GET_BITRATE(&actual_bitrate));
        std::cout << "Opus encoder initialized: target=" << bitrate << " bps, actual=" << actual_bitrate
                  << " bps, complexity=" << complexity << "\n";
    }

    bool is_decoder_initialized() const { return _decoder != nullptr; }
    bool is_encoder_initialized() const { return _encoder != nullptr; }

    void destroy_codec() {
        if (_encoder) {
            opus_encoder_destroy(_encoder);
            _encoder = nullptr;
        }
        if (_decoder) {
            opus_decoder_destroy(_decoder);
            _decoder = nullptr;
        }
    }

    void encode_opus(const float *input, int frame_size, std::vector<unsigned char> &output) {
        if (!_encoder) {
            std::cerr << "Opus encoder not initialized.\n";
            output.clear();
            return;
        }
        output.resize(512); // Larger buffer for high-quality music (was 128)
        int encoded_bytes = opus_encode_float(_encoder, input, frame_size, output.data(), output.size());
        if (encoded_bytes < 0) {
            std::cerr << "Opus encoding failed: " << opus_strerror(encoded_bytes) << "\n";
            output.clear();
        } else {
            output.resize(encoded_bytes); // Resize to actual encoded size
        }
    }

    void decode_opus(const unsigned char *input, int input_size, int frame_size, int channel_count,
                     std::vector<float> &output) {
        if (!_decoder) {
            std::cerr << "Opus decoder not initialized.\n";
            output.clear();
            return;
        }
        output.resize(frame_size * channel_count); // Allocate space for decoded PCM (frameSize is samples per channel)
        // opus_decode_float returns samples per channel decoded
        int decoded_samples_per_channel = opus_decode_float(_decoder, input, input_size, output.data(), frame_size, 0);
        if (decoded_samples_per_channel < 0) {
            std::cerr << "Opus decoding failed: " << opus_strerror(decoded_samples_per_channel) << "\n";
            output.clear();
        } else {
            // The output buffer now contains decodedSamplesPerChannel * channelCount total samples
            output.resize(decoded_samples_per_channel * channel_count);
        }
    }
};