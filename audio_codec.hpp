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
                      int application = OPUS_APPLICATION_AUDIO, int bitrate = 96000, int complexity = 5) {
        if (_encoder) {
            opus_encoder_destroy(_encoder);
            _encoder = nullptr;
        }
        if (_decoder) {
            opus_decoder_destroy(_decoder);
            _decoder = nullptr;
        }

        std::cout << "Re-initializing Opus encoder/decoder...\n";

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
    }

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

    void encode_opus(const float *input, int frameSize, std::vector<unsigned char> &output) {
        if (!_encoder) {
            std::cerr << "Opus encoder not initialized.\n";
            output.clear();
            return;
        }
        output.resize(128); // Allocate enough space for encoded data
        int encodedBytes = opus_encode_float(_encoder, input, frameSize, output.data(), output.size());
        if (encodedBytes < 0) {
            std::cerr << "Opus encoding failed: " << opus_strerror(encodedBytes) << "\n";
            output.clear();
        } else {
            output.resize(encodedBytes); // Resize to actual encoded size
        }
    }

    void decode_opus(const unsigned char *input, int inputSize, int frameSize, int channelCount,
                     std::vector<float> &output) {
        if (!_decoder) {
            std::cerr << "Opus decoder not initialized.\n";
            output.clear();
            return;
        }
        output.resize(frameSize * channelCount); // Allocate space for decoded PCM (frameSize is samples per channel)
        // opus_decode_float returns samples per channel decoded
        int decodedSamplesPerChannel = opus_decode_float(_decoder, input, inputSize, output.data(), frameSize, 0);
        if (decodedSamplesPerChannel < 0) {
            std::cerr << "Opus decoding failed: " << opus_strerror(decodedSamplesPerChannel) << "\n";
            output.clear();
        } else {
            // The output buffer now contains decodedSamplesPerChannel * channelCount total samples
            output.resize(decodedSamplesPerChannel * channelCount);
        }
    }
};