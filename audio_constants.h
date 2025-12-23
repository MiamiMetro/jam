#pragma once

namespace audio_constants {

constexpr int SAMPLE_RATE       = 48000;
constexpr int CHANNELS          = 1;    // mono
constexpr int FRAME_SIZE        = 480;  // 10ms at 48kHz
constexpr int CLIENT_FRAME_SIZE = 240;  // 5ms at 48kHz (client sends this)
constexpr int BYTES_PER_SAMPLE  = 2;    // int16
constexpr int FRAME_BYTES       = FRAME_SIZE * CHANNELS * BYTES_PER_SAMPLE;

}  // namespace audio_constants
