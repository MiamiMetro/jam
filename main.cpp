#include <asio.hpp>
#include <iostream>
#include <opus.h>

int main() {
    std::cout << "Hello, World!" << std::endl;

    // Opus initialization
    OpusDecoder *decoder = opus_decoder_create(48000, 2, NULL);
    if (!decoder) {
        std::cerr << "Failed to create Opus decoder." << std::endl;
        return 1;
    }

    // Clean up
    opus_decoder_destroy(decoder);
    return 0;
}