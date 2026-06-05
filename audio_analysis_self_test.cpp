#include <array>
#include <cmath>
#include <iostream>

#include "audio_analysis.h"

namespace {

bool nearly_equal(float a, float b) {
    return std::fabs(a - b) < 0.00001F;
}

bool expect_equal(float actual, float expected, const char* label) {
    if (!nearly_equal(actual, expected)) {
        std::cerr << label << ": expected " << expected << ", got " << actual << "\n";
        return false;
    }
    return true;
}

bool monitor_mixes_mono_input_to_stereo_output() {
    const std::array<float, 2> input{0.25F, -0.5F};
    std::array<float, 4> output{0.1F, 0.2F, 0.3F, 0.4F};

    audio_analysis::mix_local_monitor(output.data(), input.data(), input.size(), 2, 0.5F);

    return expect_equal(output[0], 0.225F, "left frame 0") &&
           expect_equal(output[1], 0.325F, "right frame 0") &&
           expect_equal(output[2], 0.05F, "left frame 1") &&
           expect_equal(output[3], 0.15F, "right frame 1");
}

bool monitor_mixes_mono_input_to_mono_output() {
    const std::array<float, 2> input{0.25F, -0.5F};
    std::array<float, 2> output{0.1F, 0.3F};

    audio_analysis::mix_local_monitor(output.data(), input.data(), input.size(), 1, 2.0F);

    return expect_equal(output[0], 0.6F, "mono frame 0") &&
           expect_equal(output[1], -0.7F, "mono frame 1");
}

}  // namespace

int main() {
    if (!monitor_mixes_mono_input_to_stereo_output()) {
        return 1;
    }
    if (!monitor_mixes_mono_input_to_mono_output()) {
        return 1;
    }
    return 0;
}
