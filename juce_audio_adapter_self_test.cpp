#include "juce_audio_adapter.h"

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <vector>

namespace {

bool almost_equal(float lhs, float rhs)
{
    return std::fabs(lhs - rhs) < 0.000001F;
}

void expect_vector(const std::vector<float>& actual, const std::vector<float>& expected)
{
    if (actual.size() != expected.size()) {
        std::cerr << "size mismatch: expected " << expected.size() << ", got " << actual.size()
                  << '\n';
        std::exit(1);
    }

    for (std::size_t index = 0; index < expected.size(); ++index) {
        if (!almost_equal(actual[index], expected[index])) {
            std::cerr << "value mismatch at " << index << ": expected " << expected[index]
                      << ", got " << actual[index] << '\n';
            std::exit(1);
        }
    }
}

void expect_array(const std::array<float, 3>& actual, const std::array<float, 3>& expected)
{
    for (std::size_t index = 0; index < expected.size(); ++index) {
        if (!almost_equal(actual[index], expected[index])) {
            std::cerr << "value mismatch at " << index << ": expected " << expected[index]
                      << ", got " << actual[index] << '\n';
            std::exit(1);
        }
    }
}

void test_mono_input_interleaving()
{
    const std::array<float, 3> mono{0.25F, -0.5F, 0.75F};
    const float* inputs[] = {mono.data()};
    std::vector<float> interleaved;

    juce_audio_adapter::copy_inputs_to_interleaved(inputs, 1, 3, 1, interleaved);

    expect_vector(interleaved, {0.25F, -0.5F, 0.75F});
}

void test_stereo_output_deinterleaving()
{
    const std::vector<float> interleaved{0.1F, 0.2F, 0.3F, 0.4F, 0.5F, 0.6F};
    std::array<float, 3> left{};
    std::array<float, 3> right{};
    float* outputs[] = {left.data(), right.data()};

    juce_audio_adapter::copy_interleaved_to_outputs(interleaved, 3, 2, outputs, 2);

    expect_array(left, {0.1F, 0.3F, 0.5F});
    expect_array(right, {0.2F, 0.4F, 0.6F});
}

void test_null_input_leaves_zeros()
{
    std::vector<float> interleaved{1.0F};

    juce_audio_adapter::copy_inputs_to_interleaved(nullptr, 1, 2, 2, interleaved);

    expect_vector(interleaved, {0.0F, 0.0F, 0.0F, 0.0F});
}

void test_multichannel_input_downmixes_to_mono()
{
    const std::array<float, 3> first{0.2F, 0.4F, 0.6F};
    const std::array<float, 3> second{0.8F, 0.6F, 0.4F};
    const float* inputs[] = {first.data(), second.data()};
    std::vector<float> interleaved;

    juce_audio_adapter::copy_inputs_to_interleaved(inputs, 2, 3, 1, interleaved);

    expect_vector(interleaved, {0.5F, 0.5F, 0.5F});
}

void test_fixed_buffer_input_interleaving()
{
    const std::array<float, 3> left{0.25F, -0.5F, 0.75F};
    const std::array<float, 3> right{1.0F, 0.5F, -1.0F};
    const float* inputs[] = {left.data(), right.data()};
    std::array<float, 6> interleaved{9.0F, 9.0F, 9.0F, 9.0F, 9.0F, 9.0F};

    juce_audio_adapter::copy_inputs_to_interleaved(inputs, 2, 3, 2, interleaved.data(),
                                                   interleaved.size());

    expect_array({interleaved[0], interleaved[2], interleaved[4]}, {0.25F, -0.5F, 0.75F});
    expect_array({interleaved[1], interleaved[3], interleaved[5]}, {1.0F, 0.5F, -1.0F});
}

void test_selected_input_channel_copy()
{
    const std::array<float, 3> first{0.1F, 0.2F, 0.3F};
    const std::array<float, 3> second{0.4F, 0.5F, 0.6F};
    const std::array<float, 3> third{0.7F, 0.8F, 0.9F};
    const float* inputs[] = {first.data(), second.data(), third.data()};
    std::array<float, 3> interleaved{};

    juce_audio_adapter::copy_selected_input_channel_to_interleaved(
        inputs, 3, 2, 3, 1, interleaved.data(), interleaved.size());

    expect_array(interleaved, {0.7F, 0.8F, 0.9F});
}

void test_selected_input_channel_falls_back_to_enabled_channel()
{
    const std::array<float, 3> enabled{0.25F, 0.5F, 0.75F};
    const float* inputs[] = {enabled.data()};
    std::array<float, 3> interleaved{};

    juce_audio_adapter::copy_selected_input_channel_to_interleaved(
        inputs, 1, 4, 3, 1, interleaved.data(), interleaved.size());

    expect_array(interleaved, {0.25F, 0.5F, 0.75F});
}

void test_output_clamps_to_last_interleaved_channel()
{
    const std::vector<float> interleaved{0.1F, 0.3F, 0.5F};
    std::array<float, 3> first{};
    std::array<float, 3> second{};
    float* outputs[] = {first.data(), second.data()};

    juce_audio_adapter::copy_interleaved_to_outputs(interleaved, 3, 1, outputs, 2);

    expect_array(first, {0.1F, 0.3F, 0.5F});
    expect_array(second, {0.1F, 0.3F, 0.5F});
}

void test_zero_interleaved_channels_outputs_silence()
{
    const std::vector<float> interleaved{1.0F, 2.0F, 3.0F};
    std::array<float, 3> output{9.0F, 9.0F, 9.0F};
    float* outputs[] = {output.data()};

    juce_audio_adapter::copy_interleaved_to_outputs(interleaved, 3, 0, outputs, 1);

    expect_array(output, {0.0F, 0.0F, 0.0F});
}

} // namespace

int main()
{
    test_mono_input_interleaving();
    test_stereo_output_deinterleaving();
    test_null_input_leaves_zeros();
    test_multichannel_input_downmixes_to_mono();
    test_fixed_buffer_input_interleaving();
    test_selected_input_channel_copy();
    test_selected_input_channel_falls_back_to_enabled_channel();
    test_output_clamps_to_last_interleaved_channel();
    test_zero_interleaved_channels_outputs_silence();

    std::cout << "juce audio adapter self-test passed\n";
    return 0;
}
