#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <samplerate.h>

class PcmClockResampler {
public:
    PcmClockResampler() {
        int error = 0;
        state_ = src_new(SRC_LINEAR, 1, &error);
        valid_ = state_ != nullptr;
    }

    ~PcmClockResampler() {
        if (state_ != nullptr) {
            src_delete(state_);
        }
    }

    PcmClockResampler(const PcmClockResampler&) = delete;
    PcmClockResampler& operator=(const PcmClockResampler&) = delete;

    bool valid() const {
        return valid_;
    }

    bool push(const float* samples, size_t frame_count) {
        if (!valid_ || samples == nullptr || frame_count == 0) {
            return false;
        }

        if (frame_count > input_.size()) {
            samples += frame_count - input_.size();
            frame_count = input_.size();
        }

        if (input_frames_ + frame_count > input_.size()) {
            const size_t drop =
                std::min(input_frames_, input_frames_ + frame_count - input_.size());
            consume_input(drop);
            overruns_++;
        }

        std::copy_n(samples, frame_count,
                    input_.begin() + static_cast<std::ptrdiff_t>(input_frames_));
        input_frames_ += frame_count;
        return true;
    }

    bool read(float* output, size_t frame_count, size_t target_input_frames) {
        if (!valid_ || output == nullptr || frame_count == 0) {
            return false;
        }

        update_ratio(target_input_frames);

        while (output_frames_ < frame_count && input_frames_ > 0) {
            if (!process_once()) {
                break;
            }
        }

        if (output_frames_ < frame_count) {
            underruns_++;
            return false;
        }

        std::copy_n(output_.begin(), frame_count, output);
        consume_output(frame_count);
        return true;
    }

    void reset() {
        input_frames_ = 0;
        output_frames_ = 0;
        ratio_ = 1.0;
        if (state_ != nullptr) {
            src_reset(state_);
        }
    }

    size_t buffered_input_frames() const {
        return input_frames_;
    }

    size_t buffered_output_frames() const {
        return output_frames_;
    }

    double ratio() const {
        return ratio_;
    }

    uint64_t underruns() const {
        return underruns_;
    }

    uint64_t overruns() const {
        return overruns_;
    }

private:
    static constexpr size_t kInputCapacityFrames = 8192;
    static constexpr size_t kOutputCapacityFrames = 4096;
    static constexpr double kMaxCorrection = 0.005;

    bool process_once() {
        const size_t output_room = output_.size() - output_frames_;
        if (output_room == 0) {
            return false;
        }

        SRC_DATA data{};
        data.data_in = input_.data();
        data.input_frames = static_cast<long>(input_frames_);
        data.data_out = output_.data() + output_frames_;
        data.output_frames = static_cast<long>(output_room);
        data.src_ratio = ratio_;
        data.end_of_input = 0;

        const int result = src_process(state_, &data);
        if (result != 0) {
            reset();
            return false;
        }

        if (data.input_frames_used > 0) {
            consume_input(static_cast<size_t>(data.input_frames_used));
        }
        if (data.output_frames_gen > 0) {
            output_frames_ += static_cast<size_t>(data.output_frames_gen);
        }

        return data.input_frames_used > 0 || data.output_frames_gen > 0;
    }

    void update_ratio(size_t target_input_frames) {
        if (target_input_frames == 0) {
            ratio_ = 1.0;
            return;
        }

        const double error =
            static_cast<double>(input_frames_) - static_cast<double>(target_input_frames);
        const double normalized = error / static_cast<double>(target_input_frames);
        const double correction = std::clamp(normalized * 0.001, -kMaxCorrection, kMaxCorrection);
        ratio_ = std::clamp(1.0 - correction, 1.0 - kMaxCorrection, 1.0 + kMaxCorrection);
    }

    void consume_input(size_t frames) {
        if (frames >= input_frames_) {
            input_frames_ = 0;
            return;
        }

        const size_t remaining = input_frames_ - frames;
        std::move(input_.begin() + static_cast<std::ptrdiff_t>(frames),
                  input_.begin() + static_cast<std::ptrdiff_t>(input_frames_),
                  input_.begin());
        input_frames_ = remaining;
    }

    void consume_output(size_t frames) {
        if (frames >= output_frames_) {
            output_frames_ = 0;
            return;
        }

        const size_t remaining = output_frames_ - frames;
        std::move(output_.begin() + static_cast<std::ptrdiff_t>(frames),
                  output_.begin() + static_cast<std::ptrdiff_t>(output_frames_),
                  output_.begin());
        output_frames_ = remaining;
    }

    SRC_STATE* state_ = nullptr;
    bool valid_ = false;
    std::array<float, kInputCapacityFrames> input_{};
    std::array<float, kOutputCapacityFrames> output_{};
    size_t input_frames_ = 0;
    size_t output_frames_ = 0;
    double ratio_ = 1.0;
    uint64_t underruns_ = 0;
    uint64_t overruns_ = 0;
};
