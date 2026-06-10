#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

struct SequenceArrivalDelta {
    uint32_t gaps_detected = 0;
    uint32_t gaps_recovered = 0;
    bool late_or_duplicate = false;
};

inline bool sequence_arrival_should_enqueue(const SequenceArrivalDelta& delta) {
    return !delta.late_or_duplicate || delta.gaps_recovered > 0;
}

inline bool sequence_number_before(uint32_t lhs, uint32_t rhs) {
    if (lhs == rhs) {
        return false;
    }
    return (lhs < rhs && rhs - lhs < 0x80000000U) ||
           (lhs > rhs && lhs - rhs > 0x80000000U);
}

inline bool sequence_number_after(uint32_t lhs, uint32_t rhs) {
    return sequence_number_before(rhs, lhs);
}

class SequenceArrivalTracker {
public:
    SequenceArrivalDelta record(uint32_t sequence) {
        SequenceArrivalDelta delta{};
        if (!initialized_) {
            initialized_ = true;
            next_sequence_ = sequence + 1;
            return delta;
        }

        if (sequence == next_sequence_) {
            ++next_sequence_;
            return delta;
        }

        if (sequence_number_after(sequence, next_sequence_)) {
            const uint32_t gap = sequence - next_sequence_;
            delta.gaps_detected = gap;
            unresolved_gaps_ += remember_missing_range(next_sequence_, gap);
            next_sequence_ = sequence + 1;
            return delta;
        }

        delta.late_or_duplicate = true;
        if (remove_missing(sequence)) {
            delta.gaps_recovered = 1;
        }
        return delta;
    }

    uint64_t unresolved_gaps() const {
        return unresolved_gaps_;
    }

    bool has_unresolved_gap(uint32_t sequence) const {
        return contains_missing(sequence);
    }

private:
    struct MissingRange {
        uint32_t first = 0;
        uint32_t count = 0;
    };

    static constexpr size_t MAX_TRACKED_RANGES = 64;

    uint32_t remember_missing_range(uint32_t first_sequence, uint32_t count) {
        if (count == 0) {
            return 0;
        }

        for (size_t i = 0; i < missing_count_; ++i) {
            auto& range = missing_[i];
            if (range.first + range.count == first_sequence) {
                range.count += count;
                return count;
            }
        }

        if (missing_count_ >= missing_.size()) {
            return 0;
        }
        missing_[missing_count_++] = MissingRange{first_sequence, count};
        return count;
    }

    bool contains_missing(uint32_t sequence) const {
        for (size_t i = 0; i < missing_count_; ++i) {
            const auto& range = missing_[i];
            const uint32_t offset = sequence - range.first;
            if (offset < range.count) {
                return true;
            }
        }
        return false;
    }

    bool remove_missing(uint32_t sequence) {
        for (size_t i = 0; i < missing_count_; ++i) {
            auto& range = missing_[i];
            const uint32_t offset = sequence - range.first;
            if (offset >= range.count) {
                continue;
            }
            if (range.count == 1) {
                erase_range(i);
                decrement_unresolved(1);
                return true;
            }

            if (offset == 0) {
                ++range.first;
                --range.count;
                decrement_unresolved(1);
                return true;
            }

            if (offset == range.count - 1) {
                --range.count;
                decrement_unresolved(1);
                return true;
            }

            const MissingRange right{sequence + 1, range.count - offset - 1};
            range.count = offset;
            if (missing_count_ < missing_.size()) {
                missing_[missing_count_++] = right;
                decrement_unresolved(1);
            } else {
                decrement_unresolved(1 + right.count);
            }
            return true;
        }
        return false;
    }

    void erase_range(size_t index) {
        if (index + 1 < missing_count_) {
            missing_[index] = missing_[missing_count_ - 1];
        }
        --missing_count_;
    }

    void decrement_unresolved(uint64_t count) {
        unresolved_gaps_ = unresolved_gaps_ > count ? unresolved_gaps_ - count : 0;
    }

    bool initialized_ = false;
    uint32_t next_sequence_ = 0;
    uint64_t unresolved_gaps_ = 0;
    std::array<MissingRange, MAX_TRACKED_RANGES> missing_{};
    size_t missing_count_ = 0;
};
