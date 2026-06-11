#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <concurrentqueue.h>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include "opus_decoder.h"
#include "protocol.h"  // For AUDIO_BUF_SIZE
#include "sequence_tracker.h"

// Opus packet with metadata (for time-driven decode)
// Uses fixed buffer to avoid allocations in hot path
struct OpusPacket {
    uint16_t                              size = 0;  // Actual data size (<= AUDIO_BUF_SIZE)
    std::array<uint8_t, AUDIO_BUF_SIZE>   data;      // Fixed buffer (no allocations)
    std::chrono::steady_clock::time_point timestamp;
    AudioCodec                            codec = AudioCodec::Opus;
    uint32_t                              sequence = 0;
    bool                                  sequence_valid = false;
    bool                                  loss_concealment = false;
    bool                                  reset_decoder = false;
    uint32_t                              sample_rate = 48000;
    uint16_t                              frame_count = 0;
    uint8_t                               channels = 1;

    // Helper to get data pointer and size (compatible with old vector API)
    const uint8_t* get_data() const {
        return data.data();
    }
    size_t get_size() const {
        return size;
    }
};

enum class ParticipantOpusDequeueStatus {
    Packet,
    Empty,
    WaitingForGap,
};

class ParticipantOpusPacketQueue {
public:
    ParticipantOpusPacketQueue() {
        unsequenced_.reserve(MAX_OPUS_QUEUE_SIZE);
        sequenced_.reserve(MAX_OPUS_QUEUE_SIZE);
    }

    bool enqueue(const OpusPacket& packet) {
        return enqueue_bounded(packet, MAX_OPUS_QUEUE_SIZE);
    }

    bool enqueue_bounded(const OpusPacket& packet, size_t max_packets) {
        const size_t limit = admission_limit(packet, max_packets);
        if (limit == 0) {
            return false;
        }

        size_t count = buffered_count_.load(std::memory_order_acquire);
        while (count < limit) {
            if (buffered_count_.compare_exchange_weak(
                    count, count + 1, std::memory_order_acq_rel,
                    std::memory_order_acquire)) {
                if (incoming_.enqueue(packet)) {
                    record_admitted_packet(packet);
                    return true;
                }
                decrement_buffered_count();
                return false;
            }
        }
        return false;
    }

    bool enqueue_bounded_or_reject_overflow(const OpusPacket& packet, size_t max_packets) {
        return enqueue_bounded(packet, max_packets);
    }

    bool try_dequeue(OpusPacket& packet) {
        return dequeue(packet, 0) == ParticipantOpusDequeueStatus::Packet;
    }

    bool try_dequeue(OpusPacket& packet, size_t gap_wait_packets) {
        return dequeue(packet, gap_wait_packets) == ParticipantOpusDequeueStatus::Packet;
    }

    ParticipantOpusDequeueStatus dequeue(OpusPacket& packet,
                                         size_t gap_wait_packets = 0) {
        drain_incoming_for_playout();
        if (!unsequenced_.empty()) {
            packet = unsequenced_.front();
            unsequenced_.erase(unsequenced_.begin());
            decrement_buffered_count();
            return ParticipantOpusDequeueStatus::Packet;
        }

        return dequeue_sequenced_for_playout(packet, gap_wait_packets);
    }

    bool discard_oldest_actual_packet() {
        drain_incoming_for_playout();
        if (!unsequenced_.empty()) {
            unsequenced_.erase(unsequenced_.begin());
            decrement_buffered_count();
            return true;
        }
        if (!sequenced_.empty()) {
            erase_sequenced_at(earliest_index_locked());
            decrement_buffered_count();
            return true;
        }
        return false;
    }

    size_t size_approx() const {
        return buffered_count_.load(std::memory_order_acquire);
    }

private:
    static bool sequence_before(uint32_t lhs, uint32_t rhs) {
        return sequence_number_before(lhs, rhs);
    }

    void drain_incoming_for_playout() {
        OpusPacket packet{};
        size_t drained = 0;
        while (drained < MAX_OPUS_QUEUE_SIZE + 1 && incoming_.try_dequeue(packet)) {
            ++drained;
            if (!packet.sequence_valid) {
                if (unsequenced_.size() >= MAX_OPUS_QUEUE_SIZE) {
                    decrement_buffered_count();
                    continue;
                }
                unsequenced_.push_back(packet);
                continue;
            }

            if (playout_initialized_ &&
                sequence_before(packet.sequence, next_playout_sequence_)) {
                decrement_buffered_count();
                continue;
            }

            if (has_sequence(packet.sequence)) {
                decrement_buffered_count();
                continue;
            }

            if (sequenced_.size() >= MAX_OPUS_QUEUE_SIZE) {
                const size_t latest = latest_index_locked();
                if (sequence_before(packet.sequence, sequenced_[latest].sequence)) {
                    sequenced_[latest] = packet;
                }
                decrement_buffered_count();
                continue;
            }

            sequenced_.push_back(packet);
        }
    }

    ParticipantOpusDequeueStatus dequeue_sequenced_for_playout(
        OpusPacket& packet, size_t gap_wait_packets) {
        if (sequenced_.empty()) {
            reset_gap_wait();
            return ParticipantOpusDequeueStatus::Empty;
        }

        if (!playout_initialized_) {
            next_playout_sequence_ = earliest_sequence_locked();
            playout_initialized_ = true;
            publish_playout_sequence();
        }

        discard_stale_packets_locked();

        if (sequenced_.empty()) {
            reset_gap_wait();
            return ParticipantOpusDequeueStatus::Empty;
        }

        const auto next_index = earliest_index_locked();
        const auto next_sequence = sequenced_[next_index].sequence;
        if (next_sequence != next_playout_sequence_) {
            if (should_wait_for_gap(gap_wait_packets, sequenced_.size())) {
                return ParticipantOpusDequeueStatus::WaitingForGap;
            }
            if (gap_loss_run_active_ &&
                gap_loss_run_packets_ >= MAX_OPUS_CONSECUTIVE_GAP_PLC_PACKETS) {
                packet = sequenced_[next_index];
                packet.reset_decoder = true;
                next_playout_sequence_ = packet.sequence + 1;
                publish_playout_sequence();
                gap_loss_run_active_ = false;
                gap_loss_run_packets_ = 0;
                reset_gap_wait();
                erase_sequenced_at(next_index);
                decrement_buffered_count();
                return ParticipantOpusDequeueStatus::Packet;
            }
            packet = make_loss_concealment_packet(sequenced_[next_index],
                                                  next_playout_sequence_);
            next_playout_sequence_ = packet.sequence + 1;
            publish_playout_sequence();
            gap_loss_run_active_ = true;
            ++gap_loss_run_packets_;
            reset_gap_wait();
            return ParticipantOpusDequeueStatus::Packet;
        } else {
            reset_gap_wait();
        }

        packet = sequenced_[next_index];
        next_playout_sequence_ = packet.sequence + 1;
        publish_playout_sequence();
        gap_loss_run_active_ = false;
        gap_loss_run_packets_ = 0;
        reset_gap_wait();
        erase_sequenced_at(next_index);
        decrement_buffered_count();
        return ParticipantOpusDequeueStatus::Packet;
    }

    bool has_sequence(uint32_t sequence) const {
        for (const auto& packet: sequenced_) {
            if (packet.sequence == sequence) {
                return true;
            }
        }
        return false;
    }

    static OpusPacket make_loss_concealment_packet(const OpusPacket& reference,
                                                   uint32_t sequence) {
        OpusPacket packet{};
        packet.codec = reference.codec;
        packet.sequence = sequence;
        packet.sequence_valid = true;
        packet.loss_concealment = true;
        packet.sample_rate = reference.sample_rate;
        packet.frame_count = reference.frame_count;
        packet.channels = reference.channels;
        packet.timestamp = std::chrono::steady_clock::now();
        return packet;
    }

    size_t admission_limit(const OpusPacket& packet, size_t max_packets) const {
        const size_t configured_limit = std::min(max_packets, MAX_OPUS_QUEUE_SIZE);
        if (configured_limit == 0) {
            return 0;
        }

        if (is_expected_late_packet(packet) || is_startup_gap_recovery_packet(packet)) {
            return configured_limit + 1;
        }
        return configured_limit;
    }

    bool is_expected_late_packet(const OpusPacket& packet) const {
        if (!packet.sequence_valid ||
            !playout_initialized_snapshot_.load(std::memory_order_acquire)) {
            return false;
        }
        return packet.sequence ==
               next_playout_sequence_snapshot_.load(std::memory_order_acquire);
    }

    bool is_startup_gap_recovery_packet(const OpusPacket& packet) const {
        return packet.sequence_valid &&
               !playout_initialized_snapshot_.load(std::memory_order_acquire) &&
               admission_tracker_.has_unresolved_gap(packet.sequence);
    }

    void record_admitted_packet(const OpusPacket& packet) {
        if (packet.sequence_valid) {
            admission_tracker_.record(packet.sequence);
        }
    }

    size_t earliest_index_locked() const {
        size_t earliest = 0;
        for (size_t i = 1; i < sequenced_.size(); ++i) {
            if (sequence_before(sequenced_[i].sequence, sequenced_[earliest].sequence)) {
                earliest = i;
            }
        }
        return earliest;
    }

    size_t latest_index_locked() const {
        size_t latest = 0;
        for (size_t i = 1; i < sequenced_.size(); ++i) {
            if (sequence_before(sequenced_[latest].sequence, sequenced_[i].sequence)) {
                latest = i;
            }
        }
        return latest;
    }

    uint32_t earliest_sequence_locked() const {
        return sequenced_[earliest_index_locked()].sequence;
    }

    void discard_stale_packets_locked() {
        for (size_t i = 0; i < sequenced_.size();) {
            if (sequence_before(sequenced_[i].sequence, next_playout_sequence_)) {
                erase_sequenced_at(i);
                decrement_buffered_count();
            } else {
                ++i;
            }
        }
    }

    void erase_sequenced_at(size_t index) {
        if (index + 1 < sequenced_.size()) {
            sequenced_[index] = sequenced_.back();
        }
        sequenced_.pop_back();
    }

    bool should_wait_for_gap(size_t gap_wait_packets, size_t /*future_packet_count*/) {
        if (gap_wait_packets == 0) {
            return false;
        }

        if (gap_loss_run_active_) {
            return false;
        }

        if (!gap_wait_initialized_ || gap_wait_sequence_ != next_playout_sequence_) {
            gap_wait_initialized_ = true;
            gap_wait_sequence_ = next_playout_sequence_;
            gap_wait_callbacks_ = 0;
        }

        if (gap_wait_callbacks_ >= gap_wait_packets) {
            return false;
        }

        ++gap_wait_callbacks_;
        return true;
    }

    void reset_gap_wait() {
        gap_wait_initialized_ = false;
        gap_wait_callbacks_ = 0;
    }

    void publish_playout_sequence() {
        next_playout_sequence_snapshot_.store(next_playout_sequence_,
                                             std::memory_order_release);
        playout_initialized_snapshot_.store(playout_initialized_,
                                            std::memory_order_release);
    }

    void decrement_buffered_count() {
        buffered_count_.fetch_sub(1, std::memory_order_release);
    }

    moodycamel::ConcurrentQueue<OpusPacket> incoming_;
    std::atomic<size_t> buffered_count_{0};
    std::vector<OpusPacket> unsequenced_;
    std::vector<OpusPacket> sequenced_;
    bool playout_initialized_ = false;
    uint32_t next_playout_sequence_ = 0;
    bool gap_wait_initialized_ = false;
    uint32_t gap_wait_sequence_ = 0;
    size_t gap_wait_callbacks_ = 0;
    bool gap_loss_run_active_ = false;
    size_t gap_loss_run_packets_ = 0;
    SequenceArrivalTracker admission_tracker_;
    std::atomic<bool> playout_initialized_snapshot_{false};
    std::atomic<uint32_t> next_playout_sequence_snapshot_{0};
};

// Per-participant audio data and state
struct ParticipantData {
    // Audio processing - store OPUS packets, decode in audio callback
    ParticipantOpusPacketQueue              opus_queue;
    std::unique_ptr<OpusDecoderWrapper>     decoder;
    std::array<float, 960>                  pcm_buffer;  // Preallocated decode buffer
    std::array<float, 1920>                 opus_pcm_buffer{};
    size_t                                  opus_pcm_buffered_frames = 0;
    double                                  opus_resample_phase = 0.0;
    uint64_t                                opus_rate_last_queue_limit_drops = 0;
    int                                     opus_rate_correction_callbacks = 0;
    std::atomic<int64_t>                    opus_playout_rate_ratio_micros{1'000'000};
    std::atomic<int>                        opus_rate_correction_callbacks_observed{0};
    std::atomic<size_t>                     opus_pcm_buffered_frames_observed{0};
    std::atomic<uint64_t>                   opus_packets_decoded_in_callback{0};
    std::atomic<uint64_t>                   opus_queue_limit_drops{0};
    std::atomic<uint64_t>                   opus_age_limit_drops{0};
    std::atomic<uint64_t>                   opus_decode_buffer_overflow_drops{0};
    std::atomic<uint64_t>                   opus_target_trim_drops{0};
    std::atomic<size_t>                     last_packet_frame_count{0};
    std::atomic<size_t>                     last_callback_frame_count{0};
    std::array<float, 960>                  last_pcm_buffer{};
    size_t                                  last_pcm_samples = 0;
    bool                                    last_pcm_valid = false;
    bool                                    pcm_concealment_used = false;
    std::atomic<uint64_t>                   pcm_drift_drops{0};

    // Participant state
    std::string                           profile_id;
    std::string                           display_name;
    std::atomic<bool>                    is_muted{false};
    std::atomic<float>                   gain{1.0F};
    std::atomic<float>                   pan{0.5F};  // 0.0 = full left, 0.5 = center, 1.0 = full right
    std::chrono::steady_clock::time_point last_packet_time;
    std::atomic<size_t>                   jitter_buffer_floor_packets{MIN_JITTER_BUFFER_PACKETS};
    std::atomic<size_t>                   jitter_buffer_min_packets{MIN_JITTER_BUFFER_PACKETS};
    std::atomic<size_t>                   opus_queue_limit_packets{MAX_OPUS_QUEUE_SIZE};
    std::atomic<bool>                     opus_jitter_manual_override{false};
    std::atomic<bool>                     opus_jitter_auto_enabled{false};
    std::atomic<size_t>                   opus_jitter_auto_floor_packets{DEFAULT_OPUS_JITTER_PACKETS};
    std::atomic<size_t>                   opus_jitter_auto_max_packets{DEFAULT_OPUS_AUTO_MAX_JITTER_PACKETS};
    std::atomic<int>                      opus_jitter_auto_stable_callbacks{0};
    std::atomic<int>                      opus_jitter_auto_instability_events{0};
    std::atomic<uint64_t>                 opus_jitter_auto_increases{0};
    std::atomic<uint64_t>                 opus_jitter_auto_decreases{0};
    std::atomic<bool>                     buffer_ready{false};
    std::atomic<int>                      opus_consecutive_empty_callbacks{0};
    std::atomic<int>                      underrun_count{0};
    std::atomic<float>                   current_level{0.0F};  // RMS audio level
    std::atomic<bool>                    is_speaking{false};  // Voice activity detection

    // Adaptive jitter buffer tracking
    std::array<size_t, 8> queue_size_history = {};  // Rolling history for adaptive buffer
    size_t                history_index      = 0;   // Current index in history
    std::atomic<size_t>   plc_count{0};             // PLC invocations (for diagnostics)
    std::atomic<AudioCodec> last_codec{AudioCodec::Opus};
    std::atomic<int64_t>   packet_age_last_ns{0};
    std::atomic<int64_t>   packet_age_max_ns{0};
    std::atomic<int64_t>   packet_age_avg_ns{0};
    std::atomic<size_t>    queue_depth_max{0};
    std::atomic<size_t>    queue_depth_avg{0};
    std::atomic<int64_t>   queue_depth_drift_milli{0};
    SequenceArrivalTracker sequence_tracker;
    std::atomic<uint64_t>   sequence_gaps{0};
    std::atomic<uint64_t>   sequence_gap_recoveries{0};
    std::atomic<uint64_t>   sequence_unresolved_gaps{0};
    std::atomic<uint64_t>   sequence_late_or_reordered{0};
    std::atomic<uint64_t>   jitter_depth_drops{0};
    std::atomic<uint64_t>   jitter_age_drops{0};
    std::atomic<uint64_t>   pcm_concealment_frames{0};
    bool                    drift_reference_initialized = false;
    uint32_t                drift_reference_sequence = 0;
    uint32_t                drift_reference_sample_rate = 48000;
    uint16_t                drift_reference_frame_count = 0;
    std::chrono::steady_clock::time_point drift_reference_time{};
    std::atomic<uint64_t>   receiver_drift_observations{0};
    std::atomic<int64_t>    receiver_drift_ppm_last_milli{0};
    std::atomic<int64_t>    receiver_drift_ppm_avg_milli{0};
    std::atomic<int64_t>    receiver_drift_ppm_abs_max_milli{0};
};

// Lightweight view for UI (snapshot of ParticipantData)
struct ParticipantInfo {
    uint32_t id;
    std::string profile_id;
    std::string display_name;
    bool     is_speaking;
    bool     is_muted;
    float    audio_level;
    float    gain;
    float    pan;  // 0.0 = full left, 0.5 = center, 1.0 = full right
    bool     buffer_ready;
    size_t   queue_size;
    size_t   queue_size_avg;
    size_t   queue_size_max;
    double   queue_drift_packets;
    size_t   jitter_buffer_min_packets;
    size_t   jitter_buffer_floor_packets;
    size_t   opus_queue_limit_packets;
    bool     opus_jitter_manual_override;
    bool     opus_jitter_auto_enabled;
    size_t   opus_jitter_auto_floor_packets;
    size_t   opus_jitter_auto_max_packets;
    uint64_t opus_jitter_auto_increases;
    uint64_t opus_jitter_auto_decreases;
    size_t   opus_pcm_buffered_frames;
    uint64_t opus_packets_decoded_in_callback;
    uint64_t opus_queue_limit_drops;
    uint64_t opus_age_limit_drops;
    uint64_t opus_decode_buffer_overflow_drops;
    uint64_t opus_target_trim_drops;
    double   opus_playout_rate_ratio;
    int      opus_rate_correction_callbacks;
    size_t   last_packet_frame_count;
    size_t   last_callback_frame_count;
    int      underrun_count;
    size_t   plc_count;  // PLC invocations for diagnostics
    double   packet_age_last_ms;
    double   packet_age_avg_ms;
    double   packet_age_max_ms;
    uint64_t sequence_gaps;
    uint64_t sequence_gap_recoveries;
    uint64_t sequence_unresolved_gaps;
    uint64_t sequence_late_or_reordered;
    uint64_t jitter_depth_drops;
    uint64_t jitter_age_drops;
    uint64_t pcm_concealment_frames;
    uint64_t pcm_drift_drops;
    double   receiver_drift_ppm_last;
    double   receiver_drift_ppm_avg;
    double   receiver_drift_ppm_abs_max;
};
