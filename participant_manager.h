#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include "logger.h"
#include "participant_info.h"

// Thread-safe participant lifecycle manager for client-side
// Manages remote participants (other clients) and their audio state
class ParticipantManager {
public:
    static constexpr size_t MAX_AUDIO_CALLBACK_PARTICIPANTS = 32;

    ParticipantManager() = default;

    // Register a new participant with decoder initialization
    bool register_participant(uint32_t id, int sample_rate, int channels) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (participants_.contains(id)) {
            return true;  // Already registered
        }

        auto new_participant = std::make_shared<ParticipantData>();
        new_participant->decoder = std::make_unique<OpusDecoderWrapper>();

        if (!new_participant->decoder->create(sample_rate, channels)) {
            Log::error("Failed to create decoder for participant {} ({}Hz, {}ch)", id, sample_rate,
                       channels);
            return false;
        }

        new_participant->pcm_buffer.fill(0.0F);  // Initialize preallocated buffer
        new_participant->last_packet_time = std::chrono::steady_clock::now();
        auto pending = pending_metadata_.find(id);
        if (pending != pending_metadata_.end()) {
            new_participant->profile_id   = pending->second.profile_id;
            new_participant->display_name = pending->second.display_name;
            pending_metadata_.erase(pending);
        }
        participants_[id]                 = std::move(new_participant);

        Log::info("New participant {} joined (decoder: {}Hz, {}ch)", id, sample_rate, channels);
        return true;
    }

    void set_participant_metadata(uint32_t id, const std::string& profile_id,
                                  const std::string& display_name) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto                        it = participants_.find(id);
        if (it != participants_.end()) {
            it->second->profile_id   = profile_id;
            it->second->display_name = display_name;
        } else {
            pending_metadata_[id] = {profile_id, display_name};
        }
    }

    // Remove a participant
    void remove_participant(uint32_t id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto                        it = participants_.find(id);
        if (it != participants_.end()) {
            participants_.erase(it);
            Log::info("Participant {} left", id);
        }
    }

    // Check if participant exists
    bool exists(uint32_t id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return participants_.contains(id);
    }

    // Access participant with lambda (thread-safe)
    template <typename Func>
    bool with_participant(uint32_t id, Func&& func) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto                        it = participants_.find(id);
        if (it != participants_.end()) {
            func(*it->second);
            return true;
        }
        return false;
    }

    // Get snapshot of all participants for UI
    std::vector<ParticipantInfo> get_all_info() const {
        std::lock_guard<std::mutex>  lock(mutex_);
        std::vector<ParticipantInfo> result;
        result.reserve(participants_.size());

        for (const auto& [id, data]: participants_) {
            ParticipantInfo info;
            info.id             = id;
            info.profile_id     = data->profile_id;
            info.display_name   = data->display_name;
            info.is_speaking    = data->is_speaking;
            info.is_muted       = data->is_muted;
            info.audio_level    = data->current_level;
            info.gain           = data->gain;
            info.pan            = data->pan;
            info.buffer_ready   = data->buffer_ready;
            info.queue_size     = data->opus_queue.size_approx();
            info.queue_size_avg = data->queue_depth_avg.load(std::memory_order_relaxed);
            info.queue_size_max = data->queue_depth_max.load(std::memory_order_relaxed);
            info.queue_drift_packets =
                data->queue_depth_drift_milli.load(std::memory_order_relaxed) / 1000.0;
            info.underrun_count = data->underrun_count;
            info.plc_count      = data->plc_count;
            info.packet_age_last_ms =
                data->packet_age_last_ns.load(std::memory_order_relaxed) / 1e6;
            info.packet_age_avg_ms =
                data->packet_age_avg_ns.load(std::memory_order_relaxed) / 1e6;
            info.packet_age_max_ms =
                data->packet_age_max_ns.load(std::memory_order_relaxed) / 1e6;
            info.sequence_gaps = data->sequence_gaps.load(std::memory_order_relaxed);
            info.sequence_late_or_reordered =
                data->sequence_late_or_reordered.load(std::memory_order_relaxed);
            info.jitter_depth_drops = data->jitter_depth_drops.load(std::memory_order_relaxed);
            info.jitter_age_drops = data->jitter_age_drops.load(std::memory_order_relaxed);
            info.pcm_concealment_frames =
                data->pcm_concealment_frames.load(std::memory_order_relaxed);
            info.pcm_drift_drops = data->pcm_drift_drops.load(std::memory_order_relaxed);
            info.pcm_fifo_depth = data->pcm_fifo_depth.load(std::memory_order_relaxed);
            info.pcm_remote_frame_count =
                data->pcm_remote_frame_count.load(std::memory_order_relaxed);
            info.pcm_format_drops = data->pcm_format_drops.load(std::memory_order_relaxed);
            info.pcm_size_mismatches =
                data->pcm_size_mismatches.load(std::memory_order_relaxed);
            info.pcm_fifo_underflows =
                data->pcm_fifo_underflows.load(std::memory_order_relaxed);
            info.pcm_fifo_overflows =
                data->pcm_fifo_overflows.load(std::memory_order_relaxed);
            result.push_back(info);
        }

        return result;
    }

    // Remove timed-out participants
    std::vector<uint32_t> remove_timed_out_participants(std::chrono::steady_clock::time_point now,
                                                        std::chrono::seconds timeout) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<uint32_t>       removed_ids;

        for (auto it = participants_.begin(); it != participants_.end();) {
            auto elapsed =
                std::chrono::duration_cast<std::chrono::seconds>(now - it->second->last_packet_time);

            if (elapsed > timeout) {
                Log::info("Participant {} timed out ({}s since last packet)", it->first,
                          elapsed.count());
                removed_ids.push_back(it->first);
                it = participants_.erase(it);
            } else {
                ++it;
            }
        }

        return removed_ids;
    }

    // Get participant count
    size_t count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return participants_.size();
    }

    // Clear all participants
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        participants_.clear();
    }

    // Iterate over all participants (thread-safe, for audio mixing)
    template <typename Func>
    void for_each(Func&& func) {
        std::array<std::pair<uint32_t, std::shared_ptr<ParticipantData>>,
                   MAX_AUDIO_CALLBACK_PARTICIPANTS>
            snapshot;
        size_t snapshot_count = 0;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (const auto& [id, participant]: participants_) {
                if (snapshot_count >= snapshot.size()) {
                    break;
                }
                snapshot[snapshot_count++] = {id, participant};
            }
        }

        for (size_t i = 0; i < snapshot_count; ++i) {
            auto& [id, participant] = snapshot[i];
            func(id, *participant);
        }
    }

private:
    struct ParticipantMetadata {
        std::string profile_id;
        std::string display_name;
    };

    mutable std::mutex                                             mutex_;
    std::unordered_map<uint32_t, std::shared_ptr<ParticipantData>> participants_;
    std::unordered_map<uint32_t, ParticipantMetadata>               pending_metadata_;
};
