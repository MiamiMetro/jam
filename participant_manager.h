#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>
#include "logger.h"
#include "participant_info.h"

// Thread-safe participant lifecycle manager for client-side
// Manages remote participants (other clients) and their audio state
class ParticipantManager {
public:
    ParticipantManager() = default;

    // Register a new participant with decoder initialization
    bool register_participant(uint32_t id, int sample_rate, int channels) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (participants_.contains(id)) {
            return true;  // Already registered
        }

        ParticipantData new_participant;
        new_participant.decoder = std::make_unique<OpusDecoderWrapper>();

        if (!new_participant.decoder->create(sample_rate, channels)) {
            Log::error("Failed to create decoder for participant {} ({}Hz, {}ch)", id, sample_rate,
                       channels);
            return false;
        }

        new_participant.pcm_buffer.fill(0.0F);  // Initialize preallocated buffer
        new_participant.last_packet_time = std::chrono::steady_clock::now();
        participants_[id]                = std::move(new_participant);

        Log::info("New participant {} joined (decoder: {}Hz, {}ch)", id, sample_rate, channels);
        return true;
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
            func(it->second);
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
            info.is_speaking    = data.is_speaking;
            info.is_muted       = data.is_muted;
            info.audio_level    = data.current_level;
            info.gain           = data.gain;
            info.buffer_ready   = data.buffer_ready;
            info.queue_size     = data.opus_queue.size_approx();
            info.underrun_count = data.underrun_count;
            info.plc_count      = data.plc_count;
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
                std::chrono::duration_cast<std::chrono::seconds>(now - it->second.last_packet_time);

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
        // CRITICAL: Don't hold mutex during decode/mix
        // 1. Lock and copy participant IDs
        std::vector<uint32_t> ids;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            ids.reserve(participants_.size());
            for (const auto& [id, _]: participants_) {
                ids.push_back(id);
            }
        }

        // 2. Process each participant without holding global lock
        for (uint32_t id: ids) {
            std::lock_guard<std::mutex> lock(mutex_);
            auto                        it = participants_.find(id);
            if (it != participants_.end()) {
                func(id, it->second);
            }
        }
    }

private:
    mutable std::mutex                            mutex_;
    std::unordered_map<uint32_t, ParticipantData> participants_;
};
