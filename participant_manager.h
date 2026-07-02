#pragma once

#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include "logger.h"
#include "participant_info.h"

// Thread-safe participant lifecycle manager for client-side
// Manages remote participants (other clients) and their audio state
class ParticipantManager {
    struct ParticipantMetadata {
        std::string profile_id;
        std::string display_name;
    };

    struct ParticipantEntry {
        uint32_t                         id = 0;
        std::shared_ptr<ParticipantData> data;
    };

    using ParticipantSnapshot = std::vector<ParticipantEntry>;
    using ParticipantSnapshotPtr = std::shared_ptr<const ParticipantSnapshot>;
    using ParticipantMetadataSnapshot = std::unordered_map<uint32_t, ParticipantMetadata>;
    using ParticipantMetadataSnapshotPtr = std::shared_ptr<const ParticipantMetadataSnapshot>;

    inline static thread_local bool in_audio_callback_ = false;

public:
    static constexpr size_t MAX_AUDIO_CALLBACK_PARTICIPANTS = 32;

    class AudioCallbackReadScope {
    public:
        AudioCallbackReadScope()
            : previous_(in_audio_callback_) {
            in_audio_callback_ = true;
        }

        ~AudioCallbackReadScope() {
            in_audio_callback_ = previous_;
        }

    private:
        bool previous_;
    };

    ParticipantManager()
        : audio_snapshot_(std::make_shared<ParticipantSnapshot>()),
          info_participant_snapshot_(std::make_shared<ParticipantSnapshot>()),
          metadata_snapshot_(std::make_shared<ParticipantMetadataSnapshot>()) {}

    // Register a new participant with decoder initialization
    bool register_participant(uint32_t id, int sample_rate, int channels) {
        {
            assert_not_audio_callback_lock();
            std::lock_guard<std::mutex> lock(mutex_);
            if (participants_.contains(id)) {
                return true;  // Already registered
            }
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

        {
            assert_not_audio_callback_lock();
            std::lock_guard<std::mutex> lock(mutex_);
            if (participants_.contains(id)) {
                return true;
            }
            auto pending = pending_metadata_.find(id);
            if (pending != pending_metadata_.end()) {
                new_participant->profile_id   = pending->second.profile_id;
                new_participant->display_name = pending->second.display_name;
                pending_metadata_.erase(pending);
            }
            participants_[id] = std::move(new_participant);
            publish_all_snapshots_locked();
        }

        Log::info("New participant {} joined (decoder: {}Hz, {}ch)", id, sample_rate, channels);
        return true;
    }

    void set_participant_metadata(uint32_t id, const std::string& profile_id,
                                  const std::string& display_name) {
        assert_not_audio_callback_lock();
        std::lock_guard<std::mutex> lock(mutex_);
        auto                        it = participants_.find(id);
        if (it != participants_.end()) {
            it->second->profile_id   = profile_id;
            it->second->display_name = display_name;
            publish_metadata_snapshot_locked();
        } else {
            pending_metadata_[id] = {profile_id, display_name};
        }
    }

    // Remove a participant (destruction is deferred; see graveyard_)
    void remove_participant(uint32_t id) {
        bool removed = false;
        {
            assert_not_audio_callback_lock();
            std::lock_guard<std::mutex> lock(mutex_);
            auto                        it = participants_.find(id);
            if (it != participants_.end()) {
                graveyard_.push_back(std::move(it->second));
                participants_.erase(it);
                publish_all_snapshots_locked();
                removed = true;
            }
        }
        if (removed) {
            Log::info("Participant {} left", id);
        }
    }

    // Check if participant exists
    bool exists(uint32_t id) const {
        assert_not_audio_callback_lock();
        std::lock_guard<std::mutex> lock(mutex_);
        return participants_.contains(id);
    }

    // Access participant with lambda (thread-safe)
    template <typename Func>
    bool with_participant(uint32_t id, Func&& func) {
        assert_not_audio_callback_lock();
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
        auto participants = load_info_participant_snapshot();
        auto metadata = load_metadata_snapshot();
        std::vector<ParticipantInfo> result;
        result.reserve(participants->size());

        for (const auto& entry: *participants) {
            if (!entry.data) {
                continue;
            }
            const ParticipantMetadata* published_metadata = nullptr;
            if (auto it = metadata->find(entry.id); it != metadata->end()) {
                published_metadata = &it->second;
            }
            result.push_back(make_info(entry.id, *entry.data, published_metadata));
        }

        return result;
    }

    // Remove timed-out participants
    std::vector<uint32_t> remove_timed_out_participants(std::chrono::steady_clock::time_point now,
                                                        std::chrono::seconds timeout) {
        std::vector<uint32_t>                      removed_ids;
        std::vector<std::pair<uint32_t, int64_t>> timed_out_logs;
        {
            assert_not_audio_callback_lock();
            std::lock_guard<std::mutex> lock(mutex_);
            bool                        changed = false;

            for (auto it = participants_.begin(); it != participants_.end();) {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    now - it->second->last_packet_time);

                if (elapsed > timeout) {
                    timed_out_logs.push_back({it->first, elapsed.count()});
                    removed_ids.push_back(it->first);
                    graveyard_.push_back(std::move(it->second));
                    it = participants_.erase(it);
                    changed = true;
                } else {
                    ++it;
                }
            }

            if (changed) {
                publish_all_snapshots_locked();
            }
        }

        for (const auto& [id, elapsed_seconds]: timed_out_logs) {
            Log::info("Participant {} timed out ({}s since last packet)", id, elapsed_seconds);
        }

        return removed_ids;
    }

    // Get participant count
    size_t count() const {
        return load_info_participant_snapshot()->size();
    }

    // Clear all participants (destruction is deferred; see graveyard_)
    void clear() {
        assert_not_audio_callback_lock();
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [id, participant]: participants_) {
            graveyard_.push_back(std::move(participant));
        }
        participants_.clear();
        publish_all_snapshots_locked();
    }

    // Destroy retired participants that no snapshot references anymore.
    // Call from the io thread only. Destruction runs outside the lock so a
    // concurrent for_each() in the audio callback is never blocked on frees.
    // Safety: once removed, a graveyard-only entry can only be referenced by
    // already-loaded published snapshots; new snapshots are built from the
    // active map, so use_count()==1 observed under the lock cannot race upward.
    size_t reap_retired_participants() {
        std::vector<std::shared_ptr<ParticipantData>> to_destroy;
        {
            assert_not_audio_callback_lock();
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto it = graveyard_.begin(); it != graveyard_.end();) {
                if (it->use_count() == 1) {
                    to_destroy.push_back(std::move(*it));
                    it = graveyard_.erase(it);
                } else {
                    ++it;
                }
            }
        }
        return to_destroy.size();
    }

    size_t retired_count() const {
        assert_not_audio_callback_lock();
        std::lock_guard<std::mutex> lock(mutex_);
        return graveyard_.size();
    }

    // Iterate over all participants (thread-safe, for audio mixing)
    template <typename Func>
    void for_each(Func&& func) {
        auto snapshot = load_audio_snapshot();
        for (const auto& entry: *snapshot) {
            if (entry.data) {
                func(entry.id, *entry.data);
            }
        }
    }

private:
    static void assert_not_audio_callback_lock() {
        assert(!in_audio_callback_);
    }

    ParticipantSnapshotPtr load_audio_snapshot() const {
        return std::atomic_load_explicit(&audio_snapshot_, std::memory_order_acquire);
    }

    ParticipantSnapshotPtr load_info_participant_snapshot() const {
        return std::atomic_load_explicit(&info_participant_snapshot_, std::memory_order_acquire);
    }

    ParticipantMetadataSnapshotPtr load_metadata_snapshot() const {
        return std::atomic_load_explicit(&metadata_snapshot_, std::memory_order_acquire);
    }

    ParticipantSnapshotPtr build_participant_snapshot_locked(size_t max_participants) const {
        auto snapshot = std::make_shared<ParticipantSnapshot>();
        snapshot->reserve(std::min(participants_.size(), max_participants));
        for (const auto& [id, participant]: participants_) {
            if (snapshot->size() >= max_participants) {
                break;
            }
            snapshot->push_back({id, participant});
        }
        return snapshot;
    }

    void publish_audio_snapshot_locked() {
        ParticipantSnapshotPtr published =
            build_participant_snapshot_locked(MAX_AUDIO_CALLBACK_PARTICIPANTS);
        std::atomic_store_explicit(&audio_snapshot_, std::move(published),
                                   std::memory_order_release);
    }

    void publish_info_participant_snapshot_locked() {
        ParticipantSnapshotPtr published = build_participant_snapshot_locked(participants_.size());
        std::atomic_store_explicit(&info_participant_snapshot_, std::move(published),
                                   std::memory_order_release);
    }

    void publish_metadata_snapshot_locked() {
        auto snapshot = std::make_shared<ParticipantMetadataSnapshot>();
        snapshot->reserve(participants_.size());
        for (const auto& [id, participant]: participants_) {
            snapshot->emplace(id, ParticipantMetadata{participant->profile_id,
                                                      participant->display_name});
        }
        ParticipantMetadataSnapshotPtr published = std::move(snapshot);
        std::atomic_store_explicit(&metadata_snapshot_, std::move(published),
                                   std::memory_order_release);
    }

    void publish_all_snapshots_locked() {
        publish_audio_snapshot_locked();
        publish_info_participant_snapshot_locked();
        publish_metadata_snapshot_locked();
    }

    static ParticipantInfo make_info(uint32_t id, const ParticipantData& data,
                                     const ParticipantMetadata* metadata) {
        ParticipantInfo info{};
        info.id = id;
        if (metadata != nullptr) {
            info.profile_id   = metadata->profile_id;
            info.display_name = metadata->display_name;
        }
        info.is_speaking    = data.is_speaking.load(std::memory_order_relaxed);
        info.is_muted       = data.is_muted.load(std::memory_order_relaxed);
        info.audio_level    = data.current_level.load(std::memory_order_relaxed);
        info.gain           = data.gain.load(std::memory_order_relaxed);
        info.pan            = data.pan.load(std::memory_order_relaxed);
        info.buffer_ready   = data.buffer_ready.load(std::memory_order_relaxed);
        info.queue_size     = data.opus_queue.size_approx();
        info.queue_size_avg = data.queue_depth_avg.load(std::memory_order_relaxed);
        info.queue_size_max = data.queue_depth_max.load(std::memory_order_relaxed);
        info.queue_drift_packets =
            data.queue_depth_drift_milli.load(std::memory_order_relaxed) / 1000.0;
        info.jitter_buffer_min_packets =
            data.jitter_buffer_min_packets.load(std::memory_order_relaxed);
        info.jitter_buffer_floor_packets =
            data.jitter_buffer_floor_packets.load(std::memory_order_relaxed);
        info.opus_queue_limit_packets =
            data.opus_queue_limit_packets.load(std::memory_order_relaxed);
        info.opus_jitter_manual_override =
            data.opus_jitter_manual_override.load(std::memory_order_relaxed);
        info.opus_jitter_auto_enabled =
            data.opus_jitter_auto_enabled.load(std::memory_order_relaxed);
        info.opus_jitter_auto_floor_packets =
            data.opus_jitter_auto_floor_packets.load(std::memory_order_relaxed);
        info.opus_jitter_auto_increases =
            data.opus_jitter_auto_increases.load(std::memory_order_relaxed);
        info.opus_jitter_auto_decreases =
            data.opus_jitter_auto_decreases.load(std::memory_order_relaxed);
        info.opus_pcm_buffered_frames =
            data.opus_pcm_buffered_frames_observed.load(std::memory_order_relaxed);
        info.opus_packets_decoded_in_callback =
            data.opus_packets_decoded_in_callback.load(std::memory_order_relaxed);
        info.opus_queue_limit_drops =
            data.opus_queue_limit_drops.load(std::memory_order_relaxed);
        info.opus_age_limit_drops =
            data.opus_age_limit_drops.load(std::memory_order_relaxed);
        info.opus_decode_buffer_overflow_drops =
            data.opus_decode_buffer_overflow_drops.load(std::memory_order_relaxed);
        info.opus_target_trim_drops =
            data.opus_target_trim_drops.load(std::memory_order_relaxed);
        info.opus_playout_rate_ratio =
            data.opus_playout_rate_ratio_micros.load(std::memory_order_relaxed) /
            1'000'000.0;
        info.opus_rate_correction_callbacks =
            data.opus_rate_correction_callbacks_observed.load(std::memory_order_relaxed);
        info.last_packet_frame_count =
            data.last_packet_frame_count.load(std::memory_order_relaxed);
        info.last_callback_frame_count =
            data.last_callback_frame_count.load(std::memory_order_relaxed);
        info.underrun_count = data.underrun_count.load(std::memory_order_relaxed);
        info.plc_count      = data.plc_count.load(std::memory_order_relaxed);
        info.packet_age_last_ms =
            data.packet_age_last_ns.load(std::memory_order_relaxed) / 1e6;
        info.packet_age_avg_ms =
            data.packet_age_avg_ns.load(std::memory_order_relaxed) / 1e6;
        info.packet_age_max_ms =
            data.packet_age_max_ns.load(std::memory_order_relaxed) / 1e6;
        info.capture_to_playout_latency_last_ms =
            data.capture_to_playout_latency_last_ns.load(std::memory_order_relaxed) / 1e6;
        info.capture_to_playout_latency_avg_ms =
            data.capture_to_playout_latency_avg_ns.load(std::memory_order_relaxed) / 1e6;
        info.capture_to_playout_latency_max_ms =
            data.capture_to_playout_latency_max_ns.load(std::memory_order_relaxed) / 1e6;
        info.capture_to_playout_latency_samples =
            data.capture_to_playout_latency_samples.load(std::memory_order_relaxed);
        info.sequence_gaps = data.sequence_gaps.load(std::memory_order_relaxed);
        info.sequence_gap_recoveries =
            data.sequence_gap_recoveries.load(std::memory_order_relaxed);
        info.sequence_unresolved_gaps =
            data.sequence_unresolved_gaps.load(std::memory_order_relaxed);
        info.sequence_late_or_reordered =
            data.sequence_late_or_reordered.load(std::memory_order_relaxed);
        info.jitter_depth_drops = data.jitter_depth_drops.load(std::memory_order_relaxed);
        info.jitter_age_drops = data.jitter_age_drops.load(std::memory_order_relaxed);
        info.pcm_concealment_frames =
            data.pcm_concealment_frames.load(std::memory_order_relaxed);
        info.pcm_drift_drops = data.pcm_drift_drops.load(std::memory_order_relaxed);
        info.receiver_drift_ppm_last =
            data.receiver_drift_ppm_last_milli.load(std::memory_order_relaxed) / 1000.0;
        info.receiver_drift_ppm_avg =
            data.receiver_drift_ppm_avg_milli.load(std::memory_order_relaxed) / 1000.0;
        info.receiver_drift_ppm_abs_max =
            data.receiver_drift_ppm_abs_max_milli.load(std::memory_order_relaxed) / 1000.0;
        return info;
    }

    mutable std::mutex                                             mutex_;
    std::unordered_map<uint32_t, std::shared_ptr<ParticipantData>> participants_;
    ParticipantSnapshotPtr                                          audio_snapshot_;
    ParticipantSnapshotPtr                                          info_participant_snapshot_;
    ParticipantMetadataSnapshotPtr                                  metadata_snapshot_;
    // Removed participants are parked here and destroyed only by
    // reap_retired_participants() on the io thread, once no audio-callback
    // snapshot references them. Destruction frees heap memory and destroys the
    // Opus decoder, so it must never run on the audio thread.
    std::vector<std::shared_ptr<ParticipantData>>                  graveyard_;
    std::unordered_map<uint32_t, ParticipantMetadata>               pending_metadata_;
};
