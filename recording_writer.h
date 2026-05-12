#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

#include <concurrentqueue.h>

class RecordingWriter {
public:
    enum class TrackKind : uint8_t {
        Master,
        Self,
        Participant,
    };

    static constexpr size_t MAX_FRAMES_PER_BLOCK = 960;

    struct Block {
        TrackKind kind = TrackKind::Master;
        uint32_t  participant_id = 0;
        uint32_t  sample_rate = 48000;
        uint16_t  frame_count = 0;
        std::array<float, MAX_FRAMES_PER_BLOCK> samples{};
    };

    struct ParticipantMetadata {
        std::string profile_id;
        std::string display_name;
    };

    ~RecordingWriter() {
        stop();
    }

    bool start(uint32_t sample_rate, const std::filesystem::path& root = "recordings") {
        stop();

        sample_rate_ = sample_rate;
        folder_ = root / timestamp_name();
        std::error_code ec;
        std::filesystem::create_directories(folder_, ec);
        if (ec) {
            folder_.clear();
            return false;
        }

        queued_blocks_.store(0, std::memory_order_release);
        dropped_blocks_.store(0, std::memory_order_release);
        stop_requested_.store(false, std::memory_order_release);
        active_.store(true, std::memory_order_release);
        writer_thread_ = std::thread([this]() { writer_loop(); });
        return true;
    }

    void stop() {
        active_.store(false, std::memory_order_release);
        stop_requested_.store(true, std::memory_order_release);
        if (writer_thread_.joinable()) {
            writer_thread_.join();
        }

        Block discarded{};
        while (queue_.try_dequeue(discarded)) {
            queued_blocks_.fetch_sub(1, std::memory_order_relaxed);
        }
    }

    bool is_active() const {
        return active_.load(std::memory_order_acquire);
    }

    std::string folder() const {
        return folder_.string();
    }

    size_t queued_blocks() const {
        return queued_blocks_.load(std::memory_order_acquire);
    }

    uint64_t dropped_blocks() const {
        return dropped_blocks_.load(std::memory_order_acquire);
    }

    void set_participant_metadata(uint32_t participant_id, std::string profile_id,
                                  std::string display_name) {
        if (participant_id == 0) {
            return;
        }
        std::lock_guard<std::mutex> lock(metadata_mutex_);
        participant_metadata_[participant_id] = {std::move(profile_id), std::move(display_name)};
    }

    void enqueue(TrackKind kind, uint32_t participant_id, uint32_t sample_rate,
                 const float* samples, size_t frame_count) {
        if (!is_active() || samples == nullptr || frame_count == 0 ||
            frame_count > MAX_FRAMES_PER_BLOCK) {
            if (is_active()) {
                dropped_blocks_.fetch_add(1, std::memory_order_relaxed);
            }
            return;
        }

        constexpr size_t MAX_QUEUED_BLOCKS = 4096;
        size_t queued = queued_blocks_.load(std::memory_order_acquire);
        if (queued >= MAX_QUEUED_BLOCKS) {
            dropped_blocks_.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        Block block{};
        block.kind = kind;
        block.participant_id = participant_id;
        block.sample_rate = sample_rate;
        block.frame_count = static_cast<uint16_t>(frame_count);
        std::copy_n(samples, frame_count, block.samples.begin());
        queue_.enqueue(block);
        queued_blocks_.fetch_add(1, std::memory_order_release);
    }

private:
    struct TrackFile {
        std::ofstream file;
        std::string key;
        TrackKind kind = TrackKind::Master;
        uint32_t participant_id = 0;
        uint32_t sample_rate = 48000;
        uint32_t data_bytes = 0;
    };

    static std::string timestamp_name() {
        const auto now = std::chrono::system_clock::now();
        const auto time = std::chrono::system_clock::to_time_t(now);
        std::tm local_time{};
#ifdef _WIN32
        localtime_s(&local_time, &time);
#else
        localtime_r(&time, &local_time);
#endif
        char buffer[32]{};
        std::strftime(buffer, sizeof(buffer), "recording_%Y%m%d_%H%M%S", &local_time);
        return buffer;
    }

    static std::string track_key(const Block& block) {
        switch (block.kind) {
            case TrackKind::Master:
                return "master_mix";
            case TrackKind::Self:
                return "self";
            case TrackKind::Participant:
                return "user_" + std::to_string(block.participant_id);
        }
        return "unknown";
    }

    TrackFile& track_for(const Block& block, std::unordered_map<std::string, TrackFile>& tracks) {
        const std::string key = track_key(block);
        auto [it, inserted] = tracks.try_emplace(key);
        if (inserted) {
            it->second.key = key;
            it->second.kind = block.kind;
            it->second.participant_id = block.participant_id;
            it->second.sample_rate = block.sample_rate == 0 ? sample_rate_ : block.sample_rate;
            const auto path = folder_ / (key + ".wav");
            it->second.file.open(path, std::ios::binary);
            write_wav_header(it->second.file, it->second.sample_rate, 0);
        }
        return it->second;
    }

    static void write_u16(std::ofstream& file, uint16_t value) {
        file.put(static_cast<char>(value & 0xFF));
        file.put(static_cast<char>((value >> 8) & 0xFF));
    }

    static void write_u32(std::ofstream& file, uint32_t value) {
        file.put(static_cast<char>(value & 0xFF));
        file.put(static_cast<char>((value >> 8) & 0xFF));
        file.put(static_cast<char>((value >> 16) & 0xFF));
        file.put(static_cast<char>((value >> 24) & 0xFF));
    }

    static void write_wav_header(std::ofstream& file, uint32_t sample_rate, uint32_t data_bytes) {
        constexpr uint16_t channels = 1;
        constexpr uint16_t bits_per_sample = 16;
        constexpr uint16_t block_align = channels * bits_per_sample / 8;
        const uint32_t byte_rate = sample_rate * block_align;

        file.write("RIFF", 4);
        write_u32(file, 36 + data_bytes);
        file.write("WAVE", 4);
        file.write("fmt ", 4);
        write_u32(file, 16);
        write_u16(file, 1);
        write_u16(file, channels);
        write_u32(file, sample_rate);
        write_u32(file, byte_rate);
        write_u16(file, block_align);
        write_u16(file, bits_per_sample);
        file.write("data", 4);
        write_u32(file, data_bytes);
    }

    static void finalize_track(TrackFile& track) {
        if (!track.file.is_open()) {
            return;
        }
        track.file.seekp(0, std::ios::beg);
        write_wav_header(track.file, track.sample_rate, track.data_bytes);
        track.file.close();
    }

    static const char* track_kind_name(TrackKind kind) {
        switch (kind) {
            case TrackKind::Master:
                return "master";
            case TrackKind::Self:
                return "self";
            case TrackKind::Participant:
                return "participant";
        }
        return "unknown";
    }

    ParticipantMetadata metadata_for(uint32_t participant_id) const {
        std::lock_guard<std::mutex> lock(metadata_mutex_);
        auto it = participant_metadata_.find(participant_id);
        if (it == participant_metadata_.end()) {
            return {};
        }
        return it->second;
    }

    void write_manifest(const std::unordered_map<std::string, TrackFile>& tracks) {
        std::ofstream manifest(folder_ / "recording_manifest.tsv", std::ios::binary);
        if (!manifest.is_open()) {
            return;
        }

        manifest << "track_file\tkind\tparticipant_id\tprofile_id\tdisplay_name\tsample_rate"
                    "\tdata_bytes\n";
        for (const auto& [_, track]: tracks) {
            ParticipantMetadata metadata;
            if (track.kind == TrackKind::Participant) {
                metadata = metadata_for(track.participant_id);
            }
            manifest << track.key << ".wav\t" << track_kind_name(track.kind) << "\t"
                     << track.participant_id << "\t" << metadata.profile_id << "\t"
                     << metadata.display_name << "\t" << track.sample_rate << "\t"
                     << track.data_bytes << "\n";
        }
    }

    void writer_loop() {
        std::unordered_map<std::string, TrackFile> tracks;
        while (!stop_requested_.load(std::memory_order_acquire) ||
               queued_blocks_.load(std::memory_order_acquire) > 0) {
            Block block{};
            if (!queue_.try_dequeue(block)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
                continue;
            }
            queued_blocks_.fetch_sub(1, std::memory_order_acq_rel);

            TrackFile& track = track_for(block, tracks);
            if (!track.file.is_open()) {
                continue;
            }

            for (size_t i = 0; i < block.frame_count; ++i) {
                const float clamped = std::clamp(block.samples[i], -1.0F, 1.0F);
                const auto sample = static_cast<int16_t>(clamped * 32767.0F);
                track.file.write(reinterpret_cast<const char*>(&sample), sizeof(sample));
                track.data_bytes += sizeof(sample);
            }
        }

        for (auto& [_, track]: tracks) {
            finalize_track(track);
        }
        write_manifest(tracks);
    }

    moodycamel::ConcurrentQueue<Block> queue_;
    std::thread writer_thread_;
    std::atomic<bool> active_{false};
    std::atomic<bool> stop_requested_{true};
    std::atomic<size_t> queued_blocks_{0};
    std::atomic<uint64_t> dropped_blocks_{0};
    uint32_t sample_rate_ = 48000;
    std::filesystem::path folder_;
    mutable std::mutex metadata_mutex_;
    std::unordered_map<uint32_t, ParticipantMetadata> participant_metadata_;
};
