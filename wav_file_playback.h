#pragma once

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "logger.h"

// Format parsing (can extract to class later)
namespace wav_format {
    struct WavHeader {
        // RIFF chunk
        char     riff_id[4];        // "RIFF"
        uint32_t riff_size;
        char     format[4];         // "WAVE"
        
        // fmt chunk
        char     fmt_id[4];         // "fmt "
        uint32_t fmt_size;          // 16 for PCM
        uint16_t audio_format;      // 1 for PCM
        uint16_t num_channels;      // 1 = mono, 2 = stereo
        uint32_t sample_rate;
        uint32_t byte_rate;
        uint16_t block_align;
        uint16_t bits_per_sample;   // 16
        
        // data chunk
        char     data_id[4];        // "data"
        uint32_t data_size;         // size of PCM data
    };

    // Validate that format is supported (16-bit PCM only for v1)
    inline bool validate_format(const WavHeader& header) {
        // Check RIFF/WAVE signature
        if (std::memcmp(header.riff_id, "RIFF", 4) != 0 ||
            std::memcmp(header.format, "WAVE", 4) != 0 ||
            std::memcmp(header.fmt_id, "fmt ", 4) != 0 ||
            std::memcmp(header.data_id, "data", 4) != 0) {
            return false;
        }
        
        // V1: Only support PCM (format 1), 16-bit
        if (header.audio_format != 1 || header.bits_per_sample != 16) {
            return false;
        }
        
        // Support mono and stereo
        if (header.num_channels < 1 || header.num_channels > 2) {
            return false;
        }
        
        return true;
    }

    // Parse WAV header from file
    inline bool parse_header(std::ifstream& file, WavHeader& header) {
        file.seekg(0, std::ios::beg);
        
        // Read RIFF chunk
        file.read(reinterpret_cast<char*>(&header.riff_id), 4);
        file.read(reinterpret_cast<char*>(&header.riff_size), 4);
        file.read(reinterpret_cast<char*>(&header.format), 4);
        
        // Find fmt chunk (skip any chunks before it)
        char chunk_id[4];
        uint32_t chunk_size;
        bool found_fmt = false;
        
        while (file.good()) {
            file.read(chunk_id, 4);
            file.read(reinterpret_cast<char*>(&chunk_size), 4);
            
            if (std::memcmp(chunk_id, "fmt ", 4) == 0) {
                found_fmt = true;
                header.fmt_id[0] = chunk_id[0];
                header.fmt_id[1] = chunk_id[1];
                header.fmt_id[2] = chunk_id[2];
                header.fmt_id[3] = chunk_id[3];
                header.fmt_size = chunk_size;
                break;
            }
            
            // Skip this chunk
            file.seekg(chunk_size, std::ios::cur);
        }
        
        if (!found_fmt) {
            return false;
        }
        
        // Read fmt chunk data
        file.read(reinterpret_cast<char*>(&header.audio_format), 2);
        file.read(reinterpret_cast<char*>(&header.num_channels), 2);
        file.read(reinterpret_cast<char*>(&header.sample_rate), 4);
        file.read(reinterpret_cast<char*>(&header.byte_rate), 4);
        file.read(reinterpret_cast<char*>(&header.block_align), 2);
        file.read(reinterpret_cast<char*>(&header.bits_per_sample), 2);
        
        // Skip any extra fmt data
        if (header.fmt_size > 16) {
            file.seekg(header.fmt_size - 16, std::ios::cur);
        }
        
        // Find data chunk
        bool found_data = false;
        while (file.good()) {
            file.read(chunk_id, 4);
            file.read(reinterpret_cast<char*>(&chunk_size), 4);
            
            if (std::memcmp(chunk_id, "data", 4) == 0) {
                found_data = true;
                header.data_id[0] = chunk_id[0];
                header.data_id[1] = chunk_id[1];
                header.data_id[2] = chunk_id[2];
                header.data_id[3] = chunk_id[3];
                header.data_size = chunk_size;
                break;
            }
            
            // Skip this chunk
            file.seekg(chunk_size, std::ios::cur);
        }
        
        return found_data;
    }
}  // namespace wav_format

// Format decoding (can extract to class later)
namespace pcm_decode {
    // Convert 16-bit PCM to float [-1.0, 1.0]
    inline void pcm16_to_float(const int16_t* input, float* output, int samples) {
        constexpr float scale = 1.0F / 32768.0F;
        for (int i = 0; i < samples; ++i) {
            output[i] = static_cast<float>(input[i]) * scale;
        }
    }
    
    // Convert stereo 16-bit PCM to mono float (average channels)
    inline void pcm16_stereo_to_mono_float(const int16_t* input, float* output, int frames) {
        constexpr float scale = 1.0F / 32768.0F;
        for (int i = 0; i < frames; ++i) {
            int16_t left  = input[i * 2];
            int16_t right = input[i * 2 + 1];
            output[i]     = (static_cast<float>(left) + static_cast<float>(right)) * 0.5F * scale;
        }
    }
}  // namespace pcm_decode

// Sample rate conversion (can extract to class later)
namespace audio_resample {
    // Simple linear interpolation resampling
    // input: source audio (already float)
    // output: destination buffer (must be pre-allocated)
    // ratio: source_rate / target_rate
    // input_frames: number of frames in input
    // output_frames: number of frames to generate in output
    inline void linear(const float* input, float* output, float ratio, int input_frames,
                       int output_frames) {
        if (ratio == 1.0F) {
            // No resampling needed
            std::copy(input, input + output_frames, output);
            return;
        }
        
        const float inv_ratio = 1.0F / ratio;
        float       src_pos   = 0.0F;
        
        for (int i = 0; i < output_frames; ++i) {
            int   src_idx = static_cast<int>(src_pos);
            float frac    = src_pos - static_cast<float>(src_idx);
            
            if (src_idx + 1 < input_frames) {
                // Linear interpolation between two samples
                output[i] = input[src_idx] * (1.0F - frac) + input[src_idx + 1] * frac;
            } else if (src_idx < input_frames) {
                // Last sample (no interpolation)
                output[i] = input[src_idx];
            } else {
                // Past end of input - output silence
                output[i] = 0.0F;
            }
            
            src_pos += inv_ratio;
        }
    }
}  // namespace audio_resample

// Main WAV playback class
class WavFilePlayback {
public:
    WavFilePlayback() = default;
    
    ~WavFilePlayback() = default;
    
    // Prevent copying (contains atomic state)
    WavFilePlayback(const WavFilePlayback&)            = delete;
    WavFilePlayback& operator=(const WavFilePlayback&) = delete;
    
    // Allow moving
    WavFilePlayback(WavFilePlayback&& other) noexcept
        : pcm_data_(std::move(other.pcm_data_)),
          file_sample_rate_(other.file_sample_rate_),
          file_channels_(other.file_channels_),
          file_bits_per_sample_(other.file_bits_per_sample_),
          playing_(other.playing_.load()),
          read_position_(other.read_position_.load()),
          resample_ratio_(other.resample_ratio_),
          resample_position_frac_(other.resample_position_frac_) {
        other.file_sample_rate_ = 0;
        other.file_channels_    = 0;
        other.file_bits_per_sample_ = 0;
        other.playing_.store(false);
        other.read_position_.store(0);
        other.resample_ratio_         = 1.0F;
        other.resample_position_frac_ = 0.0F;
    }
    
    WavFilePlayback& operator=(WavFilePlayback&& other) noexcept {
        if (this != &other) {
            pcm_data_              = std::move(other.pcm_data_);
            file_sample_rate_      = other.file_sample_rate_;
            file_channels_         = other.file_channels_;
            file_bits_per_sample_  = other.file_bits_per_sample_;
            playing_.store(other.playing_.load());
            read_position_.store(other.read_position_.load());
            resample_ratio_         = other.resample_ratio_;
            resample_position_frac_ = other.resample_position_frac_;
            
            other.file_sample_rate_ = 0;
            other.file_channels_    = 0;
            other.file_bits_per_sample_ = 0;
            other.playing_.store(false);
            other.read_position_.store(0);
            other.resample_ratio_         = 1.0F;
            other.resample_position_frac_ = 0.0F;
        }
        return *this;
    }
    
    // Load WAV file from path
    bool load_file(const std::string& path) {
        unload();
        
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) {
            Log::error("Failed to open WAV file: {}", path);
            return false;
        }
        
        wav_format::WavHeader header;
        if (!wav_format::parse_header(file, header)) {
            Log::error("Failed to parse WAV header: {}", path);
            return false;
        }
        
        if (!wav_format::validate_format(header)) {
            Log::error(
                "Unsupported WAV format: format={}, channels={}, bits={} (only 16-bit PCM mono/stereo "
                "supported)",
                header.audio_format, header.num_channels, header.bits_per_sample);
            return false;
        }
        
        // Store file metadata
        file_sample_rate_     = static_cast<int>(header.sample_rate);
        file_channels_        = static_cast<int>(header.num_channels);
        file_bits_per_sample_ = static_cast<int>(header.bits_per_sample);
        
        // Read PCM data
        const int total_samples = header.data_size / (header.bits_per_sample / 8);
        const int total_frames  = total_samples / header.num_channels;
        
        std::vector<int16_t> pcm16_data(total_samples);
        file.read(reinterpret_cast<char*>(pcm16_data.data()), header.data_size);
        
        if (file.gcount() != static_cast<std::streamsize>(header.data_size)) {
            Log::error("Failed to read all PCM data: read {} bytes, expected {}", file.gcount(),
                       header.data_size);
            return false;
        }
        
        // Convert to float, always output as mono for v1
        pcm_data_.resize(total_frames);
        if (header.num_channels == 1) {
            pcm_decode::pcm16_to_float(pcm16_data.data(), pcm_data_.data(), total_frames);
        } else {
            // Stereo to mono conversion
            pcm_decode::pcm16_stereo_to_mono_float(pcm16_data.data(), pcm_data_.data(), total_frames);
        }
        
        // Reset playback state
        playing_.store(false);
        read_position_.store(0);
        resample_ratio_         = 1.0F;
        resample_position_frac_ = 0.0F;
        
        Log::info("Loaded WAV file: {} ({}Hz, {}ch, {}bits, {} frames)", path, file_sample_rate_,
                  file_channels_, file_bits_per_sample_, total_frames);
        
        return true;
    }
    
    void unload() {
        pcm_data_.clear();
        file_sample_rate_     = 0;
        file_channels_        = 0;
        file_bits_per_sample_ = 0;
        playing_.store(false);
        read_position_.store(0);
        resample_ratio_         = 1.0F;
        resample_position_frac_ = 0.0F;
    }
    
    bool is_loaded() const {
        return !pcm_data_.empty();
    }
    
    void play() {
        if (is_loaded()) {
            playing_.store(true);
        }
    }
    
    void pause() {
        playing_.store(false);
    }
    
    void seek(int64_t frame_position) {
        // Only allow seeking when paused (boundary discipline)
        if (!playing_.load(std::memory_order_acquire)) {
            const int64_t max_pos = static_cast<int64_t>(pcm_data_.size());
            const int64_t clamped  = std::max(static_cast<int64_t>(0), std::min(frame_position, max_pos));
            read_position_.store(clamped, std::memory_order_release);
            resample_position_frac_ = 0.0F;  // Reset resampling state
        }
    }
    
    bool is_playing() const {
        return playing_.load(std::memory_order_acquire);
    }
    
    int64_t get_position() const {
        return read_position_.load(std::memory_order_acquire);
    }
    
    int64_t get_total_frames() const {
        return static_cast<int64_t>(pcm_data_.size());
    }
    
    // Read audio data (thread-safe, called from audio callback)
    // Returns number of frames read (0 = EOF, < frames_requested = partial)
    int read(float* output, int frames_requested, int target_sample_rate) {
        if (!is_loaded() || !playing_.load(std::memory_order_acquire)) {
            std::fill(output, output + frames_requested, 0.0F);
            return 0;
        }
        
        // Calculate resampling ratio (source_rate / target_rate)
        const float ratio = static_cast<float>(file_sample_rate_) / static_cast<float>(target_sample_rate);
        
        // If ratio changed, reset resampling state
        if (ratio != resample_ratio_) {
            resample_ratio_         = ratio;
            resample_position_frac_ = 0.0F;
        }
        
        const int64_t current_pos = read_position_.load(std::memory_order_acquire);
        const int64_t max_frames  = static_cast<int64_t>(pcm_data_.size());
        
        if (current_pos >= max_frames) {
            // EOF
            std::fill(output, output + frames_requested, 0.0F);
            playing_.store(false, std::memory_order_release);
            return 0;
        }
        
        if (ratio == 1.0F) {
            // No resampling needed - direct copy
            const int64_t available      = max_frames - current_pos;
            const int     frames_to_copy = static_cast<int>(std::min(static_cast<int64_t>(frames_requested), available));
            
            std::copy(pcm_data_.begin() + current_pos, pcm_data_.begin() + current_pos + frames_to_copy, output);
            
            if (frames_to_copy < frames_requested) {
                std::fill(output + frames_to_copy, output + frames_requested, 0.0F);
                playing_.store(false, std::memory_order_release);
            }
            
            read_position_.fetch_add(frames_to_copy, std::memory_order_acq_rel);
            return frames_to_copy;
        } else {
            // Resampling needed
            // For linear interpolation, we need enough source frames
            // We'll read frames_requested / ratio source frames (rounded up) + 1 for interpolation
            const float src_frames_needed_float = static_cast<float>(frames_requested) / ratio;
            const int   max_source_frames       = static_cast<int>(src_frames_needed_float) + 2;
            const int64_t available              = max_frames - current_pos;
            const int     source_frames          = static_cast<int>(std::min(static_cast<int64_t>(max_source_frames), available));
            
            if (source_frames == 0) {
                // EOF
                std::fill(output, output + frames_requested, 0.0F);
                playing_.store(false, std::memory_order_release);
                return 0;
            }
            
            // Get pointer to source data
            const float* source_ptr = pcm_data_.data() + current_pos;
            
            // Perform resampling
            audio_resample::linear(source_ptr, output, ratio, source_frames, frames_requested);
            
            // Advance read position by the actual source frames consumed
            // For linear resampling, we advance by inv_ratio per output frame
            // So after frames_requested output frames, we've consumed: frames_requested / ratio source frames
            const float src_frames_consumed = static_cast<float>(frames_requested) / ratio;
            const int64_t frames_advanced    = static_cast<int64_t>(src_frames_consumed);
            
            read_position_.fetch_add(frames_advanced, std::memory_order_acq_rel);
            
            // Check if we've reached EOF
            const int64_t new_pos = read_position_.load(std::memory_order_acquire);
            if (new_pos >= max_frames) {
                playing_.store(false, std::memory_order_release);
            }
            
            return frames_requested;
        }
    }
    
    // Metadata getters
    int get_sample_rate() const {
        return file_sample_rate_;
    }
    
    int get_channels() const {
        return file_channels_;
    }
    
    int get_bits_per_sample() const {
        return file_bits_per_sample_;
    }

private:
    // Internal structure (private - can refactor later)
    std::vector<float> pcm_data_;  // V1: Load entire file
                                   // Future: Streaming/chunked loading
    int                file_sample_rate_     = 0;
    int                file_channels_        = 0;
    int                file_bits_per_sample_ = 0;
    
    // Playback state
    std::atomic<bool>    playing_{false};
    std::atomic<int64_t> read_position_{0};
    
    // Resampling state (v1: linear, future: strategy object)
    float resample_ratio_         = 1.0F;
    float resample_position_frac_ = 0.0F;  // Note: Not currently used in linear resampling,
                                           // reserved for future interpolation methods
};

