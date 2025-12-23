#pragma once

#include <algorithm>
#include <asio.hpp>
#include <cstdint>
#include <vector>
#include "audio_constants.h"
#include "client_manager.h"
#include "logger.h"
#include "opus_decoder.h"

using namespace audio_constants;
using asio::ip::udp;

// AudioProcessor - Handles Opus decoding and audio mixing
//
// Responsibilities:
// - Decode Opus packets to PCM samples
// - Buffer decoded PCM per client
// - Mix multiple client audio streams
//
// Thread Safety:
// - Uses ClientManager for thread-safe client access
// - Decode operations are thread-safe (Opus decoder is reentrant per client)
// - Mixing happens outside locks for performance
class AudioProcessor {
public:
    explicit AudioProcessor(ClientManager& client_manager) : client_manager_(client_manager) {}

    // Decode an Opus packet and buffer it for the client
    // Returns true if decode and buffer succeeded, false otherwise
    bool process_opus_packet(const udp::endpoint& endpoint, uint16_t client_id,
                             const unsigned char* opus_data, size_t encoded_bytes) {
        // Get decoder reference (create on-demand if needed)
        OpusDecoderWrapper* decoder_ptr   = nullptr;
        bool                decoder_found = false;
        client_manager_.with_client(endpoint, [&decoder_ptr, &decoder_found](ClientInfo& client) {
            if (!client.decoder.is_initialized()) {
                if (!client.decoder.create(SAMPLE_RATE, CHANNELS)) {
                    Log::error("Failed to create decoder");
                    return;
                }
                Log::info("Created decoder on demand");
            }
            decoder_ptr   = &client.decoder;
            decoder_found = true;
        });

        if (!decoder_found || !decoder_ptr) {
            Log::error("Client not found or decoder unavailable for {}:{} (ID: {})",
                       endpoint.address().to_string(), endpoint.port(), client_id);
            return false;
        }

        // Decode outside lock (Opus decoder is thread-safe per client)
        std::vector<float> decoded_pcm;
        if (!decoder_ptr->decode(opus_data, encoded_bytes, CLIENT_FRAME_SIZE, decoded_pcm)) {
            // Decode failed - use PLC (packet loss concealment)
            Log::debug("Opus decode failed for client {}, using PLC", client_id);
            decoder_ptr->decode_plc(CLIENT_FRAME_SIZE, decoded_pcm);
        }

        // Buffer decoded PCM for mixing (brief lock inside with_client)
        bool client_still_exists = false;
        client_manager_.with_client(
            endpoint, [&decoded_pcm, &client_still_exists](ClientInfo& client) {
                // Convert float to int16 and store in client's PCM buffer
                client.pcm_buffer.resize(decoded_pcm.size());
                for (size_t i = 0; i < decoded_pcm.size(); ++i) {
                    float sample_float   = decoded_pcm[i];
                    float clamped        = std::max(-1.0f, std::min(1.0f, sample_float));
                    client.pcm_buffer[i] = static_cast<int16_t>(clamped * 32767.0f);
                }
                client_still_exists = true;
            });

        if (!client_still_exists) {
            Log::warn("Client disappeared before buffering PCM");
            return false;
        }

        return true;
    }

    // Mix all client PCM buffers into a single audio frame
    // Extracts PCM samples from all clients, sums them, and averages to prevent clipping
    // Returns mixed audio frame (silence if no clients)
    std::vector<int16_t> get_mixed_frame(size_t frame_samples) {
        std::vector<int16_t> mixed_frame(frame_samples, 0);

        // Copy client buffers out (ClientManager handles locking)
        auto client_samples = client_manager_.extract_pcm_samples(frame_samples);

        // Check if we have any clients with data
        if (client_samples.empty()) {
            if (client_manager_.empty()) {
                static int empty_count = 0;
                if (++empty_count % 1000 == 0) {
                    Log::debug("Mix: no clients registered");
                }
            }
            return mixed_frame;  // Return silence
        }

        // Mix all client samples (sum then average)
        int active_clients = static_cast<int>(client_samples.size());
        if (active_clients > 0) {
            // Sum all client samples
            for (const auto& [endpoint, samples]: client_samples) {
                for (size_t i = 0; i < samples.size(); ++i) {
                    mixed_frame[i] = static_cast<int16_t>(static_cast<int32_t>(mixed_frame[i]) +
                                                          static_cast<int32_t>(samples[i]));
                }
            }

            // Average the mixed samples to prevent clipping
            for (auto& sample: mixed_frame) {
                int32_t mixed = static_cast<int32_t>(sample) / active_clients;
                sample        = static_cast<int16_t>(std::max(-32768, std::min(32767, mixed)));
            }

            static int mix_count = 0;
            if (++mix_count % 100 == 0 || mix_count <= 5) {
                Log::debug("Mixed {} clients", active_clients);
            }
        }

        return mixed_frame;
    }

private:
    ClientManager& client_manager_;  // Reference to shared client manager
};
