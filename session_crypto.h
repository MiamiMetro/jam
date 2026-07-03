#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <string>
#include <vector>

#include "performer_join_token.h"
#include "protocol.h"

namespace session_crypto {

using SessionKey = std::array<unsigned char, 32>;

namespace detail {

inline std::vector<unsigned char> bytes_from_string(const std::string& value) {
    return std::vector<unsigned char>(value.begin(), value.end());
}

inline void append_string(std::vector<unsigned char>& out, const std::string& value) {
    out.insert(out.end(), value.begin(), value.end());
}

inline void append_u64(std::vector<unsigned char>& out, uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<unsigned char>((value >> (i * 8)) & 0xFFU));
    }
}

inline std::optional<unsigned char> from_hex_digit(char digit) {
    if (digit >= '0' && digit <= '9') {
        return static_cast<unsigned char>(digit - '0');
    }
    if (digit >= 'a' && digit <= 'f') {
        return static_cast<unsigned char>(10 + digit - 'a');
    }
    if (digit >= 'A' && digit <= 'F') {
        return static_cast<unsigned char>(10 + digit - 'A');
    }
    return std::nullopt;
}

inline std::optional<std::vector<unsigned char>> hex_to_bytes(const std::string& hex) {
    if ((hex.size() % 2) != 0) {
        return std::nullopt;
    }
    std::vector<unsigned char> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        const auto high = from_hex_digit(hex[i]);
        const auto low = from_hex_digit(hex[i + 1]);
        if (!high.has_value() || !low.has_value()) {
            return std::nullopt;
        }
        out.push_back(static_cast<unsigned char>((*high << 4) | *low));
    }
    return out;
}

inline std::vector<unsigned char> hmac_sha256_bytes(
    const std::vector<unsigned char>& key_input,
    const std::vector<unsigned char>& message) {
    constexpr size_t block_size = 64;
    std::vector<unsigned char> key = key_input;
    if (key.size() > block_size) {
        key = performer_join_token::sha256(key);
    }
    key.resize(block_size, 0);

    std::vector<unsigned char> outer_key_pad(block_size);
    std::vector<unsigned char> inner_key_pad(block_size);
    for (size_t i = 0; i < block_size; ++i) {
        outer_key_pad[i] = key[i] ^ 0x5c;
        inner_key_pad[i] = key[i] ^ 0x36;
    }

    std::vector<unsigned char> inner(inner_key_pad);
    inner.insert(inner.end(), message.begin(), message.end());
    const auto inner_hash = performer_join_token::sha256(inner);

    std::vector<unsigned char> outer(outer_key_pad);
    outer.insert(outer.end(), inner_hash.begin(), inner_hash.end());
    return performer_join_token::sha256(outer);
}

inline SessionKey session_key_from_digest(const std::vector<unsigned char>& digest) {
    SessionKey key{};
    const size_t copy_bytes = std::min(key.size(), digest.size());
    std::copy_n(digest.begin(), copy_bytes, key.begin());
    return key;
}

inline std::vector<unsigned char> key_to_vector(const SessionKey& key) {
    return std::vector<unsigned char>(key.begin(), key.end());
}

inline std::vector<unsigned char> derive_subkey(const SessionKey& key,
                                                const std::string& label) {
    return hmac_sha256_bytes(key_to_vector(key), bytes_from_string(label));
}

inline std::vector<unsigned char> auth_tag(const std::vector<unsigned char>& auth_key,
                                           const unsigned char* bytes,
                                           size_t byte_count) {
    std::vector<unsigned char> message(bytes, bytes + byte_count);
    return hmac_sha256_bytes(auth_key, message);
}

inline bool constant_time_equal(const unsigned char* left, const unsigned char* right,
                                size_t byte_count) {
    unsigned char diff = 0;
    for (size_t i = 0; i < byte_count; ++i) {
        diff |= static_cast<unsigned char>(left[i] ^ right[i]);
    }
    return diff == 0;
}

inline void xor_keystream(const std::vector<unsigned char>& enc_key, uint64_t nonce,
                          unsigned char* bytes, size_t byte_count) {
    size_t offset = 0;
    uint64_t counter = 0;
    while (offset < byte_count) {
        std::vector<unsigned char> input;
        append_string(input, "jam-audio-stream-v1");
        append_u64(input, nonce);
        append_u64(input, counter++);
        const auto block = hmac_sha256_bytes(enc_key, input);
        const size_t chunk = std::min(block.size(), byte_count - offset);
        for (size_t i = 0; i < chunk; ++i) {
            bytes[offset + i] ^= block[i];
        }
        offset += chunk;
    }
}

inline void write_header(unsigned char* out, uint64_t nonce, uint16_t ciphertext_bytes) {
    uint32_t magic = SECURE_AUDIO_MAGIC;
    uint16_t reserved = 0;
    size_t offset = 0;
    std::memcpy(out + offset, &magic, sizeof(magic));
    offset += sizeof(magic);
    std::memcpy(out + offset, &nonce, sizeof(nonce));
    offset += sizeof(nonce);
    std::memcpy(out + offset, &ciphertext_bytes, sizeof(ciphertext_bytes));
    offset += sizeof(ciphertext_bytes);
    std::memcpy(out + offset, &reserved, sizeof(reserved));
}

}  // namespace detail

inline std::string nonce_replay_key(const performer_join_token::Claims& claims) {
    return std::to_string(claims.server_id.size()) + ":" + claims.server_id + "|" +
           std::to_string(claims.room_id.size()) + ":" + claims.room_id + "|" +
           std::to_string(claims.profile_id.size()) + ":" + claims.profile_id + "|" +
           std::to_string(claims.role.size()) + ":" + claims.role + "|" +
           std::to_string(claims.nonce.size()) + ":" + claims.nonce;
}

inline SessionKey derive_key_from_join_token(
    const performer_join_token::ValidatedToken& token) {
    const auto signature_bytes =
        detail::hex_to_bytes(token.signature_hex)
            .value_or(detail::bytes_from_string(token.signature_hex));
    std::vector<unsigned char> message;
    detail::append_string(message, "jam-session-key-v1|");
    detail::append_string(message, token.signing_input);
    const auto digest = detail::hmac_sha256_bytes(signature_bytes, message);
    return detail::session_key_from_digest(digest);
}

inline std::optional<SessionKey> derive_key_from_join_token_string(
    const std::string& token) {
    const auto parts = performer_join_token::split(token, '.');
    if (parts.size() != 8 || parts[0] != "v1") {
        return std::nullopt;
    }

    performer_join_token::ValidatedToken parsed;
    try {
        parsed.claims.expires_at_ms = std::stoll(parts[1]);
    } catch (...) {
        return std::nullopt;
    }
    parsed.claims.server_id = parts[2];
    parsed.claims.room_id = parts[3];
    parsed.claims.profile_id = parts[4];
    parsed.claims.role = parts[5];
    parsed.claims.nonce = parts[6];
    parsed.signature_hex = parts[7];
    parsed.signing_input = performer_join_token::signing_message(parsed.claims);
    parsed.ok = true;
    return derive_key_from_join_token(parsed);
}

inline bool seal_audio_packet(const SessionKey& key, uint64_t nonce,
                              const unsigned char* plaintext, size_t plaintext_len,
                              unsigned char* out, size_t out_capacity,
                              size_t& bytes_written) {
    bytes_written = 0;
    if (nonce == 0 || out == nullptr ||
        (plaintext_len > 0 && plaintext == nullptr) ||
        plaintext_len > std::numeric_limits<uint16_t>::max()) {
        return false;
    }

    const size_t required =
        SECURE_PACKET_HEADER_BYTES + plaintext_len + SECURE_PACKET_TAG_BYTES;
    if (out_capacity < required) {
        return false;
    }

    detail::write_header(out, nonce, static_cast<uint16_t>(plaintext_len));
    unsigned char* ciphertext = out + SECURE_PACKET_HEADER_BYTES;
    if (plaintext_len > 0) {
        std::memcpy(ciphertext, plaintext, plaintext_len);
        const auto enc_key = detail::derive_subkey(key, "jam-audio-enc-v1");
        detail::xor_keystream(enc_key, nonce, ciphertext, plaintext_len);
    }

    const auto auth_key = detail::derive_subkey(key, "jam-audio-auth-v1");
    const auto tag = detail::auth_tag(auth_key, out,
                                      SECURE_PACKET_HEADER_BYTES + plaintext_len);
    std::memcpy(out + SECURE_PACKET_HEADER_BYTES + plaintext_len, tag.data(),
                SECURE_PACKET_TAG_BYTES);
    bytes_written = required;
    return true;
}

inline bool open_audio_packet(const SessionKey& key, const unsigned char* packet,
                              size_t packet_len, uint64_t& nonce,
                              unsigned char* plaintext_out,
                              size_t plaintext_capacity, size_t& plaintext_len) {
    nonce = 0;
    plaintext_len = 0;
    if (packet == nullptr || plaintext_out == nullptr ||
        packet_len < SECURE_PACKET_HEADER_BYTES + SECURE_PACKET_TAG_BYTES) {
        return false;
    }

    uint32_t magic = 0;
    uint16_t ciphertext_bytes = 0;
    uint16_t reserved = 0;
    size_t offset = 0;
    std::memcpy(&magic, packet + offset, sizeof(magic));
    offset += sizeof(magic);
    std::memcpy(&nonce, packet + offset, sizeof(nonce));
    offset += sizeof(nonce);
    std::memcpy(&ciphertext_bytes, packet + offset, sizeof(ciphertext_bytes));
    offset += sizeof(ciphertext_bytes);
    std::memcpy(&reserved, packet + offset, sizeof(reserved));

    if (magic != SECURE_AUDIO_MAGIC || nonce == 0 || reserved != 0 ||
        plaintext_capacity < ciphertext_bytes) {
        return false;
    }

    const size_t expected =
        SECURE_PACKET_HEADER_BYTES + ciphertext_bytes + SECURE_PACKET_TAG_BYTES;
    if (packet_len != expected) {
        return false;
    }

    const auto auth_key = detail::derive_subkey(key, "jam-audio-auth-v1");
    const auto tag = detail::auth_tag(auth_key, packet,
                                      SECURE_PACKET_HEADER_BYTES + ciphertext_bytes);
    const unsigned char* packet_tag =
        packet + SECURE_PACKET_HEADER_BYTES + ciphertext_bytes;
    if (!detail::constant_time_equal(tag.data(), packet_tag,
                                     SECURE_PACKET_TAG_BYTES)) {
        return false;
    }

    if (ciphertext_bytes > 0) {
        std::memcpy(plaintext_out, packet + SECURE_PACKET_HEADER_BYTES,
                    ciphertext_bytes);
        const auto enc_key = detail::derive_subkey(key, "jam-audio-enc-v1");
        detail::xor_keystream(enc_key, nonce, plaintext_out, ciphertext_bytes);
    }
    plaintext_len = ciphertext_bytes;
    return true;
}

class ReplayWindow {
public:
    bool accept(uint64_t nonce) {
        if (nonce == 0) {
            return false;
        }
        if (!initialized_) {
            initialized_ = true;
            highest_nonce_ = nonce;
            seen_bitmap_ = 1;
            return true;
        }
        if (nonce > highest_nonce_) {
            const uint64_t shift = nonce - highest_nonce_;
            if (shift >= 64) {
                seen_bitmap_ = 0;
            } else {
                seen_bitmap_ <<= shift;
            }
            seen_bitmap_ |= 1;
            highest_nonce_ = nonce;
            return true;
        }

        const uint64_t delta = highest_nonce_ - nonce;
        if (delta >= 64) {
            return false;
        }
        const uint64_t mask = 1ULL << delta;
        if ((seen_bitmap_ & mask) != 0) {
            return false;
        }
        seen_bitmap_ |= mask;
        return true;
    }

    void reset() {
        initialized_ = false;
        highest_nonce_ = 0;
        seen_bitmap_ = 0;
    }

private:
    bool initialized_ = false;
    uint64_t highest_nonce_ = 0;
    uint64_t seen_bitmap_ = 0;
};

}  // namespace session_crypto
