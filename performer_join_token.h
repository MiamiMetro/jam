#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include <picosha2.h>

namespace performer_join_token {

struct Claims {
    int64_t     expires_at_ms = 0;
    std::string server_id;
    std::string room_id;
    std::string profile_id;
    std::string role;
    std::string nonce;
};

struct ValidationResult {
    bool        ok = false;
    std::string reason;
};

inline int64_t now_ms() {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
}

inline std::string hex(const std::vector<unsigned char>& bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string           out;
    out.reserve(bytes.size() * 2);
    for (unsigned char byte: bytes) {
        out.push_back(digits[byte >> 4]);
        out.push_back(digits[byte & 0x0F]);
    }
    return out;
}

inline std::vector<unsigned char> sha256(const std::vector<unsigned char>& bytes) {
    std::vector<unsigned char> digest(picosha2::k_digest_size);
    picosha2::hash256(bytes.begin(), bytes.end(), digest.begin(), digest.end());
    return digest;
}

inline std::string hmac_sha256_hex(const std::string& secret, const std::string& message) {
    constexpr size_t block_size = 64;
    std::vector<unsigned char> key(secret.begin(), secret.end());
    if (key.size() > block_size) {
        key = sha256(key);
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
    const auto inner_hash = sha256(inner);

    std::vector<unsigned char> outer(outer_key_pad);
    outer.insert(outer.end(), inner_hash.begin(), inner_hash.end());
    return hex(sha256(outer));
}

inline std::string signing_message(const Claims& claims) {
    return "v1|" + std::to_string(claims.expires_at_ms) + "|" + claims.server_id + "|" +
           claims.room_id + "|" + claims.profile_id + "|" + claims.role + "|" + claims.nonce;
}

inline std::string random_nonce() {
    std::random_device              random;
    std::uniform_int_distribution<> hex_digit(0, 15);
    static constexpr char           digits[] = "0123456789abcdef";
    std::string                     nonce;
    nonce.reserve(32);
    for (int i = 0; i < 32; ++i) {
        nonce.push_back(digits[hex_digit(random)]);
    }
    return nonce;
}

inline std::string sign(const Claims& claims, const std::string& secret) {
    return hmac_sha256_hex(secret, signing_message(claims));
}

inline std::string create(const Claims& claims, const std::string& secret) {
    return "v1." + std::to_string(claims.expires_at_ms) + "." + claims.server_id + "." +
           claims.room_id + "." + claims.profile_id + "." + claims.role + "." + claims.nonce +
           "." + sign(claims, secret);
}

inline std::vector<std::string> split(const std::string& value, char delimiter) {
    std::vector<std::string> parts;
    std::string              part;
    std::istringstream       stream(value);
    while (std::getline(stream, part, delimiter)) {
        parts.push_back(part);
    }
    return parts;
}

inline bool constant_time_equal(const std::string& left, const std::string& right) {
    if (left.size() != right.size()) {
        return false;
    }
    unsigned char diff = 0;
    for (size_t i = 0; i < left.size(); ++i) {
        diff |= static_cast<unsigned char>(left[i] ^ right[i]);
    }
    return diff == 0;
}

inline ValidationResult validate(const std::string& token, const std::string& secret,
                                 const std::string& expected_server_id,
                                 const std::string& expected_room_id,
                                 const std::string& expected_profile_id,
                                 const std::string& expected_role = "performer") {
    if (secret.empty()) {
        return {false, "join secret not configured"};
    }

    const auto parts = split(token, '.');
    if (parts.size() != 8 || parts[0] != "v1") {
        return {false, "malformed token"};
    }

    Claims claims;
    try {
        claims.expires_at_ms = std::stoll(parts[1]);
    } catch (...) {
        return {false, "malformed expiry"};
    }
    claims.server_id  = parts[2];
    claims.room_id    = parts[3];
    claims.profile_id = parts[4];
    claims.role       = parts[5];
    claims.nonce      = parts[6];

    if (claims.expires_at_ms < now_ms()) {
        return {false, "expired token"};
    }
    if (claims.server_id != expected_server_id) {
        return {false, "wrong server id"};
    }
    if (claims.room_id != expected_room_id) {
        return {false, "wrong room id"};
    }
    if (claims.profile_id != expected_profile_id) {
        return {false, "wrong profile id"};
    }
    if (claims.role != expected_role) {
        return {false, "wrong role"};
    }

    const std::string expected_signature = sign(claims, secret);
    if (!constant_time_equal(expected_signature, parts[7])) {
        return {false, "invalid signature"};
    }

    return {true, ""};
}

}  // namespace performer_join_token
