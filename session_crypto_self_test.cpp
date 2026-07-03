#include "session_crypto.h"

#include <array>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>

#include "audio_packet.h"

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}

performer_join_token::Claims make_claims(const std::string& nonce) {
    performer_join_token::Claims claims;
    claims.expires_at_ms = performer_join_token::now_ms() + 120000;
    claims.server_id = "local-dev";
    claims.room_id = "secure-room";
    claims.profile_id = "secure-user";
    claims.role = "performer";
    claims.nonce = nonce;
    return claims;
}

session_crypto::SessionKey validated_key_for(const std::string& token,
                                             const std::string& secret) {
    const auto validated = performer_join_token::validate_with_claims(
        token, secret, "local-dev", "secure-room", "secure-user", "performer");
    require(validated.ok, "token should validate");
    return session_crypto::derive_key_from_join_token(validated);
}

void test_key_derivation_is_stable() {
    const std::string secret = "test-secret";
    const auto claims = make_claims("nonce-a");
    const auto token = performer_join_token::create(claims, secret);

    const auto server_key = validated_key_for(token, secret);
    const auto client_key = session_crypto::derive_key_from_join_token_string(token);
    require(client_key.has_value(), "client should derive key from token string");
    require(server_key == *client_key, "client and server keys should match");

    const auto other_token = performer_join_token::create(make_claims("nonce-b"), secret);
    const auto other_key = validated_key_for(other_token, secret);
    require(server_key != other_key, "different token nonce should produce different key");
}

void test_seal_open_round_trip_and_tamper_rejection() {
    const std::string secret = "test-secret";
    const auto token = performer_join_token::create(make_claims("nonce-c"), secret);
    const auto key = validated_key_for(token, secret);

    const std::array<unsigned char, 4> payload{0x11, 0x22, 0x33, 0x44};
    const auto audio = audio_packet::create_audio_packet_v3(
        AudioCodec::Opus, 42, 48000, 120, 1, payload.data(),
        static_cast<uint16_t>(payload.size()), 123456789LL);
    require(audio != nullptr, "audio packet should build");

    std::array<unsigned char, 2048> sealed{};
    size_t sealed_bytes = 0;
    require(session_crypto::seal_audio_packet(key, 1, audio->data(), audio->size(),
                                              sealed.data(), sealed.size(), sealed_bytes),
            "seal should succeed");

    uint32_t magic = 0;
    std::memcpy(&magic, sealed.data(), sizeof(magic));
    require(magic == SECURE_AUDIO_MAGIC, "secure packet should use secure magic");

    std::array<unsigned char, 2048> opened{};
    size_t opened_bytes = 0;
    uint64_t nonce = 0;
    require(session_crypto::open_audio_packet(key, sealed.data(), sealed_bytes, nonce,
                                              opened.data(), opened.size(), opened_bytes),
            "open should succeed");
    require(nonce == 1, "nonce should round trip");
    require(opened_bytes == audio->size(), "opened size should match plaintext");
    require(std::equal(audio->begin(), audio->end(), opened.begin()),
            "opened plaintext should match");

    auto tampered_ciphertext = sealed;
    tampered_ciphertext[SECURE_PACKET_HEADER_BYTES] ^= 0x01;
    require(!session_crypto::open_audio_packet(key, tampered_ciphertext.data(), sealed_bytes,
                                               nonce, opened.data(), opened.size(),
                                               opened_bytes),
            "ciphertext tamper should fail");

    auto tampered_tag = sealed;
    tampered_tag[sealed_bytes - 1] ^= 0x01;
    require(!session_crypto::open_audio_packet(key, tampered_tag.data(), sealed_bytes,
                                               nonce, opened.data(), opened.size(),
                                               opened_bytes),
            "tag tamper should fail");
}

void test_replay_window() {
    session_crypto::ReplayWindow window;
    require(window.accept(1), "nonce 1 should be accepted");
    require(window.accept(2), "nonce 2 should be accepted");
    require(window.accept(70), "nonce 70 should be accepted");
    require(!window.accept(2), "duplicate nonce 2 should be rejected");
    require(!window.accept(1), "old nonce outside the window should be rejected");
    require(window.accept(69), "unseen nonce inside the window should be accepted");
    window.reset();
    require(window.accept(1), "reset window should accept nonce 1 again");
    require(!window.accept(0), "nonce 0 is reserved");
}

}  // namespace

int main() {
    test_key_derivation_is_stable();
    test_seal_open_round_trip_and_tamper_rejection();
    test_replay_window();
    std::cout << "session crypto self-test passed\n";
    return 0;
}
