# Phase 5 Track A Security Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Track A only: token nonce replay tracking, per-session authenticated encrypted audio packets, and server-side protocol-aware rate limiting.

**Architecture:** Keep the existing HMAC join-token contract and derive a 32-byte session key from the validated token's signed claims/signature. Signed joins enable a new secure-audio capability; clients wrap audio datagrams with a nonce, encrypted payload, and HMAC tag, and the server decrypts, replay-checks, stamps sender IDs, then re-encrypts per recipient. Insecure dev joins remain plaintext so existing local and Track D smokes keep working.

**Tech Stack:** C++23, standalone Asio UDP, PicoSHA2-backed HMAC helpers, existing packet builders/validators, CTest self-tests and in-process server smokes.

## Global Constraints

- Execute exactly one Phase 5 track in this session: Track A security only.
- Tracker rule: one branch per phase; this work runs on branch `phase5-track-a-security`.
- Tracker rule: one commit per task; build plus full `ctest` after every task.
- Tracker rule: line numbers in plan docs are anchored to HEAD `46f91a9`; match quoted code after edits shift lines.
- Do not start Track B, C, D, or E.
- Preserve authenticated audio cadence: valid signed low-profile audio at 120 frames/48 kHz is 400 packets/s and must not be throttled.
- Apply strict limits to unauthenticated, malformed, unknown-session, replay, and abusive traffic.
- Do not add a heavyweight crypto dependency in this track; reuse the existing `token_crypto`/PicoSHA2 dependency already linked by server/client/probes.

---

## Verified Current-HEAD Citations

- `server.cpp:370-373` from the audit is now `server.cpp:367-371`: audio is accepted when `client_manager_.exists(remote_endpoint_)` says the endpoint is registered.
- `client.cpp:1507-1520` from the audit is now `client.cpp:1589-1604`: the client accepts UDP only from the configured server endpoint.
- Audio packet payloads are plaintext: `audio_packet.h` writers copy raw payload bytes after V2/V3 headers; `server.cpp` forwards copied packets after sender-id stamping.
- Join token validation is HMAC-SHA256 with expiry and constant-time compare in `performer_join_token.h`; current API returns only `ValidationResult`, so server cannot currently record claims/nonce on successful validation.
- Server token nonce replay tracking does not exist in current `server.cpp`; grep only finds `unknown_endpoints_` replay-adjacent tracking.
- `allow_insecure_dev_joins` still defaults false in `server.cpp:70`; empty tokens are rejected unless insecure dev joins are enabled in `server.cpp:315-319`.
- Unknown audio gets `JOIN_REQUIRED` rate-limited to once per second in `server.cpp:516-519`, and unknown endpoint tracking is capped by `server_config::MAX_UNKNOWN_ENDPOINTS`.
- There is no joined-client packet rate limiter in `server.cpp`; valid joined endpoints can currently send audio at any packet rate.

## File Structure

- Modify `protocol.h`: add `SECURE_AUDIO_MAGIC`, secure-audio capability bit, and secure packet constants.
- Modify `performer_join_token.h`: expose validated claims/signature and deterministic session-key derivation from the existing HMAC token.
- Create `session_crypto.h`: owns session-key type, HMAC/SHA helpers, secure datagram seal/open, and replay window.
- Create `session_crypto_self_test.cpp`: unit coverage for key derivation, encryption/authentication, tamper rejection, and replay window behavior.
- Create `server_rate_limiter.h`: small token-bucket helper plus protocol-aware audio limits.
- Create `server_rate_limiter_self_test.cpp`: unit coverage proving 400 pps authenticated audio is allowed while floods are throttled.
- Modify `client_info.h` and `client_manager.h`: store per-client session security state, token nonce, replay window, and server-send nonce.
- Modify `join_reliability.h` and `client.cpp`: derive local session key from the join token, enable secure audio only after `JOIN_ACK` includes secure capability, wrap outbound audio, and unwrap inbound secure audio.
- Modify `server.cpp`: validate/consume token nonces, register session keys, decrypt/replay-check secure audio, reject plaintext audio for signed sessions, re-encrypt relayed audio per recipient, add security smoke, and rate-limit protocol classes.
- Modify `latency_probe.cpp`, `listener_audio_sender_probe.cpp`, and `room_routing_probe.cpp` only where they already support signed tokens and send audio, so signed-token probes keep working after secure audio is enabled.
- Modify `CMakeLists.txt`: add the two self-tests and the server security smoke.
- Modify `LOW_LATENCY_ACTION_PLAN.md`: mark Track A done with validation results after implementation.

---

### Task 1: Token Claims, Session Key Derivation, and Replay Store

**Files:**
- Modify: `protocol.h`
- Modify: `performer_join_token.h`
- Create: `session_crypto.h`
- Create: `session_crypto_self_test.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Produces: `performer_join_token::ValidatedToken { bool ok; std::string reason; Claims claims; std::string signature_hex; std::string signing_input; }`
- Produces: `performer_join_token::validate_with_claims(...) -> ValidatedToken`
- Produces: `session_crypto::SessionKey`, `session_crypto::derive_key_from_join_token(const performer_join_token::ValidatedToken&)`, `session_crypto::derive_key_from_join_token_string(const std::string&)`
- Produces: `session_crypto::ReplayWindow::accept(uint64_t nonce) -> bool`
- Consumed by: Tasks 2-4 server/client security wiring.

- [ ] **Step 1: Add protocol constants**

Add to `protocol.h`:

```cpp
constexpr uint32_t SECURE_AUDIO_MAGIC = 0x53454341;  // 'SECA'
constexpr uint32_t AUDIO_CAP_SECURE_AUDIO = 1U << 2;
constexpr uint32_t AUDIO_SUPPORTED_CAPABILITIES =
    AUDIO_CAP_REDUNDANCY | AUDIO_CAP_CAPTURE_TIMESTAMP | AUDIO_CAP_SECURE_AUDIO;
constexpr size_t SECURE_PACKET_NONCE_BYTES = sizeof(uint64_t);
constexpr size_t SECURE_PACKET_TAG_BYTES = 16;
constexpr size_t SECURE_PACKET_HEADER_BYTES =
    sizeof(MsgHdr) + SECURE_PACKET_NONCE_BYTES + sizeof(uint16_t) + sizeof(uint16_t);
```

- [ ] **Step 2: Add validated token API**

Extend `performer_join_token.h` without changing existing callers:

```cpp
struct ValidatedToken {
    bool ok = false;
    std::string reason;
    Claims claims;
    std::string signature_hex;
    std::string signing_input;
};

inline ValidatedToken validate_with_claims(...same parameters as validate...) {
    // Parse the v1 token, populate claims, enforce expiry/server/room/profile/role,
    // verify constant-time signature equality, and return claims plus parts[7].
}

inline ValidationResult validate(...same parameters...) {
    const auto detailed = validate_with_claims(...);
    return {detailed.ok, detailed.reason};
}
```

The implementation must reuse existing parsing/signing code and keep current rejection reason strings.

- [ ] **Step 3: Add `session_crypto.h`**

Create a header-only helper using the existing HMAC primitive:

```cpp
namespace session_crypto {
using SessionKey = std::array<unsigned char, 32>;

SessionKey derive_key_from_join_token(const performer_join_token::ValidatedToken& token);
std::optional<SessionKey> derive_key_from_join_token_string(const std::string& token);
std::string nonce_replay_key(const performer_join_token::Claims& claims);

bool seal_audio_packet(const SessionKey& key, uint64_t nonce,
                       const unsigned char* plaintext, size_t plaintext_len,
                       unsigned char* out, size_t out_capacity, size_t& bytes_written);
bool open_audio_packet(const SessionKey& key, const unsigned char* packet, size_t packet_len,
                       uint64_t& nonce, unsigned char* plaintext_out,
                       size_t plaintext_capacity, size_t& plaintext_len);

class ReplayWindow {
public:
    bool accept(uint64_t nonce);
    void reset();
};
}
```

`seal_audio_packet` writes `SECURE_AUDIO_MAGIC`, nonce, ciphertext length, reserved zero, ciphertext, and a 16-byte HMAC tag over the header+ciphertext. Encryption is XOR with HMAC-SHA256 keystream blocks keyed separately from the tag using labels `jam-audio-enc-v1` and `jam-audio-auth-v1`.

- [ ] **Step 4: Write self-test coverage**

Create `session_crypto_self_test.cpp` with checks for:

```cpp
// same token -> same key
// different nonce -> different key
// seal/open round trip preserves an AUDIO_V3 packet
// one-byte ciphertext tamper fails
// one-byte tag tamper fails
// replay window accepts 1, 2, 70; rejects duplicate 2; rejects old nonce after window advances
```

- [ ] **Step 5: Register and run focused tests**

Add to `CMakeLists.txt`:

```cmake
add_executable(session_crypto_self_test session_crypto_self_test.cpp)
target_link_libraries(session_crypto_self_test PRIVATE token_crypto)
jam_add_executable_test(session_crypto_self_test)
```

Run:

```powershell
cmake --build build --config Release --parallel 8
ctest --test-dir build -C Release --output-on-failure -R "session_crypto_self_test|audio_packet_self_test|join_reliability_self_test"
```

Expected: build succeeds and the focused tests pass.

- [ ] **Step 6: Run full suite and commit**

Run:

```powershell
ctest --test-dir build -C Release --output-on-failure
git add protocol.h performer_join_token.h session_crypto.h session_crypto_self_test.cpp CMakeLists.txt
git commit -m "feat: derive secure session keys from join tokens"
```

Expected: full suite passes before commit.

---

### Task 2: Protocol-Aware Server Rate Limiting

**Files:**
- Create: `server_rate_limiter.h`
- Create: `server_rate_limiter_self_test.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `audio_packet::ParsedAudioHeader`
- Produces: `server_rate_limiter::TokenBucket`
- Produces: `server_rate_limiter::ProtocolRateLimiter::allow_authenticated_audio(...)`
- Produces: `allow_strict(endpoint, now)`, `allow_control(endpoint, now)`, and `allow_unknown(endpoint, now)`
- Consumed by: Task 4 server receive paths.

- [ ] **Step 1: Add rate limiter helper**

Create `server_rate_limiter.h` with a steady-clock token bucket. Required limits:

```cpp
// Unknown/malformed/replay/auth-failure strict path:
// 20 packets/s, burst 20.
// Control path for joined endpoints:
// 120 packets/s, burst 240.
// Authenticated audio:
// max(600 packets/s, ceil(sample_rate / frame_count) * 2) with a two-second burst.
```

The authenticated audio limit must treat invalid or zero frame count as strict traffic.

- [ ] **Step 2: Add self-tests**

Create `server_rate_limiter_self_test.cpp` covering:

```cpp
// 800 packets over two seconds for 120-frame/48 kHz audio are allowed.
// A same-timestamp 2000 packet flood is throttled.
// Unknown strict traffic allows 20 burst packets and rejects packet 21.
// Control traffic allows 240 burst packets and rejects packet 241 at the same timestamp.
```

- [ ] **Step 3: Register and run tests**

Add to `CMakeLists.txt`:

```cmake
add_executable(server_rate_limiter_self_test server_rate_limiter_self_test.cpp)
jam_add_executable_test(server_rate_limiter_self_test)
```

Run:

```powershell
cmake --build build --config Release --parallel 8
ctest --test-dir build -C Release --output-on-failure -R "server_rate_limiter_self_test"
ctest --test-dir build -C Release --output-on-failure
git add server_rate_limiter.h server_rate_limiter_self_test.cpp CMakeLists.txt
git commit -m "feat: add protocol-aware server packet limits"
```

Expected: full suite passes before commit.

---

### Task 3: Store Server Session Security State

**Files:**
- Modify: `client_info.h`
- Modify: `client_manager.h`
- Modify: `client_manager_self_test.cpp`

**Interfaces:**
- Consumes: `session_crypto::SessionKey`
- Produces: `ClientInfo::has_session_key`, `ClientInfo::session_key`, `ClientInfo::token_nonce_key`, `ClientInfo::audio_replay_window`, `ClientInfo::secure_send_nonce`
- Produces: `ClientManager::get_security(endpoint) -> optional<ClientSecuritySnapshot>`
- Produces: `ClientManager::next_secure_send_nonce(endpoint) -> uint64_t`
- Produces: `ClientManager::accept_audio_nonce(endpoint, nonce) -> bool`
- Consumed by: Task 4 server secure receive/relay.

- [ ] **Step 1: Extend `ClientInfo`**

Add fields:

```cpp
bool has_session_key = false;
session_crypto::SessionKey session_key{};
std::string token_nonce_key;
session_crypto::ReplayWindow audio_replay_window;
uint64_t secure_send_nonce = 1;
```

- [ ] **Step 2: Extend registration**

Change `ClientManager::register_client` to accept optional security state:

```cpp
RegistrationResult register_client(..., uint32_t capabilities = 0,
                                   std::optional<ClientSecurityConfig> security = std::nullopt);
```

Same-endpoint retries must preserve the existing client ID and refresh the security fields.

- [ ] **Step 3: Add security accessors**

Add methods for server code:

```cpp
std::optional<ClientSecuritySnapshot> get_security(const endpoint& ep) const;
bool has_session_key(const endpoint& ep) const;
bool accept_audio_nonce(const endpoint& ep, uint64_t nonce);
uint64_t next_secure_send_nonce(const endpoint& ep);
std::optional<std::string> token_nonce_key_for(const endpoint& ep) const;
```

- [ ] **Step 4: Extend self-test**

Update `client_manager_self_test.cpp` to register one secure client, assert the key is retrievable, assert nonce `1` is accepted once and rejected on replay, and assert `next_secure_send_nonce` increments from `1` to `2`.

- [ ] **Step 5: Run tests and commit**

Run:

```powershell
cmake --build build --config Release --parallel 8
ctest --test-dir build -C Release --output-on-failure -R "client_manager_self_test|session_crypto_self_test"
ctest --test-dir build -C Release --output-on-failure
git add client_info.h client_manager.h client_manager_self_test.cpp
git commit -m "feat: store per-client secure session state"
```

Expected: full suite passes before commit.

---

### Task 4: Server Token Nonce Replay, Secure Audio Relay, and Rate Limits

**Files:**
- Modify: `server.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `performer_join_token::validate_with_claims`
- Consumes: `session_crypto::seal_audio_packet`, `open_audio_packet`, `ReplayWindow`
- Consumes: `server_rate_limiter::ProtocolRateLimiter`
- Produces: `server --security-smoke`
- Produces: signed joins with secure-audio `JOIN_ACK` capability and single-token nonce ownership.

- [ ] **Step 1: Add token nonce ownership map**

In `Server`, add:

```cpp
struct UsedTokenNonce {
    udp::endpoint endpoint;
    int64_t expires_at_ms = 0;
    std::string room_id;
    std::string profile_id;
    std::string role;
};
std::unordered_map<std::string, UsedTokenNonce> used_token_nonces_;
```

On valid signed `JOIN`, clean expired entries and reject the same nonce key if owned by another endpoint. Allow same-endpoint retries so lost `JOIN_ACK` does not strand a client.

- [ ] **Step 2: Register secure sessions**

In `handle_join`, call `validate_with_claims`; derive `session_crypto::SessionKey` from the validated token; pass `ClientSecurityConfig` to `ClientManager::register_client`; send `JOIN_ACK` with `AUDIO_CAP_SECURE_AUDIO` only when the endpoint has a session key. In insecure-dev joins, omit the secure cap.

- [ ] **Step 3: Handle secure audio datagrams**

Extend `on_receive` to dispatch `SECURE_AUDIO_MAGIC` to `handle_secure_audio_message`. That function must:

```cpp
// reject unknown endpoints through strict limiter
// reject endpoints with no session key as unknown-session
// open/decrypt the packet
// reject auth failures through strict limiter
// reject replayed nonces through strict limiter
// validate the decrypted inner audio/redundant packet
// apply authenticated-audio rate limiting based on parsed frame_count
// forward through the same room relay code
```

If a signed endpoint sends plaintext audio, drop it as unauthenticated.

- [ ] **Step 4: Re-encrypt per recipient**

When forwarding to a recipient with a session key, create the capability-adjusted plaintext packet as today, then wrap it with `session_crypto::seal_audio_packet` using `ClientManager::next_secure_send_nonce(endpoint)`. In insecure dev sessions without a key, preserve existing plaintext forwarding.

- [ ] **Step 5: Apply protocol-aware rate limits**

Add `server_rate_limiter::ProtocolRateLimiter rate_limiter_;` and use:

```cpp
allow_unknown(remote_endpoint_, now) for unknown endpoints before JOIN_REQUIRED/log work
allow_strict(remote_endpoint_, now) for malformed, auth-failure, unknown-session, replay
allow_control(remote_endpoint_, now) for joined PING/ALIVE/METRONOME/LEAVE bursts
allow_authenticated_audio(remote_endpoint_, parsed_frame_count, sample_rate, now) for valid audio
```

Do not rate-limit valid 120-frame authenticated audio at 400 pps.

- [ ] **Step 6: Add in-process security smoke**

Add `run_security_smoke()` to `server.cpp`, registered as `server --security-smoke`, with this behavior:

```cpp
// Start server with --join-secret equivalent.
// Create sender and receiver tokens with unique nonces.
// Join sender and receiver; assert both receive JOIN_ACK with AUDIO_CAP_SECURE_AUDIO.
// Send plaintext V2 audio from signed sender; assert receiver gets no audio.
// Seal V2 audio with sender key and nonce 1; assert receiver gets SECURE_AUDIO_MAGIC.
// Open receiver packet with receiver key; assert inner audio is valid and sender_id is stamped.
// Replay nonce 1 from sender; assert receiver gets no second forwarded audio.
// Attempt JOIN from a different endpoint with sender's already-used token; assert no JOIN_ACK.
```

- [ ] **Step 7: Register smoke, run full suite, commit**

Add to `CMakeLists.txt`:

```cmake
add_test(NAME server_security_smoke
         COMMAND $<TARGET_FILE:server> --security-smoke)
```

Run:

```powershell
cmake --build build --config Release --parallel 8
ctest --test-dir build -C Release --output-on-failure -R "server_security_smoke|server_redundancy_relay_smoke|server_timestamp_relay_smoke|server_rate_limiter_self_test"
ctest --test-dir build -C Release --output-on-failure
git add server.cpp CMakeLists.txt
git commit -m "feat: enforce secure audio on signed server sessions"
```

Expected: existing insecure-dev server smokes still pass, and the new signed security smoke passes.

---

### Task 5: Client and Probe Secure Audio Wiring

**Files:**
- Modify: `join_reliability.h`
- Modify: `join_reliability_self_test.cpp`
- Modify: `client.cpp`
- Modify: `latency_probe.cpp`
- Modify: `listener_audio_sender_probe.cpp`
- Modify: `room_routing_probe.cpp`

**Interfaces:**
- Consumes: `session_crypto::derive_key_from_join_token_string`
- Produces: client outbound audio wrapping after secure `JOIN_ACK`
- Produces: client inbound secure audio unwrapping from server
- Produces: signed-token probe secure send/receive support for audio probes.

- [ ] **Step 1: Track secure capability in join state**

Keep `join_reliability::State` capability storage, but update the self-test to assert `AUDIO_CAP_SECURE_AUDIO` can be observed after `mark_join_ack`.

- [ ] **Step 2: Derive local client key from join token**

In `client.cpp`, add fields:

```cpp
std::optional<session_crypto::SessionKey> session_key_;
session_crypto::ReplayWindow server_audio_replay_window_;
std::atomic<uint64_t> secure_audio_send_nonce_{1};
```

`send_join()` derives `session_key_` from `performer_join_options_.join_token` when nonempty and resets nonce/replay state.

- [ ] **Step 3: Wrap outbound audio**

In `send_audio_packet_sync`, if `join_state_.server_supports(AUDIO_CAP_SECURE_AUDIO)` and `session_key_` exists, seal the audio/redundant datagram before `socket_.send_to`. If sealing fails, increment the existing send drop counter and do not send plaintext fallback.

- [ ] **Step 4: Unwrap inbound secure audio**

In client receive dispatch, recognize `SECURE_AUDIO_MAGIC`, open it with `session_key_`, reject auth failure/replay, and pass the decrypted inner packet to existing audio handling. Plain V2/V3/redundant receive remains available for insecure-dev joins and legacy servers.

- [ ] **Step 5: Update signed-token probes**

For `latency_probe.cpp`, `listener_audio_sender_probe.cpp`, and `room_routing_probe.cpp`, derive a session key whenever a join token is available, detect secure `JOIN_ACK`, seal outbound audio, and open inbound secure audio before existing parsing. Keep plaintext when no token is present or the server ACK omits secure capability.

- [ ] **Step 6: Run smoke coverage and commit**

Run:

```powershell
cmake --build build --config Release --parallel 8
ctest --test-dir build -C Release --output-on-failure -R "join_reliability_self_test|client_udp_audio_sync_send_smoke|client_audio_v3_receive_smoke|latency_probe_v3_receive_smoke|server_security_smoke"
ctest --test-dir build -C Release --output-on-failure
git add join_reliability.h join_reliability_self_test.cpp client.cpp latency_probe.cpp listener_audio_sender_probe.cpp room_routing_probe.cpp
git commit -m "feat: secure client audio packets for signed sessions"
```

Expected: full suite passes before commit.

---

### Task 6: Track A Final Validation and Tracker Update

**Files:**
- Modify: `LOW_LATENCY_ACTION_PLAN.md`
- Create during execution: `validation_logs/phase5-track-a/`

**Interfaces:**
- Consumes: completed Track A commits.
- Produces: tracker update with exact validation commands/results.

- [ ] **Step 1: Run release build and full CTest with logs**

Run:

```powershell
New-Item -ItemType Directory -Force validation_logs/phase5-track-a
cmake --build build --config Release --parallel 8 *> validation_logs/phase5-track-a/release-build.log
ctest --test-dir build -C Release --output-on-failure *> validation_logs/phase5-track-a/ctest-release.log
```

Expected: build succeeds and full suite passes.

- [ ] **Step 2: Run security-specific acceptance commands**

Run:

```powershell
build/Release/server.exe --security-smoke *> validation_logs/phase5-track-a/server-security-smoke.log
build/Release/session_crypto_self_test.exe *> validation_logs/phase5-track-a/session-crypto-self-test.log
build/Release/server_rate_limiter_self_test.exe *> validation_logs/phase5-track-a/server-rate-limiter-self-test.log
```

Expected: all commands exit 0.

- [ ] **Step 3: Update tracker**

In `LOW_LATENCY_ACTION_PLAN.md`, change Phase 5 status to say Track A and Track D are done, Tracks B/C/E are not started. Add a Track A validation snapshot with:

```text
Release build command logged in validation_logs/phase5-track-a/release-build.log.
Full test command logged in validation_logs/phase5-track-a/ctest-release.log.
Security smoke logged in validation_logs/phase5-track-a/server-security-smoke.log.
Session crypto self-test logged in validation_logs/phase5-track-a/session-crypto-self-test.log.
Rate limiter self-test logged in validation_logs/phase5-track-a/server-rate-limiter-self-test.log.
```

- [ ] **Step 4: Commit tracker update**

Run:

```powershell
git add LOW_LATENCY_ACTION_PLAN.md
git commit -m "docs: mark phase 5 track a security complete"
```

Expected: tracker records only Track A changes; no Track B/C/E work is claimed.

---

## Acceptance Checklist

- Signed-token joins derive a session key on both client and server.
- Server rejects replayed join token nonces from a different endpoint.
- Signed-session plaintext audio is not relayed.
- Secure audio packets authenticate, decrypt, replay-check, and relay.
- Relayed secure audio is re-encrypted per recipient.
- Replayed secure audio packets are dropped.
- Valid authenticated 120-frame audio at 400 pps is not throttled.
- Unknown/malformed/unknown-session/replay/abusive traffic is throttled or dropped under strict limits.
- Existing insecure-dev CTest smokes continue to pass.
- Phase 5 tracker is updated for Track A only.

## Self-Review Notes

- Spec coverage: all Track A items are mapped to tasks; no Track B/C/D/E work is included.
- Placeholder scan: no task contains TBD/TODO/implement-later wording.
- Type consistency: `SessionKey`, `ReplayWindow`, `ClientSecurityConfig`, and secure capability names are introduced before they are consumed.
