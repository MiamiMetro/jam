# Phase 3 E2E Latency Measurement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add negotiated one-way capture-to-playout latency measurement to real audio sessions, surface it in the Path panel and baseline snapshots, and guard it with a loopback ctest smoke.

**Architecture:** Add an audio V3 packet header beside V2, gated by a new `AUDIO_CAP_CAPTURE_TIMESTAMP` capability bit. Senders stamp capture time in the server-clock domain using `server_clock_offset_ns_`; receivers convert their current playout time to the same domain and observe per-participant latency when audio frames enter the output mix. Legacy clients keep V2 behavior, and the server only performs capability-based wire-shape fallback without interpreting timestamp values.

**Tech Stack:** C++23, ASIO UDP, JUCE audio callback, Opus, moodycamel queues, CMake/ctest, Node.js smoke harnesses.

## Global Constraints

- Current planning base: `main` at `ad2d80b`.
- Tracker: `LOW_LATENCY_ACTION_PLAN.md` is authoritative for phase order and acceptance.
- Phase 3 execution rules from the tracker: one branch per phase, one commit per task, Release build plus full `ctest` after every task, and mark the phase done only after acceptance command output is recorded.
- Wire-format decision: capture timestamps are negotiated via a new capability bit. `AUDIO_CAP_REDUNDANCY` in `protocol.h:43` is the precedent.
- Compatibility decision: old clients must continue to send and receive V2 audio unchanged. New clients must accept V2 and V3. The server must not compute latency or interpret `capture_server_time_ns`; it may only strip the timestamp extension for receivers that did not negotiate `AUDIO_CAP_CAPTURE_TIMESTAMP`.
- Clock-domain decision: sender stamps `capture_server_time_ns = capture_steady_ns + server_clock_offset_ns_`; receiver measures with `playout_server_time_ns = playout_steady_ns + server_clock_offset_ns_`. RTT asymmetry is accepted as the accuracy bound.
- Real-time callback rule from Phases 1-2: no `Log::` calls, no blocking locks, no heap allocation, and no freeing in the callback path.
- Baseline naming: record the first accepted loopback result as the Phase 3 baseline in `LOW_LATENCY_ACTION_PLAN.md`; Phase 4 compares its TX-path changes against that number.

## Current HEAD Citation Check

Verified against `main` at `ad2d80b` before writing this plan:

- `protocol.h:43` still defines `AUDIO_CAP_REDUNDANCY = 1U << 0`.
- `protocol.h:55-60` still defines `SyncHdr`.
- `protocol.h:125-134` still defines `AudioHdrV2` with sender id, sequence, sample rate, frame count, payload bytes, channels, codec, and payload buffer, but no capture timestamp.
- `LOW_LATENCY_ACTION_PLAN.md:97` cites `client.cpp:3799-3821` for `server_clock_offset_ns_`; that current range is ping-path feedback. The offset update is currently in `handle_ping_message()` at `client.cpp:3827-3856`, and the atomic is declared at `client.cpp:5097`.
- `LOW_LATENCY_AUDIT.md:86` cites receiver packet age at `client.cpp:3930`; that current line is decoder config validation. The behavior still exists: arrival time is assigned with `packet.timestamp = std::chrono::steady_clock::now()` at `client.cpp:3965`, and dequeue age is measured with `now - opus_packet.timestamp` at `client.cpp:4430-4467`.
- The existing server-clock offset is consumed by metronome scheduling at `client.cpp:4069-4115`.
- `latency_probe.cpp` still measures a synthetic sender/receiver/playout loop with impulse detection, not the real `Client::audio_callback`.
- `JuceAudioBackend::get_latency_info()` still reports device buffer and input/output latency at `juce_audio_backend.cpp:237-265`; it does not compose capture-to-playout session latency.

---

## File Structure

- Modify `protocol.h`: add `AUDIO_V3_MAGIC`, `AUDIO_CAP_CAPTURE_TIMESTAMP`, supported capability mask, `AudioHdrV3`, and a capability-carrying participant-info control struct.
- Modify `audio_packet.h`: add V3 header helpers, common audio header parsing, V2/V3 validation, V3 creation, V3-to-V2 stripping, and redundant packet support for mixed V2/V3 children.
- Modify `packet_builder.h`: replace hard-coded V2 payload offsets with common V2/V3 helpers.
- Modify `audio_packet_self_test.cpp`: cover V3 round-trip, V3 validation, V3-to-V2 fallback, and redundant V3 children.
- Modify `server.cpp`: negotiate the new capability, advertise capabilities in JOIN_ACK and participant metadata, validate V2/V3 packets, and perform legacy receiver fallback.
- Modify `client_manager.h` only if a helper returning endpoint plus capabilities makes server forwarding code simpler. Keep the existing `client_supports()` path if that is enough.
- Modify `join_reliability_self_test.cpp` and `latency_probe.cpp`: update capability expectations and advertise timestamp support in probes.
- Modify JS smoke helpers under `tools/`: update hard-coded capability constants where they construct JOIN packets.
- Modify `participant_info.h`: add packet timestamp fields, per-participant E2E latency atomics, fixed-size Opus PCM timestamp chunk tracking, and `ParticipantInfo` fields for UI snapshots.
- Modify `participant_manager.h`: publish the new E2E latency fields in `make_info()`.
- Modify `client.cpp`: stamp outgoing packets, parse incoming V3, observe capture-to-playout in the callback, surface the metric in Path diagnostics and baseline logs, and add a small client metric smoke.
- Modify `latency_probe.cpp`: send/receive V3 in the headless loopback probe and assert steady-state one-way latency against the budget.
- Create `tools/e2e-latency-smoke.mjs`: spawn a local server, run `latency_probe`, and expose a ctest-friendly command.
- Modify `CMakeLists.txt`: register new client/server/probe smokes and the loopback E2E latency smoke.
- Modify `LOW_LATENCY_ACTION_PLAN.md` only after implementation and verification: set Phase 3 status and record the accepted loopback baseline.

---

### Task 1: Protocol And Packet Helpers

**Files:**
- Modify: `protocol.h`
- Modify: `audio_packet.h`
- Modify: `packet_builder.h`
- Modify: `audio_packet_self_test.cpp`

**Interfaces:**
- Consumes: existing `AudioHdrV2`, `AUDIO_CAP_REDUNDANCY`, `audio_packet::v2_header_size()`, `audio_packet::create_audio_packet_v2()`, and redundant packet helpers.
- Produces: `AUDIO_CAP_CAPTURE_TIMESTAMP`, `AUDIO_SUPPORTED_CAPABILITIES`, `AudioHdrV3`, `ParticipantInfoCapsHdr`, `audio_packet::v3_header_size()`, `audio_packet::parse_audio_header()`, `audio_packet::validate_audio_packet_bytes()`, `audio_packet::audio_payload()`, `audio_packet::create_audio_packet_v3()`, `audio_packet::strip_audio_v3_timestamp()`, and redundant helpers that accept V2 or V3 children.

- [ ] **Step 1: Write the failing V3 packet tests**

Add these test helpers and calls to `audio_packet_self_test.cpp`:

```cpp
bool validates_v3(AudioCodec codec, uint32_t sample_rate, uint16_t frame_count,
                  uint8_t channels, uint16_t payload_bytes, int64_t capture_ns,
                  std::string* reason = nullptr) {
    std::vector<unsigned char> payload(std::max<size_t>(payload_bytes, 1), 0xB6);
    auto packet = audio_packet::create_audio_packet_v3(
        codec, 7, sample_rate, frame_count, channels, payload.data(), payload_bytes,
        capture_ns);
    return audio_packet::validate_audio_packet_bytes(packet->data(), packet->size(),
                                                     reason);
}

void test_v3_timestamp_packet_round_trip() {
    std::vector<unsigned char> payload{0x10, 0x20, 0x30, 0x40};
    auto packet = audio_packet::create_audio_packet_v3(
        AudioCodec::Opus, 42, 48000, 120, 1, payload.data(),
        static_cast<uint16_t>(payload.size()), 123456789LL);

    require(packet != nullptr, "v3 packet should build");
    require(packet->size() == audio_packet::v3_header_size() + payload.size(),
            "v3 packet size should be header plus payload");
    require(audio_packet::validate_audio_packet_bytes(packet->data(), packet->size()),
            "v3 packet should validate");

    const auto parsed = audio_packet::parse_audio_header(packet->data(), packet->size());
    require(parsed.valid, "v3 parsed header should be valid");
    require(parsed.magic == AUDIO_V3_MAGIC, "v3 parsed magic should match");
    require(parsed.capture_timestamp_valid, "v3 capture timestamp should be valid");
    require(parsed.capture_server_time_ns == 123456789LL,
            "v3 capture timestamp should round trip");
    require(parsed.sequence == 42, "v3 sequence should round trip");
    require(parsed.frame_count == 120, "v3 frame count should round trip");
    require(std::equal(payload.begin(), payload.end(),
                       audio_packet::audio_payload(packet->data(), packet->size())),
            "v3 payload pointer should skip timestamp header");
}

void test_v3_validation_reuses_v2_shape_rules() {
    std::string reason;
    require(validates_v3(AudioCodec::Opus, 48000, 120, 1, 8, 55),
            "valid v3 opus packet should validate");
    require(!validates_v3(AudioCodec::Opus, 44100, 120, 1, 8, 55, &reason),
            "v3 unsupported sample rate should fail");
    require(reason == "unsupported audio shape",
            "v3 unsupported sample rate reason should match v2 validation");
}

void test_v3_timestamp_packet_strips_to_v2() {
    std::vector<unsigned char> payload{0x21, 0x22, 0x23};
    auto v3 = audio_packet::create_audio_packet_v3(
        AudioCodec::Opus, 9, 48000, 120, 1, payload.data(),
        static_cast<uint16_t>(payload.size()), 777777LL);
    auto v2 = audio_packet::strip_audio_v3_timestamp(v3->data(), v3->size());

    require(v2 != nullptr, "v3 packet should strip to v2");
    require(audio_packet::validate_audio_packet_v2_bytes(v2->data(), v2->size()),
            "stripped packet should validate as v2");
    require(v2->size() == audio_packet::v2_header_size() + payload.size(),
            "stripped v2 packet should remove timestamp bytes");

    AudioHdrV2 hdr{};
    std::memcpy(&hdr, v2->data(), audio_packet::v2_header_size());
    require(hdr.magic == AUDIO_V2_MAGIC, "stripped packet should use v2 magic");
    require(hdr.sequence == 9, "stripped packet should preserve sequence");
    require(hdr.payload_bytes == payload.size(), "stripped packet should preserve payload size");
}

void test_redundant_audio_packet_accepts_v3_children() {
    std::vector<unsigned char> current_payload(8, 0x31);
    std::vector<unsigned char> previous_payload(8, 0x32);
    auto current = audio_packet::create_audio_packet_v3(
        AudioCodec::Opus, 20, 48000, 120, 1, current_payload.data(),
        static_cast<uint16_t>(current_payload.size()), 2000000LL);
    auto previous = audio_packet::create_audio_packet_v3(
        AudioCodec::Opus, 19, 48000, 120, 1, previous_payload.data(),
        static_cast<uint16_t>(previous_payload.size()), 1000000LL);

    auto redundant = audio_packet::create_redundant_audio_packet(
        {current.get(), previous.get()});
    require(redundant != nullptr, "redundant packet should build from v3 children");
    require(audio_packet::validate_redundant_audio_packet_bytes(redundant->data(),
                                                                redundant->size()),
            "redundant v3 packet should validate");

    int child_count = 0;
    audio_packet::for_each_redundant_audio_child(
        redundant->data(), redundant->size(),
        [&](const unsigned char* child, size_t child_len, uint8_t index) {
            const auto parsed = audio_packet::parse_audio_header(child, child_len);
            require(parsed.valid, "redundant v3 child should parse");
            require(parsed.magic == AUDIO_V3_MAGIC, "redundant child should keep v3 magic");
            require(parsed.capture_timestamp_valid, "redundant child should keep capture timestamp");
            require(parsed.sequence == (index == 0 ? 20U : 19U),
                    "redundant child sequence should preserve order");
            ++child_count;
        });
    require(child_count == 2, "redundant v3 packet should expose two children");
}
```

Call the new tests before the final success print:

```cpp
    test_v3_timestamp_packet_round_trip();
    test_v3_validation_reuses_v2_shape_rules();
    test_v3_timestamp_packet_strips_to_v2();
    test_redundant_audio_packet_accepts_v3_children();
```

- [ ] **Step 2: Run the packet tests to verify they fail**

Run:

```bash
cmake --build build --config Release --target audio_packet_self_test
ctest --test-dir build -C Release -R audio_packet_self_test --output-on-failure
```

Expected: compile failure naming missing `AudioHdrV3`, `audio_packet::create_audio_packet_v3`, `audio_packet::parse_audio_header`, or `audio_packet::strip_audio_v3_timestamp`.

- [ ] **Step 3: Add protocol constants and V3 structs**

In `protocol.h`, replace the packet magic and capability block with:

```cpp
// Packet identification magic numbers
constexpr uint32_t PING_MAGIC  = 0x50494E47;  // 'PING'
constexpr uint32_t CTRL_MAGIC  = 0x4354524C;  // 'CTRL'
constexpr uint32_t AUDIO_MAGIC = 0x41554449;  // 'AUDI'
constexpr uint32_t AUDIO_V2_MAGIC = 0x41553249;  // 'AU2I'
constexpr uint32_t AUDIO_V3_MAGIC = 0x41553349;  // 'AU3I'
constexpr uint32_t AUDIO_REDUNDANT_MAGIC = 0x41555244;  // 'AURD'
```

Replace the capability block with:

```cpp
// Endpoint capabilities negotiated in extended JOIN/JOIN_ACK packets.
constexpr uint32_t AUDIO_CAP_REDUNDANCY = 1U << 0;
constexpr uint32_t AUDIO_CAP_CAPTURE_TIMESTAMP = 1U << 1;
constexpr uint32_t AUDIO_SUPPORTED_CAPABILITIES =
    AUDIO_CAP_REDUNDANCY | AUDIO_CAP_CAPTURE_TIMESTAMP;
```

Add this after `ParticipantInfoHdr`:

```cpp
struct ParticipantInfoCapsHdr : ParticipantInfoHdr {
    uint32_t capabilities = 0;
};
```

Add this after `AudioHdrV2`:

```cpp
struct AudioHdrV3 : MsgHdr {
    uint32_t              sender_id;      // Server-owned sender identifier
    uint32_t              sequence;       // Sender-local packet sequence
    uint32_t              sample_rate;    // Packet sample rate
    uint16_t              frame_count;    // Frames per packet
    uint16_t              payload_bytes;  // Audio payload bytes
    uint8_t               channels;       // Channel count in payload
    AudioCodec            codec;          // Payload codec
    int64_t               capture_server_time_ns; // Capture time in server-clock domain
    Bytes<AUDIO_BUF_SIZE> buf;
};
```

- [ ] **Step 4: Add common V2/V3 packet helpers**

In `audio_packet.h`, add this near the existing header-size helpers:

```cpp
inline constexpr size_t v3_header_size() {
    return sizeof(AudioHdrV3) - AUDIO_BUF_SIZE;
}

struct ParsedAudioHeader {
    bool valid = false;
    uint32_t magic = 0;
    uint32_t sender_id = 0;
    uint32_t sequence = 0;
    uint32_t sample_rate = 0;
    uint16_t frame_count = 0;
    uint16_t payload_bytes = 0;
    uint8_t channels = 0;
    AudioCodec codec = AudioCodec::Opus;
    bool capture_timestamp_valid = false;
    int64_t capture_server_time_ns = 0;
    size_t header_size = 0;
};

inline ParsedAudioHeader parse_audio_header(const unsigned char* data, size_t len) {
    ParsedAudioHeader parsed{};
    if (data == nullptr || len < sizeof(MsgHdr)) {
        return parsed;
    }

    MsgHdr msg{};
    std::memcpy(&msg, data, sizeof(MsgHdr));
    if (msg.magic == AUDIO_V2_MAGIC) {
        if (len < v2_header_size()) {
            return parsed;
        }
        AudioHdrV2 hdr{};
        std::memcpy(&hdr, data, v2_header_size());
        parsed.valid = true;
        parsed.magic = hdr.magic;
        parsed.sender_id = hdr.sender_id;
        parsed.sequence = hdr.sequence;
        parsed.sample_rate = hdr.sample_rate;
        parsed.frame_count = hdr.frame_count;
        parsed.payload_bytes = hdr.payload_bytes;
        parsed.channels = hdr.channels;
        parsed.codec = hdr.codec;
        parsed.header_size = v2_header_size();
        return parsed;
    }

    if (msg.magic == AUDIO_V3_MAGIC) {
        if (len < v3_header_size()) {
            return parsed;
        }
        AudioHdrV3 hdr{};
        std::memcpy(&hdr, data, v3_header_size());
        parsed.valid = true;
        parsed.magic = hdr.magic;
        parsed.sender_id = hdr.sender_id;
        parsed.sequence = hdr.sequence;
        parsed.sample_rate = hdr.sample_rate;
        parsed.frame_count = hdr.frame_count;
        parsed.payload_bytes = hdr.payload_bytes;
        parsed.channels = hdr.channels;
        parsed.codec = hdr.codec;
        parsed.capture_timestamp_valid = hdr.capture_server_time_ns > 0;
        parsed.capture_server_time_ns = hdr.capture_server_time_ns;
        parsed.header_size = v3_header_size();
        return parsed;
    }

    return parsed;
}
```

Add validation wrappers:

```cpp
inline bool validate_audio_packet_shape(const ParsedAudioHeader& hdr,
                                        std::string* reason = nullptr) {
    AudioHdrV2 v2{};
    v2.magic = AUDIO_V2_MAGIC;
    v2.sender_id = hdr.sender_id;
    v2.sequence = hdr.sequence;
    v2.sample_rate = hdr.sample_rate;
    v2.frame_count = hdr.frame_count;
    v2.payload_bytes = hdr.payload_bytes;
    v2.channels = hdr.channels;
    v2.codec = hdr.codec;
    return validate_audio_packet_v2_shape(v2, reason);
}

inline bool validate_audio_packet_bytes(const unsigned char* data, size_t len,
                                        std::string* reason = nullptr) {
    const auto hdr = parse_audio_header(data, len);
    if (!hdr.valid) {
        if (reason != nullptr) {
            *reason = "short header";
        }
        return false;
    }
    if (hdr.payload_bytes > AUDIO_BUF_SIZE) {
        if (reason != nullptr) {
            *reason = "payload too large";
        }
        return false;
    }

    const size_t expected = hdr.header_size + hdr.payload_bytes;
    if (len != expected) {
        if (reason != nullptr) {
            *reason = "length mismatch";
        }
        return false;
    }
    return validate_audio_packet_shape(hdr, reason);
}

inline const unsigned char* audio_payload(const unsigned char* data, size_t len) {
    const auto hdr = parse_audio_header(data, len);
    return hdr.valid ? data + hdr.header_size : nullptr;
}
```

Keep `validate_audio_packet_v2_bytes()` for existing callers, but make redundant helpers use `validate_audio_packet_bytes()` and `parse_audio_header()` so both V2 and V3 children work.

- [ ] **Step 5: Add V3 creation and stripping helpers**

Add this after `create_audio_packet_v2()` in `audio_packet.h`:

```cpp
inline std::shared_ptr<std::vector<unsigned char>> create_audio_packet_v3(
    AudioCodec codec, uint32_t sequence, uint32_t sample_rate, uint16_t frame_count,
    uint8_t channels, const unsigned char* payload, uint16_t payload_bytes,
    int64_t capture_server_time_ns) {
    auto packet = std::make_shared<std::vector<unsigned char>>();
    packet->resize(v3_header_size() + payload_bytes);

    AudioHdrV3 hdr{};
    hdr.magic = AUDIO_V3_MAGIC;
    hdr.sender_id = 0;
    hdr.sequence = sequence;
    hdr.sample_rate = sample_rate;
    hdr.frame_count = frame_count;
    hdr.payload_bytes = payload_bytes;
    hdr.channels = channels;
    hdr.codec = codec;
    hdr.capture_server_time_ns = capture_server_time_ns;

    std::memcpy(packet->data(), &hdr, v3_header_size());
    if (payload_bytes > 0) {
        std::memcpy(packet->data() + v3_header_size(), payload, payload_bytes);
    }

    return packet;
}

inline std::shared_ptr<std::vector<unsigned char>> strip_audio_v3_timestamp(
    const unsigned char* data, size_t len) {
    const auto parsed = parse_audio_header(data, len);
    if (!parsed.valid || parsed.magic != AUDIO_V3_MAGIC ||
        len != parsed.header_size + parsed.payload_bytes) {
        return nullptr;
    }

    const unsigned char* payload = audio_payload(data, len);
    auto packet = create_audio_packet_v2(parsed.codec, parsed.sequence, parsed.sample_rate,
                                         parsed.frame_count, parsed.channels, payload,
                                         parsed.payload_bytes);
    AudioHdrV2 hdr{};
    std::memcpy(&hdr, packet->data(), v2_header_size());
    hdr.sender_id = parsed.sender_id;
    std::memcpy(packet->data(), &hdr, v2_header_size());
    return packet;
}
```

- [ ] **Step 6: Update packet builder payload helpers**

In `packet_builder.h`, keep the current V1 helpers and replace V2-specific helpers with wrappers around `audio_packet`:

```cpp
inline uint16_t extract_v2_payload_bytes(const unsigned char* packet_data) {
    const auto parsed = audio_packet::parse_audio_header(packet_data, audio_packet::v3_header_size());
    return parsed.valid ? parsed.payload_bytes : 0;
}

inline uint16_t extract_audio_payload_bytes(const unsigned char* packet_data, size_t len) {
    const auto parsed = audio_packet::parse_audio_header(packet_data, len);
    return parsed.valid ? parsed.payload_bytes : 0;
}

inline const unsigned char* audio_v2_payload(const unsigned char* packet_data) {
    return packet_data + audio_packet::v2_header_size();
}

inline const unsigned char* audio_payload(const unsigned char* packet_data, size_t len) {
    return audio_packet::audio_payload(packet_data, len);
}
```

If the short `extract_v2_payload_bytes()` wrapper cannot safely parse without full length at a caller, replace each caller with `extract_audio_payload_bytes(packet_bytes, bytes)` in the same task.

- [ ] **Step 7: Run the packet tests**

Run:

```bash
cmake --build build --config Release --target audio_packet_self_test
ctest --test-dir build -C Release -R audio_packet_self_test --output-on-failure
```

Expected: `audio packet self-test passed`.

- [ ] **Step 8: Run full tests and commit Task 1**

Run:

```bash
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Expected: all current tests pass.

Commit:

```bash
git add protocol.h audio_packet.h packet_builder.h audio_packet_self_test.cpp
git commit -m "feat: add timestamped audio packet format"
```

---

### Task 2: Capability Negotiation And Legacy Relay Compatibility

**Files:**
- Modify: `server.cpp`
- Modify: `client.cpp`
- Modify: `latency_probe.cpp`
- Modify: `join_reliability_self_test.cpp`
- Modify: `tools/audio-path-feedback-smoke.mjs`
- Modify: `tools/audio-path-adapt-probe.mjs`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: Task 1 `AUDIO_CAP_CAPTURE_TIMESTAMP`, `AUDIO_SUPPORTED_CAPABILITIES`, V3 helpers, and `ParticipantInfoCapsHdr`.
- Produces: clients/probes advertise timestamp capability, server stores the new capability, server advertises supported caps in `JOIN_ACK`, participant metadata carries peer capabilities, and server relay fallback sends V2 to timestamp-legacy receivers.

- [ ] **Step 1: Write failing server timestamp relay smoke**

In `server.cpp`, add a new `run_timestamp_relay_smoke()` near `run_redundancy_relay_smoke()`:

```cpp
int run_timestamp_relay_smoke() {
    asio::io_context server_io;
    ServerOptions options;
    options.port = 0;
    options.allow_insecure_dev_joins = true;
    options.server_id = "timestamp-relay-smoke";

    Server server(server_io, options);
    const udp::endpoint server_endpoint(asio::ip::make_address("127.0.0.1"),
                                        server.local_port());

    std::thread server_thread([&server_io]() { server_io.run(); });
    try {
        asio::io_context client_io;
        udp::socket rx_timestamp(client_io, udp::endpoint(udp::v4(), 0));
        udp::socket rx_legacy(client_io, udp::endpoint(udp::v4(), 0));
        udp::socket tx(client_io, udp::endpoint(udp::v4(), 0));

        join_smoke_client(rx_timestamp, server_endpoint, "rx-timestamp",
                          AUDIO_CAP_REDUNDANCY | AUDIO_CAP_CAPTURE_TIMESTAMP);
        join_smoke_client(rx_legacy, server_endpoint, "rx-legacy",
                          AUDIO_CAP_REDUNDANCY);
        join_smoke_client(tx, server_endpoint, "tx",
                          AUDIO_CAP_REDUNDANCY | AUDIO_CAP_CAPTURE_TIMESTAMP);

        const std::array<unsigned char, 4> payload{9, 8, 7, 6};
        auto timestamped = audio_packet::create_audio_packet_v3(
            AudioCodec::Opus, 11, opus_network_clock::SAMPLE_RATE,
            opus_network_clock::DEFAULT_FRAME_COUNT, 1, payload.data(),
            static_cast<uint16_t>(payload.size()), 123456789LL);

        send_smoke_packet(tx, server_endpoint, *timestamped);

        auto timestamp_forward = receive_smoke_until(
            rx_timestamp,
            [](const std::vector<unsigned char>& packet) {
                return packet.size() >= audio_packet::v3_header_size() &&
                       packet_magic(packet) == AUDIO_V3_MAGIC;
            },
            1500ms);
        auto legacy_forward = receive_smoke_until(
            rx_legacy,
            [](const std::vector<unsigned char>& packet) {
                return packet.size() >= audio_packet::v2_header_size() &&
                       packet_magic(packet) == AUDIO_V2_MAGIC;
            },
            1500ms);

        const auto timestamp_parsed =
            audio_packet::parse_audio_header(timestamp_forward.data(), timestamp_forward.size());
        require_smoke(timestamp_parsed.valid, "timestamp receiver should get valid v3");
        require_smoke(timestamp_parsed.capture_server_time_ns == 123456789LL,
                      "timestamp receiver should preserve capture timestamp");

        const auto legacy_parsed =
            audio_packet::parse_audio_header(legacy_forward.data(), legacy_forward.size());
        require_smoke(legacy_parsed.valid, "legacy receiver should get valid audio");
        require_smoke(legacy_parsed.magic == AUDIO_V2_MAGIC,
                      "legacy receiver should get v2 fallback");
        require_smoke(legacy_parsed.sequence == 11,
                      "legacy fallback should preserve sequence");

        server_io.stop();
        server_thread.join();
        std::cout << "server timestamp relay smoke passed\n";
        return 0;
    } catch (...) {
        server_io.stop();
        server_thread.join();
        throw;
    }
}
```

Add argument handling in `main()`:

```cpp
        if (has_arg(argc, argv, "--timestamp-relay-smoke")) {
            return run_timestamp_relay_smoke();
        }
```

Add this ctest registration beside `server_redundancy_relay_smoke`:

```cmake
    add_test(NAME server_timestamp_relay_smoke
             COMMAND $<TARGET_FILE:server> --timestamp-relay-smoke)
```

- [ ] **Step 2: Run the new server smoke to verify it fails**

Run:

```bash
cmake --build build --config Release --target server
ctest --test-dir build -C Release -R server_timestamp_relay_smoke --output-on-failure
```

Expected: compile failure until server negotiation and relay fallback are implemented.

- [ ] **Step 3: Advertise and store the new capability**

In `client.cpp::send_join()`, set:

```cpp
        join.capabilities = AUDIO_SUPPORTED_CAPABILITIES;
```

In `latency_probe.cpp`, replace both `hdr.capabilities = AUDIO_CAP_REDUNDANCY;` assignments with:

```cpp
        hdr.capabilities = AUDIO_SUPPORTED_CAPABILITIES;
```

In `server.cpp::handle_join()`, replace the capability mask with:

```cpp
        const uint32_t client_capabilities = join.capabilities & AUDIO_SUPPORTED_CAPABILITIES;
```

In `server.cpp::send_join_ack()`, replace:

```cpp
        ack.capabilities = AUDIO_CAP_REDUNDANCY;
```

with:

```cpp
        ack.capabilities = AUDIO_SUPPORTED_CAPABILITIES;
```

In JS tools that define `AUDIO_CAP_REDUNDANCY = 1`, add:

```js
const AUDIO_CAP_CAPTURE_TIMESTAMP = 2;
const AUDIO_SUPPORTED_CAPABILITIES =
  AUDIO_CAP_REDUNDANCY | AUDIO_CAP_CAPTURE_TIMESTAMP;
```

and write `AUDIO_SUPPORTED_CAPABILITIES` into JOIN packets that represent new clients.

- [ ] **Step 4: Carry participant capabilities in metadata**

Change `packet_builder::create_participant_info_packet()` to accept capabilities and build `ParticipantInfoCapsHdr`:

```cpp
inline std::shared_ptr<std::vector<unsigned char>> create_participant_info_packet(
    uint32_t participant_id, const std::string& profile_id, const std::string& display_name,
    uint32_t capabilities = 0) {
    ParticipantInfoCapsHdr info{};
    info.magic = CTRL_MAGIC;
    info.type = CtrlHdr::Cmd::PARTICIPANT_INFO;
    info.participant_id = participant_id;
    write_fixed(info.profile_id, profile_id);
    write_fixed(info.display_name, display_name);
    info.capabilities = capabilities & AUDIO_SUPPORTED_CAPABILITIES;

    auto buf = std::make_shared<std::vector<unsigned char>>(sizeof(ParticipantInfoCapsHdr));
    std::memcpy(buf->data(), &info, sizeof(ParticipantInfoCapsHdr));
    return buf;
}
```

Update `server.cpp::broadcast_participant_info()` to pass the joined endpoint's capabilities:

```cpp
        const uint32_t capabilities =
            client_manager_.get_client_capabilities(joined_endpoint);
        auto buf = packet_builder::create_participant_info_packet(
            participant_id, profile_id, display_name, capabilities);
```

Update `server.cpp::send_existing_participant_info_to()` to pass `info.capabilities`:

```cpp
            auto buf = packet_builder::create_participant_info_packet(
                info.client_id, info.profile_id, info.display_name, info.capabilities);
```

Update `client.cpp` participant-info handling to accept old and new metadata:

```cpp
                uint32_t participant_capabilities = 0;
                if (bytes >= sizeof(ParticipantInfoCapsHdr)) {
                    ParticipantInfoCapsHdr info{};
                    std::memcpy(&info, recv_data, sizeof(ParticipantInfoCapsHdr));
                    participant_capabilities = info.capabilities & AUDIO_SUPPORTED_CAPABILITIES;
                }
```

The first implementation can log this value for diagnostics. Task 3 stores it only if room-wide sender gating is added; server fallback already protects legacy receivers.

- [ ] **Step 5: Implement server V3 relay fallback**

In `server.cpp`, update audio validation to accept V2 and V3:

```cpp
    bool validate_complete_audio_packet(std::size_t bytes) {
        MsgHdr hdr{};
        std::memcpy(&hdr, recv_buf_.data(), sizeof(MsgHdr));
        if (hdr.magic != AUDIO_V2_MAGIC && hdr.magic != AUDIO_V3_MAGIC) {
            return true;
        }

        const auto* packet_data = reinterpret_cast<const unsigned char*>(recv_buf_.data());
        std::string reason;
        if (!audio_packet::validate_audio_packet_bytes(packet_data, bytes, &reason)) {
            const auto parsed = audio_packet::parse_audio_header(packet_data, bytes);
            ++invalid_audio_drops_since_log_;
            Log::warn(
                "Dropping invalid audio from {}:{}: reason={} magic=0x{:08x} got {} "
                "payload_bytes={} seq={}",
                remote_endpoint_.address().to_string(), remote_endpoint_.port(), reason,
                hdr.magic, bytes, parsed.payload_bytes, parsed.sequence);
            return false;
        }

        return true;
    }
```

Add helper functions for receiver fallback:

```cpp
    std::shared_ptr<std::vector<unsigned char>> packet_for_receiver_capabilities(
        const udp::endpoint& endpoint, void* packet_data, std::size_t packet_size) {
        MsgHdr hdr{};
        std::memcpy(&hdr, packet_data, sizeof(MsgHdr));

        const bool receiver_supports_timestamp =
            client_manager_.client_supports(endpoint, AUDIO_CAP_CAPTURE_TIMESTAMP);
        const bool receiver_supports_redundancy =
            client_manager_.client_supports(endpoint, AUDIO_CAP_REDUNDANCY);

        if (hdr.magic == AUDIO_REDUNDANT_MAGIC) {
            if (!receiver_supports_redundancy) {
                auto fallback = first_redundant_child_copy(packet_data, packet_size);
                if (fallback != nullptr && !receiver_supports_timestamp &&
                    packet_magic(*fallback) == AUDIO_V3_MAGIC) {
                    return audio_packet::strip_audio_v3_timestamp(fallback->data(),
                                                                  fallback->size());
                }
                return fallback;
            }
            if (!receiver_supports_timestamp) {
                return redundant_without_timestamps_copy(packet_data, packet_size);
            }
            return nullptr;
        }

        if (hdr.magic == AUDIO_V3_MAGIC && !receiver_supports_timestamp) {
            return audio_packet::strip_audio_v3_timestamp(
                static_cast<const unsigned char*>(packet_data), packet_size);
        }

        return nullptr;
    }
```

Implement `packet_magic(const std::vector<unsigned char>&)` for server internals if the smoke-only helper is not visible in this scope, and implement `redundant_without_timestamps_copy()` by iterating children, stripping V3 children to V2, preserving V2 children, and passing the converted child vector to `audio_packet::create_redundant_audio_packet()`.

Update `forward_audio_to_others()`:

```cpp
        for (const auto& endpoint: endpoints) {
            record_audio_forward_datagram(sender_id, endpoint, packet_data, packet_size);
            auto fallback = packet_for_receiver_capabilities(endpoint, packet_data, packet_size);
            if (fallback != nullptr) {
                send(fallback->data(), fallback->size(), endpoint, fallback);
            } else {
                send(packet_data, packet_size, endpoint, keep_alive);
            }
        }
```

- [ ] **Step 6: Update ingress/forward stats parsing**

Where `server.cpp::record_audio_ingress()` and `record_audio_forward()` currently require `AUDIO_V2_MAGIC`, replace direct V2 copies with:

```cpp
        const auto parsed = audio_packet::parse_audio_header(
            static_cast<const unsigned char*>(packet_data), packet_size);
        if (!parsed.valid ||
            (parsed.magic != AUDIO_V2_MAGIC && parsed.magic != AUDIO_V3_MAGIC)) {
            return;
        }
```

Use `parsed.sequence` and `parsed.frame_count` instead of `audio.sequence` and `audio.frame_count`.

- [ ] **Step 7: Update capability self-tests**

In `join_reliability_self_test.cpp`, keep the redundancy assertion and add:

```cpp
    state.mark_join_ack(43, AUDIO_SUPPORTED_CAPABILITIES);
    require(state.server_supports(AUDIO_CAP_CAPTURE_TIMESTAMP),
            "join state should report capture timestamp capability");
```

- [ ] **Step 8: Run targeted tests**

Run:

```bash
cmake --build build --config Release --target server audio_packet_self_test join_reliability_self_test latency_probe
ctest --test-dir build -C Release -R "audio_packet_self_test|join_reliability_self_test|server_redundancy_relay_smoke|server_timestamp_relay_smoke" --output-on-failure
```

Expected: all targeted tests pass, including the existing redundancy smoke.

- [ ] **Step 9: Run full tests and commit Task 2**

Run:

```bash
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Expected: all tests pass.

Commit:

```bash
git add server.cpp client.cpp latency_probe.cpp join_reliability_self_test.cpp tools/audio-path-feedback-smoke.mjs tools/audio-path-adapt-probe.mjs CMakeLists.txt
git commit -m "feat: negotiate capture timestamp capability"
```

---

### Task 3: Client Capture-To-Playout Observation

**Files:**
- Modify: `participant_info.h`
- Modify: `participant_manager.h`
- Modify: `client.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: Task 1 V3 packet parse/create helpers and Task 2 negotiated capability.
- Produces: sender-side V3 stamping, receiver-side V3 parsing, per-participant `capture_to_playout_*_ns` atomics, fixed-size Opus PCM timestamp chunk tracking, and `client_e2e_latency_metric_smoke`.

- [ ] **Step 1: Write a failing client E2E metric smoke**

Add a startup option in `ClientStartupOptions`:

```cpp
    bool e2e_latency_metric_smoke = false;
```

Parse it in `parse_startup_options()`:

```cpp
        } else if (arg == "--e2e-latency-metric-smoke") {
            options.e2e_latency_metric_smoke = true;
```

Add this static smoke inside `Client` near the other static smoke helpers:

```cpp
    static bool run_e2e_latency_metric_smoke(std::string& failure) {
        ParticipantData participant;
        const int64_t capture_ns = 10'000'000LL;
        const int64_t playout_ns = 35'000'000LL;

        OpusPacket packet;
        packet.capture_server_time_ns = capture_ns;
        packet.capture_timestamp_valid = true;
        observe_capture_to_playout_latency(participant, packet, playout_ns);

        const int64_t observed =
            participant.capture_to_playout_latency_last_ns.load(std::memory_order_relaxed);
        if (observed != 25'000'000LL) {
            failure = "direct packet latency observation should be 25 ms";
            return false;
        }

        append_opus_capture_chunk(participant, 120, capture_ns, true);
        append_opus_capture_chunk(participant, 120, 20'000'000LL, true);
        observe_and_consume_opus_capture_chunks(participant, 120, 40'000'000LL);
        const int64_t first_chunk =
            participant.capture_to_playout_latency_last_ns.load(std::memory_order_relaxed);
        if (first_chunk != 30'000'000LL) {
            failure = "first Opus capture chunk should observe 30 ms";
            return false;
        }
        observe_and_consume_opus_capture_chunks(participant, 120, 45'000'000LL);
        const int64_t second_chunk =
            participant.capture_to_playout_latency_last_ns.load(std::memory_order_relaxed);
        if (second_chunk != 25'000'000LL) {
            failure = "second Opus capture chunk should observe 25 ms";
            return false;
        }

        return true;
    }
```

Add the main dispatch:

```cpp
        if (startup_options.e2e_latency_metric_smoke) {
            std::string failure;
            if (!Client::run_e2e_latency_metric_smoke(failure)) {
                Log::error("E2E latency metric smoke failed: {}", failure);
                log.flush();
                return 16;
            }
            Log::info("E2E latency metric smoke passed");
            log.flush();
            return 0;
        }
```

Register in `CMakeLists.txt`:

```cmake
        add_test(NAME client_e2e_latency_metric_smoke
                 COMMAND $<TARGET_FILE:client> --e2e-latency-metric-smoke)
```

- [ ] **Step 2: Run the client metric smoke to verify it fails**

Run:

```bash
cmake --build build --config Release --target client
ctest --test-dir build -C Release -R client_e2e_latency_metric_smoke --output-on-failure
```

Expected: compile failure naming missing capture-to-playout fields or helper functions.

- [ ] **Step 3: Add packet and participant timestamp state**

In `participant_info.h::OpusPacket`, add:

```cpp
    bool                                  capture_timestamp_valid = false;
    int64_t                               capture_server_time_ns = 0;
```

Before `ParticipantData`, add:

```cpp
struct OpusPcmCaptureChunk {
    size_t frames = 0;
    int64_t capture_server_time_ns = 0;
    bool valid = false;
};
```

In `ParticipantData`, add beside the Opus PCM buffer fields:

```cpp
    std::array<OpusPcmCaptureChunk, MAX_OPUS_QUEUE_SIZE> opus_pcm_capture_chunks{};
    size_t                                  opus_pcm_capture_chunk_head = 0;
    size_t                                  opus_pcm_capture_chunk_count = 0;
```

Add per-participant latency atomics beside packet age:

```cpp
    std::atomic<int64_t>   capture_to_playout_latency_last_ns{0};
    std::atomic<int64_t>   capture_to_playout_latency_max_ns{0};
    std::atomic<int64_t>   capture_to_playout_latency_avg_ns{0};
    std::atomic<uint64_t>  capture_to_playout_latency_samples{0};
```

In `ParticipantInfo`, add:

```cpp
    double   capture_to_playout_latency_last_ms;
    double   capture_to_playout_latency_avg_ms;
    double   capture_to_playout_latency_max_ms;
    uint64_t capture_to_playout_latency_samples;
```

- [ ] **Step 4: Publish E2E latency in participant snapshots**

In `participant_manager.h::make_info()`, add after packet age fields:

```cpp
        info.capture_to_playout_latency_last_ms =
            data.capture_to_playout_latency_last_ns.load(std::memory_order_relaxed) / 1e6;
        info.capture_to_playout_latency_avg_ms =
            data.capture_to_playout_latency_avg_ns.load(std::memory_order_relaxed) / 1e6;
        info.capture_to_playout_latency_max_ms =
            data.capture_to_playout_latency_max_ns.load(std::memory_order_relaxed) / 1e6;
        info.capture_to_playout_latency_samples =
            data.capture_to_playout_latency_samples.load(std::memory_order_relaxed);
```

- [ ] **Step 5: Add client-side clock conversion helpers**

In `client.cpp`, near `steady_now_ns()`, add:

```cpp
    static int64_t steady_time_ns(std::chrono::steady_clock::time_point time) {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(time.time_since_epoch())
            .count();
    }

    int64_t server_time_for_steady_time_ns(std::chrono::steady_clock::time_point time) const {
        return steady_time_ns(time) +
               server_clock_offset_ns_.load(std::memory_order_acquire);
    }

    bool can_send_capture_timestamps() const {
        return join_state_.server_supports(AUDIO_CAP_CAPTURE_TIMESTAMP) &&
               server_clock_ready_.load(std::memory_order_acquire);
    }
```

Keep the existing `steady_now_ns()` as a wrapper:

```cpp
    static int64_t steady_now_ns() {
        return steady_time_ns(std::chrono::steady_clock::now());
    }
```

- [ ] **Step 6: Stamp outgoing V3 packets**

In `pcm_sender_loop()`, replace V2 packet creation for PCM with:

```cpp
                std::shared_ptr<std::vector<unsigned char>> packet;
                if (can_send_capture_timestamps()) {
                    packet = audio_packet::create_audio_packet_v3(
                        AudioCodec::PcmInt16, seq, frame.sample_rate, frame.frame_count, 1,
                        frame.payload.data(), frame.payload_bytes,
                        server_time_for_steady_time_ns(frame.capture_time));
                } else {
                    packet = audio_packet::create_audio_packet_v2(
                        AudioCodec::PcmInt16, seq, frame.sample_rate, frame.frame_count, 1,
                        frame.payload.data(), frame.payload_bytes);
                }
```

In the Opus branch, replace V2 creation with:

```cpp
                    std::shared_ptr<std::vector<unsigned char>> packet;
                    if (can_send_capture_timestamps()) {
                        packet = audio_packet::create_audio_packet_v3(
                            AudioCodec::Opus, seq, opus_frame.sample_rate,
                            opus_frame.frame_count, 1, encoded_data.data(),
                            static_cast<uint16_t>(encoded_data.size()),
                            server_time_for_steady_time_ns(opus_frame.capture_time));
                    } else {
                        packet = audio_packet::create_audio_packet_v2(
                            AudioCodec::Opus, seq, opus_frame.sample_rate,
                            opus_frame.frame_count, 1, encoded_data.data(),
                            static_cast<uint16_t>(encoded_data.size()));
                    }
```

Update `validate_outbound_audio_packet()` to validate `AUDIO_V2_MAGIC` and `AUDIO_V3_MAGIC` via `audio_packet::validate_audio_packet_bytes()`.

Update `maybe_wrap_opus_packet_with_redundancy()` to parse via `audio_packet::parse_audio_header()` instead of copying `AudioHdrV2`.

- [ ] **Step 7: Parse incoming V3 packets**

In `client.cpp::handle_audio_message()`, replace `const bool is_v2 = msg_hdr.magic == AUDIO_V2_MAGIC;` with:

```cpp
        const bool is_audio_v2 = msg_hdr.magic == AUDIO_V2_MAGIC;
        const bool is_audio_v3 = msg_hdr.magic == AUDIO_V3_MAGIC;
        const bool is_versioned_audio = is_audio_v2 || is_audio_v3;
```

Use:

```cpp
        const size_t min_packet_size =
            is_audio_v3 ? audio_packet::v3_header_size()
                        : (is_audio_v2 ? audio_packet::v2_header_size()
                                       : sizeof(MsgHdr) + sizeof(uint32_t) + sizeof(uint16_t));
```

Use common parsing for payload bytes:

```cpp
        const auto parsed_audio =
            is_versioned_audio ? audio_packet::parse_audio_header(packet_bytes, bytes)
                               : audio_packet::ParsedAudioHeader{};
        uint16_t payload_bytes =
            is_versioned_audio ? parsed_audio.payload_bytes
                               : packet_builder::extract_encoded_bytes(packet_bytes);
```

Validate versioned packets with:

```cpp
        if (is_versioned_audio) {
            std::string reason;
            if (!audio_packet::validate_audio_packet_bytes(packet_bytes, bytes, &reason)) {
                const uint64_t count =
                    inbound_malformed_audio_drops_.fetch_add(1, std::memory_order_relaxed) + 1;
                if (count == 1 || count % 100 == 0) {
                    Log::warn(
                        "Dropping invalid versioned audio: reason={} sender={} seq={} "
                        "sample_rate={} frame_count={} channels={} payload_bytes={} drops={}",
                        reason, sender_id, parsed_audio.sequence, parsed_audio.sample_rate,
                        parsed_audio.frame_count, static_cast<int>(parsed_audio.channels),
                        parsed_audio.payload_bytes, count);
                }
                return;
            }
        }
```

When filling `OpusPacket`, set:

```cpp
                    packet.codec = parsed_audio.codec;
                    packet.sequence = parsed_audio.sequence;
                    packet.sequence_valid = true;
                    packet.sample_rate = parsed_audio.sample_rate;
                    packet.frame_count = parsed_audio.frame_count;
                    packet.channels = parsed_audio.channels;
                    packet.capture_timestamp_valid =
                        parsed_audio.capture_timestamp_valid;
                    packet.capture_server_time_ns =
                        parsed_audio.capture_server_time_ns;
```

Use `packet_builder::audio_payload(packet_bytes, bytes)` for V2/V3 payloads.

- [ ] **Step 8: Observe direct packet latency and Opus buffered latency**

Add these static helpers in `Client` near other latency observers:

```cpp
    static void observe_capture_to_playout_latency(ParticipantData& participant,
                                                   const OpusPacket& packet,
                                                   int64_t playout_server_time_ns) {
        if (!packet.capture_timestamp_valid || packet.capture_server_time_ns <= 0 ||
            playout_server_time_ns <= packet.capture_server_time_ns) {
            return;
        }

        observe_latency_sample(participant.capture_to_playout_latency_last_ns,
                               participant.capture_to_playout_latency_avg_ns,
                               participant.capture_to_playout_latency_max_ns,
                               playout_server_time_ns - packet.capture_server_time_ns);
        participant.capture_to_playout_latency_samples.fetch_add(1,
                                                                 std::memory_order_relaxed);
    }

    static void append_opus_capture_chunk(ParticipantData& participant, size_t frames,
                                          int64_t capture_server_time_ns, bool valid) {
        if (frames == 0) {
            return;
        }
        if (participant.opus_pcm_capture_chunk_count >=
            participant.opus_pcm_capture_chunks.size()) {
            participant.opus_pcm_capture_chunk_head =
                (participant.opus_pcm_capture_chunk_head + 1) %
                participant.opus_pcm_capture_chunks.size();
            --participant.opus_pcm_capture_chunk_count;
        }
        const size_t index =
            (participant.opus_pcm_capture_chunk_head +
             participant.opus_pcm_capture_chunk_count) %
            participant.opus_pcm_capture_chunks.size();
        participant.opus_pcm_capture_chunks[index] =
            OpusPcmCaptureChunk{frames, capture_server_time_ns, valid};
        ++participant.opus_pcm_capture_chunk_count;
    }

    static void clear_opus_capture_chunks(ParticipantData& participant) {
        participant.opus_pcm_capture_chunk_head = 0;
        participant.opus_pcm_capture_chunk_count = 0;
    }

    static void observe_and_consume_opus_capture_chunks(ParticipantData& participant,
                                                        size_t consumed_frames,
                                                        int64_t playout_server_time_ns) {
        size_t remaining = consumed_frames;
        while (remaining > 0 && participant.opus_pcm_capture_chunk_count > 0) {
            auto& chunk =
                participant.opus_pcm_capture_chunks[participant.opus_pcm_capture_chunk_head];
            if (chunk.valid && chunk.capture_server_time_ns > 0) {
                OpusPacket marker;
                marker.capture_timestamp_valid = true;
                marker.capture_server_time_ns = chunk.capture_server_time_ns;
                observe_capture_to_playout_latency(participant, marker, playout_server_time_ns);
            }

            const size_t consumed_from_chunk = std::min(remaining, chunk.frames);
            chunk.frames -= consumed_from_chunk;
            remaining -= consumed_from_chunk;
            if (chunk.frames == 0) {
                participant.opus_pcm_capture_chunk_head =
                    (participant.opus_pcm_capture_chunk_head + 1) %
                    participant.opus_pcm_capture_chunks.size();
                --participant.opus_pcm_capture_chunk_count;
            }
        }
    }
```

Change `consume_opus_pcm_buffer()` to return consumed frames:

```cpp
    static size_t consume_opus_pcm_buffer(ParticipantData& participant, size_t frame_count) {
        const size_t consumed = std::min(frame_count, participant.opus_pcm_buffered_frames);
        if (participant.opus_pcm_buffered_frames <= frame_count) {
            participant.opus_pcm_buffered_frames = 0;
            participant.opus_resample_phase = 0.0;
            return consumed;
        }

        const size_t remaining = participant.opus_pcm_buffered_frames - frame_count;
        std::move(participant.opus_pcm_buffer.begin() + static_cast<std::ptrdiff_t>(frame_count),
                  participant.opus_pcm_buffer.begin() +
                      static_cast<std::ptrdiff_t>(participant.opus_pcm_buffered_frames),
                  participant.opus_pcm_buffer.begin());
        participant.opus_pcm_buffered_frames = remaining;
        return consumed;
    }
```

Change `mix_resampled_opus_pcm()` and `mix_available_opus_pcm_with_tail()` to return `size_t` and return the `consume_opus_pcm_buffer()` result.

At each call site, capture the return and observe chunks:

```cpp
                const int64_t playout_server_time_ns =
                    client->server_time_for_steady_time_ns(playout_start);
                const size_t consumed_frames = mix_resampled_opus_pcm(
                    participant, output_buffer, frame_count, out_channels,
                    participant_gain, playout_ratio);
                observe_and_consume_opus_capture_chunks(participant, consumed_frames,
                                                        playout_server_time_ns);
```

When Opus decoded frames are appended to `participant.opus_pcm_buffer`, immediately append the matching capture chunk:

```cpp
                        append_opus_capture_chunk(
                            participant, decoded_frames,
                            opus_packet.capture_server_time_ns,
                            opus_packet.capture_timestamp_valid);
```

When the Opus PCM buffer is reset, call:

```cpp
                            clear_opus_capture_chunks(participant);
```

For direct PCM packets, observe at the callback playout time after successful decode and before mixing:

```cpp
                    observe_capture_to_playout_latency(
                        participant, opus_packet,
                        client->server_time_for_steady_time_ns(playout_start));
```

- [ ] **Step 9: Run targeted client metric tests**

Run:

```bash
cmake --build build --config Release --target client
ctest --test-dir build -C Release -R "client_e2e_latency_metric_smoke|client_opus_playout_policy_smoke" --output-on-failure
```

Expected: both tests pass.

- [ ] **Step 10: Run full tests and commit Task 3**

Run:

```bash
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Expected: all tests pass.

Commit:

```bash
git add participant_info.h participant_manager.h client.cpp CMakeLists.txt
git commit -m "feat: observe capture to playout latency"
```

---

### Task 4: Path Panel And Baseline Snapshot Surfacing

**Files:**
- Modify: `client.cpp`

**Interfaces:**
- Consumes: Task 3 `ParticipantInfo::capture_to_playout_latency_*`.
- Produces: Path panel top-level E2E summary, per-participant E2E fields, baseline participant logs with `e2e_ms last/avg/max`, and regular diagnostic logs with the same metric.

- [ ] **Step 1: Write the failing surfacing expectation**

Extend `client_e2e_latency_metric_smoke` from Task 3 to verify `ParticipantManager::make_info()` publishes the values. Add this block to the smoke after the direct observation:

```cpp
        ParticipantManager manager;
        if (!manager.register_participant(99, 48000, 1)) {
            failure = "participant registration should succeed";
            return false;
        }
        manager.with_participant(99, [](ParticipantData& data) {
            data.capture_to_playout_latency_last_ns.store(11'000'000LL,
                                                          std::memory_order_relaxed);
            data.capture_to_playout_latency_avg_ns.store(12'000'000LL,
                                                         std::memory_order_relaxed);
            data.capture_to_playout_latency_max_ns.store(13'000'000LL,
                                                         std::memory_order_relaxed);
            data.capture_to_playout_latency_samples.store(3,
                                                          std::memory_order_relaxed);
        });
        const auto infos = manager.get_all_info();
        if (infos.empty() || infos.front().capture_to_playout_latency_avg_ms != 12.0 ||
            infos.front().capture_to_playout_latency_samples != 3) {
            failure = "participant info should publish E2E latency fields";
            return false;
        }
```

- [ ] **Step 2: Run the surfacing test to verify it fails**

Run:

```bash
cmake --build build --config Release --target client
ctest --test-dir build -C Release -R client_e2e_latency_metric_smoke --output-on-failure
```

Expected: failure until `ParticipantInfo` publication and client display fields are complete.

- [ ] **Step 3: Add PathDiagnostics E2E summary fields**

In `Client::PathDiagnostics`, add:

```cpp
        double e2e_latency_avg_max_ms = 0.0;
        double e2e_latency_peak_ms = 0.0;
        uint64_t e2e_latency_samples = 0;
```

In `get_path_diagnostics()`, extend the participant loop:

```cpp
            diagnostics.e2e_latency_avg_max_ms =
                std::max(diagnostics.e2e_latency_avg_max_ms,
                         participant.capture_to_playout_latency_avg_ms);
            diagnostics.e2e_latency_peak_ms =
                std::max(diagnostics.e2e_latency_peak_ms,
                         participant.capture_to_playout_latency_max_ms);
            diagnostics.e2e_latency_samples +=
                participant.capture_to_playout_latency_samples;
```

- [ ] **Step 4: Add Path panel top-level E2E display**

In the Path panel block after `Total ~...`, add:

```cpp
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
        if (path.e2e_latency_samples > 0) {
            ImGui::Text("E2E %.1f/%.1f ms",
                        path.e2e_latency_avg_max_ms, path.e2e_latency_peak_ms);
            JamGui::ShowTooltipOnHover("Capture-to-playout average max / peak across participants");
        } else {
            ImGui::Text("E2E waiting");
            JamGui::ShowTooltipOnHover("Waiting for timestamped packets and server clock sync");
        }
```

In the participant stats block after packet age, add:

```cpp
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
            if (p.capture_to_playout_latency_samples > 0) {
                ImGui::Text("E2E: %.1f ms", p.capture_to_playout_latency_avg_ms);
                ImGui::SetCursorPosX(ImGui::GetCursorPosX() + PADDING);
                ImGui::Text("Max E2E: %.1f ms", p.capture_to_playout_latency_max_ms);
            } else {
                ImGui::Text("E2E: waiting");
            }
```

- [ ] **Step 5: Add baseline and periodic diagnostic fields**

In `log_baseline_snapshot()`, update the participant log format string to include:

```cpp
                "decoded_frames={} decoded_packets={} age_ms last/avg/max={:.1f}/{:.1f}/{:.1f} "
                "e2e_ms last/avg/max={:.1f}/{:.1f}/{:.1f} e2e_samples={} "
                "drift_ppm last/avg/max={:.1f}/{:.1f}/{:.1f} underruns={} "
```

Add arguments after the packet-age arguments:

```cpp
                p.capture_to_playout_latency_last_ms,
                p.capture_to_playout_latency_avg_ms,
                p.capture_to_playout_latency_max_ms,
                p.capture_to_playout_latency_samples,
```

In the regular participant diagnostic log around `Participant diag`, add:

```cpp
                "age_avg_ms={:.1f} e2e_avg_ms={:.1f} e2e_max_ms={:.1f} "
```

and pass:

```cpp
                p.packet_age_avg_ms,
                p.capture_to_playout_latency_avg_ms,
                p.capture_to_playout_latency_max_ms,
```

- [ ] **Step 6: Run targeted surfacing tests**

Run:

```bash
cmake --build build --config Release --target client
ctest --test-dir build -C Release -R client_e2e_latency_metric_smoke --output-on-failure
```

Expected: smoke passes.

- [ ] **Step 7: Run full tests and commit Task 4**

Run:

```bash
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Expected: all tests pass.

Commit:

```bash
git add client.cpp participant_info.h participant_manager.h
git commit -m "feat: surface e2e latency diagnostics"
```

---

### Task 5: Loopback E2E Latency Smoke

**Files:**
- Modify: `latency_probe.cpp`
- Create: `tools/e2e-latency-smoke.mjs`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: Task 1 V3 helpers and Task 2 server capability negotiation.
- Produces: `latency_probe` fields for one-way E2E latency, `--max-e2e-latency-ms`, `--e2e-margin-ms`, and a ctest smoke asserting steady-state one-way latency <= jitter target + 1 packet + callback duration + margin.

- [ ] **Step 1: Write failing ctest registration and smoke script**

Create `tools/e2e-latency-smoke.mjs`:

```js
#!/usr/bin/env node

import dgram from "node:dgram";
import { spawn } from "node:child_process";

function usage(message) {
  if (message) {
    console.error(message);
  }
  console.error(
    "Usage: e2e-latency-smoke.mjs --server-exe <path> --probe-exe <path> [options]",
  );
  process.exit(message ? 2 : 0);
}

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      usage();
    }
    if (!arg.startsWith("--") || i + 1 >= argv.length) {
      usage(`unknown or incomplete argument: ${arg}`);
    }
    args[arg.slice(2)] = argv[++i];
  }
  for (const required of ["server-exe", "probe-exe"]) {
    if (!args[required]) {
      usage(`missing --${required}`);
    }
  }
  return args;
}

function argValue(args, name, fallback) {
  return args[name] ?? fallback;
}

function reserveUdpPort() {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket("udp4");
    socket.once("error", reject);
    socket.bind(0, "127.0.0.1", () => {
      const port = socket.address().port;
      socket.close(() => resolve(port));
    });
  });
}

function spawnLogged(name, command, args) {
  const child = spawn(command, args, {
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => process.stdout.write(`[${name}] ${chunk}`));
  child.stderr.on("data", (chunk) => process.stderr.write(`[${name}] ${chunk}`));
  return child;
}

function waitForOutput(child, pattern, timeoutMs, name) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`${name} did not report readiness within ${timeoutMs} ms`));
    }, timeoutMs);
    const onData = (chunk) => {
      if (pattern.test(chunk)) {
        cleanup();
        resolve();
      }
    };
    const onExit = (code, signal) => {
      cleanup();
      reject(new Error(`${name} exited before ready: code=${code} signal=${signal}`));
    };
    const cleanup = () => {
      clearTimeout(timer);
      child.stdout.off("data", onData);
      child.stderr.off("data", onData);
      child.off("exit", onExit);
    };
    child.stdout.on("data", onData);
    child.stderr.on("data", onData);
    child.once("exit", onExit);
  });
}

function runChecked(name, command, args) {
  return new Promise((resolve, reject) => {
    const child = spawnLogged(name, command, args);
    child.on("error", reject);
    child.on("exit", (code, signal) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(`${name} failed: code=${code} signal=${signal}`));
    });
  });
}

function stopChild(child) {
  if (child && child.exitCode === null && child.signalCode === null) {
    child.kill();
  }
}

const args = parseArgs(process.argv);
const serverPort = await reserveUdpPort();
let server;

try {
  server = spawnLogged("server", args["server-exe"], [
    "--port",
    String(serverPort),
    "--allow-insecure-dev-joins",
  ]);
  await waitForOutput(server, /SFU server ready/, 5000, "server");

  const frames = Number(argValue(args, "frames", "120"));
  const jitter = Number(argValue(args, "jitter", "4"));
  const marginMs = Number(argValue(args, "margin-ms", "8"));
  const packetMs = (frames * 1000) / 48000;
  const budgetMs = jitter * packetMs + packetMs + packetMs + marginMs;

  await runChecked("latency_probe", args["probe-exe"], [
    "--server",
    "127.0.0.1",
    "--port",
    String(serverPort),
    "--codec",
    argValue(args, "codec", "pcm"),
    "--frames",
    String(frames),
    "--jitter",
    String(jitter),
    "--packets",
    argValue(args, "packets", "650"),
    "--require-clean",
    "--max-e2e-latency-ms",
    String(budgetMs),
    "--e2e-margin-ms",
    String(marginMs),
  ]);
} finally {
  stopChild(server);
}
```

Add ctest registration:

```cmake
        add_test(NAME e2e_latency_loopback_smoke
                 COMMAND ${NODE_EXECUTABLE}
                         ${CMAKE_SOURCE_DIR}/tools/e2e-latency-smoke.mjs
                         --server-exe $<TARGET_FILE:server>
                         --probe-exe $<TARGET_FILE:latency_probe>)
```

- [ ] **Step 2: Run the loopback smoke to verify it fails**

Run:

```bash
cmake --build build --config Release --target server latency_probe
ctest --test-dir build -C Release -R e2e_latency_loopback_smoke --output-on-failure
```

Expected: `latency_probe` exits with unknown argument `--max-e2e-latency-ms`.

- [ ] **Step 3: Add E2E metrics to latency_probe arguments and output**

In `latency_probe.cpp::Args`, add:

```cpp
    double max_e2e_latency_ms = -1.0;
    double e2e_margin_ms = 8.0;
```

In `ProbeMetrics`, add:

```cpp
    int e2e_latency_samples = 0;
    double e2e_latency_last_ms = 0.0;
    double e2e_latency_avg_ms = 0.0;
    double e2e_latency_max_ms = 0.0;
    double e2e_latency_steady_max_ms = 0.0;
```

Parse:

```cpp
        } else if (arg == "--max-e2e-latency-ms" && i + 1 < argc) {
            args.max_e2e_latency_ms = std::stod(argv[++i]);
        } else if (arg == "--e2e-margin-ms" && i + 1 < argc) {
            args.e2e_margin_ms = std::stod(argv[++i]);
```

Print:

```cpp
    std::cout << "e2e_latency_samples: " << m.e2e_latency_samples << "\n";
    std::cout << "e2e_latency_ms last/avg/max/steady_max: "
              << m.e2e_latency_last_ms << "/" << m.e2e_latency_avg_ms << "/"
              << m.e2e_latency_max_ms << "/" << m.e2e_latency_steady_max_ms << "\n";
    if (args.max_e2e_latency_ms >= 0.0) {
        std::cout << "e2e_latency_budget_ms: " << args.max_e2e_latency_ms << "\n";
    }
```

- [ ] **Step 4: Stamp and parse V3 in latency_probe**

In `ProbeSender::send_audio_packet()`, use `create_audio_packet_v3()`:

```cpp
        const int64_t capture_server_time_ns =
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                clock_type::now().time_since_epoch())
                .count();
        auto packet = audio_packet::create_audio_packet_v3(
            audio_codec, sequence, SAMPLE_RATE, static_cast<uint16_t>(frame_count),
            CHANNELS, payload, static_cast<uint16_t>(payload_bytes),
            capture_server_time_ns);
```

In `ProbeReceiver::handle_receive()`, accept `AUDIO_V3_MAGIC` and use `audio_packet::parse_audio_header()` plus `packet_builder::audio_payload(packet_data, bytes)`. Set:

```cpp
        packet.capture_timestamp_valid = audio.capture_timestamp_valid;
        packet.capture_server_time_ns = audio.capture_server_time_ns;
```

Keep V2 support because server fallback and older probes may still deliver V2.

- [ ] **Step 5: Observe probe E2E at playout**

Add a small observation helper in `latency_probe.cpp`:

```cpp
void observe_probe_e2e_latency(const OpusPacket& packet, ProbeMetrics& metrics,
                               int tick, int warmup_ticks) {
    if (!packet.capture_timestamp_valid || packet.capture_server_time_ns <= 0) {
        return;
    }
    const int64_t now_ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            clock_type::now().time_since_epoch())
            .count();
    if (now_ns <= packet.capture_server_time_ns) {
        return;
    }
    const double latency_ms =
        static_cast<double>(now_ns - packet.capture_server_time_ns) / 1'000'000.0;
    metrics.e2e_latency_last_ms = latency_ms;
    metrics.e2e_latency_max_ms = std::max(metrics.e2e_latency_max_ms, latency_ms);
    metrics.e2e_latency_avg_ms =
        metrics.e2e_latency_samples == 0
            ? latency_ms
            : ((metrics.e2e_latency_avg_ms * 31.0) + latency_ms) / 32.0;
    ++metrics.e2e_latency_samples;
    if (tick >= warmup_ticks) {
        metrics.e2e_latency_steady_max_ms =
            std::max(metrics.e2e_latency_steady_max_ms, latency_ms);
    }
}
```

Call it in `run_playout_loop()` after a real packet is selected for output and before samples are inspected:

```cpp
            constexpr int E2E_WARMUP_TICKS = 30;
            if (!packet.loss_concealment) {
                observe_probe_e2e_latency(packet, metrics, tick, E2E_WARMUP_TICKS);
            }
```

For Opus FIFO output, carry the capture timestamp beside decoded blocks the same way Task 3 carries chunks in the real client. The probe can use:

```cpp
struct ProbeDecodedChunk {
    int frames = 0;
    bool capture_timestamp_valid = false;
    int64_t capture_server_time_ns = 0;
};
```

and a `std::vector<ProbeDecodedChunk>` because the probe is not the real-time callback. Consume chunks in `output_decoded_fifo()` when decoded FIFO frames are emitted.

- [ ] **Step 6: Enforce the budget in latency_probe**

In `main()`, after `print_result(args, result)`, add:

```cpp
        if (args.max_e2e_latency_ms >= 0.0) {
            if (result.metrics.e2e_latency_samples == 0) {
                std::cerr << "latency_probe failed: no E2E latency samples\n";
                return 6;
            }
            if (result.metrics.e2e_latency_steady_max_ms > args.max_e2e_latency_ms) {
                std::cerr << "latency_probe failed: steady E2E latency "
                          << result.metrics.e2e_latency_steady_max_ms
                          << " ms exceeds budget " << args.max_e2e_latency_ms << " ms\n";
                return 7;
            }
        }
```

- [ ] **Step 7: Run targeted loopback smoke**

Run:

```bash
cmake --build build --config Release --target server latency_probe
ctest --test-dir build -C Release -R e2e_latency_loopback_smoke --output-on-failure
```

Expected: pass. The output includes `e2e_latency_ms last/avg/max/steady_max` and `e2e_latency_budget_ms`.

- [ ] **Step 8: Run full tests and commit Task 5**

Run:

```bash
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Expected: all tests pass, with the new `e2e_latency_loopback_smoke` included.

Commit:

```bash
git add latency_probe.cpp tools/e2e-latency-smoke.mjs CMakeLists.txt
git commit -m "test: assert loopback e2e latency budget"
```

---

### Task 6: Phase 3 Acceptance, Tracker Status, And Baseline Record

**Files:**
- Modify: `LOW_LATENCY_ACTION_PLAN.md`

**Interfaces:**
- Consumes: all Task 1-5 implementation and verification output.
- Produces: Phase 3 status set to done and a recorded loopback baseline for Phase 4 comparison.

- [ ] **Step 1: Run final acceptance commands**

Run:

```bash
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
node tools/e2e-latency-smoke.mjs --server-exe build/Release/server.exe --probe-exe build/Release/latency_probe.exe --frames 120 --jitter 4 --packets 650 --margin-ms 8
```

Expected:

- Release build succeeds.
- Full `ctest` succeeds.
- The loopback smoke prints `e2e_latency_ms last/avg/max/steady_max` and exits `0`.
- Budget equals `4 * 2.5 ms + 2.5 ms + 2.5 ms + 8 ms = 23 ms`.

- [ ] **Step 2: Run baseline snapshot logging**

Run this if the local machine has usable audio devices:

```bash
node tools/baseline.mjs --seconds 15 --interval-seconds 5 --latency-profile low --skip-inventory --skip-smoke --out-dir validation_logs/phase3-e2e-baseline
```

Expected: `client-a.log` and `client-b.log` contain `Baseline participant` lines with `e2e_ms last/avg/max=` once timestamped packets and server clock sync are active.

If audio devices are unavailable, do not fake this result. Record the headless loopback smoke as the Phase 3 baseline and note that device-backed baseline snapshot capture was blocked by local audio availability.

- [ ] **Step 3: Update Phase 3 status and baseline in the tracker**

In `LOW_LATENCY_ACTION_PLAN.md`, replace the Phase 3 status line with:

```markdown
Status: Done (2026-07-02, Release build + full ctest green, E2E loopback smoke green)
```

Add this under Phase 3 acceptance after the acceptance paragraph, replacing the numeric values with the actual smoke output:

```markdown
Baseline for Phase 4 comparison: 2026-07-02 local loopback E2E smoke,
`node tools/e2e-latency-smoke.mjs --server-exe build/Release/server.exe --probe-exe build/Release/latency_probe.exe --frames 120 --jitter 4 --packets 650 --margin-ms 8`.
Budget: 23.0 ms (10.0 ms jitter target + 2.5 ms packet + 2.5 ms callback + 8.0 ms margin).
```

After the command block, add one concrete sentence copied from the smoke output, for
example: `Measured steady one-way capture-to-playout: avg 14.8 ms, max 18.2 ms; output recorded in validation_logs/phase3-e2e-baseline/e2e-smoke.log.` Use the actual numbers and log path from the execution pass, not the example values.

- [ ] **Step 4: Commit Task 6**

Run:

```bash
git add LOW_LATENCY_ACTION_PLAN.md
git commit -m "docs: record phase 3 e2e latency baseline"
```

---

## Acceptance Checklist

- [ ] New `AUDIO_CAP_CAPTURE_TIMESTAMP` exists and old clients that only know V2 keep receiving V2 audio.
- [ ] New clients advertise timestamp support and receive server support through `JOIN_ACK`.
- [ ] New clients send V3 only when server clock sync is ready and the server negotiated timestamp support.
- [ ] New clients receive both V2 and V3 packets.
- [ ] Sender timestamps are in server-clock domain using `server_clock_offset_ns_`.
- [ ] Receiver playout latency is computed in server-clock domain using the receiver's own `server_clock_offset_ns_`.
- [ ] Opus latency is observed when decoded frames are consumed into the output mix, not merely when packets are dequeued.
- [ ] Per-participant E2E latency appears in the Path panel.
- [ ] Baseline snapshot logs include `e2e_ms last/avg/max=`.
- [ ] `e2e_latency_loopback_smoke` is wired into `ctest`.
- [ ] The loopback smoke asserts steady-state one-way latency <= jitter target + 1 packet + callback duration + margin.
- [ ] Release build and full `ctest` pass after every task.
- [ ] `LOW_LATENCY_ACTION_PLAN.md` Phase 3 status and baseline measurement are updated only after acceptance commands pass.

## Self-Review

- Spec coverage: Phase 3 tracker requirements map to Tasks 1-6. Wire negotiation is Task 1-2. Server-clock stamping and receiver conversion are Task 3. Path panel and baseline logs are Task 4. Loopback ctest budget assertion is Task 5. Tracker status and baseline record are Task 6.
- Red-flag scan: this plan avoids open implementation markers in code steps. Task 6 gives an example tracker sentence but requires concrete measured values before committing.
- Type consistency: timestamp fields use `int64_t` nanoseconds, capability fields use `uint32_t`, packet frame counts use existing `uint16_t`, and UI/log snapshots expose milliseconds as `double`.
