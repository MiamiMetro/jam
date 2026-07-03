# Phase 4 TX Path Collapse Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collapse the client audio transmit path so captured audio is encoded and sent to the server from one prioritized sender thread, without routing audio packets through `asio::post` or allocating packet buffers per packet.

**Architecture:** Keep the existing single UDP socket because the server identifies joined clients by source `ip:port`. The sender thread drains the existing audio queues, encodes Opus into caller-owned storage, writes V2/V3 or redundant datagrams into a preallocated packet-buffer pool, and synchronously calls `socket_.send_to()` under `socket_mutex_` using the existing outbound generation guard. Control traffic keeps the existing async `send()` path on the io thread.

**Tech Stack:** C++23, ASIO UDP, Opus, moodycamel `ConcurrentQueue`, Windows MMCSS via Avrt, CMake/ctest, Node.js validation harnesses.

## Global Constraints

- Current planning base: `main` at `eb624ab`.
- Tracker: `LOW_LATENCY_ACTION_PLAN.md` is authoritative for Phase 4 acceptance.
- Do not add a second client send socket. The server accepts audio only from a registered source endpoint in `server.cpp::handle_audio_message()`, so a second socket would change the source port and break joined-client identity.
- Audio packets must not traverse `asio::post`. `client.cpp::send()` may remain as the control-traffic path for JOIN, LEAVE, ALIVE, metronome sync, and other non-audio messages.
- Audio sends must use the existing `socket_`, `socket_mutex_`, `outbound_enabled_`, `outbound_generation_`, and `current_server_endpoint()` mechanics so rebind, stop, and endpoint-switch behavior stays intact.
- ASIO thread-safety verification: official ASIO `basic_datagram_socket` docs say shared sockets are generally unsafe, but synchronous `send`, `send_to`, `receive`, `receive_from`, and `connect` are thread-safe with each other when the OS calls are thread-safe; `open` and `close` are not thread-safe. This plan still uses `socket_mutex_` because rebind calls `cancel`, `close`, and move-assignment while the sender thread may be active. Source: https://think-async.com/Asio/asio-1.22.2/doc/asio/reference/basic_datagram_socket.html
- Windows sender priority must use MMCSS task name `"Pro Audio"`. Microsoft documents `Audio` and `Pro Audio` as supported task names and `AvSetMmThreadCharacteristics` as the thread opt-in API. Revert with `AvRevertMmThreadCharacteristics` on the same thread before exit. Sources: https://learn.microsoft.com/en-us/windows/win32/procthread/multimedia-class-scheduler-service and https://learn.microsoft.com/en-us/windows/win32/api/avrt/nf-avrt-avsetmmthreadcharacteristicsa
- Packet-buffer allocations in the audio sender hot path must be replaced by fixed storage. This includes plain V2/V3 packet construction, Opus encoded payload storage, recent Opus packet history, and redundancy wrapping.
- The audio callback remains real-time constrained: no blocking locks, no heap allocation, no `Log::` calls, and no object destruction with unknown cost.
- Removing the per-packet `notify_one()` from the audio callback is allowed only if measured send-queue age p99 and Phase 3 E2E latency do not regress. If removing the wake adds latency, keep the existing wake and record why.
- Acceptance commands must include Release build, full `ctest`, Phase 3 E2E smoke comparison, before/after `observe_opus_send_queue_age` p99 comparison, and CI green.

---

## Current HEAD Citation Check

- `LOW_LATENCY_ACTION_PLAN.md` Phase 4 requires capture-to-wire without `asio::post`, bounded allocations, prioritized sender, and measurable p99 send-queue-age improvement against the Phase 3 baseline.
- `LOW_LATENCY_ACTION_PLAN.md` records the Phase 3 E2E baseline command and accepted direct smoke result: last `9.1425 ms`, avg `9.90777 ms`, max and steady max `11.5601 ms`, budget `23.0 ms`.
- `LOW_LATENCY_AUDIT.md` identifies the current TX path as callback enqueue -> sender thread -> Opus encode into `std::vector` -> `create_audio_packet_v2`/V3 `shared_ptr<vector>` -> redundancy allocation -> `send()` -> `asio::post` -> `async_send_to`.
- `client.cpp:1609-1646` currently implements `send()` by copying into a `shared_ptr<vector>` if needed, posting to `io_context_`, taking `socket_mutex_`, and calling `async_send_to`.
- `client.cpp:1996-2067` currently does audio sending in `pcm_sender_loop()`, but still constructs heap-backed packets and calls `send()`.
- `client.cpp:2029` currently allocates/resizes `std::vector<unsigned char> encoded_data` for each Opus packet.
- `client.cpp:2068-2118` currently keeps recent Opus packets as `std::vector<std::shared_ptr<std::vector<unsigned char>>>` and uses `audio_packet::create_redundant_audio_packet()`.
- `client.cpp:2177` currently calls `wake_pcm_sender_thread()`, which calls `pcm_sender_cv_.notify_one()` at `client.cpp:2255-2258`.
- `client.cpp:2731-2740` currently observes Opus send-queue age, but only last/avg/max are stored; no p99 metric exists yet.
- `client.cpp:4846-4852` boosts only the audio callback with `SetThreadPriority`; the sender thread has no priority setup.
- `audio_packet.h:392-429`, `audio_packet.h:464-510`, and `audio_packet.h:523-530` currently allocate packet vectors in the helper APIs.
- `opus_encoder.h:90-113` currently exposes only a vector-writing `encode()` API.
- `cmake/client.cmake` defines and links the client target; it does not link `Avrt.lib`.
- `.github/workflows/ci.yml` already runs Windows Release configure, build, and full `ctest`.

---

## File Structure

- Modify `audio_packet.h`: add non-allocating packet writer helpers for V2, V3, and redundant datagrams while keeping existing `shared_ptr<vector>` helper APIs for tests, probes, and control code that still need them.
- Modify `audio_packet_self_test.cpp`: add tests for the new non-allocating writers, capacity failure, V3 timestamp preservation, and redundancy target-byte truncation.
- Modify `opus_encoder.h`: add a caller-owned output-buffer overload for Opus encoding and keep the existing vector overload as a compatibility wrapper.
- Modify `client.cpp`: add TX packet buffer types, fixed sender-thread pool, fixed recent Opus packet history, synchronous audio send helper, p99 queue-age tracking, sender-thread MMCSS priority setup, optional wake-policy experiment, CLI smoke flag, and baseline log fields.
- Modify `cmake/client.cmake`: link the `client` target with `Avrt.lib` on Windows.
- Modify `CMakeLists.txt`: register the new client smoke test.
- Modify `LOW_LATENCY_ACTION_PLAN.md` only after implementation and verification: set Phase 4 status and record before/after send-queue p99 plus Phase 3 and Phase 4 E2E numbers.
- Create validation output under `validation_logs/phase4-tx-collapse/` during execution, not while writing this plan.

---

### Task 1: Add Real p99 Send-Queue-Age Instrumentation

**Files:**
- Modify: `client.cpp`

**Interfaces:**
- Consumes: `observe_opus_send_queue_age(std::chrono::steady_clock::time_point)`, `PathDiagnostics`, baseline snapshot logging, and existing last/avg/max send-queue-age atomics.
- Produces: `LatencyPercentileWindow`, `observe_opus_send_queue_age()` p99 tracking, `opus_send_queue_p99_ms` in `PathDiagnostics`, and `sendq_age_ms ... opus_p99=` in diagnostics/baseline logs.

- [ ] **Step 1: Add the percentile window type**

Add this helper near `CallbackTimingInfo` and `PathDiagnostics` in `client.cpp`:

```cpp
struct LatencyPercentileWindow {
    static constexpr size_t CAPACITY = 256;

    std::array<int64_t, CAPACITY> samples{};
    size_t next = 0;
    size_t count = 0;
    mutable std::mutex mutex;

    void observe(int64_t sample_ns) {
        std::lock_guard<std::mutex> lock(mutex);
        samples[next] = sample_ns;
        next = (next + 1) % CAPACITY;
        count = std::min(count + 1, CAPACITY);
    }

    int64_t percentile_99_ns() const {
        std::array<int64_t, CAPACITY> copy{};
        size_t local_count = 0;
        {
            std::lock_guard<std::mutex> lock(mutex);
            local_count = count;
            std::copy_n(samples.begin(), local_count, copy.begin());
        }
        if (local_count == 0) {
            return 0;
        }
        std::sort(copy.begin(), copy.begin() + static_cast<std::ptrdiff_t>(local_count));
        const size_t index =
            std::min(local_count - 1, static_cast<size_t>(
                                        std::ceil(static_cast<double>(local_count) * 0.99) - 1.0));
        return copy[index];
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex);
        next = 0;
        count = 0;
        samples.fill(0);
    }
};
```

- [ ] **Step 2: Add the p99 field to diagnostics**

Extend `PathDiagnostics`:

```cpp
double opus_send_queue_p99_ms = 0.0;
```

Set it in `get_path_diagnostics()`:

```cpp
diagnostics.opus_send_queue_p99_ms =
    ns_to_ms(opus_send_queue_age_p99_ns_.load(std::memory_order_relaxed));
```

- [ ] **Step 3: Add storage and observation**

Add fields beside the existing Opus send-queue-age atomics:

```cpp
std::atomic<int64_t> opus_send_queue_age_p99_ns_{0};
LatencyPercentileWindow opus_send_queue_age_window_;
```

Update `observe_opus_send_queue_age()`:

```cpp
void observe_opus_send_queue_age(std::chrono::steady_clock::time_point capture_time) {
    if (capture_time.time_since_epoch().count() == 0) {
        return;
    }

    const auto age_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::steady_clock::now() - capture_time)
                            .count();
    observe_latency_sample(opus_send_queue_age_last_ns_, opus_send_queue_age_avg_ns_,
                           opus_send_queue_age_max_ns_, age_ns);
    opus_send_queue_age_window_.observe(age_ns);
    opus_send_queue_age_p99_ns_.store(opus_send_queue_age_window_.percentile_99_ns(),
                                      std::memory_order_relaxed);
}
```

Clear the window in `clear_audio_path_queues()` after draining `opus_send_queue_`:

```cpp
opus_send_queue_age_window_.clear();
opus_send_queue_age_p99_ns_.store(0, std::memory_order_relaxed);
```

- [ ] **Step 4: Log p99 in health and baseline output**

Change the audio health log from:

```cpp
"sendq_age_ms last/avg/max={:.2f}/{:.2f}/{:.2f} rx_bytes={} tx_bytes={}"
```

to:

```cpp
"sendq_age_ms last/avg/max/opus_p99={:.2f}/{:.2f}/{:.2f}/{:.2f} rx_bytes={} tx_bytes={}"
```

and add:

```cpp
ns_to_ms(opus_send_queue_age_p99_ns_.load(std::memory_order_relaxed)),
```

after the existing `pcm_send_queue_age_max_ns_` argument.

Change the latency log from:

```cpp
"over={} txq_ms pcm={:.3f}/{:.3f}/{:.3f} opus={:.3f}/{:.3f}/{:.3f} "
```

to:

```cpp
"over={} txq_ms pcm={:.3f}/{:.3f}/{:.3f} opus={:.3f}/{:.3f}/{:.3f} opus_p99={:.3f} "
```

and add:

```cpp
ns_to_ms(opus_send_queue_age_p99_ns_.load(std::memory_order_relaxed)),
```

after `opus_send_queue_age_max_ns_`.

Add `opus_p99={:.3f}` to the main baseline snapshot line next to the existing send queue last/avg/max fields, with the same atomic load.

- [ ] **Step 5: Run a focused build**

Run:

```powershell
cmake --build build --config Release --target client --parallel 8
```

Expected: build succeeds.

- [ ] **Step 6: Commit**

```bash
git add client.cpp
git commit -m "feat: add opus send queue p99 metric"
```

---

### Task 2: Add Non-Allocating Packet Writers

**Files:**
- Modify: `audio_packet.h`
- Modify: `audio_packet_self_test.cpp`

**Interfaces:**
- Consumes: existing `AudioHdrV2`, `AudioHdrV3`, `AudioRedundantHdr`, `validate_audio_packet_bytes()`, `validate_redundant_audio_packet_bytes()`, and existing allocating helper signatures.
- Produces: `audio_packet::AudioPacketView`, `audio_packet::write_audio_packet_v2()`, `audio_packet::write_audio_packet_v3()`, and `audio_packet::write_redundant_audio_packet()`.

- [ ] **Step 1: Add failing tests for non-allocating writers**

Add these tests to `audio_packet_self_test.cpp` and call them from `main()` before the existing success message:

```cpp
void test_write_audio_packet_v3_into_caller_buffer() {
    std::array<unsigned char, 128> out{};
    const std::array<unsigned char, 4> payload{0x10, 0x20, 0x30, 0x40};
    size_t bytes_written = 0;

    require(audio_packet::write_audio_packet_v3(
                AudioCodec::Opus, 42, 48000, 120, 1, payload.data(),
                static_cast<uint16_t>(payload.size()), 123456789LL,
                out.data(), out.size(), bytes_written),
            "write_audio_packet_v3 should fit in caller buffer");
    require(bytes_written == audio_packet::v3_header_size() + payload.size(),
            "V3 writer should report exact packet size");
    require(audio_packet::validate_audio_packet_bytes(out.data(), bytes_written),
            "V3 writer should produce a valid packet");

    const auto parsed = audio_packet::parse_audio_header(out.data(), bytes_written);
    require(parsed.valid, "V3 writer parsed header should be valid");
    require(parsed.magic == AUDIO_V3_MAGIC, "V3 writer should preserve magic");
    require(parsed.sequence == 42, "V3 writer should preserve sequence");
    require(parsed.capture_server_time_ns == 123456789LL,
            "V3 writer should preserve capture timestamp");
    require(std::memcmp(audio_packet::audio_payload(out.data(), bytes_written),
                        payload.data(), payload.size()) == 0,
            "V3 writer should copy payload bytes");
}

void test_write_audio_packet_capacity_failure() {
    std::array<unsigned char, 8> out{};
    const std::array<unsigned char, 4> payload{0xAA, 0xBB, 0xCC, 0xDD};
    size_t bytes_written = 99;

    require(!audio_packet::write_audio_packet_v2(
                AudioCodec::Opus, 7, 48000, 120, 1, payload.data(),
                static_cast<uint16_t>(payload.size()),
                out.data(), out.size(), bytes_written),
            "V2 writer should fail when output buffer is too small");
    require(bytes_written == 0, "failed writer should zero bytes_written");
}

void test_write_redundant_audio_packet_into_caller_buffer() {
    std::array<unsigned char, 128> current{};
    std::array<unsigned char, 128> previous{};
    std::array<unsigned char, 256> redundant{};
    const std::array<unsigned char, 3> payload{0x01, 0x02, 0x03};
    size_t current_bytes = 0;
    size_t previous_bytes = 0;
    size_t redundant_bytes = 0;

    require(audio_packet::write_audio_packet_v3(
                AudioCodec::Opus, 11, 48000, 120, 1, payload.data(),
                static_cast<uint16_t>(payload.size()), 1111,
                current.data(), current.size(), current_bytes),
            "current V3 should write");
    require(audio_packet::write_audio_packet_v3(
                AudioCodec::Opus, 10, 48000, 120, 1, payload.data(),
                static_cast<uint16_t>(payload.size()), 1010,
                previous.data(), previous.size(), previous_bytes),
            "previous V3 should write");

    const audio_packet::AudioPacketView views[] = {
        {current.data(), current_bytes},
        {previous.data(), previous_bytes},
    };
    require(audio_packet::write_redundant_audio_packet(
                views, 2, redundant.data(), redundant.size(),
                AUDIO_REDUNDANT_TARGET_BYTES, redundant_bytes),
            "redundant writer should fit in caller buffer");
    require(audio_packet::validate_redundant_audio_packet_bytes(
                redundant.data(), redundant_bytes),
            "redundant writer should produce a valid datagram");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```powershell
cmake --build build --config Release --target audio_packet_self_test --parallel 8
```

Expected: compile fails because the non-allocating writer APIs do not exist.

- [ ] **Step 3: Implement the writer APIs**

Add this to `audio_packet.h` before the existing allocating creation helpers:

```cpp
struct AudioPacketView {
    const unsigned char* data = nullptr;
    size_t size = 0;
};

inline bool write_audio_packet_v2(AudioCodec codec, uint32_t sequence, uint32_t sample_rate,
                                  uint16_t frame_count, uint8_t channels,
                                  const unsigned char* payload, uint16_t payload_bytes,
                                  unsigned char* out, size_t out_capacity,
                                  size_t& bytes_written) {
    bytes_written = 0;
    const size_t required = v2_header_size() + payload_bytes;
    if (out == nullptr || out_capacity < required ||
        (payload_bytes > 0 && payload == nullptr)) {
        return false;
    }

    AudioHdrV2 hdr{};
    hdr.magic = AUDIO_V2_MAGIC;
    hdr.sender_id = 0;
    hdr.sequence = sequence;
    hdr.sample_rate = sample_rate;
    hdr.frame_count = frame_count;
    hdr.payload_bytes = payload_bytes;
    hdr.channels = channels;
    hdr.codec = codec;

    std::memcpy(out, &hdr, v2_header_size());
    if (payload_bytes > 0) {
        std::memcpy(out + v2_header_size(), payload, payload_bytes);
    }
    bytes_written = required;
    return true;
}

inline bool write_audio_packet_v3(AudioCodec codec, uint32_t sequence, uint32_t sample_rate,
                                  uint16_t frame_count, uint8_t channels,
                                  const unsigned char* payload, uint16_t payload_bytes,
                                  int64_t capture_server_time_ns,
                                  unsigned char* out, size_t out_capacity,
                                  size_t& bytes_written) {
    bytes_written = 0;
    const size_t required = v3_header_size() + payload_bytes;
    if (out == nullptr || out_capacity < required ||
        (payload_bytes > 0 && payload == nullptr)) {
        return false;
    }

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

    std::memcpy(out, &hdr, v3_header_size());
    if (payload_bytes > 0) {
        std::memcpy(out + v3_header_size(), payload, payload_bytes);
    }
    bytes_written = required;
    return true;
}

inline bool write_redundant_audio_packet(const AudioPacketView* packets, size_t packet_count,
                                         unsigned char* out, size_t out_capacity,
                                         size_t max_packet_bytes,
                                         size_t& bytes_written) {
    bytes_written = 0;
    if (packets == nullptr || packet_count == 0 ||
        packet_count > MAX_AUDIO_REDUNDANT_PACKETS || out == nullptr ||
        out_capacity < redundant_header_size()) {
        return false;
    }

    size_t total_bytes = redundant_header_size();
    size_t selected_count = 0;
    for (size_t i = 0; i < packet_count; ++i) {
        const auto& packet = packets[i];
        if (packet.data == nullptr ||
            !validate_audio_packet_bytes(packet.data, packet.size)) {
            return false;
        }
        if (max_packet_bytes > 0 && total_bytes + packet.size > max_packet_bytes) {
            if (selected_count == 0) {
                return false;
            }
            break;
        }
        if (total_bytes + packet.size > out_capacity) {
            return false;
        }
        total_bytes += packet.size;
        ++selected_count;
    }

    AudioRedundantHdr hdr{};
    hdr.magic = AUDIO_REDUNDANT_MAGIC;
    hdr.packet_count = static_cast<uint8_t>(selected_count);
    std::memcpy(out, &hdr, redundant_header_size());

    size_t offset = redundant_header_size();
    for (size_t i = 0; i < selected_count; ++i) {
        std::memcpy(out + offset, packets[i].data, packets[i].size);
        offset += packets[i].size;
    }
    bytes_written = total_bytes;
    return true;
}
```

- [ ] **Step 4: Make existing allocating helpers call the writers**

Change `create_audio_packet_v2()` to allocate once and call `write_audio_packet_v2()`:

```cpp
auto packet = std::make_shared<std::vector<unsigned char>>();
packet->resize(v2_header_size() + payload_bytes);
size_t bytes_written = 0;
if (!write_audio_packet_v2(codec, sequence, sample_rate, frame_count, channels,
                           payload, payload_bytes, packet->data(), packet->size(),
                           bytes_written)) {
    return nullptr;
}
packet->resize(bytes_written);
return packet;
```

Change `create_audio_packet_v3()` the same way with `write_audio_packet_v3()`.

Change `create_redundant_audio_packet()` to build a small stack array of `AudioPacketView` and call `write_redundant_audio_packet()` after selecting packet count. Keep its public behavior unchanged.

- [ ] **Step 5: Run tests**

Run:

```powershell
cmake --build build --config Release --target audio_packet_self_test --parallel 8
ctest --test-dir build -C Release -R audio_packet_self_test --output-on-failure
```

Expected: test passes.

- [ ] **Step 6: Commit**

```bash
git add audio_packet.h audio_packet_self_test.cpp
git commit -m "feat: add nonalloc audio packet writers"
```

---

### Task 3: Add Caller-Owned Opus Encode API

**Files:**
- Modify: `opus_encoder.h`
- Modify: `client.cpp`

**Interfaces:**
- Consumes: existing `OpusEncoderWrapper::encode(const float*, int, std::vector<unsigned char>&)`.
- Produces: `OpusEncoderWrapper::encode(const float*, int, unsigned char*, size_t, uint16_t&)`.

- [ ] **Step 1: Write a failing client smoke for buffer encode**

Add this static method to `Client` near the existing smoke methods:

```cpp
static bool run_opus_encode_buffer_smoke(std::string& failure) {
    OpusEncoderWrapper encoder;
    if (!encoder.create(opus_network_clock::SAMPLE_RATE, 1,
                        OPUS_APPLICATION_RESTRICTED_LOWDELAY,
                        AudioStream::AudioConfig::DEFAULT_BITRATE,
                        AudioStream::AudioConfig::DEFAULT_COMPLEXITY)) {
        failure = "failed to create Opus encoder";
        return false;
    }

    std::array<float, opus_network_clock::LOW_LATENCY_FRAME_COUNT> input{};
    std::array<unsigned char, AUDIO_BUF_SIZE> output{};
    uint16_t encoded_bytes = 0;
    if (!encoder.encode(input.data(), static_cast<int>(input.size()),
                        output.data(), output.size(), encoded_bytes)) {
        failure = "caller-owned encode failed";
        return false;
    }
    if (encoded_bytes == 0 || encoded_bytes > output.size()) {
        failure = "caller-owned encode returned invalid size";
        return false;
    }
    return true;
}
```

Wire it to a CLI flag `--opus-encode-buffer-smoke` in `ClientStartupOptions`, `parse_args()`, and `main()`.

- [ ] **Step 2: Register the smoke**

Add to `CMakeLists.txt` inside `if(TARGET client)`:

```cmake
add_test(NAME client_opus_encode_buffer_smoke
         COMMAND $<TARGET_FILE:client> --opus-encode-buffer-smoke)
```

- [ ] **Step 3: Run test to verify it fails**

Run:

```powershell
cmake --build build --config Release --target client --parallel 8
ctest --test-dir build -C Release -R client_opus_encode_buffer_smoke --output-on-failure
```

Expected: compile fails because the caller-owned overload does not exist.

- [ ] **Step 4: Implement the overload**

Add this overload to `OpusEncoderWrapper` before the vector overload:

```cpp
bool encode(const float* input, int frame_size, unsigned char* output,
            size_t output_capacity, uint16_t& encoded_bytes) {
    encoded_bytes = 0;
    if (encoder_ == nullptr) {
        Log::error("Opus encoder not initialized.");
        return false;
    }
    if (output == nullptr || output_capacity == 0 ||
        output_capacity > static_cast<size_t>(std::numeric_limits<opus_int32>::max())) {
        Log::error("Invalid Opus output buffer.");
        return false;
    }
    if (!is_legal_frame_size(sample_rate_, frame_size)) {
        Log::error("Illegal Opus frame size: {} samples at {} Hz", frame_size, sample_rate_);
        return false;
    }

    const int result = opus_encode_float(
        encoder_, input, frame_size, output,
        static_cast<opus_int32>(output_capacity));
    if (result < 0) {
        Log::error("Opus encoding failed: {}", opus_strerror(result));
        return false;
    }
    encoded_bytes = static_cast<uint16_t>(result);
    return true;
}
```

Add `#include <limits>` to `opus_encoder.h`.

- [ ] **Step 5: Keep vector API as wrapper**

Replace the body of the existing vector overload with:

```cpp
bool encode(const float* input, int frame_size, std::vector<unsigned char>& output) {
    output.resize(ENCODE_BUFFER_SIZE);
    uint16_t encoded_bytes = 0;
    if (!encode(input, frame_size, output.data(), output.size(), encoded_bytes)) {
        output.clear();
        return false;
    }
    output.resize(encoded_bytes);
    return true;
}
```

- [ ] **Step 6: Run tests**

Run:

```powershell
cmake --build build --config Release --target client --parallel 8
ctest --test-dir build -C Release -R client_opus_encode_buffer_smoke --output-on-failure
```

Expected: test passes.

- [ ] **Step 7: Commit**

```bash
git add opus_encoder.h client.cpp CMakeLists.txt
git commit -m "feat: encode opus into caller buffers"
```

---

### Task 4: Add TX Packet Pool And Redundancy Ring

**Files:**
- Modify: `client.cpp`

**Interfaces:**
- Consumes: Task 2 writer APIs and Task 3 Opus buffer encode API.
- Produces: `TxPacketBuffer`, `TxPacketBufferPool`, fixed recent Opus packet ring, and non-allocating `build_audio_packet_into()` / `maybe_wrap_opus_packet_with_redundancy()` paths.

- [ ] **Step 1: Add fixed TX packet storage**

Add these declarations inside `Client` near `PcmSendFrame` and `OpusSendFrame`:

```cpp
static constexpr size_t TX_PACKET_BUFFER_BYTES = AUDIO_REDUNDANT_TARGET_BYTES;
static constexpr size_t TX_PACKET_POOL_SIZE = 8;
static constexpr size_t RECENT_OPUS_PACKET_SLOTS =
    static_cast<size_t>(MAX_AUDIO_REDUNDANT_PACKETS) - 1;

struct TxPacketBuffer {
    std::array<unsigned char, TX_PACKET_BUFFER_BYTES> bytes{};
    size_t size = 0;

    unsigned char* data() {
        return bytes.data();
    }

    const unsigned char* data() const {
        return bytes.data();
    }

    size_t capacity() const {
        return bytes.size();
    }

    audio_packet::AudioPacketView view() const {
        return audio_packet::AudioPacketView{bytes.data(), size};
    }
};

class TxPacketBufferPool {
public:
    TxPacketBufferPool() {
        for (size_t i = 0; i < free_indices_.size(); ++i) {
            free_indices_[i] = free_indices_.size() - 1 - i;
        }
        free_count_ = free_indices_.size();
    }

    TxPacketBuffer* acquire() {
        if (free_count_ == 0) {
            return nullptr;
        }
        TxPacketBuffer& buffer = buffers_[free_indices_[--free_count_]];
        buffer.size = 0;
        return &buffer;
    }

    void release(TxPacketBuffer* buffer) {
        if (buffer == nullptr) {
            return;
        }
        const auto index = static_cast<size_t>(buffer - buffers_.data());
        if (index >= buffers_.size() || free_count_ >= free_indices_.size()) {
            return;
        }
        buffer->size = 0;
        free_indices_[free_count_++] = index;
    }

private:
    std::array<TxPacketBuffer, TX_PACKET_POOL_SIZE> buffers_{};
    std::array<size_t, TX_PACKET_POOL_SIZE> free_indices_{};
    size_t free_count_ = 0;
};

class TxPacketLease {
public:
    explicit TxPacketLease(TxPacketBufferPool& pool) : pool_(&pool), buffer_(pool.acquire()) {}
    ~TxPacketLease() {
        if (pool_ != nullptr) {
            pool_->release(buffer_);
        }
    }
    TxPacketLease(const TxPacketLease&) = delete;
    TxPacketLease& operator=(const TxPacketLease&) = delete;

    TxPacketBuffer* get() const {
        return buffer_;
    }

    TxPacketBuffer& operator*() const {
        return *buffer_;
    }

    TxPacketBuffer* operator->() const {
        return buffer_;
    }

private:
    TxPacketBufferPool* pool_ = nullptr;
    TxPacketBuffer* buffer_ = nullptr;
};
```

- [ ] **Step 2: Replace recent Opus packet storage**

Replace:

```cpp
std::vector<std::shared_ptr<std::vector<unsigned char>>> recent_opus_audio_packets_;
```

with:

```cpp
std::array<TxPacketBuffer, RECENT_OPUS_PACKET_SLOTS> recent_opus_audio_packets_{};
size_t recent_opus_audio_packet_count_ = 0;
```

Change every `.clear()` call on `recent_opus_audio_packets_` to:

```cpp
recent_opus_audio_packet_count_ = 0;
```

- [ ] **Step 3: Add non-allocating audio packet builders**

Add this helper:

```cpp
bool build_audio_packet_into(TxPacketBuffer& out, AudioCodec codec, uint32_t sequence,
                             uint32_t sample_rate, uint16_t frame_count, uint8_t channels,
                             const unsigned char* payload, uint16_t payload_bytes,
                             std::chrono::steady_clock::time_point capture_time) const {
    const auto capture_server_time_ns =
        capture_timestamp_for_steady_time_if_ready(capture_time);
    if (capture_server_time_ns.has_value()) {
        return audio_packet::write_audio_packet_v3(
            codec, sequence, sample_rate, frame_count, channels, payload, payload_bytes,
            *capture_server_time_ns, out.data(), out.capacity(), out.size);
    }
    return audio_packet::write_audio_packet_v2(
        codec, sequence, sample_rate, frame_count, channels, payload, payload_bytes,
        out.data(), out.capacity(), out.size);
}
```

- [ ] **Step 4: Add non-allocating redundancy helpers**

Replace `maybe_wrap_opus_packet_with_redundancy()` and `remember_recent_opus_audio_packet()` with:

```cpp
TxPacketBuffer* maybe_wrap_opus_packet_with_redundancy(
    const TxPacketBuffer& packet, TxPacketBuffer& redundant_out) {
    if (!join_state_.server_supports(AUDIO_CAP_REDUNDANCY)) {
        recent_opus_audio_packet_count_ = 0;
        return nullptr;
    }

    const auto parsed = audio_packet::parse_audio_header(packet.data(), packet.size);
    if (!parsed.valid) {
        return nullptr;
    }

    const int configured_depth = get_opus_redundancy_depth_setting();
    const int effective_depth =
        effective_opus_redundancy_depth(configured_depth, parsed.frame_count);
    if (effective_depth <= 0) {
        recent_opus_audio_packet_count_ = 0;
        return nullptr;
    }

    const size_t child_count = opus_redundancy_child_count_for_policy(
        configured_depth, parsed.frame_count, recent_opus_audio_packet_count_);

    std::array<audio_packet::AudioPacketView, MAX_AUDIO_REDUNDANT_PACKETS> views{};
    size_t view_count = 0;
    views[view_count++] = packet.view();
    for (size_t i = 0; i < recent_opus_audio_packet_count_ && view_count < child_count; ++i) {
        views[view_count++] = recent_opus_audio_packets_[i].view();
    }
    if (view_count <= 1) {
        return nullptr;
    }

    size_t bytes_written = 0;
    if (!audio_packet::write_redundant_audio_packet(
            views.data(), view_count, redundant_out.data(), redundant_out.capacity(),
            AUDIO_REDUNDANT_TARGET_BYTES, bytes_written)) {
        return nullptr;
    }
    redundant_out.size = bytes_written;
    return &redundant_out;
}

void remember_recent_opus_audio_packet(const TxPacketBuffer& packet) {
    if (packet.size == 0) {
        return;
    }
    const size_t limit = recent_opus_audio_packets_.size();
    const size_t move_count = std::min(recent_opus_audio_packet_count_, limit - 1);
    for (size_t i = move_count; i > 0; --i) {
        recent_opus_audio_packets_[i] = recent_opus_audio_packets_[i - 1];
    }
    recent_opus_audio_packets_[0] = packet;
    recent_opus_audio_packet_count_ =
        std::min(recent_opus_audio_packet_count_ + 1, limit);
}
```

- [ ] **Step 5: Convert the sender loop to pool-backed packet construction**

At the top of `pcm_sender_loop()` add:

```cpp
TxPacketBufferPool packet_pool;
std::array<unsigned char, AUDIO_BUF_SIZE> encoded_data{};
```

Replace PCM packet construction in the `pcm_send_queue_` branch with:

```cpp
TxPacketLease packet(packet_pool);
if (packet.get() == nullptr) {
    pcm_send_drops_.fetch_add(1, std::memory_order_relaxed);
    continue;
}

const uint32_t seq = audio_tx_sequence_.fetch_add(1, std::memory_order_relaxed);
if (!build_audio_packet_into(*packet, AudioCodec::PcmInt16, seq, frame.sample_rate,
                             frame.frame_count, 1, frame.payload.data(),
                             frame.payload_bytes, frame.capture_time)) {
    pcm_send_drops_.fetch_add(1, std::memory_order_relaxed);
    continue;
}
observe_audio_packet_send_pacing();
send_audio_packet_sync(packet->data(), packet->size);
```

Replace the Opus branch allocation:

```cpp
std::vector<unsigned char> encoded_data;
```

with:

```cpp
uint16_t encoded_bytes = 0;
```

and replace the encode/packet path with:

```cpp
if (audio_encoder_.encode(opus_frame.samples.data(), opus_frame.frame_count,
                          encoded_data.data(), encoded_data.size(), encoded_bytes) &&
    encoded_bytes <= AUDIO_BUF_SIZE) {
    observe_tx_encode_time(std::chrono::steady_clock::now() - encode_start);
    TxPacketLease packet(packet_pool);
    TxPacketLease redundant_packet(packet_pool);
    if (packet.get() == nullptr || redundant_packet.get() == nullptr) {
        opus_send_drops_.fetch_add(1, std::memory_order_relaxed);
        continue;
    }

    const uint32_t seq = audio_tx_sequence_.fetch_add(1, std::memory_order_relaxed);
    if (!build_audio_packet_into(*packet, AudioCodec::Opus, seq, opus_frame.sample_rate,
                                 opus_frame.frame_count, 1, encoded_data.data(),
                                 encoded_bytes, opus_frame.capture_time)) {
        opus_send_drops_.fetch_add(1, std::memory_order_relaxed);
        continue;
    }

    TxPacketBuffer* send_packet =
        maybe_wrap_opus_packet_with_redundancy(*packet, *redundant_packet);
    if (send_packet == nullptr) {
        send_packet = packet.get();
    }
    observe_audio_packet_send_pacing();
    send_audio_packet_sync(send_packet->data(), send_packet->size);
    remember_recent_opus_audio_packet(*packet);
} else {
    observe_tx_encode_time(std::chrono::steady_clock::now() - encode_start);
}
```

`send_audio_packet_sync()` is introduced in Task 5. In this task, add a temporary private declaration with the final signature but leave the call sites ready for Task 5.

- [ ] **Step 6: Build to expose missing sync send**

Run:

```powershell
cmake --build build --config Release --target client --parallel 8
```

Expected: compile fails at `send_audio_packet_sync()` if Task 5 has not been implemented in the same execution batch. If using subagents, stop here and pass the compile failure to Task 5. If executing inline, continue directly into Task 5 before committing.

- [ ] **Step 7: Commit after Task 5 passes**

Do not commit a non-building state. Commit this task together with Task 5 if using inline execution:

```bash
git add client.cpp
git commit -m "feat: pool audio tx packet buffers"
```

---

### Task 5: Send Audio Synchronously From The Sender Thread

**Files:**
- Modify: `client.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: Task 4 sender-loop call sites, existing `send()` control path, `socket_mutex_`, `current_server_endpoint()`, `outbound_enabled_`, `outbound_generation_`, and `validate_outbound_audio_packet()`.
- Produces: `send_audio_packet_sync(const unsigned char*, size_t)`, `client_udp_audio_sync_send_smoke`, and no audio sender-loop calls to `send()`.

- [ ] **Step 1: Add a failing smoke for sync audio send**

Add this static method to `Client` near the other smoke methods:

```cpp
static bool run_udp_audio_sync_send_smoke(std::string& failure) {
    asio::io_context io_context;
    asio::io_context aux_context;

    udp::socket dummy_server(aux_context);
    uint16_t dummy_port = 0;
    if (!bind_udp_socket_in_range(dummy_server, 19300, 19350, dummy_port)) {
        failure = "could not bind dummy server port";
        return false;
    }

    PerformerJoinOptions join_options{};
    Client client(io_context, "127.0.0.1", dummy_port, join_options);
    client.join_state_.mark_join_ack(1, AUDIO_SUPPORTED_CAPABILITIES);
    client.server_clock_ready_.store(true, std::memory_order_release);

    std::array<unsigned char, 128> packet{};
    const std::array<unsigned char, 3> payload{0x31, 0x32, 0x33};
    size_t packet_bytes = 0;
    if (!audio_packet::write_audio_packet_v3(
            AudioCodec::Opus, 99, opus_network_clock::SAMPLE_RATE,
            opus_network_clock::LOW_LATENCY_FRAME_COUNT, 1, payload.data(),
            static_cast<uint16_t>(payload.size()), 12345,
            packet.data(), packet.size(), packet_bytes)) {
        failure = "failed to build V3 packet";
        client.stop_connection();
        return false;
    }

    client.send_audio_packet_sync(packet.data(), packet_bytes);

    dummy_server.non_blocking(true);
    const auto deadline = std::chrono::steady_clock::now() + 500ms;
    std::array<unsigned char, 256> received{};
    udp::endpoint sender;
    bool got_packet = false;
    while (std::chrono::steady_clock::now() < deadline) {
        std::error_code ec;
        const size_t bytes = dummy_server.receive_from(asio::buffer(received), sender, 0, ec);
        if (!ec && bytes == packet_bytes &&
            std::memcmp(received.data(), packet.data(), packet_bytes) == 0) {
            got_packet = true;
            break;
        }
        if (ec != asio::error::would_block && ec != asio::error::try_again) {
            failure = "dummy receive failed: " + ec.message();
            client.stop_connection();
            return false;
        }
        std::this_thread::sleep_for(1ms);
    }

    client.stop_connection();
    if (!got_packet) {
        failure = "sync audio packet was not received without running io_context";
        return false;
    }
    return true;
}
```

Wire it to CLI flag `--udp-audio-sync-send-smoke` and add to `CMakeLists.txt`:

```cmake
add_test(NAME client_udp_audio_sync_send_smoke
         COMMAND $<TARGET_FILE:client> --udp-audio-sync-send-smoke)
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```powershell
cmake --build build --config Release --target client --parallel 8
ctest --test-dir build -C Release -R client_udp_audio_sync_send_smoke --output-on-failure
```

Expected before implementation: compile fails because `send_audio_packet_sync()` does not exist, or runtime fails if it accidentally uses the posted `send()` path without running `io_context`.

- [ ] **Step 3: Implement synchronous audio send**

Add this private method next to `send()`:

```cpp
void send_audio_packet_sync(const unsigned char* data, std::size_t len) {
    if (data == nullptr || !validate_outbound_audio_packet(
                               const_cast<unsigned char*>(data), len)) {
        return;
    }
    if (!outbound_enabled_.load(std::memory_order_acquire)) {
        return;
    }

    const auto target = current_server_endpoint();
    const auto outbound_generation =
        outbound_generation_.load(std::memory_order_acquire);

    std::error_code error_code;
    {
        std::lock_guard<std::mutex> lock(socket_mutex_);
        if (!outbound_enabled_.load(std::memory_order_acquire) ||
            outbound_generation !=
                outbound_generation_.load(std::memory_order_acquire)) {
            return;
        }
        socket_.send_to(asio::buffer(data, len), target, 0, error_code);
    }

    if (!error_code) {
        total_bytes_tx_.fetch_add(len, std::memory_order_relaxed);
        return;
    }
    if (error_code != asio::error::would_block &&
        error_code != asio::error::try_again &&
        error_code != asio::error::operation_aborted &&
        outbound_enabled_.load(std::memory_order_acquire)) {
        Log::error("audio send error: {}", error_code.message());
    }
}
```

Keep `send()` unchanged for control traffic.

- [ ] **Step 4: Verify audio sender-loop call sites no longer call `send()`**

In `pcm_sender_loop()`, there must be no call like:

```cpp
send(packet->data(), packet->size(), packet);
send(send_packet->data(), send_packet->size(), send_packet);
```

The only audio send calls in the sender loop should be:

```cpp
send_audio_packet_sync(packet->data(), packet->size);
send_audio_packet_sync(send_packet->data(), send_packet->size);
```

- [ ] **Step 5: Run source check**

Run:

```powershell
rg -n "send\\((send_packet|packet)->data|asio::post\\(io_context_" client.cpp
```

Expected: `asio::post(io_context_` remains for control/rebind paths, but there are no `send(packet->data()` or `send(send_packet->data()` calls in `pcm_sender_loop()`.

- [ ] **Step 6: Run tests**

Run:

```powershell
cmake --build build --config Release --target client --parallel 8
ctest --test-dir build -C Release -R "client_udp_audio_sync_send_smoke|client_udp_endpoint_guard_smoke|client_opus_redundancy_policy_smoke|client_audio_v3_receive_smoke" --output-on-failure
```

Expected: all selected tests pass. `client_udp_endpoint_guard_smoke` must still pass because control `send()` remains async and generation-guarded.

- [ ] **Step 7: Commit**

```bash
git add client.cpp CMakeLists.txt
git commit -m "feat: send audio packets from sender thread"
```

---

### Task 6: Raise Sender Thread Priority With MMCSS

**Files:**
- Modify: `client.cpp`
- Modify: `cmake/client.cmake`

**Interfaces:**
- Consumes: `start_pcm_sender_thread()`, `pcm_sender_loop()`, Windows APIs already included in `client.cpp`.
- Produces: `ScopedMmcssThreadPriority` and sender-thread `"Pro Audio"` MMCSS registration on Windows.

- [ ] **Step 1: Add Windows Avrt include and link**

In `client.cpp`, under the existing Windows includes, add:

```cpp
#include <avrt.h>
```

In `cmake/client.cmake`, add after `target_link_libraries(client PRIVATE ...)`:

```cmake
if(WIN32)
    target_link_libraries(client PRIVATE Avrt)
endif()
```

- [ ] **Step 2: Add scoped MMCSS helper**

Add this private helper inside `Client` before `pcm_sender_loop()`:

```cpp
class ScopedSenderThreadPriority {
public:
    ScopedSenderThreadPriority() {
#ifdef _WIN32
        DWORD task_index = 0;
        handle_ = AvSetMmThreadCharacteristicsA("Pro Audio", &task_index);
        if (handle_ != nullptr) {
            AvSetMmThreadPriority(handle_, AVRT_PRIORITY_HIGH);
        } else {
            SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
        }
#endif
    }

    ~ScopedSenderThreadPriority() {
#ifdef _WIN32
        if (handle_ != nullptr) {
            AvRevertMmThreadCharacteristics(handle_);
        }
#endif
    }

    ScopedSenderThreadPriority(const ScopedSenderThreadPriority&) = delete;
    ScopedSenderThreadPriority& operator=(const ScopedSenderThreadPriority&) = delete;

private:
#ifdef _WIN32
    HANDLE handle_ = nullptr;
#endif
};
```

Use `AVRT_PRIORITY_HIGH` first. Do not use `AVRT_PRIORITY_CRITICAL` unless validation shows high is insufficient; the audio callback is already the true real-time deadline owner.

- [ ] **Step 3: Apply priority at sender-loop entry**

At the start of `pcm_sender_loop()` add:

```cpp
ScopedSenderThreadPriority sender_priority;
```

before creating `TxPacketBufferPool packet_pool`.

- [ ] **Step 4: Build and run focused tests**

Run:

```powershell
cmake --build build --config Release --target client --parallel 8
ctest --test-dir build -C Release -R "client_udp_audio_sync_send_smoke|client_opus_encode_buffer_smoke" --output-on-failure
```

Expected: tests pass on Windows. On non-Windows, the helper compiles to a no-op and no Avrt link is required.

- [ ] **Step 5: Commit**

```bash
git add client.cpp cmake/client.cmake
git commit -m "feat: boost audio sender thread priority"
```

---

### Task 7: Evaluate Removing Callback `notify_one()`

**Files:**
- Modify if accepted: `client.cpp`
- Modify after validation: `LOW_LATENCY_ACTION_PLAN.md`

**Interfaces:**
- Consumes: `enqueue_pcm_send_frame()`, `enqueue_opus_send_frame()`, `wake_pcm_sender_thread()`, `pcm_sender_cv_`, p99 metric from Task 1, and Phase 3 E2E smoke.
- Produces: either a landed no-notify sender wait policy or a recorded decision to keep `notify_one()` because latency regressed.

- [ ] **Step 1: Add a compile-time experiment switch**

Add near the other constants:

```cpp
constexpr bool EXPERIMENT_DISABLE_AUDIO_CALLBACK_NOTIFY = false;
```

Change `wake_pcm_sender_thread()` to:

```cpp
void wake_pcm_sender_thread() {
    pcm_sender_wake_.store(true, std::memory_order_release);
    if constexpr (!EXPERIMENT_DISABLE_AUDIO_CALLBACK_NOTIFY) {
        pcm_sender_cv_.notify_one();
    }
}
```

- [ ] **Step 2: Run baseline with notifications still enabled**

Run:

```powershell
$env:JAM_SERVER_EXE='build/Release/server.exe'
$env:JAM_CLIENT_EXE='build/Release/client.exe'
node tools/baseline.mjs --seconds 30 --interval-seconds 5 --frames 120 --codec opus --latency-profile low --jitter 4 --out-dir validation_logs/phase4-tx-collapse/notify-enabled
```

Expected: `client-a.log` and `client-b.log` contain `opus_p99=` values in baseline or latency diagnostics.

- [ ] **Step 3: Test no-notify locally**

Temporarily set:

```cpp
constexpr bool EXPERIMENT_DISABLE_AUDIO_CALLBACK_NOTIFY = true;
```

Build and run the same baseline:

```powershell
cmake --build build --config Release --target client server --parallel 8
$env:JAM_SERVER_EXE='build/Release/server.exe'
$env:JAM_CLIENT_EXE='build/Release/client.exe'
node tools/baseline.mjs --seconds 30 --interval-seconds 5 --frames 120 --codec opus --latency-profile low --jitter 4 --out-dir validation_logs/phase4-tx-collapse/notify-disabled
```

Expected for landing removal: Opus send-queue p99 is no worse than the notify-enabled run by more than `0.10 ms`, no callback over-deadline increase is visible, and there are no new send drops.

- [ ] **Step 4: Keep or revert based on the measured result**

If no-notify passes the criterion, keep `EXPERIMENT_DISABLE_AUDIO_CALLBACK_NOTIFY = true`, rename it to:

```cpp
constexpr bool AUDIO_CALLBACK_NOTIFY_ENABLED = false;
```

and change the branch to:

```cpp
if constexpr (AUDIO_CALLBACK_NOTIFY_ENABLED) {
    pcm_sender_cv_.notify_one();
}
```

If no-notify fails the criterion, restore:

```cpp
constexpr bool AUDIO_CALLBACK_NOTIFY_ENABLED = true;
```

and keep the `notify_one()` path. Record in the tracker that Phase 4 evaluated removal but retained notification because the sender queue p99 or E2E number regressed.

- [ ] **Step 5: Run E2E smoke after the decision**

Run:

```powershell
node tools/e2e-latency-smoke.mjs --server-exe build/Release/server.exe --probe-exe build/Release/latency_probe.exe --frames 120 --jitter 4 --packets 650 --margin-ms 8
```

Expected: smoke passes under the `23.0 ms` budget.

- [ ] **Step 6: Commit**

```bash
git add client.cpp LOW_LATENCY_ACTION_PLAN.md
git commit -m "chore: evaluate audio callback wake policy"
```

---

### Task 8: Record Before/After Metrics And Tracker Acceptance

**Files:**
- Modify: `LOW_LATENCY_ACTION_PLAN.md`
- Create during execution: `validation_logs/phase4-tx-collapse/before/`
- Create during execution: `validation_logs/phase4-tx-collapse/after/`

**Interfaces:**
- Consumes: p99 logs from Task 1, TX path changes from Tasks 4-6, optional wake decision from Task 7, and Phase 3 baseline in `LOW_LATENCY_ACTION_PLAN.md`.
- Produces: Phase 4 tracker entry with status, before/after send-queue p99, Phase 3 E2E baseline, Phase 4 E2E result, and validation command references.

- [ ] **Step 1: Capture before metrics if not already captured**

If Task 7 did not produce a clean before log with the final p99 field before the path collapse, use the earliest p99-enabled pre-collapse commit and run:

```powershell
cmake --build build --config Release --target client server --parallel 8
$env:JAM_SERVER_EXE='build/Release/server.exe'
$env:JAM_CLIENT_EXE='build/Release/client.exe'
node tools/baseline.mjs --seconds 30 --interval-seconds 5 --frames 120 --codec opus --latency-profile low --jitter 4 --out-dir validation_logs/phase4-tx-collapse/before
```

Expected: `validation_logs/phase4-tx-collapse/before/client-a.log` and `client-b.log` include `opus_p99=`.

- [ ] **Step 2: Capture after metrics**

On the final Phase 4 code, run:

```powershell
cmake --build build --config Release --target client server latency_probe --parallel 8
$env:JAM_SERVER_EXE='build/Release/server.exe'
$env:JAM_CLIENT_EXE='build/Release/client.exe'
node tools/baseline.mjs --seconds 30 --interval-seconds 5 --frames 120 --codec opus --latency-profile low --jitter 4 --out-dir validation_logs/phase4-tx-collapse/after
```

Expected: after-run `opus_p99=` is lower than the before-run value in both client logs, or the tracker explains why one side is unchanged while max/avg and E2E improved.

- [ ] **Step 3: Capture Phase 4 E2E result**

Run the same direct smoke recorded for the Phase 3 comparison:

```powershell
node tools/e2e-latency-smoke.mjs --server-exe build/Release/server.exe --probe-exe build/Release/latency_probe.exe --frames 120 --jitter 4 --packets 650 --margin-ms 8 *> validation_logs/phase4-tx-collapse/e2e-smoke.log
```

Expected: command exits `0` and logs `e2e_latency_ms last/avg/max/steady_max`.

- [ ] **Step 4: Update tracker**

Parse the numeric values from the validation logs:

```powershell
Select-String -Path validation_logs\phase4-tx-collapse\before\client-a.log -Pattern "opus_p99="
Select-String -Path validation_logs\phase4-tx-collapse\before\client-b.log -Pattern "opus_p99="
Select-String -Path validation_logs\phase4-tx-collapse\after\client-a.log -Pattern "opus_p99="
Select-String -Path validation_logs\phase4-tx-collapse\after\client-b.log -Pattern "opus_p99="
Select-String -Path validation_logs\phase4-tx-collapse\e2e-smoke.log -Pattern "e2e_latency_ms last/avg/max/steady_max"
```

Replace the Phase 4 status block in `LOW_LATENCY_ACTION_PLAN.md` with prose that includes:

```text
Status: Done on the execution date.
Implemented: audio packets are encoded and synchronously sent from the sender thread on the existing UDP socket; control traffic still uses the io-thread send() path.
Validation: before send queue p99 for client-a and client-b, after send queue p99 for client-a and client-b, Phase 3 E2E baseline last 9.1425 ms / avg 9.90777 ms / steady_max 11.5601 ms, Phase 4 E2E rerun last/avg/max/steady_max from e2e-smoke.log, full Release ctest passed, and the green GitHub Actions run URL.
```

The committed tracker must contain actual dates, numeric measurements, log paths, and CI URL from the execution run.

- [ ] **Step 5: Commit**

```bash
git add LOW_LATENCY_ACTION_PLAN.md validation_logs/phase4-tx-collapse
git commit -m "docs: record phase 4 validation"
```

---

### Task 9: Full Verification

**Files:**
- No source changes expected unless verification finds a defect.

**Interfaces:**
- Consumes: all earlier tasks.
- Produces: final local verification and CI-ready branch.

- [ ] **Step 1: Configure**

Run:

```powershell
cmake -B build
```

Expected: configure succeeds.

- [ ] **Step 2: Build Release**

Run:

```powershell
cmake --build build --config Release --parallel 8
```

Expected: build succeeds.

- [ ] **Step 3: Run full ctest**

Run:

```powershell
ctest --test-dir build -C Release --output-on-failure
```

Expected: all tests pass, including:

```text
client_udp_audio_sync_send_smoke
client_opus_encode_buffer_smoke
client_udp_endpoint_guard_smoke
e2e_latency_loopback_smoke
```

- [ ] **Step 4: Run source acceptance checks**

Run:

```powershell
rg -n "send\\((send_packet|packet)->data|std::vector<unsigned char> encoded_data|recent_opus_audio_packets_.*shared_ptr|create_redundant_audio_packet\\(" client.cpp
```

Expected: no sender-loop hot-path hits. Test-only or smoke-only uses are acceptable only if they are outside `pcm_sender_loop()`.

Run:

```powershell
rg -n "asio::post\\(io_context_" client.cpp
```

Expected: remaining hits are control/rebind paths, not audio packet send call sites.

- [ ] **Step 5: Push and verify CI**

Run:

```bash
git status --short
git push
```

Expected: worktree is clean before push or contains only intentionally uncommitted local files. GitHub Actions workflow `.github/workflows/ci.yml` passes on Windows Release.

---

## Self-Review Checklist

- [ ] Phase 4 socket ownership is covered: one UDP socket, no second send socket, synchronous audio send under `socket_mutex_`.
- [ ] ASIO thread-safety is verified against official docs and composed with rebind by keeping `socket_mutex_` around synchronous send and close/move operations.
- [ ] Audio packets no longer traverse `asio::post`; control traffic may still use `send()`.
- [ ] Per-packet heap allocations are removed from Opus encode, V2/V3 packet construction, recent redundancy history, and redundancy wrapping.
- [ ] Sender thread priority uses MMCSS `"Pro Audio"` on Windows and reverts on thread exit.
- [ ] Per-packet callback `notify_one()` is either removed after measurement or explicitly retained with measured justification.
- [ ] `observe_opus_send_queue_age` produces p99, and before/after p99 is recorded in `LOW_LATENCY_ACTION_PLAN.md`.
- [ ] Phase 3 E2E baseline and Phase 4 E2E rerun are recorded in `LOW_LATENCY_ACTION_PLAN.md`.
- [ ] Release build, full `ctest`, and CI green are required before marking Phase 4 done.
