# Latency Findings & Fix Plan

## Current Latency Budget (no network)

| Stage | Current | After Fix | Notes |
|-------|---------|-----------|-------|
| Audio in buffer | 5.0 ms | 5.0 ms | 240 frames @ 48kHz, fine |
| Opus encode | 5.0+ ms | 5.0 ms | FEC adds overhead, disable it |
| Jitter buffer wait | 15.0 ms | 5.0 ms | 3 packets minimum -> 1 |
| Opus decode | 5.0 ms | 5.0 ms | |
| Audio out buffer | 5.0 ms | 5.0 ms | |
| Mutex stalls | 0-10 ms | 0 ms | Lock-free audio path |
| malloc stalls | 0-5 ms | 0 ms | Preallocated buffers |
| **Total** | **35-45 ms** | **~25 ms** | + network one-way on top |

## Problem 1: Mutex in Audio Callback (Robotic Sound)

**File:** `participant_manager.h:146`

`for_each()` takes a `std::lock_guard<std::mutex>` per participant inside the audio callback. The network receive thread holds the same mutex when enqueueing packets. When contention happens, the audio callback misses its deadline -> glitches/robotic sound.

This is the #1 reason you can't go to smaller buffer sizes.

**Fix:** Replace mutex-guarded `std::unordered_map` with a lock-free design. Options:
- Lock-free ring buffer per participant (network thread writes, audio thread reads)
- RCU-style: network thread builds a new participant list, atomically swaps a pointer, audio thread reads the old pointer without locking
- Pre-allocated participant slots with atomic flags

## Problem 2: Heap Allocations in Audio Callback

**File:** `client.cpp:1005-1006`
```cpp
std::vector<float> silence_frame(frame_count, 0.0F);  // malloc in RT thread
```

**File:** `opus_encoder.h:101`
```cpp
output.resize(ENCODE_BUFFER_SIZE);  // malloc in RT thread
```

Any `malloc`/`new` in the audio callback is non-deterministic (can take milliseconds). Replace with preallocated `std::array` buffers.

## Problem 3: FEC Adds Encoding Latency

**File:** `opus_encoder.h:71-72`
```cpp
OPUS_SET_INBAND_FEC(1)        // Adds redundancy data -> larger packets, more encoder work
OPUS_SET_PACKET_LOSS_PERC(5)  // Tells encoder to expect loss -> even more redundancy
```

FEC is designed for voice conferencing where 200ms latency is fine. For jamming, accept occasional packet loss (PLC already handles it on the decode side). Disable both.

## Problem 4: Jitter Buffer Too Conservative

**File:** `protocol.h:16-18`
```cpp
constexpr size_t MAX_OPUS_QUEUE_SIZE       = 10;
constexpr size_t TARGET_OPUS_QUEUE_SIZE    = 3;
constexpr size_t MIN_JITTER_BUFFER_PACKETS = 3;  // 15ms wait before playback starts
```

3 packets = 15ms of pure buffering latency. For jamming on a decent connection, 1 packet (5ms) is enough. PLC already covers gaps.

## Problem 5: Adaptive Jitter Buffer Only Ratchets Up

**File:** `client.cpp:839-851`

The adaptive logic increases `jitter_buffer_min_packets` when avg queue < 2, but it can never decrease below `MIN_JITTER_BUFFER_PACKETS` (3). On a stable network, latency never improves after an initial hiccup.

**Fix:** Allow minimum to go down to 1. Use a decay timer so it trends toward lower latency over time.

## Problem 6: Opus Encode + Network Send Inside Audio Callback

**The PortAudio callback is sacred.** It runs on a real-time OS thread. Any blocking or non-deterministic work causes missed deadlines = glitches.

Currently the callback does ALL of this:

1. **Opus encode** (`client.cpp:984`, `:1006`) -- CPU-heavy codec work
2. **Heap allocations** (`client.cpp:1005` `std::vector<float>`, `opus_encoder.h:101` `output.resize()`, `audio_packet.h:18` `make_shared<vector>` + multiple `insert()` calls)
3. **Network send** (`client.cpp:1024` -> `:532`) -- `socket_.async_send_to()` touches kernel, ASIO internals

### What the callback should do

**Only:**
- Read mic input (and mix WAV if active)
- Copy PCM into a lock-free SPSC queue
- Read decoded PCM from participant ring buffers for output
- Return

No Opus. No send. No vector. No malloc. No mutex.

### Fix: Split into sender thread

```
Audio callback (RT thread)     Sender thread (normal thread)
  |                               |
  | push 240 floats               | pop 240 floats
  | into SPSC queue  ---------->  | Opus encode
  | return                        | build packet (preallocated)
                                  | send UDP
                                  | sleep_until(next_send += 5ms)
```

**Pacing matters:** The sender thread must NOT spin-drain the queue (bursty = jitter). It should pace at 5ms intervals using `sleep_until(steady_clock)` to maintain consistent packet cadence.

### Queue element (zero-allocation)

```cpp
struct MicFrame {
    std::array<float, 240> pcm;  // fixed 5ms @ 48kHz mono
};
```

SPSC queue with ~64 slots. If queue depth > 3-5 frames, drop oldest to bound latency.

### Specific lines to move out of callback

| What | Current location | Move to |
|------|-----------------|---------|
| `audio_encoder_.encode(...)` | `client.cpp:984`, `:1006`, `:1011` | sender thread |
| `audio_packet::create_audio_packet(...)` | `client.cpp:1023` | sender thread (or eliminate, use preallocated buffer) |
| `client->send(...)` | `client.cpp:1024` | sender thread |
| `std::vector<float> silence_frame(...)` | `client.cpp:1005` | eliminate (use preallocated `std::array`) |
| `std::vector<unsigned char> encoded_data` | `client.cpp:941` | sender thread (preallocated) |

### audio_packet.h is also a problem

`audio_packet::create_audio_packet()` (`audio_packet.h:14-41`) does:
- `make_shared<vector<unsigned char>>()` -- heap alloc
- 4x `insert()` calls -- potential reallocs
- Returns `shared_ptr` -- atomic refcount overhead

Replace with a preallocated fixed-size packet buffer in the sender thread.

---

## Server Findings

The server is a dumb packet forwarder -- architecturally correct for an SFU. No decode, no mix, no re-encode. Two issues in the hot path:

### Server Problem 1: Heap Allocation Per Audio Packet

**File:** `server.cpp:194`
```cpp
auto packet_copy = std::make_shared<std::vector<unsigned char>>(recv_buf_.data(),
                                                                recv_buf_.data() + bytes);
```

Every incoming audio packet triggers `make_shared` + `vector` copy. At 200 packets/sec per client with 5 clients = 1000 allocs/sec. Under load this causes allocation pressure and forwarding jitter.

**Fix:** Preallocated packet pool. Fixed-size buffers (max packet size is bounded by `RECV_BUF_SIZE` = 1024). Pool of ~64-128 buffers, grab one on receive, release in send completion handler.

### Server Problem 2: Vector Allocation Per Forward

**File:** `client_manager.h:91-101`
```cpp
std::vector<endpoint> get_endpoints_except(const endpoint& exclude) const {
    std::vector<endpoint> endpoints;          // heap alloc
    endpoints.reserve(clients_.size());       // every single audio packet
    ...
}
```

Called on every audio packet to get the forward list. Allocates + copies endpoints every time.

**Fix:** Keep a preallocated endpoint list. Update it only on JOIN/LEAVE (rare), not on every audio packet. Or iterate directly over the client map inside `forward_audio_to_others` instead of copying to a temp vector.

### Server Problem 3: Single-Threaded IO

**File:** `server.cpp:259`
```cpp
io_context.run();  // single thread handles all receive + forward
```

Fine for <10 clients. For scaling, consider `io_context.run()` on multiple threads or use `io_context` per-core with SO_REUSEPORT. Not urgent but worth noting.

### Server Future: Multiroom

Straightforward. No architectural change needed. The server already partitions sends via `get_endpoints_except()` -- just add a `room_id` per client and filter by it.

- Add `uint32_t room_id` to `ClientInfo`
- Room assignment via a new CTRL command (e.g., `JOIN_ROOM`) or as a field in the existing `JOIN`
- `get_endpoints_in_room_except(room_id, sender)` replaces `get_endpoints_except(sender)`
- Everything else stays the same -- the forwarding loop, packet format, async sends

No impact on latency. Tackle after client-side fixes are solid.

### Server: What's Fine

- `async_receive_from` / `async_send_to` -- correct async pattern
- Socket buffer sizes 128KB -- reasonable
- Mutex in `ClientManager` -- uncontested since single-threaded IO, harmless
- Packet forwarding logic -- clean, no unnecessary copies beyond the issues above
- Alive/timeout cleanup on timer -- correct

---

## Competitive Gap: What Industry Leaders Do That We Don't

### Target: ~10-15ms glass-to-glass on LAN (currently ~35-45ms)

| Technique | JackTrip | Jamulus | SonoBus | Us |
|-----------|----------|--------|---------|-----|
| Configurable buffer 64/128/256 samples | yes | yes | yes | **no** (hardcoded 240) |
| ASIO/JACK/CoreAudio direct (not through PortAudio defaults) | yes | yes | yes | partial (selector exists, but no ASIO-specific low-latency config) |
| Uncompressed audio option | yes | no | yes | **no** |
| Lock-free audio path | yes | yes | yes | **no** |
| Adaptive resampling (clock drift compensation) | yes | yes | yes | **no** |
| Configurable jitter buffer (user chooses latency vs stability) | yes | yes | yes | **no** (hardcoded 3 packets) |
| Sender thread separate from audio callback | yes | yes | yes | **no** |
| Per-platform RT thread priority | yes | yes | yes | partial (Windows only) |

### Gap 1: Configurable Buffer Sizes (biggest latency win)

Currently hardcoded at 240 samples (5ms). Competitive apps let users choose:

| Samples | Latency | Requires |
|---------|---------|----------|
| 64 | 1.3 ms | ASIO with good driver |
| 128 | 2.7 ms | ASIO or WASAPI Exclusive |
| 256 | 5.3 ms | WASAPI Exclusive |
| 512 | 10.7 ms | Anything |

At 128 samples with a clean audio path:
```
Audio in:        2.7 ms  (128 samples)
Opus encode:     2.7 ms  (128 sample frame)
Jitter buffer:   2.7 ms  (1 packet)
Opus decode:     2.7 ms
Audio out:       2.7 ms
                --------
Total:          ~13.5 ms  (no network)
```

That's competitive with Jamulus. But this **requires the lock-free audio path first** -- at 128 samples you have 2.7ms to complete the callback, any mutex/malloc blows it.

### Gap 2: Uncompressed Audio Option

For LAN jamming, skip Opus entirely. Send raw PCM over UDP.

- 128 samples × 4 bytes (float32) × 1 channel = **512 bytes per packet**
- At 48kHz that's ~375 packets/sec = **1.5 Mbps** (trivial for LAN, fine for good internet)
- Eliminates encode AND decode latency completely

Budget with uncompressed + 128 sample buffers:
```
Audio in:        2.7 ms
Network packet:  0.0 ms  (no codec)
Jitter buffer:   2.7 ms  (1 packet)
Audio out:       2.7 ms
                --------
Total:          ~8 ms    (no network)
```

That matches JackTrip territory.

### Gap 3: Adaptive Resampling (Clock Drift)

Different sound cards run at slightly different actual sample rates (e.g., one card's "48000 Hz" is actually 47998.3 Hz). Over time this causes:
- Buffer underruns (remote clock faster than local)
- Buffer overruns / growing latency (remote clock slower)

This is why you see periodic glitches even on a perfect network.

**Fix:** Track the jitter buffer fill level over time. If it's trending up, the remote clock is slower -- slightly speed up local playback by resampling (e.g., consume 241 samples instead of 240). If trending down, slow down (consume 239). Jamulus and SonoBus both do this.

This requires a small high-quality resampler (libsamplerate or a simple linear interpolator for <1% rate adjustment).

### Gap 4: Direct ASIO Integration

PortAudio CAN use ASIO, but you need to:
- Set `suggestedLatency` to the ASIO driver's minimum (not `defaultLowInputLatency` which is often higher)
- Use ASIO-specific buffer sizes that the driver supports (often powers of 2: 64, 128, 256)
- Handle ASIO's preferred buffer size callback

Currently `audio_stream.h:221-225` uses `defaultLowInputLatency` / `defaultLowOutputLatency` which may be 5-10ms even on ASIO. Should query the ASIO driver's minimum and use that.

### Gap 5: Cross-Platform RT Thread Priority

Currently only Windows (`client.cpp:744`):
```cpp
SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
```

Need:
- **Linux:** `pthread_setschedparam(SCHED_FIFO, priority)` or JACK's RT thread
- **macOS:** `thread_policy_set()` with `THREAD_TIME_CONSTRAINT_POLICY`
- **Sender thread** also needs elevated priority (not just callback)

---

## Revised Latency Budget (competitive target)

### Mode 1: Opus (internet jamming)
```
Buffer size:     128 samples = 2.7 ms (configurable)
Opus encode:     2.7 ms (frame = buffer)
Jitter buffer:   2.7 ms (1 packet, user-configurable)
Opus decode:     2.7 ms
Output buffer:   2.7 ms
                --------
Total:          ~13.5 ms + network one-way
```

### Mode 2: Uncompressed (LAN jamming)
```
Buffer size:     128 samples = 2.7 ms
Raw PCM packet:  0 ms (no codec)
Jitter buffer:   2.7 ms (1 packet)
Output buffer:   2.7 ms
                --------
Total:          ~8 ms + network one-way
```

### Mode 3: Ultra (LAN, accept glitches)
```
Buffer size:     64 samples = 1.3 ms
Raw PCM packet:  0 ms
Jitter buffer:   0 ms (play immediately, PLC on miss)
Output buffer:   1.3 ms
                --------
Total:          ~2.6 ms + network one-way
```

---

## User-Facing Latency Presets

Three underlying settings control everything: `buffer_size`, `codec_mode`, `jitter_buffer_packets`.

| Preset | Buffer | Codec | Jitter Buffer | Target Latency | Use Case |
|--------|--------|-------|---------------|----------------|----------|
| **Studio** | 64 | Uncompressed | 0 | ~3-4ms | LAN, good audio interface, accept rare glitches |
| **LAN** | 128 | Uncompressed | 1 packet | ~6-8ms | LAN, reliable |
| **Balanced** | 128 | Opus | 1 packet | ~11-13ms | Internet jamming, decent connection |
| **Safe** | 256 | Opus | 2 packets | ~20-25ms | Bad internet, stability over latency |

Plus **Advanced** mode: user picks buffer size, codec, and jitter buffer independently.

### Implementation

```cpp
enum class CodecMode { Uncompressed, Opus };

struct LatencyPreset {
    int       buffer_size;            // 64, 128, 256, 512
    CodecMode codec;                  // Uncompressed or Opus
    int       jitter_buffer_packets;  // 0, 1, 2, ...
};
```

Switching presets requires restarting the audio stream (buffer size change) but NOT reconnecting to the server. The server doesn't care -- it forwards bytes regardless of codec or buffer size.

### Per-Client Independence

Presets do NOT need to match across the room. Each setting's scope:

| Setting | Scope | Why |
|---------|-------|-----|
| Buffer size | Local only | Controls your sound card callback rate, no one else sees it |
| Jitter buffer | Local only | Controls how long YOU wait before playing received audio |
| Codec | Needs signaling | Receiver must know how to decode incoming bytes |

**Codec solution:** Add a 1-byte codec flag to the `AudioHdr` packet header. Receiver checks it and routes to Opus decode or raw PCM copy. No negotiation needed -- each client can send in whatever codec it wants, receivers auto-detect per packet.

```cpp
struct AudioHdr : MsgHdr {
    uint32_t sender_id;
    uint8_t  codec;          // 0 = Opus, 1 = Uncompressed PCM
    uint16_t encoded_bytes;
    // ...payload...
};
```

This means a guitarist on Studio (64 buf, uncompressed, ASIO) and a vocalist on Safe (256 buf, Opus, laptop) can be in the same room with zero issues. Each hears the other at their own chosen latency/stability tradeoff.

---

## Priority Order (revised for competitive target)

### Phase 1: Fix the foundation (stop the bleeding)
1. **Split callback: sender thread** - move encode + send + allocations out of RT thread
2. **Lock-free participant read path** - replace mutex with lock-free design
3. **Disable FEC** - remove `INBAND_FEC` and `PACKET_LOSS_PERC`

### Phase 2: Configurable low-latency
4. **Configurable buffer sizes** - let user choose 64/128/256/512 samples
5. **Jitter buffer = user-configurable** - slider from 0 to 5 packets, default 1
6. **ASIO minimum latency** - query driver's actual minimum, don't use PortAudio defaults
7. **Adaptive jitter buffer fix** - allow decrease down to user's chosen minimum

### Phase 3: Competitive features
8. **Uncompressed audio mode** - raw PCM option for LAN, auto-negotiate based on bandwidth
9. **Adaptive resampling** - clock drift compensation using jitter buffer fill trend
10. **Cross-platform RT thread priority** - Linux SCHED_FIFO, macOS thread policy
