# VPS Robotic Audio Handoff

Date: 2026-06-09

## Goal

Make the VPS-hosted Jam UDP SFU reliable. The symptom is intermittent robotic/corrupt voice over the VPS. Sometimes the same build sounds fine, then later sounds robotic. The user wants the VPS path fixed and does not want to continue with Tailscale or homelab workarounds.

## Current VPS Setup

- VPS host: `194.62.55.226`
- SSH: `jam@194.62.55.226 -p 2222`
- Server UDP port: `9999`
- Service: `jam-server`
- Service binary path from runbook: `/home/jam/jam/build/server`
- Env file: `/etc/jam/server.env`
- Current env values observed on VPS:

```text
SERVER_ID=istanbul-test
JOIN_SECRET=replace-with-a-long-random-secret
```

The server is a UDP SFU. It does not decode/re-encode audio; it forwards packets between clients.

## Important Commits / Code State

Latest relevant commits:

```text
ba67bb9 server fix test 2
c10b8dc server fix test
```

`ba67bb9` changed:

- `audio_packet.h`: added strict V2 audio packet validator.
- `client.cpp`: refuses malformed outbound V2 audio and logs `BUG: refusing malformed outbound V2 audio`.
- `client.cpp`: receive path now uses strict zero-tolerance payload length validation.
- `server.cpp`: drops malformed V2 packets instead of forwarding them.
- `server.cpp`: increases UDP socket buffers to 4 MB.
- `server.cpp`: changes forward diagnostics to show interval stats plus totals.

Do not blindly revert this commit. It did not fix robotic audio, but it adds useful instrumentation and prevents forwarding malformed packets.

## What We Observed

### Clean Periods

When audio was good, server logs showed forward diagnostics like:

```text
Forward diag sender=4 target=3 forwarded=11912 seq_gap=0 seq_late=0
Forward diag sender=3 target=4 forwarded=11918 seq_gap=0 seq_late=0
```

This means the SFU received and forwarded packets in order for that interval.

### Bad Periods

When audio was robotic, server logs showed very high sequence gaps and late/reordered packet counts:

```text
Forward diag sender=2 target=1 forwarded=2820 seq_gap=1391 seq_late=1400
Forward diag sender=1 target=2 forwarded=2772 seq_gap=1578 seq_late=1559
Forward diag sender=4 target=3 forwarded=2334 seq_gap=1119 seq_late=1166
Forward diag sender=3 target=4 forwarded=2215 seq_gap=1456 seq_late=1395
```

This is a hard signal: the VPS/server is seeing missing or late/out-of-order audio sequence numbers during bad audio.

### Malformed / Short V2 Packets

Logs also showed:

```text
Dropping incomplete V2 audio from 195.155.171.37:9903: got 32, expected 82 (payload_bytes=60)
Dropping incomplete V2 audio from 195.155.171.37:9769: got 32, expected 82 (payload_bytes=60)
```

Important: UDP does not normally deliver a partial datagram. With server receive buffer size `1024`, an expected 82-byte packet should not arrive as 32 bytes because of normal UDP truncation. This implies one of:

- A client emitted a malformed datagram.
- Stale/old binary/client sent bad data.
- Some non-client/old process sent data to UDP 9999.
- The log was from an old build before strict client-side guard.

The latest client guard should prove this. If a fixed client creates such a packet, client logs should contain:

```text
BUG: refusing malformed outbound V2 audio
```

If no fixed client logs that but VPS still sees invalid packets, some old/stale process or non-updated client is still sending.

### Expired Token / Packet Too Small Noise

Bad logs also contained repeated:

```text
Rejecting JOIN ... expired token
Rejecting JOIN ... packet too small
```

These are probably noisy stale clients/retry loops. They are not the main robotic-audio signal. The main signal is `seq_gap` / `seq_late` on active forwarding pairs.

## What We Tried

### VPS Kernel UDP Buffer Tuning

Applied on VPS:

```bash
sudo tee /etc/sysctl.d/99-jam-udp.conf >/dev/null <<'EOF'
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.core.rmem_default=1048576
net.core.wmem_default=1048576
net.core.netdev_max_backlog=50000
net.ipv4.udp_rmem_min=16384
net.ipv4.udp_wmem_min=16384
EOF

sudo sysctl --system
sudo systemctl restart jam-server
```

This did not solve the issue. Robotic periods still showed high `seq_gap` / `seq_late`.

### Homelab Attempt

Homelab:

- LAN IP: `192.168.1.50`
- Public IP reported by homelab: `195.155.171.37`
- Server built and ran successfully under `/home/phil/jam/build/server`.
- `jam-server` was active and listening on `0.0.0.0:9999`.
- UFW allowed `9999/udp`.
- Router ZTE port forward rule was created:

```text
WAN host: 0.0.0.0 ~ 255.255.255.255
LAN host: 192.168.1.50
WAN port: 9999 ~ 9999
LAN host port: 9999 ~ 9999
Protocol: UDP
```

- DMZ was also tried.
- External UDP probes from VPS to `195.155.171.37:9999` did not appear in `journalctl` or `tcpdump`.

Conclusion: homelab public inbound UDP was not reaching the machine. This was a router/ISP/NAT problem, not useful for solving the VPS issue. Homelab setup was removed:

```bash
sudo systemctl disable --now jam-server
sudo rm -f /etc/systemd/system/jam-server.service
sudo systemctl daemon-reload
sudo rm -rf /etc/jam
rm -rf /home/phil/jam
sudo ufw delete allow 9999/udp
```

## Current Best Diagnosis

The issue is not “simple UDP is impossible”; it is that the current app behaves badly when the VPS path has packet loss, jitter, reordering, or burst loss.

The server is probably not CPU-bound and is not decoding audio. The robotic sound is more likely from one or more of:

1. **Real UDP packet loss/reordering on VPS path**
   - Supported by high `seq_gap` / `seq_late` during bad audio.
   - Could be VPS provider network, route, peering, Wi-Fi/client uplink, or transient congestion.

2. **Packet rate too high for unstable paths**
   - Current Opus network clock supports only 120-frame and 240-frame packets at 48 kHz.
   - 120 frames = 2.5 ms = 400 packets/sec per sender.
   - 240 frames = 5 ms = 200 packets/sec per sender.
   - Normal internet voice apps often use 10-20 ms Opus frames, around 50-100 packets/sec, plus jitter/FEC/PLC.
   - Raising GUI bitrate does not fix packet loss; it can make network behavior worse.

3. **Receiver jitter/concealment not robust enough**
   - The receiver logs show participant sequence gaps, late packets, rebuffering, underruns, and PLC.
   - Robotic sound is consistent with repeated PLC/concealment or decode/playout starvation.

4. **Old/stale clients or duplicate clients still sending**
   - Expired token spam and malformed short V2 packets suggest old endpoints can still hit the server.
   - Need a clean test with all clients rebuilt from the same commit and unique fresh room/token.

## Strong Next Steps

### 1. Build a Real Pass/Fail Test

Do not keep guessing from subjective “robotic” reports only. Create a test matrix:

- Same LAN client A/B through VPS.
- Friend LAN client through VPS.
- Fresh room/token only.
- All clients built from same commit.
- Collect:
  - sender client log
  - receiver client log
  - VPS `journalctl -u jam-server`
  - exact time window when robotic starts

During bad period, inspect:

```text
server Forward diag interval seq_gap / seq_late
client tx_malformed
client participant seq gap/late
client underruns / PLC / jitter_depth_drops / jitter_age_drops
client callback over deadline
client tx_drops pcm/opus
```

### 2. Add 10 ms / 20 ms Opus Packet Modes

This is the most pragmatic code fix candidate.

Current `opus_network_clock.h`:

```cpp
LOW_LATENCY_FRAME_COUNT = 120; // 2.5 ms
STABLE_FRAME_COUNT = 240;      // 5 ms
DEFAULT_FRAME_COUNT = 240;
```

Recommended:

```cpp
LOW_LATENCY_FRAME_COUNT = 120;       // 2.5 ms, LAN/experimental
BALANCED_FRAME_COUNT = 480;          // 10 ms
STABLE_FRAME_COUNT = 960;            // 20 ms, internet/demo default
DEFAULT_FRAME_COUNT = STABLE_FRAME_COUNT;
```

Update `is_supported_frame_count`, UI options, and `opus_network_clock_self_test.cpp`.

For demo/VPS, default to 20 ms packets, jitter buffer around 8-12 packets, age limit 250 ms.

Expected effect:

- 240-frame current default: about 200 audio UDP packets/sec per sender.
- 960-frame stable default: about 50 audio UDP packets/sec per sender.

This reduces packet pressure by 4x and should make the app much less sensitive to VPS path jitter/loss.

### 3. Add Server-Side Interval Loss Percent

Current server interval logs show counts. Make them easier to interpret:

```text
loss_pct = seq_gap / (forwarded + seq_gap)
late_pct = seq_late / (forwarded + seq_late)
```

Example desired log:

```text
Forward diag interval sender=3 target=4 forwarded=1000 seq_gap=20 loss=2.0% seq_late=5 late=0.5%
```

This will quickly answer whether robotic audio correlates with network loss.

### 4. Add Per-Endpoint Receive Counters on Server

Track incoming sequence continuity per sender endpoint before forwarding. The current `sender->target` stats are useful, but receiver-specific forwarding can obscure whether loss is already present at server ingress.

Add:

```text
Ingress diag endpoint=<ip:port> client=<id> received=<n> seq_gap=<n> seq_late=<n>
```

If ingress has gaps, loss is before/during VPS receive path.
If ingress is clean but target forwarding has gaps, bug is in server forwarding logic.

### 5. Clean Stale Token / Retry Noise

Expired JOIN spam should not break audio, but it pollutes logs and may indicate old app instances. For tests:

- Kill all old clients.
- Start fresh room.
- Use fresh token.
- Confirm server logs only expected participant IPs.

Optional server improvement:

- Rate-limit expired token logs per endpoint/room.
- Do not let stale unjoined endpoint traffic dominate logs.

## Useful Commands

VPS logs:

```bash
journalctl -u jam-server -f
```

VPS status:

```bash
systemctl status jam-server --no-pager
ss -lunp | grep ':9999'
ip -s link
```

VPS rebuild:

```bash
cd /home/jam/jam
git restore CMakeLists.txt
git pull
sed -i 's/^include(cmake\/client.cmake)/# include(cmake\/client.cmake)/' CMakeLists.txt
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target server
sudo systemctl restart jam-server
sudo systemctl status jam-server --no-pager
```

Client local logs from Electron launcher are under:

```text
C:\Users\Berkay\AppData\Roaming\jam-desktop\native-client-logs\
```

## Decision

Stop spending time on Tailscale/homelab. The next real fix should be in the app:

1. Add 10 ms / 20 ms Opus network packet modes.
2. Make 20 ms the VPS/demo default.
3. Keep strict malformed packet guards.
4. Improve server ingress/interval diagnostics.
5. Run controlled fresh-room tests and correlate robotic audio with ingress loss and receiver jitter stats.

