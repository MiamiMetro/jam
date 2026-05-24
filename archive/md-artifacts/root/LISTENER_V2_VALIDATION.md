# Listener V2 Validation

Status: local Windows validation, 2026-05-13.

## Environment

- Host: Windows development machine
- Branch: `v2-listener-service`
- Build: `cmake --build build --config Release`
- FFmpeg: available on PATH
- nginx: validated through Docker Compose using `nginx:alpine`
- Server host: `127.0.0.1`
- Rooms: `room-a`, `room-b`
- Performer probe codec: Opus V2, 48 kHz, mono, 240-frame packets
- HLS codec: AAC-LC, 48 kHz, mono
- HLS segment duration: 0.5 seconds
- HLS playlist size: 6
- HLS roots used: `hls/`, `validation_logs/listener_v2/hls*`
- RTT: local loopback probes; no WAN RTT measured
- Observed media latency: not measured with a browser player; generated HLS
  segment cadence and media parsing were validated

## Runs

### Room Routing And Listener Role

Command shape:

```text
server --port 10021 --allow-insecure-dev-joins
room_routing_probe --server 127.0.0.1 --port 10021
```

Result:

```text
same_room_received=1
different_room_received=0
listener_received=1
listener_announced=0
same_room_metronome_received=1
different_room_metronome_received=0
stale_duplicate_forwarded=0
rejoined_sender_forwarded=1
```

### Multi-Room Service Smoke

Command shape:

```text
server --port 10022 --allow-insecure-dev-joins
listener_service --server 127.0.0.1 --port 10022 \
  --allow-insecure-dev-joins --no-hls --duration-ms 1200 \
  --room room-a --room room-b
```

Result: both room listeners started, joined, ran independent mix/writer
threads, and stopped cleanly.

### Token-Required Listener Join And Opus V2 Decode

Command shape:

```text
server --port 10011 --server-id local-dev --join-secret listener-v2-secret
listener_service --server 127.0.0.1 --port 10011 --no-hls \
  --duration-ms 2800 \
  --room room-a:<listener-token>::listener-room-a:Listener-room-a
listener_audio_sender_probe --server 127.0.0.1 --port 10011 \
  --server-id local-dev --secret listener-v2-secret \
  --room room-a --profile probe-performer --duration-ms 1200
```

Result:

```text
packets_sent=77
listener stopped packets=77 decoded=75 decode_failures=0
```

### Invalid Listener Token Role

Command shape:

```text
server --port 10014 --server-id local-dev --join-secret listener-v2-secret
listener_service --server 127.0.0.1 --port 10014 --no-hls \
  --duration-ms 1200 \
  --room room-a:<performer-role-token>::listener-room-a:Listener-room-a
```

Result:

```text
invalid_listener_token_rejected=True
```

### Malformed V2 Packet Rejection

Command shape:

```text
server --port 10012 --allow-insecure-dev-joins
listener_service --server 127.0.0.1 --port 10012 \
  --allow-insecure-dev-joins --no-hls --duration-ms 1800 --room room-a
listener_audio_sender_probe --server 127.0.0.1 --port 10012 \
  --room room-a --profile malformed-sender --malformed-v2
```

Result:

```text
sent_malformed_v2=1
malformed_rejected=True
```

### HLS Generation

Command shape:

```text
server --port 10013 --allow-insecure-dev-joins
listener_service --server 127.0.0.1 --port 10013 \
  --allow-insecure-dev-joins --duration-ms 5000 --keep-hls-output \
  --hls-root validation_logs/listener_v2/hls \
  --segment-duration 0.5 --playlist-size 6 --room room-a
listener_audio_sender_probe --server 127.0.0.1 --port 10013 \
  --room room-a --profile hls-sender --duration-ms 2800
```

Result:

```text
packets_sent=180
playlist_exists=True
segments=2
ffprobe format_name=hls
ffprobe codec_name=aac sample_rate=48000 channels=1
```

Output:

```text
validation_logs/listener_v2/hls/room-a/stream.m3u8
validation_logs/listener_v2/hls/room-a/stream_*.m4s
```

### nginx Multi-Room Serve

Command shape:

```text
listener_service --server 127.0.0.1 --port 10034 \
  --allow-insecure-dev-joins --duration-ms 6500 --keep-hls-output \
  --hls-root hls --segment-duration 0.5 --playlist-size 6 \
  --room room-a --room room-b
docker compose up -d nginx
curl -D - http://127.0.0.1:8080/hls/room-a/stream.m3u8
curl -D - http://127.0.0.1:8080/hls/room-b/stream.m3u8
curl -D - http://127.0.0.1:8080/hls/room-a/<segment>.m4s
ffprobe http://127.0.0.1:8080/hls/room-a/stream.m3u8
```

Result:

```text
room_a_ok=True
room_b_ok=True
playlist_cache=True
segment_cache=True
ffprobe codec_name=aac sample_rate=48000 channels=1
```

### HLS Room Restart

Command shape:

```text
server --port 10016 --allow-insecure-dev-joins
listener_service --server 127.0.0.1 --port 10016 \
  --allow-insecure-dev-joins --duration-ms 6500 --keep-hls-output \
  --hls-root validation_logs/listener_v2/hls_restart \
  --segment-duration 0.5 --playlist-size 6 \
  --restart-room-after room-a:1800 --room room-a
listener_audio_sender_probe --server 127.0.0.1 --port 10016 \
  --room room-a --profile restart-sender --duration-ms 4300
```

Result:

```text
packets_sent=275
restart_logged=True
playlist_exists=True
segments=1
```

### Two Active Sender Mix

Command shape:

```text
server --port 10017 --allow-insecure-dev-joins
listener_service --server 127.0.0.1 --port 10017 \
  --allow-insecure-dev-joins --duration-ms 5500 --keep-hls-output \
  --hls-root validation_logs/listener_v2/hls_two_senders \
  --segment-duration 0.5 --playlist-size 6 --room room-a
listener_audio_sender_probe --server 127.0.0.1 --port 10017 \
  --room room-a --profile mix-sender-1 --duration-ms 3000
listener_audio_sender_probe --server 127.0.0.1 --port 10017 \
  --room room-a --profile mix-sender-2 --duration-ms 3000
```

Result:

```text
playlist_exists=True
segments=3
ffprobe codec_name=aac sample_rate=48000 channels=1
```

### Moderate Jitter Decode

Command shape:

```text
server --port 10018 --allow-insecure-dev-joins
udp_impair_proxy --listen-port 10019 --server 127.0.0.1 \
  --server-port 10018 --jitter-ms 25 --reorder-every 17 \
  --reorder-delay-ms 20
listener_service --server 127.0.0.1 --port 10018 \
  --allow-insecure-dev-joins --no-hls --duration-ms 4200 --room room-a
listener_audio_sender_probe --server 127.0.0.1 --port 10019 \
  --room room-a --profile jitter-sender --duration-ms 2500
```

Result:

```text
packets_sent=159
decoded=156
decode_failures=0
```

### FFmpeg Writer Failure Isolation

Command shape:

```text
server --port 10033 --allow-insecure-dev-joins
listener_service --server 127.0.0.1 --port 10033 \
  --allow-insecure-dev-joins --no-hls \
  --simulate-ffmpeg-write-failures --duration-ms 3800 \
  --room room-a --room room-b
listener_audio_sender_probe --server 127.0.0.1 --port 10033 \
  --room room-a --profile fail-sender-a --duration-ms 1800
listener_audio_sender_probe --server 127.0.0.1 --port 10033 \
  --room room-b --profile fail-sender-b --duration-ms 1800
```

Result:

```text
ffmpeg_failures=764
decoded=115
```

## Manual Follow-Up

- Browser UI playback of the generated HLS stream can be checked manually. HTTP
  serving and media parsing were validated with `curl` and `ffprobe`.
- A manual UI run with one SFU, two native performers, and `listener_service`
  is still useful before merging, because it checks the subjective audio path
  that automated protocol probes cannot hear.
