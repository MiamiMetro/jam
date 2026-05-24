# Listener V2 Docker

Status: VPS listener helper.

`docker-compose.listener.yml` runs only the listener streaming side:

```text
existing jam-server -> listener-service -> ffmpeg -> /hls -> nginx
```

The native SFU server remains managed separately, for example by the systemd
setup in `VPS_SETUP.md`. This compose file does not start a server and does not
publish UDP `9999`.

## Services

- `listener-service`
  - Runs `listener_service`.
  - Connects to an existing SFU using `SFU_HOST` and `SFU_PORT`.
  - Joins one or more rooms as listener role.
  - Spawns `ffmpeg` internally.
  - Writes HLS output to `/hls`.
- `nginx`
  - Serves `html/index.html`.
  - Serves room HLS under `/hls/<room>/stream.m3u8`.

## First VPS Deployment

Set up the native SFU first using `VPS_SETUP.md`.

Create the RAM-backed HLS root:

```sh
mkdir -p /dev/shm/jam-hls
```

Run one listener room against the SFU on the same VPS:

```sh
SFU_HOST=host.docker.internal \
SFU_PORT=9999 \
LISTENER_ROOMS='room-a:<listener-token>' \
docker compose -f docker-compose.listener.yml up --build -d
```

For temporary local/dev testing only, tokenless joins can be enabled:

```sh
ALLOW_INSECURE_DEV_JOINS=1 \
LISTENER_ROOMS=room-a \
docker compose -f docker-compose.listener.yml up --build -d
```

Open:

```text
http://<vps-ip>:8080/
http://<vps-ip>:8080/hls/room-a/stream.m3u8
```

Native clients still connect to the existing SFU:

```text
<vps-ip>:9999 UDP
```

## Separate Listener VPS Later

The same compose file can run on a separate listener VPS later. Set `SFU_HOST`
to the reachable SFU host or IP and ensure the SFU firewall accepts listener
UDP traffic.

```sh
SFU_HOST=<sfu-vps-ip-or-dns> \
SFU_PORT=9999 \
LISTENER_ROOMS='room-a:<listener-token>' \
docker compose -f docker-compose.listener.yml up --build -d
```

## Configuration

- `LISTENER_ROOMS`
  - Required.
  - The listener container exits with a clear error if this is not set.
  - Comma-separated room specs.
  - Production form: `room-a:<listener-token>`.
  - Dev-only form with insecure joins enabled: `room-a`.
- `SFU_HOST`
  - Existing SFU host visible from the listener container.
  - Default: `host.docker.internal`.
- `SFU_PORT`
  - Existing SFU UDP port.
  - Default: `9999`.
- `JAM_HLS_ROOT`
  - Host path shared between listener and nginx.
  - Default: `/dev/shm/jam-hls`.
- `LISTENER_HTTP_PORT`
  - Host HTTP port for nginx.
  - Default: `8080`.
- `SEGMENT_DURATION`
  - HLS segment duration.
  - Default: `0.5`.
- `PLAYLIST_SIZE`
  - HLS playlist size.
  - Default: `3`.
- `OUTPUT_GAIN`
  - Listener output gain before AAC encoding.
  - Default: `4.0`.
- `ALLOW_INSECURE_DEV_JOINS`
  - Allows tokenless room joins for local/dev testing only.
  - Default: `0`.

## Notes

- `/dev/shm/jam-hls` is RAM-backed on Linux. HLS still uses playlist and
  segment files, but they live in memory rather than persistent disk.
- Do not use `ALLOW_INSECURE_DEV_JOINS=1` on a public VPS.
- Each active room gets a separate FFmpeg process.
