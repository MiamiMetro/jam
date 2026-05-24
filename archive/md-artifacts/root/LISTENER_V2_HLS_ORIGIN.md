# Listener V2 HLS Origin

Status: draft for the native V2 listener service.

The first production origin should be a tmpfs-backed HLS directory served by
nginx. This keeps live segment churn off persistent disk and leaves Cloudflare
as a cache in front of a normal HTTP origin.

## Output Layout

Run one `listener_service` process per SFU host or per listener host:

```text
listener_service \
  --server 127.0.0.1 \
  --port 9999 \
  --hls-root /dev/shm/jam-hls \
  --room room-a:<listener-token> \
  --room room-b:<listener-token>
```

Each room writes:

```text
/dev/shm/jam-hls/<room-id>/stream.m3u8
/dev/shm/jam-hls/<room-id>/stream_<sequence>.m4s
```

Use room IDs that are safe as path components. The service sanitizes unsafe
characters for its local path, but product routing should still prefer stable
ASCII room IDs.

## nginx Route

Example nginx location:

```nginx
location /hls/ {
    alias /dev/shm/jam-hls/;
    types {
        application/vnd.apple.mpegurl m3u8;
        video/mp4 m4s;
    }
    add_header Access-Control-Allow-Origin "*" always;
}
```

The public playlist URL for `room-a` becomes:

```text
https://<origin-host>/hls/room-a/stream.m3u8
```

## Cache Headers

Playlists change continuously and should be revalidated:

```nginx
location ~ ^/hls/.+\.m3u8$ {
    alias /dev/shm/jam-hls/;
    add_header Cache-Control "no-cache, must-revalidate" always;
    add_header Access-Control-Allow-Origin "*" always;
}
```

Segments are immutable once written and can be cached:

```nginx
location ~ ^/hls/.+\.m4s$ {
    alias /dev/shm/jam-hls/;
    add_header Cache-Control "public, max-age=60, immutable" always;
    add_header Access-Control-Allow-Origin "*" always;
}
```

Cloudflare should cache segment files but should not aggressively cache
`.m3u8` playlists. A stale playlist is worse than a missed segment cache hit.

## Operational Notes

- Start `listener_service` after the SFU is reachable.
- Use listener-role join tokens in production auth mode.
- Use `--allow-insecure-dev-joins` only for local testing.
- Use `--keep-hls-output` only for validation and debugging; the default is to
  remove a room's HLS output on shutdown.
- Monitor per-room log counters for decoded packets, decode failures,
  underruns, PCM queue drops, and FFmpeg write failures.
