#!/bin/sh
set -eu

SFU_HOST="${SFU_HOST:-host.docker.internal}"
SFU_PORT="${SFU_PORT:-9999}"
HLS_ROOT="${HLS_ROOT:-/hls}"
SEGMENT_DURATION="${SEGMENT_DURATION:-0.5}"
PLAYLIST_SIZE="${PLAYLIST_SIZE:-3}"
OUTPUT_GAIN="${OUTPUT_GAIN:-4.0}"
ALLOW_INSECURE_DEV_JOINS="${ALLOW_INSECURE_DEV_JOINS:-0}"
LISTENER_ROOMS="${LISTENER_ROOMS:-}"

if [ -z "$LISTENER_ROOMS" ]; then
    echo "LISTENER_ROOMS is required. Example: LISTENER_ROOMS=room-a:<listener-token>" >&2
    exit 64
fi

set -- /usr/local/bin/listener_service \
    --server "$SFU_HOST" \
    --port "$SFU_PORT" \
    --hls-root "$HLS_ROOT" \
    --segment-duration "$SEGMENT_DURATION" \
    --playlist-size "$PLAYLIST_SIZE" \
    --output-gain "$OUTPUT_GAIN"

if [ "$ALLOW_INSECURE_DEV_JOINS" = "1" ] || [ "$ALLOW_INSECURE_DEV_JOINS" = "true" ]; then
    set -- "$@" --allow-insecure-dev-joins
fi

old_ifs="$IFS"
IFS=","
for room in $LISTENER_ROOMS; do
    if [ -n "$room" ]; then
        set -- "$@" --room "$room"
    fi
done
IFS="$old_ifs"

exec "$@"
