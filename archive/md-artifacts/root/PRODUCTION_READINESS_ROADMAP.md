# Production Readiness Roadmap

This file tracks the V1 production gates only. The full historical production
notes were broader than the current launch target.

## Gate 1: SFU Production Hardening

Before public official or community SFU usage, the server needs basic
production controls.

### Required

- Bounded handling for unknown UDP endpoints.
- Log throttling for unauthorized or malformed packets.
- Per-IP packet and byte rate limits.
- Per-room packet and participant rate limits.
- Per-server capacity limits.
- Max active rooms per server.
- Max performers per room enforced at the SFU.
- Max unauthenticated endpoints tracked per time window.
- Malformed packet counters.
- Abuse logs that never include full token values.
- Metrics for joins, rejects, drops, room count, performer count, CPU, memory,
  RX/TX bytes, jitter, underruns, and reconnects.
- Process supervision and automatic restart.
- Deployment health checks.
- Network-edge UDP abuse protection.
- Firewall/security-group rules exposing only intended ports.

## Gate 2: SFU-Authoritative Presence And Capacity

Convex and Electron can support the product UI, but active performer presence
and capacity should come from the SFU.

### Required

- SFU reports server heartbeat to the backend.
- SFU reports active room ids and performer counts.
- SFU reports performer joins, leaves, stale endpoints, and room-empty events.
- Backend marks rooms live while the SFU reports active performers.
- Backend marks rooms idle when the SFU reports room empty or heartbeat expiry.
- Backend uses SFU-known performer count for `maxPerformers`.
- Backend prevents token minting when the SFU reports the room is full.
- Backend handles stale native clients and duplicate launches using SFU state.
- Electron native process state remains local UI state only.

## Gate 7: Room Lifecycle, Rules, And Moderation

Keep this after the SFU hardening and authoritative presence work, because room
rules depend on reliable live room state.

### Required

- Define inactivity cleanup for global rooms.
- Define inactivity cleanup for community rooms.
- Enforce one global room plus one room per community.
- Improve private room rules.
- Define host controls.
- Add kick, mute, or ban controls if needed.
- Add performer/listener switching policy if listener mode exists.
- Add duplicate room launch behavior.
- Add stale room/session cleanup.

### Open Decisions

- Whether private rooms are host/friends only, invite-only, or role-based.
- Whether community admins can override room settings.
- Whether community rooms can be public inside the community but hidden
  globally.
