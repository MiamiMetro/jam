# Production Readiness Roadmap

## Purpose

The MVP roadmap proved the core path:

1. standalone native performer jamming
2. Windows and macOS validation
3. signed SFU join contract
4. Electron/Convex launch integration
5. community-hosted room MVP

This document tracks what remains before public production use.

The MVP can be used for controlled testing. It is not yet production hardened for public official or community server hosting.

## Current MVP State

The current product path is:

- Convex owns product rooms, users, communities, and token minting.
- Electron launches the native client with room, user, server, codec, frame-size, and token context.
- The native client joins the SFU with a short-lived signed performer token.
- The SFU validates the token and routes audio only inside the joined room.
- Official rooms use backend-selected official servers.
- Community rooms use the exact community-configured server and never fall back to official servers.
- Opus `120` is the production internet default candidate.
- PCM remains a LAN/reference mode.
- Listener/HLS is still out of scope for the performer-jamming MVP.

## Gate 1: SFU Production Hardening

Do this before exposing public official or community SFU servers broadly.

### Required

- Add bounded unknown UDP handling.
- Add log throttling for unauthorized or malformed packets.
- Add per-IP packet and byte rate limits.
- Add per-room packet and participant rate limits.
- Add per-server capacity limits.
- Add max active rooms per server.
- Add max performers per room enforced at the SFU.
- Add max unauthenticated endpoints tracked per time window.
- Add malformed packet counters.
- Add abuse logs that never include full token values.
- Add metrics for accepted joins, rejected joins, packet drops, room count, performer count, CPU, memory, RX/TX bytes, jitter, underruns, and reconnects.
- Add process supervision and automatic restart.
- Add deployment health checks.
- Add provider or network-edge UDP DDoS protection.
- Add firewall/security-group rules that expose only intended UDP/TCP ports.

### Deferred But Expected

- Region-aware capacity planning.
- Load tests with synthetic clients.
- Alerting for packet floods, high rejection rates, and server saturation.
- Dashboard for server health and room load.

## Gate 2: SFU-Authoritative Presence And Capacity

The current product bridge uses Convex session refresh plus Electron process state. That is acceptable for MVP testing only.

The production source of truth for active performers should be the SFU.

### Required

- SFU reports server heartbeat to the backend.
- SFU reports active room ids and performer counts.
- SFU reports performer joins, leaves, stale endpoints, and room-empty events.
- Backend marks rooms live while the SFU reports active performers.
- Backend marks rooms idle when the SFU reports a room empty or the SFU heartbeat expires.
- Backend uses SFU-known performer count for `maxPerformers`.
- Backend prevents minting tokens when the SFU reports the room is full.
- Backend handles stale native clients and duplicate launches using SFU state.
- Electron native process state remains local UI state only, not authoritative room presence.

### Design Notes

- The SFU should not own permanent product rooms.
- Convex remains the product database.
- The SFU owns live in-memory audio room state.
- The backend should tolerate SFU restarts and stale heartbeat expiry.

## Gate 3: Token And Auth Hardening

The MVP signed token is a short-lived bearer token. That is acceptable for controlled testing, but not the strongest end state.

### Required

- Add nonce replay protection in the SFU.
- Reject the same accepted token nonce if reused.
- Add key ids or key versions to tokens.
- Add key rotation for official and community servers.
- Add compromised-server revocation.
- Add duplicate-token behavior.
- Keep full token values out of logs.
- Keep join secrets out of frontend queries.
- Audit Convex queries and mutations for accidental server config leakage.

### Stronger End State

- Native client generates an ephemeral session keypair before requesting a token.
- Backend signs a token bound to the session public key.
- SFU requires the joining client to prove it owns the private key.
- A stolen token alone is no longer enough to join.

### Open Decisions

- HMAC per-server secrets vs asymmetric signing.
- Whether community servers use app-issued tokens, community-issued tokens, or both.
- Whether Convex should store community server secrets directly or use a secret manager.
- How server key rotation is exposed to community owners.

## Gate 4: Electron And Desktop Security Boundary

The MVP bridge trusts the Electron renderer to request launch context and ask main to launch the native client.

This is acceptable for MVP testing, but it should be tightened before production.

### Required

- Treat the renderer as untrusted.
- Minimize sensitive data passed through renderer state.
- Move token request and launch orchestration toward stricter main-process IPC.
- Validate all native launch arguments in the main process.
- Prevent arbitrary executable/path launch.
- Prevent renderer-controlled server secret access.
- Avoid exposing join tokens longer than needed.
- Review command-line token exposure.
- Add stale native process cleanup.
- Add duplicate native process handling.
- Add reconnect and leave cleanup behavior.

## Gate 5: Official Server Deployment

Official servers need a managed deployment path before real users depend on them.

### Required

- Define official server inventory.
- Define per-server `serverId`, region, host, UDP port, and secret/key material.
- Add official server health checks.
- Add official server status: enabled, disabled, draining, unhealthy.
- Add room assignment strategy.
- Add deployment scripts or infrastructure definition.
- Add crash restart and log collection.
- Add observability for room count, performer count, packet rate, CPU, memory, and network.
- Add region strategy.

### Later

- Region selection by user location or room host location.
- Multi-server assignment and load balancing.
- Draining behavior for maintenance.
- Automatic failover policy.

## Gate 6: Community Server Productization

The Phase 5 community server MVP lets a community owner manually configure a server. Production needs stronger product controls.

### Required

- Add community server approval or verification.
- Add server setup/testing UX.
- Add health check before a community server is considered usable.
- Add clear community owner setup docs.
- Add validation for reachable UDP host/port.
- Add community server status: enabled, disabled, unhealthy, pending verification.
- Add community-level room and performer limits.
- Add policy for who can enable or edit community jam settings.
- Add safe secret rotation flow for community servers.
- Add audit logs for server setting changes.

### Later

- Public or semi-public server directory if needed.
- Verified community hosting badge.
- Community-specific moderation controls.
- Community-configurable inactivity cleanup windows.
- Community-specific listener/HLS policy if listener mode is added.

## Gate 7: Room Lifecycle, Rules, And Moderation

The MVP room rules are intentionally small.

### Required

- Define room inactivity cleanup for global rooms.
- Define room inactivity cleanup for community rooms.
- Enforce one global room plus one room per community.
- Improve private room rules.
- Define host controls.
- Add kick/mute/ban if needed.
- Add performer/listener switching policy if listener mode exists.
- Add duplicate room launch behavior.
- Add stale room/session cleanup.

### Open Decisions

- Whether private rooms are host/friends only, invite-only, or role-based.
- Whether community admins can override room settings.
- Whether community rooms can be public inside the community but hidden globally.

## Gate 8: Audio Reliability And Recovery

The current native engine is good enough for the MVP path, but production needs broader coverage.

### Required

- Continue real-device validation on Windows WASAPI.
- Continue real-device validation on macOS CoreAudio.
- Validate ASIO with real hardware if it remains supported.
- Validate device switching during an active session.
- Validate device unplug/replug behavior.
- Add reconnect behavior for network loss.
- Add reconnect behavior for SFU restart.
- Add clear UI/logging for backend latency unknown states.
- Keep Opus `120` as default internet mode until a better validated default replaces it.
- Keep PCM as LAN/reference mode.
- Keep unsafe low-buffer modes hidden or clearly marked experimental.

### Automated Quality Gates

- Latency probe regression.
- Room routing probe.
- Token rejection probe.
- Packet-loss simulation.
- Jitter simulation.
- Corruption/robotic audio proxies.
- Long-session Opus and PCM smoke logs.
- Cross-platform build checks.

## Gate 9: Product UX Polish

The MVP UI should be cleaned up after the production architecture is stable enough.

### Required

- Product presets for Opus internet mode and PCM LAN/studio mode.
- Clear warnings for unsafe low-buffer modes.
- Better native launch state: launching, running, failed, exited, reconnecting.
- Better error messages for bad server config, disabled server, bad token, full room, and unreachable SFU.
- Community server setup copy that avoids implying HTTP links work for UDP.
- UI for server health and disabled/unhealthy states.
- Room cards that clearly show room name, handle, locked state, genre, performer count, and host.

## Gate 10: Listener And HLS

Listener/HLS remains intentionally deferred.

Do not let listener mode destabilize performer jamming.

### Before Starting

- Performer jamming should remain stable over real official/community server tests.
- SFU-authoritative presence and capacity should exist.
- Room lifecycle should be clear.
- Product rules should define who is a performer and who is a listener.

### Open Decisions

- Whether community servers support listener/HLS.
- Whether listener traffic is served by the same SFU host or separate media infrastructure.
- Whether listener mode is near-live or intentionally delayed.
- Whether listener presence belongs in Convex only or also in SFU/media services.

## Gate 11: Documentation And Operations

Production needs repeatable operations, not only code.

### Required

- Official server runbook.
- Community server setup guide.
- Secret rotation guide.
- Incident response guide for compromised server secrets.
- Deployment checklist.
- Local development checklist.
- Manual validation checklist.
- Release packaging checklist for Windows and macOS.
- Troubleshooting guide for UDP/firewall/tunnel issues.

## Completion Definition

The product is production-ready for public performer jamming only when:

- public official servers are deployed and monitored
- community servers have approval or verification
- SFU hardening is complete
- SFU-authoritative presence and capacity are complete
- token replay/key rotation risks are handled
- Electron/native launch boundary is hardened
- room lifecycle and moderation rules are defined
- Windows and macOS audio validation remains clear
- reconnect and stale cleanup behavior are reliable
- listener/HLS remains disabled or is separately validated

Until then, the system should be treated as an MVP suitable for controlled testing, trusted communities, local testing, and manual community-hosted trials.
