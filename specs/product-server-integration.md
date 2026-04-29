# Product Integration Spec

## Purpose

Phase 4 connects the proven native performer path to the Electron/Convex product shell.

The product app should let an authenticated performer open an existing jam room, click Start Jamming, receive a short-lived signed join token from Convex, and launch the native client against an official SFU server.

Phase 4 is official-server-only in behavior. Community-compatible fields may exist in backend data so the future model is not blocked, but community server selection, approval, UI, and productization are not part of this phase.

## Decisions And Reasons

### Official Servers Only For Phase 4

Phase 4 uses official servers only.

Reason:

- the first integration target is proving Electron/Convex/native launch end to end
- community server approval, ownership, health, and moderation are productization problems
- community server UI belongs in community surfaces later, not room settings
- this avoids mixing Phase 5 behavior into Phase 4

Future:

- community servers can use the same token contract
- community rooms should select only their own community's approved server
- official/community discovery, approval, health, and deployment belong to Phase 5

### Server Data Is Backend Operational Data

Users do not choose or edit SFU host, port, server id, or secret in the room UI.

Reason:

- server assignment is infrastructure, not room content
- `joinSecret` is a real secret and must never enter renderer UI
- existing rooms should work without manual room backfill
- room settings should remain focused on room identity and access

Phase 4 behavior:

- `jam_servers` is backend-only operational data
- there is no public server list query
- room query responses do not include server/session details
- official server rows are inserted manually in the Convex dashboard for now

Future:

- admin tooling or deployment automation can manage official servers
- community server management belongs to community/admin flows

### Live Assignment Uses `jam_sessions`, Not Rooms

Rooms do not store hardcoded server assignment.

Reason:

- rooms are permanent product identity: owner, handle, name, privacy, max performers
- server assignment is live runtime state
- if a room is already jamming, new performers should reuse that active session's server
- if nobody is jamming, backend can choose an available official server

Phase 4 behavior:

- Convex looks for an active `jam_sessions` row for the room
- if active and not expired, reuse its server
- if expired, mark it expired and create a new session
- if none exists, select an enabled official server and create a session

Future:

- SFU-authoritative room presence should replace this bridge
- backend should eventually know active sessions from SFU heartbeat, not Electron refresh

### Session Activity Is A Temporary Bridge

Phase 4 uses Convex `jam_sessions` plus Electron refresh as an MVP bridge.

Reason:

- the SFU does not yet report performer presence to Convex
- Convex cannot know exactly when a native room becomes empty
- Electron already knows local native process state well enough for a first bridge

Phase 4 behavior:

- join token TTL is 2 minutes
- jam session TTL is 5 minutes
- token minting creates/reuses a session and marks the room live
- renderer polls native process status every 2 seconds
- renderer refreshes the Convex jam session every 60 seconds while native is running
- native exit stops refresh; session expires naturally

Future:

- SFU reports room/performer heartbeat to backend
- backend marks rooms live/idle from SFU state
- backend enforces `maxPerformers` from SFU-known performer count
- Electron process state becomes local UI state only

### Capacity Is Not Enforced Yet

Phase 4 does not enforce exact native performer capacity.

Reason:

- Convex does not yet know authoritative SFU performer count
- existing room presence is not the same as native performer presence
- enforcing capacity from stale bridge state would be unreliable

Future:

- capacity enforcement belongs with SFU-authoritative performer presence

### Token Delivery Is MVP-Grade

The renderer may receive a short-lived join token and pass it to Electron main through a typed launch IPC.

Reason:

- renderer already owns Convex authenticated hooks
- Electron main does not currently have Convex auth/session wiring
- token TTL is short
- this avoids changing native C++ in Phase 4

Phase 4 behavior:

- renderer calls Convex mutation to get launch context
- renderer calls typed Electron IPC `launchJamClient(context)`
- Electron main constructs native argv
- renderer never sees `joinSecret`

Future:

- reduce renderer/command-line token exposure
- move token request/launch orchestration out of renderer if needed
- combine token delivery with native session-key binding

## Current Phase 4 Security Limitations

Phase 4 is an MVP bridge, not the final security boundary.

Known limitations:

- The Electron renderer is trusted to request the join token from Convex and pass the launch context to Electron main.
- A compromised renderer, browser devtools session, injected script, or malicious renderer dependency could read the short-lived join token.
- Electron main validates the IPC payload shape, but it still accepts launch context supplied by the renderer.
- The join token is passed to the native client as a command-line argument, which may be visible to local process-inspection tools.
- The token is a bearer token. Whoever has a valid token can attempt to join as that profile until the token expires.
- The SFU does not yet reject reused token nonces.
- The token is not bound to a native session key, device key, or proof-of-possession challenge.
- Convex `jam_sessions` and Electron refresh are temporary session liveness signals; they are not authoritative SFU performer presence.
- Exact performer capacity is not enforced because Convex does not yet know real SFU performer count.
- Server secrets are stored directly in Convex table data for the MVP; there is no key id, rotation flow, revocation flow, or secret manager integration yet.
- Unauthorized UDP traffic is dropped by the SFU, but this is not production-grade UDP abuse or DDoS protection.

These limitations are acceptable only for controlled MVP testing because:

- tokens are short-lived
- tokens are bound to server id, room id, profile id, and role
- server secrets are backend-only and never returned from public queries
- public community/official server hosting is not considered production-ready yet

Planned hardening order:

1. Add SFU nonce replay protection.
2. Reduce renderer and command-line token exposure.
3. Move toward main-process/native launch orchestration or native session-key binding.
4. Add SFU-authoritative presence and capacity.
5. Add key ids, key rotation, compromised-server revocation, metrics, abuse logs, rate limits, and deployment hardening.

## Backend Data Model

`jam_servers`:

- `kind: "official" | "community"`
- `communityId?: Id<"communities">`
- `status: "enabled" | "disabled"`
- `serverId: string`
- `name: string`
- `host: string`
- `port: number`
- `joinSecret: string`
- `priority: number`
- `region?: string`
- `createdAt: number`
- `updatedAt: number`

Indexes:

- `by_kind_status_priority: ["kind", "status", "priority"]`

Notes:

- Phase 4 selects only `kind === "official"`
- `communityId` and `region` are passive future-compatible fields
- `joinSecret` is used only inside backend mutations and is never returned

`jam_sessions`:

- `roomId: Id<"rooms">`
- `jamServerId: Id<"jam_servers">`
- `serverId: string`
- `status: "active" | "expired"`
- `startedAt: number`
- `lastJoinAt: number`
- `lastRefreshAt: number`
- `expiresAt: number`

Indexes:

- `by_room_status: ["roomId", "status"]`
- `by_expires_at: ["expiresAt"]`

Notes:

- `jamServerId` links to the backend server config
- `serverId` snapshots the SFU identity used for debugging
- no `codec` or `frames` are stored; Phase 4 returns Opus `120`

## Backend Functions

`rooms.createPerformerJoinToken({ roomId })`:

- requires authenticated profile
- checks room exists and is active
- checks public/private room access
- expires stale active session for that room if needed
- reuses active session or creates a new official-server session
- validates selected server has a usable secret before creating a session
- marks room `status = "live"` and updates `lastActiveAt`
- signs Phase 3 token with server secret
- returns launch context plus `sessionId`

`rooms.refreshJamSession({ sessionId })`:

- requires authenticated profile
- checks session exists
- checks room exists and access still passes
- refreshes only active non-expired sessions
- updates `lastRefreshAt`, `expiresAt`, room `status`, and `lastActiveAt`
- returns `{ refreshed: true }` or `{ refreshed: false }`
- does not create sessions and does not mint tokens

`rooms.expireStaleJamSessions(...)`:

- available as a simple helper/manual cleanup path
- marks expired active sessions as expired
- marks room idle only if there is no newer active non-expired session
- no cron in Phase 4

## Electron Contract

Product UI uses typed IPC only:

- `launchJamClient(context)`
- `getJamClientStatus()`

Remove or stop using generic raw-argv launch paths for product flow.

Electron main owns native argv construction:

- `--server`
- `--port`
- `--room`
- `--room-handle`
- `--user-id`
- `--display-name`
- `--join-token`
- `--codec opus`
- `--frames 120`

Phase 4 allows one native jam client process per Electron app instance.

## Out Of Scope

- native C++ changes
- listener/HLS mode
- community server UI
- community server approval
- public server directory
- server health checks
- load balancing
- region-based selection
- exact performer capacity enforcement
- SFU-to-Convex heartbeat
- moving ImGui jam UI into Electron
