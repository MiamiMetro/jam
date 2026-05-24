# Jam Engine Phase 4 Plan

## Phase

Phase 4 is Product Integration.

The goal is to connect Electron/Convex to the existing native room/auth contract using official SFU servers only.

Community-compatible schema fields are allowed, but community server behavior is not implemented in this phase.

## Implementation Checklist

- [x] Add backend-only `jam_servers` table.
- [x] Add backend-only `jam_sessions` table.
- [x] Add official-server selector helper:
  - select enabled official server
  - order by lowest priority
  - ignore region/load/community fields for Phase 4
- [x] Add `rooms.createPerformerJoinToken`.
- [x] Add `rooms.refreshJamSession`.
- [x] Add simple stale-session expiry helper/manual cleanup path.
- [x] Keep room create/edit modal unchanged.
- [x] Keep server details out of room query responses.
- [x] Add typed Electron IPC `launchJamClient(context)`.
- [x] Add Electron IPC `getJamClientStatus()`.
- [x] Remove or stop using generic raw-argv product launch.
- [x] Update `JamRoom.tsx` Start Jamming flow:
  - call token mutation
  - call typed launch IPC
  - poll local native status every 2 seconds
  - refresh Convex jam session every 60 seconds while running
  - stop refresh when native exits/fails or room component unmounts
- [x] Map common backend errors to user-friendly messages.
- [x] Refresh `apps/desktop/resources/client/client.exe` from the current Phase 3 native client if needed.
- [x] Update validation log with actual commands and manual smoke results.

## Manual Official Server Seed

Insert this row manually in Convex dashboard for Phase 4 development:

```ts
{
  kind: "official",
  status: "enabled",
  serverId: "local-dev",
  name: "Local Official",
  host: "127.0.0.1",
  port: 9999,
  joinSecret: "dev-secret",
  priority: 0,
  region: "local",
  createdAt: Date.now(),
  updatedAt: Date.now()
}
```

Matching SFU command:

```powershell
.\build\Release\server.exe --port 9999 --server-id local-dev --join-secret dev-secret
```

Operator rule:

- do not change `serverId`, `host`, `port`, or `joinSecret` while a jam is active
- Phase 4 does not enforce this in code
- later admin tooling should prevent unsafe edits or create versioned server records

## Reasons For Temporary Bridge Decisions

`jam_sessions` is temporary.

Reason:

- the SFU does not yet report authoritative performer presence
- Convex needs a short-term way to route later joiners to the same SFU
- Electron can refresh while the local native process is running

Future replacement:

- SFU heartbeat reports room/performer state to backend
- backend live/idle/capacity decisions come from SFU state

No max performer enforcement in Phase 4.

Reason:

- Convex does not yet know real SFU performer count
- enforcing capacity from bridge state would be inaccurate

Future replacement:

- enforce capacity from SFU-known performer count

Renderer token delivery is temporary.

Reason:

- renderer already has authenticated Convex access
- token is short-lived
- Electron main does not yet own Convex auth/session

Future replacement:

- reduce renderer/command-line token exposure
- consider main-process launch orchestration or native session-key binding

No community server behavior in Phase 4.

Reason:

- community servers require approval, ownership, health, moderation, and community-page UX
- those are Phase 5/productization concerns

Future replacement:

- community rooms use only their own community's approved server
- public/community server lifecycle gets explicit product flows

## Current Security Limitations To Revisit

These are intentionally deferred from Phase 4 and must be revisited before public official/community hosting:

- Renderer trust: the Electron renderer currently requests the token and passes launch context to Electron main.
- Token visibility: the renderer can see the short-lived token, and the native process receives it as a command-line argument.
- Bearer-token replay: a copied token can be used until expiry; the SFU does not yet enforce nonce replay protection.
- No proof of possession: the token is not bound to a native session key or device/private key.
- Main-process boundary: Electron main validates shape but still trusts renderer-provided launch context.
- Session liveness: Convex `jam_sessions` plus Electron refresh are not authoritative SFU performer presence.
- Capacity: `maxPerformers` is not enforced from real SFU performer count yet.
- Secrets: `joinSecret` is stored directly in Convex table data; there is no key id, rotation, revocation, or secret-manager model yet.
- UDP abuse: unknown/unauthorized packets are handled at the app level, but this is not DDoS protection.

Preferred hardening order:

1. Add SFU nonce replay protection.
2. Reduce renderer and command-line token exposure.
3. Move launch orchestration toward Electron main/native proof-of-possession if needed.
4. Replace bridge session liveness with SFU-authoritative presence/capacity.
5. Add key rotation, compromised-server revocation, observability, rate limits, and deployment hardening.

## Validation Log

2026-04-28:

- `npm run convex:codegen` passed.
- `npm --prefix apps/desktop run build` passed.
- `cmake --build build --target server --config Release` passed.
- `cmake --build build --target client --config Debug` did not complete because Windows denied access to `ZERO_CHECK.tlog\unsuccessfulbuild`; no process was force-killed.
- `cmake --build build --target client --config Release` passed.
- `cmake --build build --target room_routing_probe --config Debug` passed.
- `cmake --build build --target latency_probe --config Debug` passed.
- Refreshed `apps/desktop/resources/client/client.exe` from `build/Release/client.exe`.
- Secure local SFU smoke:
  - server command: `.\build\Release\server.exe --port 9999 --server-id local-dev --join-secret dev-secret`
  - probe command: `.\build\Debug\room_routing_probe.exe --server 127.0.0.1 --port 9999 --server-id local-dev --secret dev-secret`
  - result: `same_room_received=1`, `different_room_received=0`
- Legacy `latency_probe` against secure SFU did not pass because the project removed unauthenticated legacy joins by decision. Follow-up: update latency/audio probes to use the signed join contract instead of legacy JOIN.
- Manual Electron click-through smoke:
  - inserted an enabled official `jam_servers` row in Convex dashboard using `serverId=local-dev`, `host=127.0.0.1`, `port=9999`, `joinSecret=dev-secret`
  - started matching SFU with `.\build\Release\server.exe --port 9999 --server-id local-dev --join-secret dev-secret`
  - clicked Start Jamming from Electron room
  - SFU accepted JOIN with Convex room id, profile id, display name, and token present
  - result: product-to-native signed launch path works for one client
- Manual mixed product/native same-room smoke:
  - Electron-launched client joined through Convex-minted token
  - manual `build\Release\client.exe` joined the same room through `tools/dev-join-token.mjs`
  - result: same-room product client and manual client can connect through the secure SFU path
- Manual different-room isolation from Electron is still pending. Routing isolation is covered by `room_routing_probe`.

## Test Plan

Build/codegen:

```bash
npm run convex:codegen
npm --prefix apps/desktop run build
cmake --build build --target server --config Release
cmake --build build --target client --config Release
cmake --build build --target room_routing_probe --config Debug
cmake --build build --target latency_probe --config Debug
```

Backend validation:

- no enabled official server returns `JAM_SERVER_NOT_CONFIGURED`
- enabled official server without secret returns `JAM_SERVER_SECRET_MISSING`
- inactive room rejects token minting
- guest/unauthenticated user rejects token minting
- private room access rules are respected
- active non-expired session is reused
- expired session is marked expired and replaced
- refresh extends only active non-expired session
- refresh returns false for expired/missing session
- room is marked live on token mint/refresh

Product smoke:

- insert official server dashboard row
- start SFU with matching server id and secret
- sign in
- open existing room without editing/backfilling it
- click Start Jamming
- native client launches
- SFU accepts JOIN
- native client uses Opus `120`
- local status polling notices native exit/failure
- session refresh keeps a long-running native process routed to the same server

Audio/routing smoke:

- two clients in the same room hear each other
- different rooms remain isolated
- wrong server id or wrong secret causes clear SFU rejection
- update latency/audio probes to use signed joins before treating them as secure-SFU acceptance checks

## Acceptance

Phase 4 is accepted when:

- existing rooms can Start Jamming without room server backfill
- Convex mints signed performer tokens for official servers
- Electron launches the native client through typed IPC
- server secrets never reach frontend query data
- room/session/server details stay backend operational state
- local official SFU smoke works with Opus `120`
- bridge limitations and future SFU-authoritative replacement are documented
