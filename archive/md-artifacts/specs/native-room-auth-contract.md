# Performer Room/Auth Contract Spec

## Purpose

This spec defines the standalone performer room and auth contract for performer jamming.

The goal is to prove room-aware SFU routing and JOIN authorization inside this repo before integrating Electron, Convex, official server hosting, community server registration, or listener/HLS mode.

## Product Boundary

The jam SFU owns live audio routing only.

The jam SFU should know:

- server id
- live room id
- performer profile/user id
- display name for diagnostics/UI
- endpoint
- join time
- last alive time
- codec/frame metadata needed for routing diagnostics

The jam SFU should not know:

- product room ownership
- private/public room policy
- social graph
- chat
- HLS listeners
- mobile users
- billing or subscriptions
- permanent room lifecycle

Those product concepts belong to a future backend such as Convex.

## Room Model

Rooms in the jam SFU are in-memory routing groups.

A room exists in the SFU only when at least one performer has joined or until stale room state is cleaned up.

The same SFU can host multiple room ids at the same time.

Audio packets must only be forwarded to validated or explicitly dev-allowed performers in the same room id.

Different-room isolation is a hard requirement.

## Join Modes

The SFU supports two join modes.

### Secure JOIN

Secure JOIN is the production-shaped path.

The client sends an extended join containing:

- room id
- optional room handle
- profile/user id
- display name
- join token

The SFU accepts the join only if the token validates for the configured server, room, user, and role.

### Insecure Dev Join

Insecure dev join is allowed only when the SFU is started with an explicit dev flag.

This mode exists for local audio debugging and standalone engine tests.

It must be visibly logged and must not be the default when a join secret or secure mode is configured.

Probes and dev tools use the same structured `JOIN` packet as product clients. There is no separate legacy join path.

## Token Contract

The first secure token design is a short-lived bearer token.

The token is issuer-agnostic. It may be minted by:

- a local dev token tool
- an official backend later
- Convex later
- a community owner's backend later

The SFU only validates the contract.

Initial token fields:

- version
- expiresAtMs
- serverId
- roomId
- profileId
- role
- nonce
- signature

Initial role:

- `performer`

Initial signature design:

- HMAC-SHA256 is acceptable for the performer/dev phase.
- The signed payload should include every security-sensitive field.
- The full token must not be logged.

Open production signing decisions remain deferred:

- per-server HMAC secrets vs asymmetric keys
- key versioning
- secret manager strategy
- community-issued vs app-issued tokens
- compromised server revocation

## Security Boundaries

Private room authorization is not performed by the SFU.

In the future product app, a backend decides whether a signed-in user may join a private room before minting a token.

The SFU enforces only:

- token is present when secure join is required
- token is well formed
- token is not expired
- token signature is valid
- token server id matches this SFU
- token room id matches the join
- token profile id matches the join
- token role permits performer audio

Bearer-token risk is accepted for the first secure version because tokens are short-lived and narrowly scoped.

Later hardening should add nonce replay protection and, if needed, session-key binding.

## Client Contract

The jam client should accept startup flags for standalone room/auth testing:

- `--server <host>`
- `--port <port>`
- `--room <roomId>`
- `--room-handle <handle>`
- `--user-id <profileId>`
- `--display-name <name>`
- `--join-token <token>`
- `--codec <pcm|opus>`
- `--frames <count>`

For local insecure dev mode, room/user/display-name may still be provided without a token only when the SFU explicitly allows insecure joins.

## Server Contract

The jam SFU should accept startup configuration for standalone testing:

- `--port <port>`
- `--server-id <serverId>`
- `--join-secret <secret>`
- `--allow-insecure-dev-joins`

Secure JOINs should fail closed if a token is supplied but no join secret is configured.

Denial reasons should be logged clearly without logging the full token.

## Acceptance Gate

This phase is accepted when:

- same-room performers hear each other
- different-room performers do not hear each other
- secure valid token joins are accepted
- expired tokens are rejected
- wrong-room tokens are rejected
- wrong-user tokens are rejected
- malformed/signature-invalid tokens are rejected
- insecure dev joins work only behind an explicit flag
- probes use the same structured JOIN path as clients
- Opus and PCM accepted audio paths still work after room/auth changes

## Out Of Scope

This phase does not include:

- Convex token minting
- Electron launcher integration
- official server deployment
- community server registration
- server health API
- product room UI
- listener/HLS mode
- performer authoritative presence reporting to a backend
- host moderation controls
