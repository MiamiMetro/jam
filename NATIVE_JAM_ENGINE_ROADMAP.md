# Native Jam Engine Roadmap

## Direction

We are building a standalone native jam engine first.

Electron, Convex, rooms, auth UI, social presence, and mobile integration are explicitly paused until the native engine reaches a stable acceptance gate.

The goal is to prove that the core jamming system is good enough before attaching it to the product shell.

## Why This Order

The original problem was not room management or auth. The original problem was whether the audio stack can support low-latency jamming without robotic, corrupt, or unstable sound.

If the engine is unstable, adding Electron, Convex, room state, auth, process lifecycle, and product UI will make debugging harder. The native engine should be independently testable and shippable as a subsystem.

Competitor-style jamming apps are native-audio-first systems. The product shell should wrap a proven native engine, not define the engine too early.

## High-Level Product Split

### Native Jam Engine

The native repo owns:

- low-latency audio capture and playback
- Opus and PCM transport modes
- UDP packet protocol
- SFU audio routing
- jitter buffering and playout behavior
- device/backend handling
- native jam UI and diagnostics
- standalone secure and insecure dev flows
- automated audio quality and latency validation

### Product App

The Electron/Convex app owns later:

- auth
- user profiles
- social graph
- room discovery
- official room listing
- community server listing
- room ownership rules
- listener/HLS experience
- product lifecycle around launching native jam

Mobile remains social/listener/product-only unless we later decide otherwise.

## Room Model

Convex should eventually own the real product rooms:

- room id
- owner id
- name and handle
- visibility
- permissions
- capacity rules
- assigned official or community SFU server

The SFU should only own live in-memory audio room instances:

- room id to active UDP endpoints
- profile id to endpoint
- endpoint last-seen time
- codec and frame-size state
- audio routing group

The SFU does not create or own permanent product rooms. It lazily creates an in-memory routing bucket when a valid native client joins, and removes it when the room is empty or stale.

## Official And Community Servers

The product can support both official jam servers and community-hosted servers.

Official servers are operated by us and assigned to rooms by the backend.

Community servers are operated by community owners in their own regions or environments. They should be registered in the product backend later, but the native SFU should not require Convex to function.

This means the native SFU should support a standalone auth contract:

- secure mode with signed join tokens
- insecure dev mode only when explicitly enabled
- no hard dependency on Convex

Convex can later become one token issuer for the same contract.

## Auth And Authorization Direction

Authentication and authorization can be designed and tested inside this repo first.

The native repo can define:

- the signed join token format
- server id binding
- room id binding
- user/profile id binding
- role binding
- short expiry
- local SFU token validation
- rejection behavior
- standalone token generation tool or script

Convex integration can come later because it only needs to mint the same token format after checking product permissions.

In other words, Convex should not be required to prove the SFU auth model. The native repo can prove the contract first.

## Token Security Notes

The first signed-token design is a bearer-token design. Whoever has a valid token can attempt to use it until it expires.

All token security levels should remain issuer-agnostic. The issuer may be Convex, an official backend service, a community owner's backend, or a local dev token tool, as long as it follows the same token contract trusted by the SFU.

This is acceptable for the early MVP only if the blast radius is kept small:

- tokens are short lived
- tokens are bound to one server id
- tokens are bound to one room id
- tokens are bound to one profile id
- tokens are bound to one role
- full token values are never logged
- production token minting uses HTTPS through the product app/backend
- insecure joins require an explicit dev-only flag

Private room authorization remains a backend responsibility. Convex should refuse to mint a token unless the signed-in account is allowed to join the room.

Security should progress in this order:

### MVP

Use short-lived bearer tokens.

This means a token is valid proof by itself until it expires. If a user shares or leaks the token, another client may be able to join as that profile for the short token lifetime.

This is acceptable for the first secure version only because the token is short lived and narrowly scoped.

### Better

Add nonce replay protection inside the SFU.

The SFU should remember recently accepted token nonces and reject the same token if it is presented again. This prevents one copied token from being reused repeatedly or by multiple clients at the same time.

This does not stop the first client who presents a stolen token before the real user, but it reduces accidental sharing and simple replay.

### Stronger

Bind the token to a native session key.

The native client would generate an ephemeral keypair before requesting a join token. Convex would sign a token that includes the public key, and the SFU would require the joining client to prove it owns the matching private key.

With this model, a stolen token alone is not enough to join.

This is more complex and should be deferred until the native engine and simpler signed-token model are stable.

Later hardening also includes:

- clear duplicate-token rejection behavior
- safer token delivery than long-lived visible command-line arguments if needed
- audit logs for denied joins without exposing token secrets

## Acceptance Gate Before Electron Integration

Electron integration should stay paused until the native engine satisfies this gate:

- local two-client and multi-client jamming is stable
- Opus at 120 frames is clear enough for the production internet default
- PCM remains available as a LAN/reference mode
- unsafe low-buffer modes are clearly marked or hidden
- macOS CoreAudio is validated as a first-class target
- Windows WASAPI is validated as a first-class target
- ASIO remains optional/reference if useful
- device selection and basic device failure behavior are understood
- reconnect and stale endpoint behavior are defined
- same-room routing is proven
- different-room isolation is proven
- signed native join tokens are validated locally by the SFU
- insecure dev joins are possible only through an explicit dev flag
- automated probes cover latency, routing, auth rejection, and basic audio corruption signals
- manual listening remains clear during representative sessions

## Phase Order

### Phase 1: Native Audio Baseline

Finish the standalone audio engine path before product integration.

This includes stabilizing the current low-latency modes, validating Opus 120, keeping PCM as reference, and making sure robotic/corrupt audio is understood rather than hidden.

### Phase 2: Cross-Platform Native Validation

Validate the same engine on Windows and macOS.

macOS is not a secondary target. CoreAudio behavior must be tested before the product shell depends on this engine.

### Phase 3: Native SFU Room And Auth Contract

Add room-aware routing and local signed-token validation inside the native repo.

This phase should stay product-agnostic. It should work with a local token tool, not only Convex.

### Phase 4: Product Integration

After the native acceptance gate is met, integrate Electron and Convex.

At that point, Convex mints the already-defined join token, Electron launches the native client with product context, and the native SFU validates the token without needing to understand the full social product.

### Phase 5: Official And Community Server Productization

Add official server assignment, community server registration, server health, capacity policy, moderation policy, and deployment tooling.

This is a product layer on top of the proven native engine.

### Pre-Production SFU Hardening Gate

Before official or community SFU servers are exposed publicly, add a dedicated hardening gate.

Phase 3 application-level unknown UDP handling is only for development and controlled testing. Public hosting needs production-grade server protection, including:

- UDP DDoS protection at the provider or network edge
- firewall and security group rules
- per-IP, per-room, and per-server rate limits
- replay protection or nonce caches for join tokens
- token key rotation, key ids, and compromised-server revocation
- metrics, alerting, abuse logs, and clear denial reasons
- server capacity limits and room capacity enforcement
- process supervision, crash restart, and deployment health checks
- region strategy for official and community servers

## Current Decision

We should continue in this order:

1. Standalone native jam engine.
2. Cross-platform native validation.
3. Native room/auth contract in this repo.
4. Electron/Convex integration.
5. Official and community server productization.

Convex integration should be one of the last parts of the MVP path, not the next blocker.

## Open Architecture Decisions

### Server Secrets And Token Signing

We should not assume one global environment secret for production.

Early native/dev work may use one local shared secret, but production design must support multiple official and community servers.

Open questions:

- should official servers use per-server HMAC secrets, asymmetric signing keys, or a secret-manager-backed model?
- should community servers use app-issued tokens, community-issued tokens, or both?
- how should key rotation work?
- should tokens include key version?
- what secret material should Convex store directly, if any?
- how do we revoke or disable one compromised server without affecting others?
