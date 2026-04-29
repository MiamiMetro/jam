# Community Jam Servers Spec

## Purpose

Phase 5 adds community-hosted performer jamming to the product model.

The goal is to keep the same jam room experience users already have on the global Jams page, but scope it to a community and route its native performer traffic through that community's configured SFU server.

This phase is not a public server marketplace, approval system, listener/HLS feature, or production hardening phase.

## Product Model

There are two room scopes:

- global rooms
- community rooms

Global rooms:

- live on the global Jams page
- have no `communityId`
- use official SFU server selection

Community rooms:

- live inside a community's `Jam` tab
- have `communityId` set
- use that exact community's configured SFU server
- do not appear on the global Jams page in Phase 5

The SFU remains multi-room. Community hosting changes which server receives tokens for a room; it does not change the SFU routing model.

## Community Jam Tab

Add a `Jam` tab next to `Feed` on the community page.

The tab should:

- be visible to everyone who can view the community
- reuse the same room-card/form visual language as the global Jams page
- list only rooms where `room.communityId === community._id`
- let community members create a room in that community
- show a locked/join prompt for non-members
- keep server configuration out of the tab

Community room detail pages continue to use `/jam/:handle` for Phase 5.

Reason:

- handles remain globally unique
- existing room detail UI can be reused
- community-specific URLs can be added later without breaking the model

## Room Ownership Rule

Users may have:

- one global room
- one room per community

This replaces the current one-room-total product rule.

Recommended implementation:

- add a room scope key, such as `scopeKey`
- global room scope: `global`
- community room scope: `community:<communityId>`
- enforce uniqueness with `hostId + scopeKey`

Room handles stay globally unique in Phase 5.

Reason:

- avoids route ambiguity
- preserves `/jam/:handle`
- avoids scoped-handle complexity in the first community version

## Community Server Configuration

Community server configuration lives in the existing `jam_servers` table.

Community jam is enabled when there is an enabled server row:

- `kind: "community"`
- `communityId: <community id>`
- `status: "enabled"`

Community jam is disabled when:

- no community server row exists, or
- the community server row is disabled

Only the community owner can edit community jam server configuration in Phase 5.

Owner settings live in the existing community settings page as a Jam section.

Editable fields:

- enabled/disabled state
- server display name
- host
- UDP port
- server id
- join secret replacement

The full join secret must not be shown after save.

Normal users must never see server secrets or backend server configuration.

## Active Session Edit Block

Community server config edits should be blocked while active non-expired jam sessions use that community server.

Reason:

- changing host, port, server id, or join secret mid-session can strand active clients
- blocking edits is simpler than versioned server records for Phase 5

Future:

- versioned server records can allow changes that apply only to new sessions

## Server Selection

Token minting selects server by room scope:

- global room: select enabled official server
- community room: select enabled community server for that exact community

Community rooms never fall back to official servers.

Failure should be clear:

- community jam disabled
- community jam server not configured
- community jam server secret missing
- community server config edit blocked by active sessions

Reason:

- community-hosted traffic should not silently move onto official infrastructure
- missing configuration should be visible to the owner/user

## Membership And Access

Community membership is required for:

- creating community rooms
- starting native performer jamming in community rooms

Non-members may see the community `Jam` tab and room list, but cannot create rooms or receive performer join tokens.

Existing private-room behavior remains for Phase 5, with community membership added for community rooms.

Rules:

- global public room: signed-in user can Start Jamming
- global private room: host/friends can Start Jamming
- community public room: community member can Start Jamming
- community private room: community member plus existing private rule, meaning host/friends

Future privacy/access phase:

- richer private room rules for official and community rooms
- invites
- role-based community permissions
- listener vs performer permissions
- mod or host approval flows

## Disabled Community Jam

Disabling community jam does not delete or hide existing community rooms.

Behavior:

- existing community rooms stay visible
- room creation is disabled
- Start Jamming fails clearly
- re-enabling community jam restores create/start behavior

Reason:

- server availability should not destroy room identity/history
- owners can temporarily disable jamming without losing rooms

## Out Of Scope

Phase 5 excludes:

- listener/HLS mode
- public community server directory
- community server approval/verification
- test-connection button
- server health checks
- region/load balancing
- room inactivity cleanup
- exact SFU-authoritative performer capacity
- SFU-to-backend heartbeat
- production UDP hardening
- moving ImGui jam UI into Electron

## Future Work

After Phase 5 MVP:

- verified/approved community server hosting
- community server health/status
- server heartbeat and version reporting
- SFU-authoritative performer presence and capacity
- room inactivity lifecycle for global and community rooms
- richer privacy/access rules
- key rotation and secret replacement UX
- production SFU hardening before public official/community hosting
