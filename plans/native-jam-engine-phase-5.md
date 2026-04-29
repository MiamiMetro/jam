# Jam Engine Phase 5 Plan

## Phase

Phase 5 is Community Server Productization MVP.

The goal is to let communities host their own performer jam rooms using the same room UX and the same native signed-token SFU contract.

This phase should not become a public server marketplace, listener/HLS feature, or production hardening phase.

## Decisions

- Community page gets a `Jam` tab next to `Feed`.
- Community `Jam` tab uses the same look and behavior as global Jams, scoped to the community.
- Global Jams shows only global rooms.
- Community rooms show only in their community tab for Phase 5.
- Users can have one global room plus one room per community.
- Room handles remain globally unique.
- Existing room form/modal is reused; `communityId` is injected silently when creating from a community.
- Only community members can create community rooms.
- Only community members can Start Jamming in community rooms.
- Non-members can see the tab but get a locked/join prompt.
- Community owner configures the community SFU in existing community settings.
- Server configuration is stored in `jam_servers` with `kind: "community"` and `communityId`.
- Community rooms use only their own community server.
- Community rooms never fall back to official servers.
- Existing private-room behavior stays, with community membership added for community rooms.
- Listener/HLS stays out of scope.
- SFU-authoritative presence/capacity stays after Phase 5 MVP.

## Implementation Checklist

### Backend Schema And Rules

- [x] Add explicit room scope field, recommended `scopeKey`.
- [x] Backfill or tolerate existing global rooms with `scopeKey = "global"`.
- [x] Add/use index for one room per host per scope.
- [x] Update room create rule:
  - global create checks one global room for host
  - community create checks one room for host in that community
  - community create requires community membership
- [x] Keep room handles globally unique.
- [x] Add room listing query for community rooms.
- [x] Update global room listing to exclude community rooms.
- [x] Update token minting server selection:
  - global rooms use official server
  - community rooms use enabled server for exact `communityId`
  - missing/disabled community server fails clearly
- [x] Update token minting access checks:
  - community room requires membership
  - private community room also applies existing private-room rule
- [x] Add community owner-only mutation for community jam server config.
- [x] Ensure community server secret is never returned from public queries.
- [x] Block community server config edits while active non-expired sessions use that server.

### Desktop UI

- [x] Add `Jam` tab next to `Feed` on community page.
- [x] Reuse global Jams visual patterns for community rooms.
- [x] Reuse room create/edit modal with hidden community context.
- [x] Show locked/join prompt for non-members.
- [x] Disable community room creation when community jam is disabled.
- [x] Show clear disabled/not-configured state.
- [x] Link community room cards to existing `/jam/:handle`.
- [x] Add Jam section to existing community settings page for owners.
- [x] Hide full join secret after save.
- [x] Do not add server fields to the room form.

### Product Boundaries

- [x] Keep community rooms out of global Jams page.
- [x] Keep listener/HLS out of this phase.
- [x] Do not add public server approval/discovery.
- [x] Do not add test-connection button.
- [x] Do not add room inactivity cleanup.
- [x] Do not add SFU-authoritative capacity in this phase.

## Validation Log

2026-04-29:

- `npm run convex:codegen` passed.
- `npm --prefix apps/desktop run build` passed.
- Manual product smoke is still pending:
  - owner saves community jam server settings: passed
  - member creates a community room: passed
  - community `Jam` tab hides when jam is disabled and no community rooms exist: passed
  - community room cards and personal room cards show room name plus handle: passed
  - community server settings are separate from community profile save: passed
  - community server settings are blocked while room presence/native session is active: passed
  - community room Start Jamming uses community SFU: passed
  - non-member locked/join prompt: pending
  - global room Start Jamming still uses official SFU: pending

## Expected User Flows

### Community Member Creates Room

1. User opens community page.
2. User clicks `Jam` tab.
3. User clicks create room.
4. Existing room form opens.
5. Form submits with hidden `communityId`.
6. Backend enforces one room for that user in that community.
7. Room appears in community `Jam` tab.

### Community Member Starts Jamming

1. User opens a community room.
2. User clicks Start Jamming.
3. Convex verifies membership and private-room access.
4. Convex selects enabled server for that exact community.
5. Convex mints signed token with room id/profile id/server id.
6. Electron launches native client with Opus `120`.
7. SFU validates token and routes by room id.

### Non-Member Opens Jam Tab

1. User opens community page.
2. User sees `Jam` tab.
3. User sees room list or locked state.
4. User cannot create room.
5. User cannot Start Jamming.
6. UI prompts user to join community.

### Owner Configures Community Server

1. Owner opens community settings.
2. Owner opens Jam section.
3. Owner enables jam and enters server config.
4. Backend stores/updates `jam_servers` row.
5. If active sessions exist, config edit is blocked.
6. Secret is accepted but not displayed after save.

## Test Plan

Backend:

- [ ] User can create one global room and one room in a community.
- [ ] User cannot create two rooms in the same community.
- [ ] Non-member cannot create a community room.
- [ ] Community room handles remain globally unique.
- [ ] Global room listing excludes community rooms.
- [ ] Community room listing includes only that community's rooms.
- [ ] Community token minting fails when community jam is disabled.
- [ ] Community token minting fails when community server config is missing.
- [ ] Community token minting fails for non-members.
- [ ] Community private room token minting applies membership plus private-room rule.
- [ ] Community room token uses the community server, not official server.
- [ ] Community server secret is not returned by public queries.
- [ ] Active session blocks community server config edits.

Desktop:

- [ ] Community page shows `Feed` and `Jam` tabs.
- [ ] Community `Jam` tab matches global Jams visual style.
- [ ] Member can create a community room.
- [ ] Non-member sees locked/join prompt.
- [ ] Community owner can save jam server settings.
- [ ] Full secret is hidden after save.
- [ ] Room form does not show server fields.
- [ ] Community room opens through `/jam/:handle`.
- [ ] Start Jamming launches native client with community server context.

Native/product smoke:

- [ ] Start community SFU with matching `serverId` and `joinSecret`.
- [ ] Create/open community room.
- [ ] Start Jamming from Electron.
- [ ] SFU accepts JOIN.
- [ ] Manual second client in same community room can join with signed token.
- [ ] Global room still uses official server.
- [ ] Community room fails clearly if server config is disabled.

## Acceptance

Phase 5 is accepted when:

- community page has a working `Jam` tab
- members can create community-scoped rooms
- each user can have one global room plus one room per community
- community rooms are not shown on the global Jams page
- community server config is owner-only and backend-only
- community rooms mint tokens against their community server
- community rooms do not fall back to official servers
- non-members cannot create/start community jams
- existing global official-room flow still works
- listener/HLS, approval, health checks, hardening, and SFU-authoritative capacity remain documented follow-ups

## Follow-Up Gates

After Phase 5 MVP:

- SFU-authoritative presence and capacity
- production SFU hardening
- community server approval/verification
- server health and test-connection UX
- room inactivity lifecycle
- richer privacy and access rules
- listener/HLS decision for community servers
