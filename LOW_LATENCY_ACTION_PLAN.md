# Low-Latency Production Action Plan

Source: `LOW_LATENCY_AUDIT.md` rev b, verified against `main` at `23aebf8`.
Structure: this file is the phase tracker. Each phase gets its own detailed, executable
implementation plan under `docs/superpowers/plans/` when it is next up; phases are not
executed from this file directly.

Detailed plans:

- Phase 0 + 1: `docs/superpowers/plans/2026-07-02-phase0-1-ci-rt-safety.md` (written)
- Phase 2–5: written when the preceding phase lands (their designs depend on earlier outcomes)
- Ready-to-paste prompts for the sessions that finish each phase:
  `docs/superpowers/plans/2026-07-02-session-prompts.md`

## Current State

- Release build passes; full test suite passes 32/32 (verified 2026-07-02).
- Receive-side jitter/playout policy is in good shape and regression-tested.
- Top remaining risk: real-time safety of the audio callback.
- CI exists and is green for the Phase 0+1 PR.

## Phase 0: CI (do this first)

Status: Done (2026-07-02, 32/32 tests, CI green)
Why first: it is the cheapest item in the whole plan and it gates every other phase.
The original ordering (CI inside the final phase) meant Phases 1–4 would land unguarded.

Work: GitHub Actions workflow — Windows Release build + full `ctest`, with `build/_deps`
cached. Windows-only initially (matches the dev platform); extend the matrix later.

Acceptance: a PR that breaks the build or any test shows a red check.

## Phase 1: RT Safety

Status: Done (2026-07-02, 32/32 tests, CI green)

Goal: make the audio callback trustworthy under participant churn, log storms, and queue
pressure. Detailed tasks, code, and per-task verification are in the Phase 0+1 plan doc.

Work (summary — the plan doc is authoritative):

- Logger: async overflow `block` → `overrun_oldest` (`logger.h:182`).
- De-log the callback-reachable decoder methods: `decode_into`, `decode_plc(float*, int)`,
  `reset` (`opus_decoder.h`). The vector-based overloads have no callers and are untouched.
- Remove every `Log::*` call from `audio_callback` (`client.cpp:4359, 4462-4469, 4475-4482,
  4503-4512, 4614-4645, 4668-4700, 4808-4823`); replace with atomic counters drained and
  logged by the io-thread cleanup timer.
- Pre-size RT-side queues and switch callback-side `enqueue` → `try_enqueue` with drop
  counters (`client.cpp:2066, 2091, 4998-4999`; `recording_writer.h:126, 294`).
- Deferred participant reclamation: removals park the `shared_ptr` in a graveyard; an
  io-thread reap destroys entries only when no callback snapshot references them
  (`participant_manager.h`), so destruction (heap free + `opus_decoder_destroy`) can never
  run on the audio thread. Covered by a new `participant_manager_self_test`.
- Assert the stream-stopped precondition in `clear_audio_path_queues()` (`client.cpp:1633`).

Acceptance (all mechanically checkable — see plan doc for exact commands):

- Zero `Log::`/`Logger` references inside the `audio_callback` function body (scoped grep).
- `opus_decoder.h` hot methods contain no `Log::` calls (scoped grep with expected output).
- New reclamation self-test passes, including the "live snapshot defers destruction" case.
- No allocating `enqueue(` remains in `client.cpp`/`recording_writer.h` callback paths.
- Release build passes; `ctest` passes 32/32 (31 existing + new self-test).

## Phase 2: Participant Snapshot

Status: Not started — plan doc written after Phase 1 lands.

Goal: the audio callback never acquires `ParticipantManager::mutex_`.

Design decision to make in the plan doc (do not start coding without it): publication
mechanism for the immutable participant snapshot — recommended: io thread rebuilds an
immutable `std::shared_ptr<const std::vector<...>>` on every membership change and
publishes via `std::atomic_store`; callback does `std::atomic_load` (lock-free reads,
single-writer). GUI/stats read a separately published snapshot so they stop contending
entirely. Also move decoder creation and `Log::*` calls out of registration critical
sections (`participant_manager.h:24-50`).

Acceptance: scoped grep proves no mutex acquisition in the callback path; participant
join/leave/timeout/metadata behavior covered by extending `participant_manager_self_test`;
build + full ctest.

## Phase 3: E2E Latency Measurement

Status: Not started — plan doc written after Phase 2 lands.

Goal: mouth-to-ear latency measurable in real sessions and asserted in tests.

Design decisions to make in the plan doc:

- Wire format: extend audio packets with a capture timestamp. Precedent for negotiation
  exists (`AUDIO_CAP_REDUNDANCY` capability bit, `protocol.h:43`); add a capability bit so
  mixed-version rooms keep working — the server relays payloads opaquely, so only clients
  must agree.
- Clock domain: sender stamps in server-clock domain using its existing offset
  (`server_clock_offset_ns_`, `client.cpp:3799-3821`); receiver converts with its own
  offset. Accuracy is bounded by RTT asymmetry — good enough for ms-level reporting.

Acceptance: per-participant one-way capture→playout latency in the Path panel and baseline
snapshots; a loopback smoke asserting steady-state one-way latency ≤ jitter target +
1 packet + callback + margin; build + full ctest.

## Phase 4: TX Path Collapse

Status: Not started — plan doc written after Phase 3 lands (so the improvement is measurable).

Goal: capture-to-wire without the `asio::post` hop; bounded allocations; prioritized sender.

Design decision to make in the plan doc (this is the landmine the original plan ignored):
**socket ownership.** The sender thread must transmit while the io thread receives on the
same socket. A second socket is NOT acceptable — the server identifies clients by source
`ip:port` (`server.cpp:370-382`). Recommended: synchronous `send_to` from the sender thread
under `socket_mutex_` (hold times are sub-microsecond; the io thread only takes it to re-arm
receives and during rebind, `client.cpp:1563, 1727-1740`), which also composes with the
existing rebind/generation logic. Verify no asio thread-safety violation remains, or drop to
the native socket handle for sends.

Acceptance: audio packets no longer traverse `asio::post`; per-packet allocations replaced
by a reusable pool; sender thread runs at raised priority (MMCSS "Pro Audio" on Windows);
p99 send-queue age (`observe_opus_send_queue_age`) measurably lower than the Phase 3
baseline; build + full ctest.

## Phase 5: Production Hardening

Status: Not started — split into independent tracks; each gets its own plan doc.

- Track A (security): per-packet authentication via session key derived at join, then
  payload encryption; server-side token nonce tracking; per-client rate limiting.
- Track B (network): DSCP/QoS marking (qWAVE on Windows — plain `IP_TOS` is ignored there);
  dual-stack IPv4/IPv6 sockets.
- Track C (operations): server metrics export (machine-readable), log rotation
  (`basic_file_sink` never rotates, `logger.h:147`), crash reporting.
- Track D (testing): soak (multi-hour, churn + drift), load (room-scale relay benchmark),
  impairment matrix (loss/reorder/burst × latency profiles) with defined budgets.
- Track E (devices): real capability enumeration and input-channel selection in the JUCE
  backend (`juce_audio_backend.cpp:376-387`).

## Production Gate

Do not call the app production-ready until all of these are true:

- Phase 0–2 complete (CI green, RT-safe callback, no callback mutex).
- E2E latency measured in real sessions (Phase 3).
- Packet authentication implemented; encryption decision made and implemented if hosting
  requires privacy; token replay protection; joined-client rate limiting (Track A).
- Device latency warnings or adaptation exist (audit "granted vs requested" finding).
- Soak/load/impairment tests pass against defined budgets (Track D).
- Server metrics and log rotation exist (Track C).

## Execution Rules

- One branch per phase; one commit per task; build + full ctest after every task.
- Line numbers in plan docs are anchored to the commit named in that doc — match on the
  quoted code, not the number, once earlier tasks have shifted lines.
- A phase is "Done" only when its plan doc's acceptance commands have been run and their
  output recorded in the phase's PR description.
