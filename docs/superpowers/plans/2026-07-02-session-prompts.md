# Session Prompts — Finishing the Low-Latency Roadmap

Copy one prompt per fresh chat, in order. Each session finishes one phase (or one Phase-5
track). Rules that apply to every session are baked into each prompt.

Authoritative files: `LOW_LATENCY_AUDIT.md` (rev b, evidence) and
`LOW_LATENCY_ACTION_PLAN.md` (tracker). `docs/audio-latency-stability-audit.md` and
`archive/` are **historical** — do not treat them as current.

---

## Prompt A — Execute Phase 0+1 (use next)

```
Execute the implementation plan at docs/superpowers/plans/2026-07-02-phase0-1-ci-rt-safety.md
task by task, using superpowers:executing-plans (or subagent-driven-development).
Context files: LOW_LATENCY_ACTION_PLAN.md (phase tracker) and LOW_LATENCY_AUDIT.md rev b
(evidence). docs/audio-latency-stability-audit.md and archive/ are historical — ignore them.

Rules:
- Branch: phase1-rt-safety. One commit per task, in the plan's order.
- After every task: cmake --build build --config Release --parallel 8, then
  ctest --test-dir build -C Release --output-on-failure. Expect 31/31 until Task 7 adds
  participant_manager_self_test, then 32/32.
- The plan's line numbers are anchored to commit 23aebf8 — locate every edit by the quoted
  code, not the line number.
- Do not drift into the plan's "Explicitly Out of Scope" list: no ParticipantManager locking
  redesign, no packet-format changes, leave the dead decoder overloads alone.
- Optional improvement to Task 1's workflow: add a concurrency group with
  cancel-in-progress and an sccache step for faster warm CI runs (repo is public, minutes
  are free — this only reduces wall-clock time).
- Finish with Task 8 exactly as written: run the acceptance commands, record their output,
  set Phase 0 and Phase 1 to Done in LOW_LATENCY_ACTION_PLAN.md, push, confirm CI green
  with gh run watch --exit-status, open a PR.
```

---

## Prompt B — Phase 2: Participant Snapshot (after A is merged)

```
Phase 1 (RT-safe audio callback) is merged on main. Do Phase 2 "Participant Snapshot" from
LOW_LATENCY_ACTION_PLAN.md.

1) Read LOW_LATENCY_ACTION_PLAN.md Phase 2 (the design decision is recorded there — do not
   re-litigate it) and the LOW_LATENCY_AUDIT.md findings "Audio callback takes a
   non-priority-inheriting mutex" and "Participant teardown can run inside the audio
   callback". Audit line numbers are from commit 23aebf8 and have shifted — verify every
   citation against current HEAD before planning.

2) Using superpowers:writing-plans, write
   docs/superpowers/plans/<today>-phase2-participant-snapshot.md. Design (already decided):
   the io thread rebuilds an immutable participant array on every membership change and
   publishes it via atomic shared_ptr store; the audio callback reads it lock-free — it
   must never acquire ParticipantManager::mutex_. GUI/stats read a separately published
   snapshot so they stop contending too. Move decoder creation and Log:: calls out of
   registration critical sections. Keep the Phase-1 graveyard reclamation guarantee intact
   (destruction never on the audio thread).

3) Acceptance must include: a mechanical check that the callback path acquires no mutex
   (scoped grep or debug assertion); participant_manager_self_test extended to cover
   join/leave/timeout/metadata through the snapshot, including the deferred-destruction
   case; full build + ctest green; CI green.

4) Execute the plan with the tracker's execution rules (one branch, one commit per task,
   build+ctest per task). Set Phase 2 status in LOW_LATENCY_ACTION_PLAN.md when done.
```

---

## Prompt C — Phase 3: E2E Latency Measurement (after B is merged)

```
Phases 1-2 are merged on main. Do Phase 3 "E2E Latency Measurement" from
LOW_LATENCY_ACTION_PLAN.md.

1) Read the tracker's Phase 3 section (wire-format and clock-domain decisions are recorded
   there) and the LOW_LATENCY_AUDIT.md finding "No end-to-end latency measurement; audio
   packets carry no capture timestamp". Verify citations against current HEAD.

2) Using superpowers:writing-plans, write
   docs/superpowers/plans/<today>-phase3-e2e-latency.md. Decisions (already made):
   - Capture timestamps are negotiated via a new capability bit — precedent is
     AUDIO_CAP_REDUNDANCY in protocol.h; old clients must interoperate unchanged and the
     server keeps relaying payloads opaquely.
   - Sender stamps in the server-clock domain using its existing offset
     (server_clock_offset_ns_, maintained by the ping/SyncHdr path); receiver converts
     using its own offset. Accuracy bounded by RTT asymmetry is acceptable.

3) Deliverables: per-participant one-way capture-to-playout latency surfaced in the Path
   panel and in baseline snapshot logs; a loopback smoke test wired into ctest asserting
   steady-state one-way latency <= jitter target + 1 packet + callback duration + margin.

4) Execute with the tracker's rules; set Phase 3 status; record a loopback measurement in
   the tracker as the baseline the Phase 4 work will be compared against.
```

---

## Prompt D — Phase 4: TX Path Collapse (after C is merged)

```
Phases 1-3 are merged on main (E2E latency is measurable — that is why this phase comes
now). Do Phase 4 "TX Path Collapse" from LOW_LATENCY_ACTION_PLAN.md.

1) Read the tracker's Phase 4 section. The critical recorded constraint: do NOT add a
   second send socket — the server identifies clients by source ip:port
   (server.cpp handle_audio_message). Recommended design: synchronous send_to from the
   sender thread under socket_mutex_ (hold times are tiny; the io thread takes it only to
   re-arm receives and during rebind), composing with the existing rebind/generation
   logic. Verify asio thread-safety for this pattern or send via the native socket handle.

2) Using superpowers:writing-plans, write
   docs/superpowers/plans/<today>-phase4-tx-collapse.md covering: encode + send on one
   sender thread (audio packets never traverse asio::post), a preallocated packet buffer
   pool including the redundancy-wrapping path, sender thread priority (MMCSS "Pro Audio"
   on Windows), and removing the per-packet notify_one syscall from the audio callback if
   the design allows.

3) Acceptance: audio packets no longer go through asio::post; per-packet heap allocations
   replaced by a pool; before/after comparison of send-queue age p99
   (observe_opus_send_queue_age) AND the Phase-3 E2E number, recorded in the tracker;
   full ctest + CI green. Control traffic may keep using the io thread.
```

---

## Prompt E — Phase 5: Production Hardening (one track per session, after D)

```
Phases 1-4 are merged on main. Phase 5 in LOW_LATENCY_ACTION_PLAN.md is five independent
tracks; do exactly ONE this session — track <X>:

  A security: per-packet authentication via a session key derived in the existing HMAC
    join flow, then payload encryption; server-side token nonce replay tracking;
    per-client packet rate limiting on the server.
  B network: DSCP/QoS marking (qWAVE on Windows — plain IP_TOS is ignored there; IP_TOS
    elsewhere); dual-stack IPv4/IPv6 sockets (currently udp::v4() only).
  C operations: server metrics export in a machine-readable form; log rotation (logger.h
    uses basic_file_sink which never rotates); crash reporting.
  D testing: multi-hour soak with participant churn asserting zero over-deadline callbacks
    and bounded queue drift; room-scale relay load benchmark; impairment matrix
    (loss/reorder/burst x latency profiles) with defined budgets, using the existing
    udp_impair_proxy.
  E devices: real JUCE device-capability enumeration (channels, sample rates — currently
    hardcoded 2ch/48kHz) and input-channel selection.

Read the tracker and the matching LOW_LATENCY_AUDIT.md findings, verify citations against
current HEAD, write the track's plan with superpowers:writing-plans into
docs/superpowers/plans/, execute it under the tracker's rules, update the tracker.
Recommended order: D or A first — D protects everything after it; A gates any public
hosting. Do not start a second track in the same session.
```
