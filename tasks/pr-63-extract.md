# Extract freeunit-exp#63 (both commits) to the main repo

- **Status:** in-progress — commits local, not compiled (memory gate)
- **Created:** 2026-10-16
- **Agent:** Space Bunny Free (OpenCode v2.0.29)

Supersedes `pr-63a-extract.md` for the branch state; that file keeps the
first commit's detail.

## What needs to be done

Port the PR's two own commits onto upstream master as two commits with a
measurement note on the second and a changelog entry on the first.

## Findings

- **PR identity.** `gh pr view 63 --json commits` shows the PR's own work is
  the last two commits, `93f0b54d8` and `8b2ef3d5`; the ~50 earlier commits in
  the diff are upstream work the fork base lacks. Porting the diff itself would
  have rewritten upstream.
- **Commit 1, atomics (`2f3ea988`)** — VERIFIED race: `nxt_router_app_can_start()`
  is called at src/nxt_router.c:6827 before the unlock, so its three-counter sum
  is not serialised by `app->mutex`; `nxt_router_app_prefork_ready()` updates
  three counters with no lock. No portability hole: `nxt_atomic_fetch_add()` and
  `nxt_atomic_cmp_set()` are in src/nxt_atomic.h and auto/atomic fails configure
  without them. `%A` is the right modifier (src/nxt_sprintf.c:359); the nine
  test edits are `%uD` -> `%uA`. Added a CHANGES + changes.xml entry, which the
  exp commit lacked; precedent `1f5028db2`, `7517669e`, `f682d447f`.
- **Commit 2, lock skip (`676597b5`)** — VERIFIED the drain asymmetry holds:
  `nxt_router_app_start_failed()` removes the link under the lock and leaves the
  flag set (src/nxt_router.c:7168, 7189), which costs only the lock and an
  empty re-check; the reverse error (a false zero leaving the link queued) is
  not reachable because both writers of 0 sit next to a `nxt_queue_remove()`.
  VERIFIED layout-safe: neither `nxt_request_rpc_data_s` nor `nxt_app_s` is in
  tools/perf/layout-structs.txt, so the shm layout gate does not fire.
- **Measurement hygiene** — the A/A numbers (acquisitions 3.77-4.11 -> 3.03,
  rps within noise of ~30.5k/~31.5k, 2 vCPU shared host, wrk -t2 -c100) are
  quoted in the commit body as the measurement recorded in exp#63, explicitly
  not reproduced here, with the claim narrowed to the acquisition count because
  the contended share was noise-level on that host. No CHANGES entry on this
  commit: nothing observable changes for an operator.

## Gates run here

| gate | result |
|---|---|
| cherry-pick of both commits onto `b09815f1` | clean, no conflicts |
| `check-trailers.py` | exit 0 on both commits |
| `check-public.sh` rules applied to all 154 added lines | no hits |
| `ast-grep test -c tools/ast-grep/sgconfig.yml` | 8 passed, 0 failed |
| `tools/ast-grep/check_baseline.py` | 53 violations, all in baseline, OK |
| full-tree `check-public.sh --all` | 359 findings on origin/master, 359 after commit 1, identical and none in the added ranges (the run for commit 2 exceeded the 120 s tool timeout, so the rules were applied to the diff directly instead) |

## Build result (MEASURED, o-build, aarch64)

`<remote-workdir>/router-atomics`: configure 0, `make -j2` 0, **0 warnings**,
`make tests` 0, `./build/tests` **exit 0**, 96 "passed" lines.  The alert and
warn lines in the log are the negative-path output the tests assert on, not
failures.

**No tripwire.**  Neither commit adds a test, so nothing here catches a
regression in the lock-skip logic.  That commit's only evidence is the
acquisition-count measurement quoted in it, taken on the fork.  Re-measure on a
quiet host before repeating the throughput claim anywhere.

## Local artefacts

| what | where |
|---|---|
| FreeUnit branch | `<worktree>/router-atomic-accounting`, branch `fix/router-atomic-accounting`, commits `2f3ea988` then `676597b5` |

## Next steps

1. On o-build: `./configure --tests && make -j2 && make tests && ./build/tests`.
   The router suites that matter: start-fail, remove-pid soak, detached, proto
   death, proto wedge, websocket, app-timeout (it gained the flag set).
2. Re-measure the acquisition count on a quiet host if the throughput claim is
   ever going to be made; do not restate the 2 vCPU numbers as a speed-up.
3. Merge order with the h1proto guard: independent. Both append to the same
   1.37.1 section, so whichever merges second lands below the other.
4. Next extractions: #31 then #39 (kTLS), which need their own CHANGES entries.
