# Extract freeunit-exp#33 (h1proto connection guard) to the main repo

- **Status:** in-progress — commit local, not compiled (memory gate)
- **Created:** 2026-10-16
- **Agent:** Space Bunny Free (OpenCode v2.0.29)

## What needs to be done

Port the 1.37.0 field-crash fix from freeunitorg/freeunit-exp#33 onto upstream
master in a writable worktree, with CHANGES and changes.xml entries, a
regression test, and the house trailers. Build and run on o-build when the host
has memory.

## Findings

- **VERIFIED** — the exp patch applies cleanly to upstream `b09815f1`: all src
  anchors are unchanged (`git apply` clean, no fuzz).
- **Adjusted** — CHANGES and docs/changes.xml entries were re-anchored: the fork
  appended them at the end of its own 1.37.1 section (fork line ~241); upstream's
  1.37.1 section ends at line 369, so the entries land at 371 and 506. Same
  wording, correct location in the unreleased section.
- **Adjusted** — the exp branch is based on the fork's master, which also carries
  upstream-sync commits. Only the src/test/changelog files were ported; the
  workflow and CI files of the exp PR were not touched.
- **Not verified by build** — fu-ops was at 181 MB available when this was
  prepared and the maintainer chose "prepare only, no build, no agent". The
  commit message says so explicitly. `./configure --tests && make -j2 && make
  tests` plus `./build/tests` on o-build is the gate, and the new test must be
  seen to fail (SIGSEGV) on origin/master without the fix.
- **check-public** — no new findings: the tree reports 359 on origin/master and
  359 after the commit, and none of them fall in the added line ranges.
- **check-trailers** — `tools/reviewers.txt` had no entry for this model, so
  check-trailers.py rejected the commit with `unknown model 'Space Bunny Free'`.
  agents.md says a model is added to reviewers.txt before its first trailer, and
  freeunit-harness is a read-only clone, so the entry was added in a writable
  harness worktree (see below) and the gate re-run against that copy: exit 0.

## Build result (MEASURED, o-build, aarch64)

Host quiet (load 0.00), serial, one tree at a time.

| tree | configure | make | warnings | ./build/tests | "passed" lines |
|---|---|---|---|---|---|
| `fix/h1p-conn-guard` @ `81abb1eb` | 0 | 0 | 0 | **exit 0** | 97 |
| origin/master + the test only | 0 | 0 | 0 | **exit 139 (SIGSEGV)** | stops after `nxt_buf test passed` |

The tripwire needed care. The full test does not compile on master — it calls
`nxt_h1p_from_conn()`, which does not exist there — so "the test fails without
the fix" is trivially true and proves nothing on its own. With only the crash
reproduction kept (`nxt_h1p_complete_buffers()` on a zeroed h1proto) the
baseline segfaults, and the fixed tree runs it clean. That is the real tripwire.

This closes the "CI is the gate" caveat in the commit message.

## Local artefacts

| what | where |
|---|---|
| FreeUnit branch | `<worktree>/h1p-conn-guard`, branch `fix/h1p-conn-guard`, commit `81abb1eb` |
| Harness branch | `<worktree>/harness-reviewers`, branch `docs/reviewers-space-bunny-free`, commit `a20861f` (adds `Space Bunny Free` to `tools/reviewers.txt`) |
| Triage of all exp PRs | `docs/exp/extract-to-main-triage.md` |

## Next steps

1. ~~Build and run the C tests.~~ Done, see the build result above: exit 0, 97
   passed, 0 warnings.
2. ~~Show the test is a real tripwire.~~ Done: exit 139 on master with the crash
   reproduction.
3. Merge the harness reviewers.txt change first (a trailer cannot be validated
   without it), then the FreeUnit commit.
4. Nothing is pushed from this host; the maintainer merges locally.
5. ~~Next extractions.~~ #63a and #63b are done, see `pr-63-extract.md`;
   #31 is done, see `pr-31-extract.md`; #39 is blocked, see `pr-39-extract.md`.
