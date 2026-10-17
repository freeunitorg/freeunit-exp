# Extract freeunit-exp#31 (kTLS listener option) to the main repo

- **Status:** in-progress — commit local, not compiled (memory gate)
- **Created:** 2026-10-16
- **Agent:** Space Bunny Free (OpenCode v2.0.29)

## What needs to be done

Port the opt-in `tls.ktls` listener option to upstream master as the first step
of the kTLS work, with the constraints of a feature commit rather than a
bugfix one.

## Findings

- **VERIFIED** the validator message the test asserts: the generic type error is
  `The "%V" value must be %V, but not %V.` at src/nxt_conf_validation.c:1848, so
  `startswith('The "ktls" value must be a boolean')` matches.
- **VERIFIED** no uninitialised read: `nxt_tls_init_t` comes from `nxt_mp_get()`,
  which does not zero, so a new field must be assigned on every path. The new
  `ktls` assignment sits inside the `certificate != NULL` block, before
  nxt_router_conf_tls_insert() and before any use, and every other field of the
  structure is assigned there too. Worth noting in review: this structure is a
  trap for the next field anyone adds.
- **VERIFIED** the warning fires once per listener: `server_init()` receives
  `tls->last`, which the certificate loop sets from `i == 0`, so exactly one call
  per listener has it set. (The name says "last" and the loop passes the first
  index; that inversion predates this change and is used the same way at
  src/nxt_openssl.c:309 and :387.)
- **VERIFIED** no CI entry needed: the shard builder globs `test/test_*.py`, and
  the heavy table only fails when it names a file that is not shared.
- **Changelog decision** — the entry is deliberately absent. 1.37.1 is untagged
  on master (tags stop at 1.37.0), so master is still preparing 1.37.1, and a
  configuration option is a minor-version surface. Upstream opens version
  sections as a dedicated commit (47d2f933, "changelog: open the 1.37.1
  section"), so opening 1.38.0 here would take a decision that is the
  maintainer's. The drafted entry is in the commit body, ready to paste.
- **No product behaviour beyond the option**: no read or write path changes, and
  SSL_read()/SSL_write() behave the same on a kTLS socket.

## Gates run here

| gate | result |
|---|---|
| `git apply` of the PR 31 patch onto `b09815f1` | clean |
| `check-trailers.py` | exit 0 |
| `check-public.sh` rules against all 90 added lines | no hits |
| `ast-grep test -c tools/ast-grep/sgconfig.yml` | 8 passed, 0 failed |
| `tools/ast-grep/check_baseline.py` | 53 violations, all in baseline, OK |

## Build result (MEASURED, o-build, aarch64)

OpenSSL 3.5.9, kernel 6.18.54.

| tree | configure | make | warnings | ./build/tests | pytest `test_tls_ktls.py` |
|---|---|---|---|---|---|
| `feat/tls-ktls-option` @ `f287eb66` (`--openssl --tests`) | 0 | 0 | 0 | exit 0, 98 passed | **2 passed** |
| origin/master + the test file only | 0 | 0 | - | - | **2 failed** |

Both tripwires confirmed on this host, with the failure detail the exp PR
predicted: `Unknown parameter "ktls".` on master against
`The "ktls" value must be a boolean...` with the option.  The fetch test moves a
real 1 MB body over TLS, so the response path ran here too.

Still uncovered: the no-kTLS-OpenSSL warning path, which needs a build whose
headers lack `SSL_OP_ENABLE_KTLS`.  No such OpenSSL exists on this host.

## Local artefacts

| what | where |
|---|---|
| FreeUnit branch | `<worktree>/tls-ktls-option`, branch `feat/tls-ktls-option`, commit `f287eb66` |

## Next steps

1. ~~Build and run.~~ Done: 0 warnings, C tests exit 0, both pytest tests pass,
   both fail on master.
2. The no-kTLS-OpenSSL warning path has never been exercised — the exp PR says
   so too. A build without `SSL_OP_ENABLE_KTLS` is the only way to cover it.
3. The changelog entry still needs a 1.38.0 section; the text is in the commit
   body.
4. PR 39 must be rebased onto this branch, see `pr-39-extract.md`.
