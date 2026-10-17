# Extract freeunit-exp#39 (SSL_sendfile for static files) to the main repo

- **Status:** in-progress — two commits local, built and tested (o-build)
- **Created:** 2026-10-16
- **Agent:** Space Bunny Free (OpenCode v2.0.29)

Supersedes the earlier "blocked" state: the blocker was a missing compiler, and
o-build turned out to work, so it was a caution rather than a constraint.

## What needs to be done

Port the file-buffer send path in two commits, rebased onto the kTLS option
(`pr-31-extract.md`).

## Findings

- **The branch re-adds the option.** `compare/5edbeecfc...ac8f74f6c` says
  `behind=1`: the sendfile branch was cut before `tls.ktls` landed and carries
  its own copy. Not just the option hunks — the debug log of the kTLS status is
  duplicated too. Both are byte-identical to `f287eb66` and were stripped; five
  of seven hunks in the openssl patch and all of the rest applied clean.
- **`test/test_tls_ktls.py` is also a duplicate.** Commit `61f26a4cd` adds it as
  a new file; it is identical to PR 31's apart from the diff header, so nothing
  was needed.
- **Commit B does not need commit A.** `nxt_http_static_sendfile()` returns 1
  for `!r->tls` unconditionally — a plain connection always can, because the
  existing `nxt_conn_io_sendbuf()` routes a file-only buffer to sendfile(). Only
  the TLS arm consults `sendfile_ready()`. So the plain path is independent of
  kTLS and of OpenSSL's kTLS support.
- **Syscall baselines: hand-edited here, and the capture disagrees on libc.**
  The exp branch added `sendfile`/`sendto` and dropped `kill`. Running
  `test/syscalls/capture.sh` on o-build (aarch64, musl) confirms both new
  syscalls appear and `kill` is gone — but the captured set differs from the
  pinned debian-glibc baseline in 12 syscalls each way (`epoll_create1` vs
  `epoll_create`, `pwritev2` vs `pwrite64`, ...), exactly the libc/arch drift the
  README warns about. The hand-edit is right for the baseline's own environment;
  re-capturing in the pinned container is the follow-up.

## Build result (MEASURED, o-build, aarch64, OpenSSL 3.5.9)

`<remote-workdir>/tls-sendfile`, `--openssl --tests`:

| step | result |
|---|---|
| configure / make | 0 / 0, **0 warnings** |
| `make tests` / `./build/tests` | 0 / **exit 0**, 98 passed |
| `pytest test_static_sendfile.py test_tls_ktls.py` | **5 passed** |
| `pytest test_tls.py + test_tls_ktls.py + test_static.py + test_static_sendfile.py` | **68 passed, 76 skipped** |
| `test/syscalls/capture.sh` | exit 0; `sendfile` and `sendto` present, `kill` absent |

The capture is the part that matters: it is the exercised configuration serving
a `share` over a **plain** connection, so `sendfile` appearing is proof the
commit-B path is live and not just compiling.

Gates: trailers exit 0 on both commits · ast-grep 8 passed, baseline 53/53 OK ·
`check-public.sh` 359 findings, all pre-existing upstream lines that my diff
only shifts (RFC section numbers, a historical CVE comment); none in the added
ranges, and the one `ipv4` hit is an RFC section number.

## Local artefacts

| what | where |
|---|---|
| FreeUnit branch | `<worktree>/tls-sendfile`, branch `feat/tls-sendfile`, `5fec24e2` then `4d2a831c` |
| Builds and logs | `<remote-workdir>/` on o-build (`h1p-conn-guard`, `h1p-baseline`, `router-atomics`, `tls-ktls`, `tls-sendfile`, `baseline-ktls`) |

## Next steps

1. Stacked on `feat/tls-ktls-option` (`f287eb66`), which is stacked on
   origin/master. Merge order: option, then sendfile, then the plain-sendfile
   generalisation.
2. Both add or change what a connection sends, so they need a changelog entry
   in a 1.38.0 section; none is written, see `pr-31-extract.md` for why.
3. Re-capture both syscall baselines in the pinned containers.
4. Throughput claims are still unverified here. The fork's numbers (4 MiB
   transfer 8.8 -> 7.4 ms CPU) are its measurements on its base; re-measure on a
   quiet host before repeating them.
5. The kTLS-off TLS send path and the `NXT_EINVAL` failure branch (kTLS stops
   being active between the readiness check and the send) are covered by no
   test. Both are reachable in production.
