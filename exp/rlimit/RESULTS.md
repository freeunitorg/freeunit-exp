# `exp/rlimit` harness — measured results

Run 2026-10-25. Every cell has a matched control; `--self-test` exits non-zero if
a control agrees with its case, so a green run means the mechanism, not the
script, produced the difference.

```
$ python3 exp/rlimit/rlimit_harness.py --self-test
inflight               PASS   sent=33 err=109
inflight-control       PASS   sent=40 err=None
ctrunc                 PASS   fds=0 flags=8
ctrunc-control         PASS   fds=1 flags=0
as                     PASS   reserved=112M err=OSError
as-control             PASS   reserved=256M err=None
stack-musl             PASS   default=2052K lowered=2052K restored=2052K
stack-method-control   PASS   explicit=516K default=2052K
softhard-raise-hard    PASS   -
softhard-raise-beyond  PASS   ValueError
rc=0
```

Environment:

```
Alpine edge, musl 1.2.6, kernel 6.8.0-136-generic, uid 1000, CPython 3.14
/proc/self/limits:  NOFILE 4096/524288, MEMLOCK 8 MiB,
                    NPROC unlimited, AS unlimited, STACK 8 MiB soft
cgroup v2:          memory.max=805306368  pids.max=256  cpu.max=80000 100000
```

What each row establishes:

| row | evidence |
|---|---|
| `inflight` | A sender whose **own** soft limit is 32 fails with errno 109 (`ETOOMANYREFS`) on the 33rd fd-carrying message. The ceiling is `> limit`, not `= limit`. |
| `inflight-control` | The same 40 messages at the same limit succeed once the receiver drains, so the failure is caused by descriptors accumulating in flight, not by the send count. |
| `ctrunc` / `-control` | With the receiver's table full the payload arrives and the descriptor does not, with `MSG_CTRUNC` (`flags=8`); one free slot yields exactly one descriptor and no flag. |
| `as` / `-control` | A 512 MiB `mmap` reservation stops at 112 MiB under a 128 MiB soft `RLIMIT_AS`, and succeeds uncapped. Reservation alone reaches the limit — no page touched, no RSS. |
| `stack-musl` | The thread stack mapping is identical at the default, at a 1 MiB soft limit and after restoring it: musl does not consult `RLIMIT_STACK`. |
| `stack-method-control` | An explicit 512 KiB stack is measured as 516 KiB, so the mapping-diff method really does see a thread stack. |
| `softhard-*` | The hard limit cannot be raised by this process; a soft value above the hard limit is refused. |

Not measurable here, and deliberately not filled in:

- **glibc** — this host has no glibc. The thread-stack-per-`RLIMIT_STACK` cell and
  the PHP-under-`AS` cell need `ubuntu-latest` / a built PHP runtime.
- **FreeBSD** — no host, no CI job.
- **Live `unitd`** — the `NOFILE` → `MSG_CTRUNC` → port-teardown path is proven
  here only at the syscall level.

Four defects this harness had before it was trusted, each caught by a control:
rows lost in forked children (first version printed nothing and exited 0); hard
limits lowered instead of soft, so controls inherited the case's limit;
`threading.stack_size()` being process-global and corrupting the next cell; and a
draining control that was not matched until a readiness pipe removed the fork
race.
