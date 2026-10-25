# Per-application resource limits: what the kernel already enforces, and what FreeUnit does not expose

**Upstream revision:** `freeunitorg/freeunit` `master` @ `4a0271cc50042c59f6452e23fdec408ff6063256` (2026-10-24).
**Fork base:** `freeunitorg/freeunit-exp` `main` @ `d2e585aac1df4d26e2588df13879361ac7a9e581`.

Companion to `kernel-io-and-limits-research.md`, which covers kernel AIO/`sendfile`
and the limits visible in C code. This document covers what happens *at the
kernel interface* when a limit is reached, which of those failures reach FreeUnit,
and the one knob that is still missing: a per-application limit.

---

## 1. What FreeUnit handles today, and what it does not

`nxt_process_nofile_raise()` (`src/nxt_process.c:993`, called at `:881`) raises
the **soft** `RLIMIT_NOFILE` to `max(cur, min(rlim_max, NXT_PROCESS_NOFILE_MAX))`
with `NXT_PROCESS_NOFILE_MAX = 1048576` (`:951`). It runs **only** for
`NXT_PROCESS_ROUTER` and `NXT_PROCESS_CONTROLLER`.

Application processes get no raise. They inherit whatever `unitd` started with.
So on a host that starts the daemon at the common `1024:524288` pair, the router
works with 524 288 descriptors and every application works with **1024** — the
processes that hold sockets, log files and PHP streams are the ones left at the
distro default.

No other limit is touched anywhere in the tree: no `RLIMIT_AS`, `RLIMIT_NPROC`,
`RLIMIT_MEMLOCK`, `RLIMIT_CORE`, `RLIMIT_CPU`.

---

## 2. What the kernel actually does at the boundary

Measured on Alpine edge, musl 1.2.6, kernel 6.8.0, with
`exp/rlimit/rlimit_harness.py` (five cells, each with a matched control; see
`exp/rlimit/RESULTS.md`).

| limit | syscall result | reaches FreeUnit as |
|---|---|---|
| receiver's `NOFILE` full | payload delivered, excess descriptors **closed**, `MSG_CTRUNC` on the message | a port message that looks whole but carries no descriptor — the refusal added for `#291` |
| sender's own `NOFILE` reached by in-flight descriptors | `sendmsg()` → `ETOOMANYREFS` (errno 109) | a failed port post; **not** the receiver's limit, which is the easy misreading |
| `RLIMIT_AS` | `mmap()` → `NULL`, `ENOMEM` | `nxt_mp` growth or SHM segment mapping failing; distinct from OOSM, which is Unit's own backpressure |
| `RLIMIT_NPROC` / cgroup `pids.max` | `fork()` → `-1`, `EAGAIN` | `nxt_process_start()` failure → `nxt_router_app_port_error()`; before the `#255` fix this stranded `proto_port_requests` and wedged the application |

Two measured details that decide test assertions:

- the in-flight ceiling is **strictly greater than** the limit: at soft 32 the
  33rd fd-carrying message fails, so a test must not assert 32;
- `RLIMIT_AS` is reachable with `mmap()` reservation alone, without touching a
  page — which is precisely why it is a poor proxy for a container memory limit,
  where the OOM killer acts on resident pages.

## 3. libc and OS: same syscall, different failure

- **musl never reads `RLIMIT_STACK`.** 128 KiB is the library default
  (`src/internal/pthread_impl.h:197`), raised only by the executable's
  `PT_GNU_STACK` and capped at 8 MiB (`src/env/__init_tls.c:100`). Measured: the
  thread mapping did not move when the soft limit was lowered to 1 MiB.
- **glibc/NPTL does read it,** at program start (`pthread_create(3)` NOTES): the
  soft limit in force when the process started sizes every default thread stack,
  with a per-architecture fallback when unlimited.
  Consequence: one configuration value is harmless on an Alpine image and cuts
  thread stacks on a Debian image.
- **FreeBSD `RLIMIT_NPROC` counts processes only.** The check is `chgproccnt()`
  in `kern_fork.c`; `kern_thr.c` (the `pthread_create` path) has no such call, and
  threads are bounded by `kern.threads.max_threads_per_proc` (1500). On Linux the
  same limit counts threads. One knob, two meanings.
- **macOS/xnu** externalizes SCM rights before measuring the receive buffer, so a
  short receive there does not report `MSG_CTRUNC`.

### OpenBSD and macOS

- **OpenBSD** — nine resources only: `CORE`, `CPU`, `DATA`, `FSIZE`, `MEMLOCK`,
  `NOFILE`, `NPROC`, `RSS`, `STACK` (`getrlimit(2)`, man.openbsd.org). There is
  **no `RLIMIT_AS`**: `RLIMIT_DATA` is the address-space knob and by the manual's
  own wording covers `malloc()` and all anonymous `mmap()`. `RLIMIT_RSS` is "no
  longer enforced, but retained for compatibility", and `RLIMIT_STACK` "is only
  used by the main thread". `RLIMIT_NPROC` is charged per uid in `fork1()`
  (`sys/kern/kern_fork.c`), while `pthread_create` reaches `thread_fork()` through
  `sys___tfork` and meets only the global `kern.maxthread` check — so **threads do
  not count against `NPROC`**.
- **macOS (xnu)** — nine resources, and two silent clamps. `RLIMIT_NOFILE`: the
  kernel enforces `MIN(rlimit, kern.maxfilesperproc)` (`kern_resource.c`), and
  `maxfilesperproc` defaults to `OPEN_MAX`, so asking for more than the sysctl is
  silently ineffective. `RLIMIT_NPROC`: `setrlimit()` clamps the value to
  `maxprocperuid` — `maxproc` for root — so the number you set is not necessarily
  the number in force. `RLIMIT_AS` is real (`vm_map_set_size_limit`), but a value
  below current usage fails with `EINVAL`, and `RLIMIT_RSS` is a **source
  compatibility alias** of `RLIMIT_AS` (`bsd/sys/resource.h`) — two names, one
  limit. `RLIMIT_MEMLOCK` sets the Mach VM wire limit. Thread creation does not
  charge `RLIMIT_NPROC`: `bsd/kern/kern_thread.c` has no `chgproccnt` call.
- Common to OpenBSD, FreeBSD and macOS: **`RLIMIT_NPROC` counts processes, not
  threads.** Only Linux charges threads against it. A shared `nproc` knob would
  therefore mean two different things across the platforms this project builds on.
- Build status: macOS is in CI (`build-test-macos.yml`, `macos-15`); OpenBSD has a
  configure branch (`auto/os/conf`, `kqueue` engine) and **no CI job**, so every
  OpenBSD statement here is source-read.

## 4. Containers: the rlimit is usually not the governor

Measured in a Docker container on this host: `Max open files 4096/524288`,
`Max processes unlimited`, `Max address space unlimited`, while cgroup v2 carried
`memory.max=805306368`, `pids.max=256`, `cpu.max=80000 100000`.

- A Kubernetes memory limit becomes `memory.max`, and the OOM killer acts on
  charge, not on virtual size. Deriving `RLIMIT_AS` from a pod limit is **not**
  equivalent.
- A PID limit becomes `pids.max`. `RLIMIT_NPROC` is worse than useless inside a
  container: the counter lives in the uid's user namespace and is shared with
  every other task of that uid on the host. Measured: 29 tasks visible in the
  container, `NPROC=60` denied the very first thread because the host uid was
  already above it.
- `NOFILE` and `MEMLOCK` have **no cgroup v2 counterpart**, so they must stay
  rlimits — and `NOFILE` is the one whose exhaustion silently truncates
  descriptor passing.

## 5. Proposal: one knob, in `isolation`

```json
"isolation": { "limits": { "nofile": 4096, "memlock": 1, "core": true } }
```

- `nofile` — the only justified addition. It contains one application's
  descriptor leak to that application: the router keeps its own raised table, and
  the app cannot exhaust the router's descriptors through its own account.
- `memlock` — opt-in, for runtimes that lock pages; no cgroup equivalent either.
- `core` — a debugging switch, not a quota.
- **No `as`, `nproc`, `cpu`.** cgroup v2 `memory.max` / `pids.max` / `cpu.max`
  express them better, `isolation.cgroup` already exists, and `nproc` means two
  different things on Linux and FreeBSD (§3).

Constraints that the code makes load-bearing:

1. Set the limit in the child between `fork()` and the language module's
   initialisation. Not because "nothing is mapped yet" — the child inherits the
   parent's address space copy-on-write — but because the runtime has not yet
   sized its pools, stacks or shared memory.
2. Validate at config time against the daemon's inherited `rlim_max`: a soft value
   above it cannot be set without `CAP_SYS_RESOURCE`, so refusing it belongs in
   the validator, not in the fork path.
3. Per-OS gate. `nofile` and `memlock` exist everywhere; anything else needs an
   `#ifdef` and a FreeBSD CI cell, which does not exist in this repository.

## 6. What is still unmeasured

- glibc cells: thread-stack sizing against `RLIMIT_STACK`, and PHP under an `AS`
  limit (does the Zend allocator report cleanly or abort?). The CI job
  `.github/workflows/exp-rlimit-harness.yml` runs the harness on `ubuntu-latest`
  (glibc) and `alpine:edge` (musl) to settle the first; the PHP case needs a
  built runtime.
- FreeBSD: no CI job and no host here. All FreeBSD statements above are
  source-read.
- End-to-end: `prlimit` on a live `unitd` to prove the `NOFILE` → `MSG_CTRUNC` →
  port-teardown path with a real router.

## 7. Fault modelling

The failure shapes above are the input for `andypost/freeunit-model`'s fourth
fault class (`fork EAGAIN`, truncated descriptor delivery, `mmap ENOMEM`), where
the `#255` wedge needs an admission-counter invariant that the existing six do not
have: a stranded `proto_port_requests` leaves `active_streams` empty, so a
progress check over streams stays green while the application can never start
again.
