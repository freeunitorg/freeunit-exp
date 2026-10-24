# Kernel I/O, `sendfile`, and Resource Limits in FreeUnit

**Pinned upstream revision:** `freeunitorg/freeunit` `master` @ `4a0271cc50042c59f6452e23fdec408ff6063256` (2026-10-24).
All `file:line` references below are at this revision unless a line says otherwise.

**Fork base:** `freeunitorg/freeunit-exp` `main` @ `d2e585aac1df4d26e2588df13879361ac7a9e581`.
The fork base does not have these upstream changes that this document describes:
the `RLIMIT_NOFILE` raise (§3.1, §4), and close-on-exec on sockets that
`nxt_socket_create()` makes (`SOCK_CLOEXEC`), on opened files (`NXT_FILE_CLOEXEC`), on received descriptors
(`MSG_CMSG_CLOEXEC`) and on the epoll engine descriptors (§3.1). It has the other
§3.1 mechanisms, including close-on-exec on accepted sockets (`FD_CLOEXEC` after `accept()`,
`SOCK_CLOEXEC` on `accept4()`), `pipe2(O_CLOEXEC)` and `memfd_create(MFD_CLOEXEC)`.

This document records what the source shows about:

1. Why FreeUnit does not use Linux kernel AIO (`io_submit`, `libaio`) or `io_uring`, and what it uses instead.
2. How `sendfile()` is detected, implemented and used.
3. Which resource limits FreeUnit handles in C code, and which are host (`sysctl`) settings only.
4. What the `RLIMIT_NOFILE` raise does with common `soft:hard` defaults.
5. How musl implements `rlim_t`, `getrlimit()` and `setrlimit()`.

---

## 1. Kernel AIO is not used: what the code does instead

`git grep -iE 'io_submit|io_setup|io_getevents|libaio|aio_read|aio_write|io_uring' -- src auto` finds nothing.

`src/` and `auto/` do not record why kernel AIO or `io_uring` was not adopted: no comment there gives a reason. Item 1 is an inferred reason, from the kernel interface. Items 2-4 are observed: they describe what the code does instead.

1. **Inferred: classic Linux AIO does not give nonblocking buffered file I/O.**
   `io_submit(2)` accepts buffered file I/O as well as `O_DIRECT` I/O. But on a buffered file the submission can block: on a page-cache miss, on filesystem metadata work and on writeback. `O_DIRECT` gives more predictable asynchronous behavior, but it bypasses the page cache and requires aligned offsets, lengths and buffers, and for hot static files the page cache is the fast path. So classic AIO would not make the static file path nonblocking without giving up the page cache. The same reasoning does not cover `io_uring`, which can complete buffered reads asynchronously; `src/` and `auto/` give no reason for not using it.
2. **A readiness event loop.**
   Each router and worker thread runs a non-blocking loop around `epoll_wait(2)`: `nxt_epoll_poll()`, `src/nxt_epoll_engine.c:995-1126`. An `eventfd(2)` wakes the loop for posted work (`nxt_epoll_enable_post()`, `:870-929`), and a `signalfd(2)` delivers signals (`nxt_epoll_add_signal()`, `:747-808`). Other systems use `kqueue`, event ports, `/dev/poll`, `pollset` (AIX), `poll` or `select`.
3. **Static files come from the page cache.**
   - **`pread(2)`:** static bodies are read with `nxt_file_read()` (`src/nxt_file.c:147-171`), which calls `pread()`. See §2.4.
   - **`mmap(2)`:** static compression maps the source file (`src/nxt_http_compression.c:407`, `:503`). The `nxt_sendfile()` fallback for systems without `sendfile()` maps the range (`src/nxt_conn_write.c:303`).
   - **`sendfile(2)`:** the connection write path can send a file buffer with `sendfile()` (`src/nxt_conn_write.c:210-267`). On master, static responses do not reach it (§2.4).
   - **No read-ahead hint is used.** `nxt_file_read_ahead()` (`src/nxt_file.c:179-269`) wraps `posix_fadvise(fd, offset, size, POSIX_FADV_WILLNEED)` on Linux, `fcntl(F_READAHEAD)` on FreeBSD and `fcntl(F_RDAHEAD)` on macOS. Nothing in `src/` calls it.
4. **Blocking work and application isolation.**
   - **Thread pool:** `nxt_thread_pool_t` (`src/nxt_thread_pool.c`) uses a `nxt_locked_work_queue_t` and a semaphore (`nxt_sem_post()` at `:52`, `nxt_sem_wait()` at `:181`). A pool hands work back to an engine with `nxt_event_engine_post()` (`src/nxt_event_engine.c:237`), which wakes the loop through the eventfd above.
   - **Application processes:** application code runs in separate processes. They talk to the router over non-blocking `AF_UNIX` sockets and shared-memory segments (`memfd_create()` at `src/nxt_port_memory.c:509`).

---

## 2. `sendfile()` in FreeUnit

### 2.1 Configure detection (`auto/sendfile`)

`auto/sendfile` probes, in order:

- **Linux** (`NXT_HAVE_LINUX_SENDFILE`): `auto/sendfile:14-31`, `sendfile(-1, -1, &offset, 0)` from `<sys/sendfile.h>`.
- **FreeBSD** (`NXT_HAVE_FREEBSD_SENDFILE`): `auto/sendfile:34-59`, `sendfile(-1, -1, 0, 0, NULL, &sent, 0)`.
- **macOS** (`NXT_HAVE_MACOSX_SENDFILE`): `auto/sendfile:62-84`, `sendfile(-1, -1, 0, &sent, NULL, 0)`.

If none of the three is found, `auto/sendfile:86-89` sets `nxt_found=yes` ("Using our replacement"). The Solaris `sendfilev()`, AIX `send_file()` and HP-UX `sendfile()` probes that follow (the guard at `:94`) run only when `nxt_found` is `no`, so they never run. On those systems `nxt_sendfile()` uses the `mmap()` + `write()` replacement (§2.3).

### 2.2 64-bit offsets and `sendfile64()`

FreeUnit does not call `sendfile64()` by name. It builds with 64-bit file offsets:

- `auto/os/conf:27`, `:80`, `:234` and `:258` add `-D_FILE_OFFSET_BITS=64` to `NXT_CFLAGS`.
- `src/nxt_unix.h:31` (Linux), `:65` (Solaris) and `:118` (HP-UX) define `_FILE_OFFSET_BITS 64` if it is not set, before `<sys/types.h>` (`:180`) and `<sys/sendfile.h>` (`:227`, `:231`).
- So `off_t` is 64-bit on 32-bit and 64-bit targets. glibc's `<sys/sendfile.h>` then maps `sendfile()` to `sendfile64()`. In musl `off_t` is always 64-bit, and `sendfile()` uses the 64-bit syscall.
- `src/nxt_linux_sendfile.c:10-18` records the kernel history: `sendfile()` came in Linux 2.2 with 32-bit offsets; Linux 2.4.21 added `sendfile64()`, which still returned `EINVAL` for a count above 2G-1; Linux 2.6.17 moved `sendfile()` onto `splice()`. Since then a count above `MAX_RW_COUNT` (2 GiB minus one page) is truncated to it instead of giving `EINVAL`.

### 2.3 The active and the legacy `sendfile` paths

1. **Active path, `src/nxt_conn_write.c`:**
   - `nxt_conn_io_write()` (`:17-162`) writes up to `sb.limit = 10 * 1024 * 1024` bytes per call (`:61`) through `c->io->sendbuf(task, &sb)` (`:66`).
   - Plain connections use `.sendbuf = nxt_conn_io_sendbuf` (`src/nxt_conn.c:26`, `src/nxt_epoll_engine.c:110`, `src/nxt_kqueue_engine.c:124`). TLS connections use `nxt_openssl_conn_io_sendbuf` (`src/nxt_openssl.c:174`).
   - `nxt_conn_io_sendbuf()` (`:183-206`) collects leading memory buffers into an `iovec` with `nxt_sendbuf_mem_coalesce0()` (`:188`). When there is no memory buffer and the first buffer is a file buffer (`:201`), it calls `nxt_conn_io_sendfile()` (`:210-267`), which calls `nxt_sendfile()` (`:222`).
   - `nxt_sendfile()` (`:271-319`) selects the call at compile time:
     - `NXT_HAVE_MACOSX_SENDFILE`: `sendfile(fd, s, pos, &sent, NULL, 0)`
     - `NXT_HAVE_FREEBSD_SENDFILE`: `sendfile(fd, s, pos, size, NULL, &sent, 0)`
     - `NXT_HAVE_LINUX_SENDFILE`: `sendfile(s, fd, &pos, size)`
     - otherwise (`:295-316`): `nxt_mem_mmap()` of the page-aligned range, `write(s, ...)`, then `nxt_mem_munmap()`.

2. **Legacy `.old_sendbuf` functions, `src/nxt_*_sendfile.c`:**
   - `src/nxt_linux_sendfile.c` (`nxt_linux_event_conn_io_sendfile()`, `:46-139`, which sends the header buffers with `MSG_MORE` before `sendfile()`), `src/nxt_freebsd_sendfile.c`, `src/nxt_macosx_sendfile.c`, `src/nxt_solaris_sendfilev.c`, `src/nxt_aix_send_file.c` and `src/nxt_hpux_sendfile.c`.
   - They are assigned to `.old_sendbuf` (`src/nxt_conn.c:29-41`, `src/nxt_epoll_engine.c:113-115`, `src/nxt_kqueue_engine.c:127-131`). Nothing in `src/` calls `->old_sendbuf`.

### 2.4 Static files: upstream master and the fork

- **Upstream master (`4a0271cc`).**
  `nxt_http_static_send()` (`src/nxt_http_static.c:552-1345`) allocates `fb` with `nxt_http_static_buf_alloc()` (`:1229`), sets `fb->file`, `fb->file_pos` and `fb->file_end`, and puts `fb` in `r->out`. It does not set the `NXT_BUF_FILE` flag on `fb`. `nxt_http_static_body_handler()` (`:1979-2030`) allocates up to `NXT_HTTP_STATIC_BUF_COUNT` (2, `:32`) memory buffers of `NXT_HTTP_STATIC_BUF_SIZE` (128 KiB, `:33`). `nxt_http_static_buf_completion()` (`:2041-2125`) fills them with `nxt_file_read()` (`:2064`) and sends them with `nxt_http_request_send()` (`:2094`). So a static body goes through two 128 KiB user-space buffers, `pread()` and `writev()`/`send()`, and not through `nxt_conn_io_sendfile()`. The fork base `d2e585aa` does the same.
- **Proposed in the fork, not merged.**
  Commit `7b458a03` ("static: send file buffers with sendfile() on plain connections too") is on the `ktls-sendfile` branch of https://github.com/freeunitorg/freeunit-exp/pull/39 (open). It marks `fb` with `nxt_buf_set_file()` and passes it to `nxt_http_request_send()`, so that `nxt_conn_io_sendbuf()` calls `nxt_conn_io_sendfile()`. The measurement in `docs/exp/sendfile-throughput.md` on https://github.com/freeunitorg/freeunit-exp/pull/101 (open) gives, at 4 connections, -6.5% at 12 KiB, +81.1% at 16 KiB, +230.6% at 128 KiB and +51.5% at 4 MiB, and -37% for a 1 KiB body. That document says the commit is "not safe to merge as written" and proposes a 16 KiB minimum for the `sendfile()` path.

---

## 3. Resource limits: handled in code, or `sysctl` only

### 3.1 Handled in FreeUnit C code

| Limit or resource | Where | What the code does |
|---|---|---|
| `RLIMIT_NOFILE` (open descriptors per process) | `src/nxt_process.c:928-951` (comment and `NXT_PROCESS_NOFILE_MAX`), `nxt_process_nofile_target()` `:973`, `nxt_process_nofile_raise()` `:993-1038`, call at `:881` | The router and the controller (only) raise the soft limit to `max(cur, min(rlim_max, NXT_PROCESS_NOFILE_MAX))`, where `NXT_PROCESS_NOFILE_MAX` is `1048576`, the default Linux `fs.nr_open`. On macOS the target is also not more than `OPEN_MAX`. A soft limit that is already higher stays. Main does not raise its limit, so the application processes keep the limit that `unitd` started with. Not in the fork base. |
| `EMFILE`, `ENFILE`, `ENOBUFS`, `ENOMEM` on accept | `nxt_conn_accept_error()` `src/nxt_conn_accept.c:413`, cases at `:434-441`; `nxt_conn_accept_close_idle()` `:320-351`; `nxt_conn_accept_close_idle_handler()` `:355` | Each failed accept logs an alert (`:438`). On the first failure the listener stops reading and logs a second alert (`:342-345`); it arms a 100 ms retry timer (`:335`) and queues a pass that closes up to 10 idle keep-alive connections (`times = 10`, `:367`). |
| Close-on-exec (no descriptor leaks into exec'd applications) | `src/nxt_socket.c:34-35`, `src/nxt_file.h:173-174` (`NXT_FILE_CLOEXEC`, with fallbacks at `src/nxt_file.c:25` and `:75`), `src/nxt_file.c:959`, `src/nxt_socket_msg.c:60`, `src/nxt_conn_accept.c:207-216`, `src/nxt_epoll_engine.c:270`, `:764`, `:884`, `src/nxt_port_memory.c:509` | `SOCK_CLOEXEC` on sockets, `O_CLOEXEC` on files, `pipe2(O_CLOEXEC)`, `MSG_CMSG_CLOEXEC` on received descriptors, `FD_CLOEXEC` after `accept()` (`accept4()` uses `SOCK_CLOEXEC`, `src/nxt_epoll_engine.c:1152`), `epoll_create1(EPOLL_CLOEXEC)`, `signalfd(SFD_CLOEXEC)`, `eventfd(EFD_CLOEXEC)` and `memfd_create(MFD_CLOEXEC)`. Where a flag is not defined, `nxt_fd_cloexec()` sets `FD_CLOEXEC` after the call. In the fork base only the accepted-socket flags, `pipe2(O_CLOEXEC)` and `MFD_CLOEXEC` are present. |
| `listen()` backlog (`net.core.somaxconn`) | `src/nxt_listen_socket.h:38-50`; `backlog` in the listener API | `NXT_LISTEN_BACKLOG` is `-1` on Linux, FreeBSD, OpenBSD and macOS, where the kernel then uses `somaxconn`. It is `511` on other systems, because "Solaris and NetBSD treat negative value as 0". A listener can set `backlog`. |
| Shared-memory segments per process pair | `src/nxt_port_memory_int.h:75` (and the comment above it); checks at `src/nxt_port_memory.c:66`, `:420`, `src/nxt_unit.c:5459` | `NXT_PORT_MMAPS_MAX` is `65536U`. It bounds the segment ids that the router and libunit accept or create, so that a bad id cannot grow the arrays. It is a bound on ids, not a memory-map limit, and it is not derived from `vm.max_map_count`, which counts VMAs per process. The two are not directly comparable: one mapping is not always one VMA. |

### 3.2 Not handled in C code (host `sysctl` only)

| Kernel parameter | Why it is host-only | Symptom when exhausted |
|---|---|---|
| `fs.file-max`, `fs.nr_open` | System-wide file table and per-process ceiling. An unprivileged process cannot raise them, and `nxt_process_nofile_raise()` never asks for more than `rlim_max`. | `ENFILE` on the host (`VFS: file-max limit <N> reached`), or `EPERM` when `RLIMIT_NOFILE` is set above `fs.nr_open`. |
| `fs.epoll.max_user_watches` | Per-user limit on registered epoll watches. | `epoll_ctl(EPOLL_CTL_ADD)` fails with `ENOSPC`. |
| `net.ipv4.tcp_max_syn_backlog` | Half-open (`SYN_RECV`) queue size. | SYN cookies (with the default `tcp_syncookies=1`) or dropped SYNs under connection bursts. `TcpExtListenDrops` and `TcpExtListenOverflows` count accept-queue (`listen()` backlog) drops, not SYN-queue drops. |
| `net.core.netdev_max_backlog` | Per-CPU ingress packet queue before the IP stack. | Drops in `/proc/net/softnet_stat` before TCP sees the packet. |
| `net.ipv4.ip_local_port_range` | Ephemeral source ports for outbound `connect()` (proxy, OTLP exporter). | `connect()` fails with `EADDRNOTAVAIL` when the 4-tuples are in use or in `TIME_WAIT`. |
| `fs.aio-max-nr` | System-wide kernel AIO slots. FreeUnit does not use kernel AIO, so this matters only to other software on the host. | `io_setup()` fails with `EAGAIN` in those processes. |
| `vm.dirty_ratio`, `vm.dirty_background_ratio` | Page-cache writeback thresholds. FreeUnit does not `fsync()` its logs. | `write()` stalls when dirty pages pass `vm.dirty_ratio` under heavy logging or uploads. |

---

## 4. `RLIMIT_NOFILE` defaults and the raise

`nxt_process_nofile_raise()` sets the router and controller soft limit to `max(cur, min(rlim_max, 1048576))` (§3.1). The result for common `soft:hard` pairs:

| `soft:hard` at start | Soft limit after the raise | Where this pair is common |
|---|---|---|
| `1024:4096` | `4096` | Linux `init_task` default (`INR_OPEN_CUR`, `INR_OPEN_MAX`), when nothing else sets the limit |
| `1024:524288` | `524288` | systemd `DefaultLimitNOFILE` since v240; services and containers that inherit it |
| `65536:1048576` | `1048576` | hosts that set the soft limit to 65536 and the hard limit to `fs.nr_open` |
| `1048576:1048576` | `1048576` (no change) | runtimes that set both limits to 1048576 |
| `1024:infinity` | `1048576` | a hard limit of `RLIM_INFINITY` |

The application processes do not get this raise. They keep the limit that `unitd` started with.

Not verified here: which `soft:hard` pair a given Docker, containerd, EKS or GKE release uses. These change between releases. Check on the target with `cat /proc/<unitd pid>/limits`.

---

## 5. musl: `rlim_t`, `getrlimit()` and `setrlimit()`

Read at musl `bd54dc3e` (2026-10-22), from the https://github.com/kraj/musl mirror.

1. **`rlim_t` is 64-bit on every architecture.**
   `include/sys/resource.h:20` has `typedef unsigned long long rlim_t;`, and `:72` has `#define RLIM_INFINITY (~0ULL)`. `_FILE_OFFSET_BITS` does not change it.
2. **`getrlimit()` (`src/misc/getrlimit.c`)** calls `SYS_prlimit64` first. If that fails with `ENOSYS` (kernels older than 2.6.36), and the architecture has `SYS_getrlimit`, it calls `SYS_getrlimit` and maps `-1UL` to `RLIM_INFINITY`. Values at or above `SYSCALL_RLIM_INFINITY` become `RLIM_INFINITY`.
3. **`setrlimit()` (`src/misc/setrlimit.c`)** calls `SYS_prlimit64` first. Where `SYSCALL_RLIM_INFINITY` differs from `RLIM_INFINITY`, it first maps values at or above `SYSCALL_RLIM_INFINITY` to `RLIM_INFINITY`. Only when `prlimit64` returns `ENOSYS` does it call `SYS_setrlimit`, with the values clamped to `MIN(-1UL, SYSCALL_RLIM_INFINITY)`, in every thread through `__synccall()`.

So `nxt_process_nofile_raise()` on Alpine makes one `prlimit64` call for each of `getrlimit()` and `setrlimit()`.
