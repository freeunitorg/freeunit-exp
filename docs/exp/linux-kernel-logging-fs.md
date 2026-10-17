# Linux kernel practices for log safety, performance, and filesystems

Working note for the structured access log design. Context: FreeUnit's router
writes one NDJSON record per request to a file fd opened by the main process
(`src/nxt_router_access_log.c`, `nxt_fd_write` at the call site). This note
summarises what the Linux kernel and common filesystems actually guarantee so
the writer contract is not built on wishful thinking.

## 1. Safety

- Durability is not default: page-cache writes succeed before data reaches
  media. For audit-critical logs, call `fdatasync`/`fsync` (or open with
  `O_DSYNC`/`O_SYNC`) after each record. This is expensive (~hundreds of
  fsync/s on consumer SSDs, ~ms per fsync), so FreeUnit should expose it as
  an option, not force it per record (research note: 100-300 fsync/s on
  typical SSDs; kernel best practice is batching).
- No userland partial-record safety: POSIX does not guarantee atomic writes
  of arbitrary size, and signals/interruption can turn large writes into short
  writes (Linux 3.x+ behaviour on writes straddling page boundaries; bug 55651).
  FreeUnit already refuses whole records past the cap, retries short writes, and
  drops the whole record on residual failure (#541). Keep the "whole record or
  nothing" invariant at the byte level, not only the logical one.
- Multi-writer safety: `O_APPEND` makes offset-advance and write one kernel
  operation under the inode lock, so concurrent writers do not overwrite each
  other (POSIX O_APPEND). But:
  - `pwrite` on an `O_APPEND` fd appends on Linux (contrary to POSIX),
    so never mix modes.
  - Inherited descriptors share one open file description and its offset;
    reopening a file per process without O_APPEND is a known data-loss trap.
  - Readers concurrent with writers may see torn/partial records unless they use
    `O_DIRECT` and aligned buffers; FreeUnit record format must stay
    self-synchronising with per-record error detection so a reader can resync.
- NFS breaks the model entirely: NFS < v5 does not support atomic append and
  simulates it with a race. Dokument: access logs on NFS are not supported for
  concurrent writers; recommend local filesystems. HDFS similarly.
- Secure files: open the fd with `O_CREAT|O_WRONLY|O_APPEND|O_CLOEXEC|O_NOFOLLOW`
  and fixed mode (e.g. 0640), validate the path is a regular file, and refuse a
  path that is a symlink/device (our log fd already comes from the main process
  reopen path; keep the O_NOFOLLOW invariant). Set immutable/append-only
  (`FS_APPEND_FL`) for tamper resistance where the operator requests it.
- Kernel security around file metadata: SELinux/AppArmor labels are a policy
  concern; ensure the unitd context can write the log path and that logrotate
  (or a privileged reopener) handles rotation. Never let an unprivileged
  worker choose or reopen the destination path.

## 2. Performance

- O_APPEND writes to page cache are cheap; the expensive part is `fsync`.
  Batch records in memory and flush periodically (e.g. every N records or every
  M ms) rather than per record unless `O_DSYNC` is requested. The fsync cadence
  should be jittered (memoryless/probabilistic flushing) to avoid synchronised
  bursts across many log files (prior art in the log_file_append library).
- Direct I/O (`O_DIRECT`) gives atomicity of updates up to device limits and
  removes double buffering, but requires aligned buffers (sector size / page
  size) and aligned lengths. FreeUnit records are not page-aligned, so do not
  use O_DIRECT for normal logs; use buffered writes + periodic fsync.
- Avoid splitting logical records in buffered I/O. Buffered streams flush on
  size thresholds; if a 4096-byte buffer is cut in the middle of a record and a
  crash follows, the partial tail becomes invalid JSON. Our refusal of torn
  records at write time is not enough on its own; the write must be attempted as
  one `write()` (it already is), and retry must be on whole-record boundaries.
- `io_uring` can reduce syscall overhead (batched 32+ write+fsync pairs instead
  of 2 syscalls/operation), but its buffered-write fast paths are filesystem-
  and kernel-version-dependent (ext4/xfs/btrfs async buffered write support was
  added ~5.19+/6.x). Benefits are largest with high operation counts, and
  complexity/maintenance cost is real. For a single sequential append log,
  plain `write()` + periodic `fsync()` is the lower-risk choice; revisit
  io_uring if profiling on a quiet `o-build` host shows write syscall overhead
  dominates (it usually does not; requests are dominated by TLS/HTTP/PHP).
- Scheduler/block-layer overhead: block I/O schedulers (BFQ/mq-deadline/kyber)
  can reduce throughput 14-57% on NVMe at high depth; for latency-sensitive
  logs on fast SSDs consider the `none` scheduler for the log volume. Not a
  default change.
- `sync_file_range` can mark dirty pages for write-out without forcing
  completion, but partial-page (`flush_end` not rounded) overwrites hurt
  throughput; round the flushed range down to a generous alignment (e.g.
  1-2 MiB) and keep a bounded lookback.

## 3. Filesystems

- ext4: inode metadata journaling; appends extend the file and update size;
  `fdatasync` is cheaper for append than for overwrite (may avoid journal
  commit in some cases). Concurrent-append atomicity empirically ~4 KiB
  without O_DIRECT in older measurements, but O_APPEND guarantees record
  positioning. journal IO count on ext4 is typically 1 per fdatasync.
- xfs: fast extent-based appends and good concurrency, but historically
  observed 2 journal IOs per small sync (inode update + commit record) unless
  the xfs fix lands; streams are efficient for large sequential writes.
- btrfs: copy-on-write; io_uring async buffered write fast path added in recent
  kernels (6.x). Reflinks/snapshots interact badly with in-place logs; do not
  enable CoW (chattr +C) on log files if you want stable performance, and avoid
  btrfs snapshots of active log files. Fragmentation over time is an operational
  concern.
- tmpfs: log files in memory for benchmarking only; no durability and no
  cross-host semantics.
- block sizes/mount options: `noatime`/`relatime`, larger writeback
  dirty/expire thresholds (`vm.dirty_*`) affect latency-vs-throughput tradeoffs.
  Do not change host-wide tuning for product defaults.
- Filesystem support matrix summary:
  - local POSIX (ext4, xfs): supported, with the caveats above.
  - btrfs: supported with CoW disabled on the log dir.
  - NFS/HDFS: unsupported for concurrent/multi-writer logs.
  - FUSE userspace filesystems: avoid (single-threaded, high overhead).

## 4. Implications for FreeUnit's implementation

1. Open log descriptors with O_APPEND + O_CLOEXEC + O_NOFOLLOW; treat rotation
   via reopen (existing handler) rather than removing the file under the fd.
2. Keep one `write()` per record after full assembly (already planned), with
   retry on whole-record boundaries (never resume mid-JSON-object).
3. Add optional flush mode: `immediate` (best effort page cache, default),
   `sync` (fdatasync per record, operator-opt-in), `batched` (flush every N or
   time). Default stays `immediate`.
4. Document "NFS not supported" and "O_DIRECT not used" explicitly.
5. Keep records <= 4096 bytes and self-synchronising; do not claim fsync-grade
   durability by default.
6. Performance acceptance remains: within A/A noise on the same host and
   filesystem; re-run after adding any flushing mode.

Sources: pvk.ca log append dark arts, kernel bug 55651, man pages for
open(2)/O_APPEND, maxdoubin O_APPEND analysis, xfs/ext4/btrfs discussions
(LWN, mail archives).
