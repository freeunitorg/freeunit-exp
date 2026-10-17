# Sendfile path measurement: MEASURED, o-build, 2026-10-17

Answers the question "did you measure the effect on the hot path and throughput".
Yes, now. Earlier state: not measured at all.

## Method

- Host: `o-build`, aarch64, **2 vCPU**, 11 GB RAM, load 0.00 throughout, no other
  build or bench running. Alpine/musl, OpenSSL 3.5.9.
- No hardware PMU on this host (`perf stat -e cycles` → "No supported events
  found"), as `~/agents.md` warns. So **no instructions/cycles counters**. CPU is
  `/proc/<pid>/task/*/schedstat` field 1, summed over unitd and every
  descendant — the same on-CPU source `tools/perf-lab/cells.sh` uses. The
  perf-lab itself was not usable here: it needs a Docker image and `oha`, and
  o-build is not configured as PERF_HOST.
- Server pinned to core 0 with `taskset`, wrk pinned to core 1. wrk -t1.
- Workload: a `share` action over a plain HTTP/1 listener, no language module in
  the path, body warmed into page cache before the first cell.
- Trees: `base-nosendfile` (branch `feat/tls-ktls-option`) vs `tls-sendfile`
  (branch `feat/tls-sendfile`, one commit on top of it). Both built
  `--openssl`, 0 warnings. The commits are in a local worktree of the main
  repository and are not pushed, so they are named by subject below rather than
  by hash.
- Harness: `scripts/bench-static-sendfile.sh` in this repo, run on o-build.
  Prints rps and on-CPU ns per cell.
  Median of 6 alternating cells per point, old and new interleaved to cancel
  drift.

## A/A noise floor (same binary, same tree, 6 runs)

| body | median | min | max | stdev/mean | max/min spread |
|---|---|---|---|---|---|
| 1 KiB | 89542 rps | 88509 | 89809 | **0.53%** | 1.47% |
| 4 MiB | 763.9 rps | 738.6 | 787.9 | **2.56%** | 6.67% |

The big-file floor is much worse than the small one: at ~700-1100 rps a 4 MiB
transfer saturates loopback, so run-to-run variance is large. **Deltas below
1.5% (small) and 6.7% (big) are noise and are not claimed as effects.**

## A/B result

| body | conns | old (master) | new (sendfile) | delta | verdict |
|---|---|---|---|---|---|
| 1 KiB | 4 | 89493 rps | 56268 rps | **-37.1%** | **REGRESSION** |
| 1 KiB | 8 | 73734 rps | 63147 rps | **-14.4%** | **REGRESSION** |
| 8 KiB | 4 | 75171 rps | 68100 rps | **-9.4%** | regression |
| 12 KiB | 4 | 71700 rps | 67016 rps | **-6.5%** | regression |
| 16 KiB | 4 | 37958 rps | 68737 rps | **+81.1%** | win |
| 32 KiB | 4 | 25768 rps | 70054 rps | **+171.9%** | win |
| 128 KiB | 4 | 10364 rps | 34264 rps | **+230.6%** | win |
| 4 MiB | 4 | 698 rps | 1058 rps | **+51.5%** | win |

Every delta above is many multiples of its noise floor. The 1 KiB regression is
25x the small-file floor; the 4 MiB win is 8x the big-file floor.

The 32 KiB and 128 KiB "old" numbers look low next to 8 KiB because old-path
throughput rises with body size toward the ~1.3 GB/s loopback ceiling
(75k x 8 KiB = 600 MB/s; 25.8k x 32 KiB = 843 MB/s; 10.4k x 128 KiB = 1.3 GB/s).
The new path moves the ceiling well past it, which is exactly the intended win.

## What this means

The commit *static: send file buffers with sendfile() on plain connections
too* is **not safe to merge as written**. It turns on `sendfile()` for
every static response on every plain connection, and for a 1 KiB body that costs
a syscall that the memory path did not need: -37% at 4 connections, -14% at 8.
The regression shrinks as concurrency rises (the syscall amortises against more
in-flight work), which is why both levels are reported — the regression is real
at both, just less bad at 8.

The crossover is sharp and sits between 12 KiB (-6.5%) and 16 KiB (+81.1%). A
size threshold in `nxt_http_static_sendfile()` — send a file buffer at or above
16 KiB, keep the memory path below — would capture the whole win and none of the
loss. That threshold should still be confirmed at 2 and 8 connections and against
a compression path before it is fixed in the code.

## kTLS SSL_sendfile (commit *tls: send static files through SSL_sendfile when kTLS is active*)

The kTLS leg is measurable on this host: the kernel `tls` module is loaded and
OpenSSL 3.5.9 has the kTLS BIO calls.  `strace` confirms the path is taken —
one `sendfile(17, 18, [0] => [65536], 65536) = 65536` for a 64 KiB body, the
file descriptor handed to the socket in a single call, which is `SSL_sendfile()`.

A/A floor, same binary, 256 KiB over TLS with `ktls` on, 6 runs: **1.65%
stdev, 4.21% max/min spread**.

| body | ktls | old (memory path) | new (SSL_sendfile) | delta |
|---|---|---|---|---|
| 256 KiB | true | 2089 rps | 3802 rps | **+82.0%** |
| 256 KiB | false | ~2070-2400 | ~2360-2372 | no consistent effect |
| 16 KiB | true | 23993 rps | 25298 rps | +5.4% (single order, not corrected) |

The 256 KiB figure is pooled over 12 cells per side and both run orders, and it
reproduces in both: **+82.7%** with the new tree second, **+81.7%** with it
first.  That is 50x the A/A floor.

### The control, and why it mattered

`ktls=false` must show no difference, because both trees then take the memory
path.  The first control run showed **+14.3%**, which is nonsense and was almost
taken at face value.  Re-running with the order reversed gave **-1.7%**, which
is what the design predicts.  The two batches disagree, and the tree values
show why: the new tree sits at ~2366 in both batches, while the old tree reads
2074 in one and 2402 in the other.  That is **batch-to-batch drift of up to 15%
on this 2 vCPU host**, not an order effect — which is why the kTLS figure is
quoted from both orderings rather than one.

### What this means for the change

The kTLS half is the part that works: at 256 KiB it is an 82% throughput win and
`SSL_sendfile()` is demonstrably the mechanism, not a code path that merely
compiles.  The plain-sendfile half is the part that regresses below 16 KiB.
Those are two separate commits and can be judged separately: the kTLS path is
ready for review, the plain path needs a size threshold first.

## Limits of this measurement

- 2 vCPU, shared-class box, loopback. Absolute rps are not a property of the
  code; only the ratios between two trees measured here are.
- No TLS leg. This measures the **plain** sendfile path only, i.e. commit B.
  The kTLS `SSL_sendfile()` path, commit *tls: send static files through
SSL_sendfile when kTLS is active*, is unmeasured and needs the
  `tls.ktls` option on with the kernel `tls` module, which this host does not
  load by default.
- No hardware counters, so "CPU per request" is unavailable; only rps and
  on-CPU ns were captured, and the ns column is too sparse at these rates to
  draw a conclusion from.
- `wrk` reads and discards; no per-request latency percentile was retained
  beyond wrk's own summary.

## Reproduction

    scripts/bench-static-sendfile.sh TREE LABEL SIZE CONNS DUR REPS PORT

`scripts/bench-static-sendfile.sh` retries the next port on EADDRINUSE, warms the
page cache, pins server and load to separate cores, kills its server on exit, and
fails loudly rather than reporting an empty rps.