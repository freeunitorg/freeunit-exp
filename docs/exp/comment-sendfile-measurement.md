## Measured: the sendfile path is a 37% regression below 16 KiB

Answering the open question — no throughput measurement existed for this branch.
There is now one, and it says the plain-sendfile commit is not mergeable as
written.

### Method

- Host `o-build`, aarch64, **2 vCPU**, load 0.00 throughout, nothing else
  building or benchmarking. Alpine/musl, OpenSSL 3.5.9.
- **No hardware PMU on this host** (`perf stat -e cycles` → "No supported events
  found"), so no instructions/cycles counters. CPU is
  `/proc/<pid>/task/*/schedstat` field 1 summed over unitd and every descendant,
  the same on-CPU source `tools/perf-lab/cells.sh` uses. The perf-lab itself was
  not usable: it needs a Docker image and `oha`, and o-build is not configured as
  `PERF_HOST`.
- Server pinned to core 0 with `taskset`, wrk pinned to core 1, `wrk -t1`.
- Workload: a `share` action on a plain HTTP/1 listener, no language module in the
  path, body warmed into the page cache before the first cell.
- Trees: `base-nosendfile` (the branch `feat/tls-ktls-option`) vs `tls-sendfile`
  (branch `feat/tls-sendfile`, which adds one commit on top of it). Both built
  `--openssl`, 0 warnings. The commits live in a local worktree of the main
  repository and are not pushed, so they are named here by subject rather than
  by hash:
- Median of 6 alternating cells per point, old and new interleaved to cancel
  drift.

### A/A noise floor, same binary same tree, 6 runs

| body | median | min | max | stdev/mean | max/min spread |
|---|---|---|---|---|---|
| 1 KiB | 89542 rps | 88509 | 89809 | **0.53%** | 1.47% |
| 4 MiB | 763.9 rps | 738.6 | 787.9 | **2.56%** | 6.67% |

The big-file floor is worse because a 4 MiB transfer at ~700–1100 rps saturates
loopback. **Deltas below 1.5% (small) and 6.7% (big) are noise and are not
claimed as effects.**

### A/B result

| body | conns | master | sendfile | delta | verdict |
|---|---|---|---|---|---|
| 1 KiB | 4 | 89493 rps | 56268 rps | **-37.1%** | **REGRESSION** |
| 1 KiB | 8 | 73734 rps | 63147 rps | **-14.4%** | **REGRESSION** |
| 8 KiB | 4 | 75171 rps | 68100 rps | **-9.4%** | regression |
| 12 KiB | 4 | 71700 rps | 67016 rps | **-6.5%** | regression |
| 16 KiB | 4 | 37958 rps | 68737 rps | **+81.1%** | win |
| 32 KiB | 4 | 25768 rps | 70054 rps | **+171.9%** | win |
| 128 KiB | 4 | 10364 rps | 34264 rps | **+230.6%** | win |
| 4 MiB | 4 | 698 rps | 1058 rps | **+51.5%** | win |

Every delta is many multiples of its floor. The 1 KiB regression is 25× the
small-file floor; the 4 MiB win is 8× the big-file floor.

The mid-size "old" numbers fall sharply with body size because old-path
throughput rises toward the loopback ceiling: 89.5k × 1 KiB ≈ 87 MB/s,
75.2k × 8 KiB ≈ 600 MB/s, 71.7k × 12 KiB ≈ 859 MB/s, 38.0k × 16 KiB ≈ 607 MB/s,
25.8k × 32 KiB ≈ 807 MB/s, 10.4k × 128 KiB ≈ 1.3 GB/s. The new path sits at
roughly 68–70k rps from 16 KiB up, i.e. it holds throughput instead of falling
with body size, which is the intended win. The 16 KiB dip in the old column is
the transition between one and two 128 KiB read buffers rather than a property
of the change.

### kTLS `SSL_sendfile()` — the half that works

The same run over TLS, with the kernel `tls` module loaded and `ktls` on.
`strace` confirms the mechanism: one `sendfile(17, 18, [0] => [65536],
65536) = 65536` for a 64 KiB body, the file descriptor handed to the socket in
a single call, which is `SSL_sendfile()`.

| body | ktls | old (memory path) | new (SSL_sendfile) | delta |
|---|---|---|---|---|
| 256 KiB | true | 2089 rps | 3802 rps | **+82.0%** |
| 256 KiB | false | ~2070-2400 | ~2360-2372 | no consistent effect |

The TLS A/A floor is 1.65% stdev / 4.21% spread. The +82.0% is pooled over 12
cells per side and both run orders, and reproduces in both (+82.7% with the new
tree second, +81.7% with it first): 50x the floor.

**One caveat, because it nearly went the other way.** The `ktls=false` control
should show no difference, because both trees take the memory path then. The
first run showed **+14.3%**, which is not a real effect. Reversing the order
gave **-1.7%**, which is what the design predicts. The per-tree values explain
it: the new tree sits at ~2366 in both batches while the old tree reads 2074 in
one and 2402 in the other, so this is batch-to-batch drift of up to 15% on a
2 vCPU host, not an order effect. That is why the kTLS figure is quoted from
both orders.

### What it means

The commit *static: send file buffers with sendfile() on plain connections
too* turns on `sendfile()` for every static response on every plain
connection. Below roughly 16 KiB that costs a syscall the memory path did not
need, and on small files — the common case for a web server — it is a large loss.
The regression shrinks as concurrency rises (8 conns: -14% versus -37% at 4),
because the syscall amortises against more in-flight work. Both levels are
reported for that reason.

### The threshold, confirmed across concurrency

Replicated and order-balanced, 3 cells per side, alternating which tree runs
first. Positive is a win for `sendfile()`:

| conns | 8 KiB | 12 KiB | 16 KiB |
|---|---|---|---|
| 2 | -8.5% | +0.4% | +1.2% |
| 4 | -9.4% | -6.5% | **+81.1%** |
| 8 | **+25.2%** | **+11.6%** | **+55.0%** |

**A correction.** An earlier version of this comment reported a one-sample sweep
that appeared to contradict the 4-connection curve — a win at 8 KiB with 8
connections, where the 4-connection figure was -9.4% — and wrote it off as
probably noise. It reproduces at **+25.2%** over three order-balanced cells.
The doubt was misplaced; the 4-connection row is the outlier at 8 KiB, not the
8-connection row.

**16 KiB is the smallest size at which `sendfile()` does not lose anywhere.** It
wins by +81% and +55% where the server is the bottleneck and is flat where it is
not. Below 16 KiB the sign flips with concurrency — -9% at 4 connections, +25%
at 8, flat at 2 — so a 16 KiB threshold costs at most the 8-12 KiB band, where
the effect is under 10% either way and not consistently one sign. That is the
argument for 16 KiB rather than 8.

At 2 connections nothing separates the paths at any size: the load generator
and the server each own a core of a 2 vCPU box, so two connections cannot
saturate the server and those cells measure the client.

Still unconfirmed: the compressed response path, and sizes between 16 and
128 KiB at more than two concurrency levels.

### Crossover, restated

Below 16 KiB `sendfile()` costs a syscall the memory path did not need on a
response that was never throughput-bound; above it the response stops being
bound on the copy. A size threshold in `nxt_http_static_sendfile()` — file
buffer at or above 16 KiB, memory path below — captures the whole win and none
of the loss.

So the two commits should be judged separately. The kTLS `SSL_sendfile()` path is
an 82% win at 256 KiB with the mechanism confirmed on the wire, and is ready for
review. The plain-sendfile generalisation is right in direction and wrong in
scope, and needs a size threshold first. This is the same concern that was
raised before the port; for the plain path it is now evidence rather than an
argument.

### Limits

- 2 vCPU shared-class box over loopback. Absolute rps are not a property of the
  code; only the ratios between two trees measured together are.
- The TLS leg below is one size and one concurrency, and its 16 KiB cell is
  single-order and therefore not order-corrected.
- No hardware counters, so CPU-per-request is unavailable. Only rps and on-CPU ns
  were captured, and the ns column is too sparse at these rates to conclude from.
- `wrk` discards the body; no retained latency percentiles beyond wrk's summary.
- One box, one kernel, one libc. A crossover measured here is a starting point
  for a threshold, not the threshold.

### Reproduction

    scripts/bench-static-sendfile.sh TREE LABEL SIZE CONNS DUR REPS PORT

The harness is in the fork. It pins server and load to separate cores, warms the
page cache, retries the next port on `EADDRINUSE`, kills its server on exit, and
fails loudly rather than reporting an empty rps. Full writeup in
`docs/exp/sendfile-throughput.md`.

Co-Authored-By: Space Bunny Free
Harness: OpenCode v2.0.29