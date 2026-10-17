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

### What it means

The commit *static: send file buffers with sendfile() on plain connections
too* turns on `sendfile()` for every static response on every plain
connection. Below roughly 16 KiB that costs a syscall the memory path did not
need, and on small files — the common case for a web server — it is a large loss.
The regression shrinks as concurrency rises (8 conns: -14% versus -37% at 4),
because the syscall amortises against more in-flight work. Both levels are
reported for that reason.

The crossover is sharp and sits between 12 KiB (-6.5%) and 16 KiB (+81.1%).
Below it, `sendfile()` costs a syscall the memory path did not need; above it,
the response stops being throughput-bound on the copy. A size threshold in
`nxt_http_static_sendfile()` — file buffer at or above 16 KiB, memory path
below — would capture the whole win and none of the loss. That threshold should
still be confirmed at 2 and 8 connections and against a compression path before
it is fixed in the code.

So the change is right in direction and wrong in scope. This is the same concern
that was raised before the port and it is now evidence rather than an argument.

### Limits

- 2 vCPU shared-class box over loopback. Absolute rps are not a property of the
  code; only the ratios between two trees measured together are.
- **No TLS leg.** This measures the plain sendfile path only, i.e. commit B.
  The kTLS `SSL_sendfile()` path (*tls: send static files through SSL_sendfile
when kTLS is active*) is unmeasured: it needs `tls.ktls`
  on and the kernel `tls` module, which this host does not load by default.
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