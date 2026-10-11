# kTLS step 1 — can the kernel own the TLS record layer for FreeUnit?

**Status:** probe written, numbers pending CI (the coordinator box cannot answer — measured below).
**Measurement:** the `exp-ktls-probe` workflow; per-kernel numbers land in the job summary.

## Question

Static files over TLS are the one place where FreeUnit pays twice. TLS forces `sendfile = OFF` at
connection init (`nxt_openssl.c:1243`), so a response is userspace read + encrypt + copy, once per
4096-byte record, for every byte on the wire. kTLS moves exactly that step into the kernel — the
window only opens after the handshake, which stays in userspace either way.

Step 1 answers three things *before* any FreeUnit code moves:

1. does a kernel we support accept `TLS_TX` (i.e. `CONFIG_TLS` with a loadable `tls` module)?
2. is the plaintext really transformed by the kernel, and does **`sendfile()`** drive it — the payoff?
3. what does it cost, measured the same way in both arms: user + sys CPU time and wall time, plain
   socket vs kTLS socket, both written with `sendfile()`.

## Method

`exp/ktls-probe/ktls_probe.py` — stdlib only, no handshake and no certificates: `TLS_TX` carries the
cipher parameters (`crypto_info`: cipher, key, iv, salt, rec_seq) directly, so the probe is
self-contained and its receiver reads **raw bytes**, meaning every byte on the wire can be checked
(application-data record header present, plaintext absent). No sleeps, no fixed port, bounded runtime.

CI: `.github/workflows/exp-ktls-probe.yml`, legs `ubuntu-24.04` (kernel 6.8) and `ubuntu-22.04`
(5.15) — the pair the project already treats as its floor. `modprobe tls` is attempted and logged so
the module question is answered from the log, not assumed. Probe exit code `2` means "kTLS not
available on this kernel" and is a **result**, not a job failure; any other non-zero code fails.

## Result

### Resolved: the first run measured a probe bug, not the kernel (2026-10-11)

The first CI run reported `TLS_TX accepted: false, errno 92 ENOPROTOOPT` — and so did the coordinator,
on three different kernels, with the `tls` module loaded on all of them. That was read as "no TLS
protocol handler"; it was this probe skipping a documented step.

`Documentation/networking/tls.rst`: "First create a new TCP socket and once the connection is
established set the TLS ULP" — `setsockopt(SOL_TCP, TCP_ULP, "tls")` — "Setting the TLS ULP allows us
to set/get TLS socket options". Kernel-side (`net/tls/tls_main.c`) `tls_init(sk)` is that ULP's
`.init`: it returns `-ENOTCONN` unless `sk_state == TCP_ESTABLISHED`, creates the `tls_context` and
calls `update_sk_prot()`. Only then does `setsockopt(SOL_TLS, …)` reach `do_tls_setsockopt`; without
it the socket layer answers the generic ENOPROTOOPT — exactly the errno an unknown level `31337` also
gets, which is what made the negative look like a kernel property.

**The ULP is mandatory, and the coordinator is not special:** the same connected socket accepts
`TCP_ULP=tls` and then `TLS_TX` locally, and the peer sees `170303002d` with the plaintext hidden. The
earlier "cause not decidable from inside" wording is retracted in the KB.

A second, arithmetic bug surfaced only because the numbers were inspected: every timing column read
`5 × 10.006 s` with ~0.001 s of process CPU. `sendfile()` returns short once the socket buffer is
full, and the drain loop waited for the *requested* payload, sitting in the recv timeout while every
byte the kernel had accepted had already arrived — and the short-read counter compares against what
was actually sent, so it stayed clean.

### Measured — run 38170196534, both legs green, run 38170020740 for the mechanics

| Runner | kernel | `tls` module | `TLS_TX` | route | record transform | `sendfile()` |
|---|---|---|---|---|---|---|
| ubuntu-24.04 | 6.17.0-1022-azure | loaded | accepted | **ulp** | `1703030033`, plaintext hidden | drives it |
| ubuntu-22.04 | 6.8.0-1064-azure | loaded | accepted | **ulp** | `1703030033`, plaintext hidden | drives it |

Cost, 5 reps × 4 MiB requested per rep (`sendfile()` handed over ~2.5 MiB per call, the same in both
arms):

| Arm | plaintext moved | sys CPU | wall | per MiB | throughput |
|---|---|---|---|---|---|
| plain socket (24.04) | 12.57 MiB | 0.0045 s | 0.005 s | 0.36 ms | ~2 770 MiB/s |
| kTLS (24.04) | 12.42 MiB | 0.0101 s | 0.010 s | 0.81 ms | ~1 230 MiB/s |
| plain socket (22.04) | 12.46 MiB | 0.0046 s | 0.005 s | 0.37 ms | ~2 710 MiB/s |
| kTLS (22.04) | 12.42 MiB | 0.0115 s | 0.012 s | 0.92 ms | ~1 020 MiB/s |

**Read this correctly: kTLS is ~2.4× slower than plain here, and that is expected — not a
refutation.** The plain arm performs no cryptography; the kTLS arm pays AES-GCM in the kernel. What
decides anything for FreeUnit is kTLS against **userspace OpenSSL**, which is what would be replaced
(userspace read + encrypt + copy per 4 KiB record + write). This run therefore establishes the
**mechanism** and a **cost baseline** (~0.8–0.9 ms of system CPU per MiB of encrypted plaintext,
~1.0–1.2 GiB/s through `sendfile()` on a shared runner), not the win.

Step 1b, before any FreeUnit code moves: add the OpenSSL arm to the same harness (same loopback pair,
same payload, `SSL_write` in 4 KiB records) so a three-way comparison exists.

## Decision gate

- **Both legs green** (option accepted, transformation true, `sendfile()` drives it, CPU not worse) →
  step 2 is worth building: the `auto/ktls` build probe, the runtime probe, and a kTLS
  `nxt_conn_io_t` variant behind an explicit opt-in, with a cipher gate and a fallback to the
  existing userspace path.
- **5.15 red** → kTLS becomes an opt-in for newer kernels only, or the track stops here. Either way
  the verdict is written into this file, with the numbers.

## What this does not decide

- whether FreeUnit's sendbuf lifetime rules satisfy the two constraints the kernel documentation
  states: with device offload the `sendfile()` data must not be modified while in flight; on the
  receive side a control-message buffer is required or an incoming alert/close_notify returns an
  error (`TLS_SET_RECORD_TYPE`). Both are K-step work, and the receive-side one is new.
- the **SCM_RIGHTS** question: a listening socket is unaffected, but an fd carrying `TLS_TX` that
  crosses a process boundary keeps its offload — must be verified before worker-mode is claimed to
  work.
- the **config surface** (`tls.ktls`): it is API, therefore a minor release, not a patch. It does not
  belong in a 1.37.x patch whatever the CI numbers say.

## Evidence

- kernel documentation, quoted with its corpus in the KB page `engineering/tls-abstraction-ktls.md`
  (`sendfile()` over kTLS; `setsockopt(SOL_TLS, TLS_TX, crypto_info)` after the handshake;
  `TLS_SET_RECORD_TYPE` for control messages).
- CI run URL, when it exists.
