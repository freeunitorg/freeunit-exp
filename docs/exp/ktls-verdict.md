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

### Step 1b — userspace TLS, the arm that decides (run 38170607310, both legs green)

Same loopback pair, same payload, `SSL_write` in 4 KiB pieces (`NXT_TLS_BUFFER_SIZE`), OpenSSL
version recorded per runner. Normalised by plaintext moved:

| Arm | ubuntu-24.04 / k6.17 / OpenSSL 3.0.13 | ubuntu-22.04 / k6.8 / OpenSSL 3.0.2 |
|---|---|---|
| plain socket | 0.058 ms user + 0.293 ms sys per MiB — 2 875 MiB/s | 0.055 + 0.178 — 4 345 MiB/s |
| kTLS (`sendfile()`) | 0.100 + 0.714 — 1 232 MiB/s | 0.040 + 0.649 — 1 458 MiB/s |
| **userspace OpenSSL, 4 KiB writes** | **3.309 + 3.214 — 69.5 MiB/s** | **3.649 + 2.066 — 69.5 MiB/s** |

**kTLS against userspace OpenSSL, measured: 17.7× (k6.17) and 21.0× (k6.8) more plaintext per second,
4.5× and 3.2× less system CPU per MiB, and roughly 30× less user CPU** (3.3 ms → 0.1 ms per MiB:
the record loop and the encryption leave the process entirely).

Caveats, stated because they bound the claim:

- The OpenSSL arm is driven from Python (`ssl`, on top of the same OpenSSL), so its absolute figure
  carries per-call interpreter overhead that a C `SSL_write` loop would not pay. What it measures
  structurally — one read + one encrypt + one write per 4 KiB record, against one `sendfile()` — is
  the shape FreeUnit's static-over-TLS path has today.
- The sendfile arms hand over what fits per call (~2.5 MiB of the 4 MiB requested), so their totals
  are smaller than the OpenSSL arm's 20 MiB. That is why the report normalises per MiB and why the
  **ratios, not the totals, are the result**.
- Loopback on a shared runner: absolute MiB/s will differ on real hardware, and device offload — not
  exercised here — can move more of it to the NIC.

The probe now prints these ratios itself (`per_mib`, `ktls_vs_openssl`) in the JSON and in the job
summary, so the next run does not need this note to be read.

## Decision gate

**The gate is passed, with the numbers above.** Both legs agree: kTLS is ~18–21× the throughput of
the userspace OpenSSL path it would replace, with ~3–4.5× less system CPU and ~30× less user CPU per
MiB, on two kernels (6.17 and 6.8) and two OpenSSL versions (3.0.13, 3.0.2). Step 2 is therefore
justified: `auto/ktls` build probe, runtime probe, and a kTLS `nxt_conn_io_t` behind an explicit
opt-in with a cipher gate and a fallback to the existing path.

Two things the numbers do **not** settle, and step 2 must:

- the Python-driven OpenSSL arm sets the floor, not the ceiling, of the userspace path — a C driver
  narrows the gap. The structural gain (no per-record read/encrypt/copy in the worker) survives that,
  but the multiplier will be smaller against a C-level comparison; measure before quoting a factor.
- nothing here says the freed CPU shows up as capacity under a real listener: that needs FreeUnit
  itself, i.e. step 2, not this harness.

The version decision is unchanged: `tls.ktls` is API surface, so it ships in a **minor** and never in
a 1.37.x patch.

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
