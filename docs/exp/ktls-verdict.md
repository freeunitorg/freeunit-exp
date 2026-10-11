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

### Coordinator box — cannot answer (measured 2026-10-11)

`setsockopt(SOL_TLS, TLS_TX, …)` on a connected loopback TCP socket fails with errno 92 ENOPROTOOPT
(kernel `6.8.0-136-generic`, Alpine 3.25 container, `CapEff 0`, one seccomp filter). Two precision
points, because the first reading was wrong:

- the `tls` module **is loaded** (`/sys/module/tls` exists, `^tls ` in `/proc/modules`);
- errno 92 is the socket layer's **generic** answer — an unknown level (`31337`) returns the same —
  while `TCP_ULP="tls"` reaches the real kernel path (`ENOTCONN` on an unconnected socket).

So "no TLS protocol handler" is **not** established: missing kTLS hook versus a container filter for
level 282 are both open hypotheses, and neither is decidable from inside. The transferable fact is
narrow and enough for planning: **this container cannot exercise kTLS**, so CI is the measurement
environment. Details and the reproduction snippet live in the KB page on the environment.

### CI — to be filled in from the workflow run

| kernel | `tls` loaded after modprobe | `TLS_TX` accepted | record transform | `sendfile()` ok | plain user/sys CPU | kTLS user/sys CPU |
|---|---|---|---|---|---|---|
| 6.8 (ubuntu-24.04) | — | — | — | — | — | — |
| 5.15 (ubuntu-22.04) | — | — | — | — | — | — |

Run URL: _added by the bot when the workflow reports._

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
