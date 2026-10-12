# kTLS in FreeUnit — step 2: the capability layer

_Increment 2b-i. Complements `docs/exp/ktls-verdict.md`, which records why the kTLS path is
worth building at all and what the numbers were._

## What this increment adds

| Piece | File | Behaviour |
|---|---|---|
| Build probe | `auto/ktls` (sourced from `configure`) | `NXT_HAVE_KTLS` when the headers carry the interface: `SOL_TLS`, `TLS_TX`/`TLS_RX`, `TCP_ULP`, `struct tls12_crypto_info_aes_gcm_128` |
| Source registration | `auto/sources` | adds `src/nxt_ktls.c` to `NXT_LIB_SRCS` when the probe found the header |
| Runtime capability | `src/nxt_ktls.h`, `src/nxt_ktls.c` | `nxt_ktls_supported()` — decides once, on a real loopback connection, whether **this kernel** can offload, and caches the verdict |

No configuration surface, no data-path change, no behaviour change in this increment. The point is
that the interface question and the capability question are separated, because they have different
answers: the header can be present while the running kernel has no `tls` module, and only a real
connection settles that.

## What it relies on, measured rather than assumed

From `docs/exp/ktls-verdict.md` and its runs:

- the TLS ULP must be set on an **established** connection (`TCP_ULP`), and `EEXIST` simply means a
  ULP is already attached — which is the state `TLS_TX` needs, so the probe treats it as success;
- `TLS_TX` then carries version, cipher, key, salt/IV and a record sequence; for TLS 1.3 the
  application-data sequence starts at **0** (measured, not derived);
- the kernel's records are accepted by OpenSSL: 256 KiB in 7 KiB writes arrived complete and in
  order, on kernels 6.17 and 6.8 with OpenSSL 3.0.13 and 3.0.2;
- against the path it replaces, kTLS moved ~18–21× more plaintext per second with ~3–5× less
  system CPU per MiB — with the caveat that the OpenSSL arm was Python-driven, so the multiplier
  will be smaller against a C-level comparator.

`nxt_ktls_supported()` deliberately holds no OpenSSL knowledge: the keys and the cipher belong to
the TLS backend, which is why this file only knows how to hand the kernel a `crypto_info`.

## What is deliberately not here

- **Key extraction from the handshake.** The data path needs the traffic keys: TLS 1.3 gets them
  from the OpenSSL keylog callback (`CLIENT_TRAFFIC_SECRET_0` → HKDF-Expand-Label, as the step 2a
  probe does today), TLS 1.2 from the master secret and the PRF. That is backend work, not
  capability work.
- **The `tls.ktls` opt-in.** A configuration member is API surface: it can only ship in a minor
  release, and it should only exist once there is a data path to switch on.
- **The data path itself**: a kTLS `nxt_conn_io_t` behind that opt-in, `sendfile` re-enabled for
  the connection, a cipher gate that falls back to the userspace path for unsupported ciphers, and
  the shutdown path — `SSL_shutdown`'s close_notify once the kernel owns the record layer, which
  the kernel documentation says travels as `sendmsg()` + `TLS_SET_RECORD_TYPE`.
- **Worker-mode verification**: an fd carrying `TLS_TX` that crosses a process boundary keeps its
  offload. This is an SCM_RIGHTS question and must be answered before kTLS is used behind the
  process split.
- **A C unit test.** There is nothing behavioural to assert beyond what the CI probe already
  measures end to end, and a test that only re-runs `nxt_ktls_supported()` would assert the
  runner's kernel rather than the code. The test belongs with the data path.

## Verified in CI (run 38190157060, every job green)

```
checking for Linux kTLS (SOL_TLS, TLS_TX/TLS_RX) ... found
  CC     build/src/nxt_ktls.o
  CC     build/src/test/nxt_ktls_test.o
  CC     build/src/nxt_ktls.test.o
tests: [notice] kTLS offload: supported by this kernel
```

Four lines, four separate claims: the build probe finds the interface; the source is compiled; the
test is linked; and the runtime probe, executed by the test runner on the CI kernel, answers
"supported". Build & Test (macOS) and the no-TLS build stay green — there the file is not compiled
at all.

## The bug this caught, and why the test exists

The first version of `auto/ktls` did not set the shell variable `NXT_HAVE_KTLS`. `auto/feature`
defines the macro in the generated header but **not** the shell variable, so the `auto/sources`
condition never fired and `src/nxt_ktls.c` never joined `NXT_LIB_SRCS` — **every CI job was green
and the new file was never compiled.** A compiler would not have caught it: there was nothing to
compile.

Two changes follow from that: the probe now sets the variable the way the sendfile probe beside it
does, and `src/test/nxt_ktls_test.c` references `nxt_ktls_supported()` so that a missing file fails
to link instead of hiding behind a green build. The test asserts nothing about the machine —
whether a kernel offloads is the kernel's business, and the log line says which it is.
