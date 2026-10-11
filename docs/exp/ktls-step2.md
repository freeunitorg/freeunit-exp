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

## How this increment is verified

CI compiles `src/nxt_ktls.c` through the project's own Build & Test on the pull request, which is
also what exercises the new `configure` step on two Linux images (and the no-TLS build, where the
file is not compiled at all). The runtime semantics are verified by `exp/ktls-probe/` — the Python
probes that measure the same interface without depending on FreeUnit's plumbing.
