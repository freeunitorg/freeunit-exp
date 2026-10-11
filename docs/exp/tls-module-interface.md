# TLS module: the interface the core needs (prototype, 2026-10-11)

Status: proposal + prototype. Nothing here is wired into the server build.

## Why the module owns ALPN

The HTTP/2 stack adds ALPN inside the TLS backend file, not in the protocol code:

- `nxt_openssl_alpn_select()` — the select callback
- `SSL_CTX_set_alpn_select_cb()` — where it is installed
- `nxt_openssl_conn_alpn_h2()` — the question the HTTP/2 code asks, via
  `SSL_get0_alpn_selected()`

Evidence: pull request 463 (`+61` in `src/nxt_openssl.c`). No protocol file
(`nxt_h2proto.*`) exists on `master`; the stack lives in pull requests.

Consequence: if TLS moves into a loadable module, that callback must move with it.
A protocol layer that calls an OpenSSL helper in a core file would keep the core
dependent on the TLS library — the exact dependency the module exists to remove.

## Consumers of the interface

| Side | Consumer | What it needs |
|---|---|---|
| server | control API TLS | build a context, load a certificate and key, offer `http/1.1` (and `h2` when the listener asks for it) |
| client | ACME | build a context, verify a peer, offer no ALPN, connect |
| both | HTTP/2 frontend | one question after the handshake: was `h2` negotiated |

## What the prototype implements

- `exp/tls-module/nxt_tls_backend.h` — the table the module must expose, plus the
  one exported symbol `nxt_tls_backend()`.
- `exp/tls-module/tls_backend_openssl.c` — an OpenSSL backend: context create and
  free, certificate and key, the ALPN preference list on both sides, the select
  callback, and `conn_alpn_h2`.
- `exp/tls-module/smoke.c` — loads the module the way the core would, checks the
  interface version, then runs three ALPN cases over a real handshake.
- `.github/workflows/exp-tls-module.yml` — builds the module and runs the smoke
  test on a clean runner.

## The three cases the smoke test proves

1. Client offers `h2` and `http/1.1` — the module selects `h2`.
2. Client offers `http/1.1` only — the module selects `http/1.1`.
3. Client offers no ALPN — the module sends no ALPN extension, the handshake
   completes, HTTP/1 follows.

Case 3 is the one that decides correctness: a select callback that answers with an
empty protocol instead of "no acknowledgement" breaks the plain HTTP/1 client.

## Result

Filled from the CI run of this branch (see the pull request checks for
`exp-tls-module`). The prototype pins TLS 1.2 on purpose: in TLS 1.3 a
"no acknowledgement" from the ALPN callback is a different code path, and this
prototype only needs the 1.2 semantics that the current callback relies on.

## Migration path

1. Put the interface in the core, with a built-in OpenSSL backend behind it. No
   behaviour change: the same callback, reached through the table.
2. Build the same backend as a module and load it when configured. The core build
   `--openssl` keeps working.
3. Move configuration to a module selector. The configure flag becomes a default,
   not a build-time dependency.

## Open questions

- TLS 1.3: what does the callback return when there is no overlap, and does the
  server still answer HTTP/1? The prototype avoids the question by pinning 1.2.
- Certificate reload: today the control API reloads a certificate in place. Which
  side owns that transaction — the core or the module?
- Health: how does the module report a failed handshake or a missing key to
  `/status` and to the error log?
- Module loading: `dlopen` at runtime with a built-in fallback, or a fixed module
  path chosen at configure time?

---

Reviewed-by: FreeUnitOPS (DeepSeek V4.1 Flash, Hermes Agent)
