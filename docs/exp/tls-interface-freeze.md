# TLS module interface — frozen (v1)

TLS module 1.38, step 1 — workbench `freeunitorg/freeunit-exp#57`. The interface
move itself is this branch (`#28`); the module prototype and its CI are `#23`.

## What is frozen (v1)

The module ABI is `src/nxt_tls_backend.h`. Frozen:

- **The table shape** — `nxt_tls_backend_t`: `version`, `name`, `ctx_create`,
  `ctx_free`, `ctx_set_cert`, `ctx_set_alpn`, `conn_alpn_selected`,
  `conn_alpn_h2`.
- **The single exported symbol** — `nxt_tls_backend()`. The loader resolves
  exactly this name; nothing else is exported.
- **The version rule** — `NXT_TLS_BACKEND_VERSION = 1`. The loader refuses a
  mismatch, so a module built against another version does not load.
- **ALPN belongs to the module** — the protocol above TLS is chosen through it;
  the core keeps no OpenSSL helper for that choice.

Changing any of the four is a **version bump**, not a silent edit. The prototype
(header + OpenSSL backend + smoke test under `exp/tls-module/`) stays in `#23`;
this branch freezes the shape and lands the header in-tree.
