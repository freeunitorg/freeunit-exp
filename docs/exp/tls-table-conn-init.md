# TLS backend table: the connection entry point (increment A1)

Status: proposal + patch. Opens as a draft until the 1.37.1 tag; the TLS stream
is held until then (see `STREAMS.md` and the review on pull request 23).

## What changes

`nxt_tls_lib_t` (`src/nxt_tls.h`) gains a `conn_init` member. The core reaches
the connection entry point through the table, not through a function pointer
the backend stores on the configuration.

Before: `nxt_tls_conf_s.conn_init` held the pointer. The backend set it in
`nxt_openssl_server_init()` (`conf->conn_init = nxt_openssl_conn_init`), and the
core called it directly in `nxt_h1proto.c` (`tls->conn_init(...)`).

After:

- `src/nxt_tls.h` — `conn_init` moves onto `nxt_tls_lib_t`; the field is removed
  from `nxt_tls_conf_s`.
- `src/nxt_openssl.c` — the backend declares `.conn_init = nxt_openssl_conn_init`
  in its table; the `conf->conn_init = ...` assignment is dropped.
- `src/nxt_router.c` — the core links the configuration to the selected backend:
  `tlscf->lib = runtime->tls`.
- `src/nxt_h1proto.c` — the call becomes `tls->lib->conn_init(...)`.

No behaviour change: the same callback runs, reached one level of indirection
later.

## Why

The cross-vendor review of the loadable-module prototype (pull request 23) names
this gap: "the core cannot use the table without OpenSSL" — the table had no
connection entry point, and the pointer sat on the configuration where only the
backend could write it. This is step 1 of the migration path in
`docs/exp/tls-module-interface.md` on `hermes/tls-module-proto`: put the
interface in the core, same callback, no behaviour change. Pull request 463
bypasses the table entirely with an `extern`; this closes that bypass.

## Evidence

CI (`.github/workflows/exp-tls-table.yml`):

- `./configure --openssl --tests`, then `test/test_tls.py` — TLS still works.
- `./configure --tests` with no `--openssl` — the core still builds when TLS is
  compiled out. `conn_init` on the table must not become a dependency of the
  no-TLS build.

Reviewed-by: FreeUnitOPS (DeepSeek V4.1 Flash, Hermes Agent)
