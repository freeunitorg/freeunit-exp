# JSON access-log writer contract and measurement plan

Issue: freeunit-exp#70 (workbench lane). Companion design: `docs/exp/logs-structured-json.md`.
No product code; test vectors and contracts only.

## Escaping contract (summary)

Full frozen vectors: `data/json-access-log-escape-vectors.json`.

1. Mandatory: `"` -> `\"`, `\` -> `\\`, and every byte below 0x20:
   `\b \t \n \f \r` as named escapes, all others as `\u00XX` (uppercase hex).
2. `/` is **not** escaped (RFC 8259 does not require it; extra escapes only
   break naive substring consumers).
3. `U+007F` and all higher code points are passed through unchanged when they
   form valid UTF-8; invalid byte sequences are replaced with `U+FFFD` before
   the writer ever sees them (`nxt_utf8_sanitize`, `src/nxt_router_access_log.c:327-341`).
4. The fast path scans for the first byte that needs escaping and copies the
   rest in bulk (`src/nxt_conf.c:2745-2785` shape).

## Writer contract (interface only, no implementation)

- **Record boundary**: one record per line, terminated by `\n`. A record is
  written whole or not at all: it must never appear as a torn/partial JSON value.
- **Maximum record size**: 4096 bytes including the trailing newline. Past that,
  refuse the whole record (return `NXT_ERROR`); do not truncate, because
  truncation produces invalid JSON by construction. Size is computed with
  `nxt_conf_json_length()` before allocation; an overflow of that computation
  refuses the record.
- **Buffering**: a reusable per-request buffer (`r->mem_pool` / `nxt_buf_t`
  chain). No field addition may allocate after the first member is written; field
  values are queried into temporaries owned by `r->mem_pool`.
- **Fast path**: find the first escapable byte; bulk-copy the clean prefix; escape
  from there. One scan, one copy.
- **One write per record**: assemble the full record, then a single `write()`.
- **Loss handling (#541)**: inspect the return value. Short write: retry the
  remainder in a bounded loop (max 3 attempts). On residual short write or
  error, drop the record; increment the per-access-log `dropped_records` counter
  (`access_log` already carries `count`, `src/nxt_router_access_log.c:54,117`);
  emit a rate-limited warning to the error log (`src/nxt_log_moderation.c`); and,
  optionally, write the marker line
  `#freeunit: dropped N access log record(s)` to the same fd so the gap is
  visible where the records would have been. The count must be exposed through the
  control API status entry beside the log path.

## Measurement plan

- **Harness**: `freeunit-harness` (`make dev`, `make test`, plus perf-lab), built
  inside the source tree (`src/nxt_router_access_log.c` depends on `build/`).
- **Counters**: instructions per request (perf stat), syscalls per request
  (`strace -c` or eBPF), write count per record (one write per record is the
  target), bytes written per record, peak allocations per request.
- **Hosts**: quiet `o-build` box first (`uptime`, `ps`), core pinning with
  `SERVER_CPUS`/`LOAD_CPUS`, A/A noise floor before any claim.
- **Comparison**: current text format vs. JSON shorthand vs. object form, same
  build, same host, same body sizes (small response, large response), keep-alive
  on and off.
- **Acceptance target**: within the A/A noise floor of the text format, stated
  as a number only after measurement. No unverified performance claims
  (measurement hygiene).
