# Structured (JSON) access logs — analysis and plan

Issue: freeunit-exp#69 (workbench lane). Companion: freeunit-exp#70 (writer contract,
escaping vectors, measurement plan). Constrained to analysis/planning: no product code,
no `CHANGES`/`docs/changes.xml` edits, no posts to `freeunitorg/freeunit`.

## 1. What is written today, and by whom

Producers (all in FreeUnit router process unless noted):

| Producer | File | Shape | Destination |
|---|---|---|---|
| Error log | `src/nxt_log.c:74` (`nxt_log_handler`) | `[level] *ident text\n` via `nxt_vsprintf` into `NXT_MAX_ERROR_STR` byte buffer | `nxt_write_console(nxt_stderr,...)` (`src/nxt_log.c:103`); `nxt_log_time_handler` (`src/nxt_app_log.c:28`) same shape with timestamp prefix |
| Time-prefixed error log | `src/nxt_app_log.c:28-95` | `[time] [level] pid#tid ...` | stderr, one trailing `\n`; truncates at `end - "\n"` (`src/nxt_app_log.c:84-88`) |
| Access log, text | `src/nxt_router_access_log.c:262-283` (`nxt_router_access_log_text`) | operator template resolved by `nxt_tstr_query()` | fd opened by main process, attached in `nxt_router_access_log_ready` (`:366-375`); written with `nxt_fd_write` (`:374` in current master) |
| Access log, object/JSON | `src/nxt_router_access_log.c:286-354` (`nxt_router_access_log_json`) | one `nxt_conf_value_t` object, printed by `nxt_conf_json_print()` + `\n` | same fd |
| Access log shorthand | PR #196 (`"format": "json"`) builds the fixed 8-member object listed below | same | same |
| Moderation marker | `src/nxt_log_moderation.c:90-93` | `msg N times` into error log | stderr, rate-limited |

Per-route access logs share the same writer via `nxt_router_access_log_writer`
(`src/nxt_router_access_log.c:237-261`); `nxt_http_request_close_handler` is
always called from there (`:259`), so a record failure still closes the request.

## 2. Who consumes it

- **Log shippers / aggregators** (Vector, Fluent Bit, filebeat, journald
  readers): current text format has no stable field boundary; the object form gives
  names but values are not guaranteed valid UTF-8 today.
- **fail2ban / intrusion tooling**: relies on one record per line; #376 showed a
  client can synthesize a line through `%0d%0a` in `$uri` (`src/nxt_http_variables.c:291-300`,
  `src/nxt_http_parse.c:859`).
- **Humans (`grep`/`awk`)**: text format is readable; JSON needs a parser.
- **Docker / containers**: stderr is the conventional sink; error log already goes there.
- **Dashboards (Grafana/Loki)**: want typed fields (`status` as number, `request_time`
  as number), which the shorthand currently emits as strings.

## 3. Correlation

- `request_id` is a computed variable: `nxt_http_var_request_id`
  (`src/nxt_http_variables.c:405-422`), a fresh 32-hex string per call, stored only
  when the template references `$request_id`. It is **not** computed or stored
  otherwise, and there is **no request id in the error log** (`src/nxt_log.c`,
  `src/nxt_app_log.c`). Correlation today is therefore absent unless the operator
  logs `request_id` in both places; even then it is two independent random
  generators, so equality across them is not guaranteed. Assumption (not verified
  against njs): no other producer stores a request id.

## 4. Gaps

Correctness:
- Forged lines in the text format (#376): `nxt_router_access_log_text()` hands
  `nxt_tstr_query()` output to `nxt_fd_write()` with no inspection
  (`src/nxt_router_access_log.c:262-283`, `:374`).
- Invalid UTF-8 reaches the consumer in all three paths: `nxt_conf_json_escape()`
  (`src/nxt_conf.c:2745`) copies bytes `> 0x1F` unchanged; the JSON path already
  runs `nxt_utf8_sanitize()` per value (`src/nxt_router_access_log.c:327-341`);
  the text path does not; the object template path does not escape at all (PR #196).
- No null-byte guard parity noted for access log inputs (#377, #311).

Reliability:
- `nxt_fd_write()` performs one `write()` and only alerts when `n <= 0`
  (`src/nxt_file.c:619-636`, call site `src/nxt_router_access_log.c:374`); a
  short write loses the rest silently and counts nothing (#541).

Usability:
- Field types in the JSON shorthand are all strings (PR #196 example: `"status":"200"`,
  `"bytes_sent":"0"`, `"request_time":"0.000"`).
- Absent header renders as `"-"`, empty header as `""` (PR #196 follow-ups,
  undocumented).
- No documented maximum record size; `nxt_conf_json_length()` uses sentinel
  `SIZE_MAX` for overflow (`src/nxt_conf.h:124`) but the caller (`:351`) only
  checks the `nxt_size_add` result, not the inner `SIZE_MAX`; a malformed member
  set can produce a huge allocation attempt via `nxt_mp_nget` (`:354`).

## 5. Design (the deliverable that gets judged)

### Format

- NDJSON: one JSON object per line, terminated by `\n`. Field set for the access
  log is the fixed 8-member set already in PR #196: `request`, `status`,
  `bytes_sent`, `remote_addr`, `user_agent`, `referer`, `request_time`,
  `request_id`. Field names stay decoupled from the variables they expand to.
- Types: `status` and `bytes_sent` become JSON numbers, `request_time` a JSON
  number, the rest strings (breaking-ish but only in the shorthand; the object
  form already lets the operator choose). This is the one decision issue #69
  forces; see the comment.
- Error log keeps its text form, but with a documented single-line structure:
  `[time] [level] pid#tid *ident: message`, one line, control bytes in `message`
  escaped the same way as access-log strings where the message originates from a
  request. Full JSONification of the error log is **not in scope** for this step.

Not in scope: replacing nginx-style escapes in the text format (covered by #376
separately), application-process logging changes, njs log path, control API
output.

### Writer contract

See `docs/exp/logs-json-writer-contract.md` and the frozen vectors in
`data/json-access-log-escape-vectors.json`.

- One record per line, written whole or not at all: build the whole record in a
  reusable per-request buffer (the `nxt_buf_t` chain / `r->mem_pool`), then a
  single write; never interleave.
- Maximum record size: `NXT_MAX_ERROR_STR`-class ceiling (4096 bytes) for a single
  record; past it the record is refused (function returns `NXT_ERROR`) rather
  than truncated, because a truncated record is invalid JSON by construction.
- No allocation per field: `nxt_conf_json_print` already allocates only for the
  object; the shorthand must build the member array once at config time and query
  values into the same `r->mem_pool`. Field addition must not call `nxt_malloc`.
- Fast path: scan for the first byte requiring escape, then copy the rest in bulk
  (`nxt_conf_json_escape` shape, `src/nxt_conf.c:2745`).
- Failure: inspect the write result (#541). Short write: retry the remainder once
  within a bounded loop; on still-short or error, drop the whole record (it is
  already not written), increment a per-access-log `dropped_records` counter, and
  emit a rate-limited error-log warning. Optionally emit a marker line
  `#freeunit: dropped N access log record(s)` to the same fd so the gap is
  visible in place.

### Safety

- Never log: `Authorization`, `Cookie`, `Set-Cookie`, TLS material, request
  bodies that may carry secrets, and personal data from cookies. Enforce by name:
  the fixed field set does not include these variables, and the object form must
  be checked for them at configuration load.
- **That check must warn, not refuse.** An earlier version of this note said the
  object form "must refuse" a member naming a credential variable. Upstream built
  exactly that (freeunitorg/freeunit `4ba018f1`) and had to take it out again
  (`faa87a8d`): it is a new restriction in a patch release, a configuration that
  1.37.0 accepted became refused, and the check did not look at `vldt->restored`,
  so a stored `conf.json` naming such a variable was refused at startup — unitd
  then ran with the empty default configuration and the first successful update
  through the control API overwrote the stored file. The configuration was lost.
  Refusing here is a data-loss risk, not a safety gain. The current behaviour is
  the right shape: accept the format, and warn from the router when it compiles
  one, naming the field for the object format.
- #376 closure in the JSON path: escaping is mandatory because the format is
  structured; `"` and `\` and every byte `< 0x20` are always escaped, and invalid
  UTF-8 is replaced before serialisation. No hand-assembled `sprintf`/`strcat`.

### Phasing

1. Freeze escaping vectors and the writer contract (freeunit-exp#70) — this task.
2. Land the contract as a tested C helper that takes an `nxt_str_t` and appends
   its escaped form to a provided buffer (no allocation), with the frozen vectors as
   the test oracle. Convert the JSON shorthand to use it.
3. Convert the text format to escape variables separately (#376).
4. Add the lost-record counter and the marker.
5. Typed fields and object-form escape hardening last.

## 6. Assumptions

- `NXT_MAX_ERROR_STR` is the right ceiling for a single record; verify against
  `src/nxt_main.h`.
- `nxt_utf8_sanitize` performance (per-byte loop) is acceptable on the access
  path; needs measurement per the plan, not assumption of harmlessness.
- Error-log JSONification deferred; text form is retained.
