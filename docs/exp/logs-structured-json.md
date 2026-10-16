# Structured (JSON) access logs — analysis and plan

> Analysis drafted in the fu-ops opencode lane for freeunit-exp#69, published here
> after a citation review: every `file:line` below was re-read against `08c3b866`
> and corrected where it was wrong, and the writer contract it used to restate now
> points at the verified one instead of duplicating it.


Issue: freeunit-exp#69 (workbench lane). Companion: freeunit-exp#70 (writer contract,
escaping vectors, measurement plan). Constrained to analysis/planning: no product code,
no `CHANGES`/`docs/changes.xml` edits, no posts to `freeunitorg/freeunit`.

## 1. What is written today, and by whom

Producers (all in FreeUnit router process unless noted):

| Producer | File | Shape | Destination |
|---|---|---|---|
| Error log | `src/nxt_log.c:67-119` (`nxt_log_handler`), buffer at `:74` | `[level] *ident text\n` via `nxt_vsprintf` into `NXT_MAX_ERROR_STR` (2048, `src/nxt_log.h:19`) | `nxt_write_console(nxt_stderr, ...)` (`src/nxt_log.c:106`); `nxt_log_time_handler` (`src/nxt_app_log.c:20-78`) is the same shape with a timestamp prefix, writing at `:65` |
| Time-prefixed error log | `src/nxt_app_log.c:20-78` | `[time] [level] pid#tid ...` | stderr, one trailing `\n` |
| Access log, text | `src/nxt_router_access_log.c:270-295` (`nxt_router_access_log_text`) | operator template resolved by `nxt_tstr_query()` | fd opened by the main process and attached in `nxt_router_access_log_ready` (`:445-462`); written with `nxt_fd_write` (`:388`) |
| Access log, object/JSON | `src/nxt_router_access_log.c:299-381` (`nxt_router_access_log_json`) | one `nxt_conf_value_t` object, printed by `nxt_conf_json_print()` + `\n` (`:375-376`) | same fd |
| Access log shorthand | PR #196 (`"format": "json"`) builds the fixed 8-member object listed below | same | same |
| Moderation marker | `src/nxt_log_moderation.c:60-97` | `msg N times` into error log | stderr, rate-limited |

Per-route access logs share the same writer via `nxt_router_access_log_writer`
(`src/nxt_router_access_log.c:243-266`). `nxt_http_request_close_handler` is
called by `nxt_router_access_log_write()` (`:390`), which the writer runs only
when the record was built (`:263-265`), so a record failure still closes the
request.

## 2. Who consumes it

- **Log shippers / aggregators** (Vector, Fluent Bit, filebeat, journald
  readers): current text format has no stable field boundary; the object form gives
  names but values are not guaranteed valid UTF-8 today.
- **fail2ban / intrusion tooling**: relies on one record per line; #376 showed a
  client can synthesize a line through `%0d%0a` in `$uri`
  (`src/nxt_http_variables.c:292-387`, `src/nxt_http_parse.c:859`).
- **Humans (`grep`/`awk`)**: text format is readable; JSON needs a parser.
- **Docker / containers**: stderr is the conventional sink; error log already goes there.
- **Dashboards (Grafana/Loki)**: want typed fields (`status` as number, `request_time`
  as number), which the shorthand currently emits as strings.

## 3. Correlation

- `request_id` is a computed variable: `nxt_http_var_request_id`
  (`src/nxt_http_variables.c:404-431`), a fresh 32-hex string per call, stored only
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
  (`src/nxt_router_access_log.c:270-295`, `:388`).
- Invalid UTF-8 reaches the consumer in all three paths: `nxt_conf_json_escape()`
  (`src/nxt_conf.c:2745`) copies bytes `> 0x1F` unchanged; the JSON path already
  runs `nxt_utf8_sanitize()` per value (`src/nxt_router_access_log.c:353`; the
  reason it is here and not in the serializer is the comment at `:337-351`);
  the text path does not; the object template path does not escape at all (PR #196).
- No null-byte guard parity noted for access log inputs (#377, #311).

Reliability:
- `nxt_fd_write()` performs one `write()` and only alerts when `n <= 0`
  (`src/nxt_file.c:707-723`, call site `src/nxt_router_access_log.c:388`); a
  short write loses the rest silently and counts nothing (#541).

Usability:
- Field types in the JSON shorthand are all strings (PR #196 example: `"status":"200"`,
  `"bytes_sent":"0"`, `"request_time":"0.000"`).
- Absent header renders as `"-"`, empty header as `""` (PR #196 follow-ups,
  undocumented).
- No documented maximum record size; `nxt_conf_json_length()` uses sentinel
  `SIZE_MAX` for overflow (`src/nxt_conf.h:124-127`) but the caller only checks
  the `nxt_size_add` result around it (`src/nxt_router_access_log.c:362-366`),
  not the inner `SIZE_MAX`; a malformed member set can produce a huge allocation
  attempt via `nxt_mp_nget` (`:368`).

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

The contract is `docs/exp/logs-json-writer-contract.md`, with the frozen data in
`data/json-access-log-escape-vectors.json` and the C test in
`src/test/nxt_conf_json_escape_test.c`. It is not restated here: two copies of a
contract is how the two drift. The record shape, the bound and its past-bound
behaviour, the write-result handling for #541, the descriptor facts and the
measurement plan all live there, each claim carrying a line number read at
`08c3b866`.

### Safety

- Never log: `Authorization`, `Cookie`, `Set-Cookie`, TLS material, request
  bodies that may carry secrets, and personal data from cookies. The record path
  makes this easy for the fixed field set, because it simply does not name those
  variables. The object form is the hole: an operator can name any variable, and
  today nothing refuses it (`src/nxt_conf_validation.c:1641-1656` lists the
  permitted members, and a format field is a string). **Measured for #75 on a
  running build: it leaks.** A format naming `$header_authorization` and
  `$header_cookie` is accepted with no warning and writes
  `auth=[Bearer SUPERSECRET-TOKEN] cookie=[session=COOKIEVALUE]` in cleartext,
  in both the text and the object form. The proposal there is a refusal at
  configuration load for a fixed deny-list of header names; it is a guardrail,
  not a guarantee, because a secret in another header or in the target still
  passes.
- #376 closure in the JSON path: escaping is mandatory because the format is
  structured. The rules and their evidence are in the contract; the short form
  is that `"`, `\` and every byte below `0x20` are always escaped and invalid
  UTF-8 is replaced before serialisation.

### Phasing

1. **Done** (freeunit-exp#70): the escaping vectors, their verifier, the C test
   and the writer contract. 27 vectors, the C test at 15 records, both proven to
   fail on a wrong row before being trusted.
2. **Next**: the writer itself, which is the #541 fix and the real gate. Inspect
   the write result, retry the remainder of the same record, count every loss
   once, emit the marker line, and add the counter beside `access_log->count`.
   The escaping helper comes with it, as the record path's own routine.
3. Then the text format's variables, which is #376 and a separate change.
4. Then the typed fields and the object-form hardening.
5. **Before any of 3 to 5**: the schema questions this document cannot answer
   alone. #72 fixes the correlation id, #71 fixes what one record is under h2/h3,
   and #74 owns the typed-record test. Freezing typed fields without #71 means
   every h2 deployment gets ambiguous records.

## 6. Assumptions

- `NXT_MAX_ERROR_STR` is the right ceiling for a single record; verify against
  `src/nxt_main.h`.
- `nxt_utf8_sanitize` performance (per-byte loop) is acceptable on the access
  path; needs measurement per the plan, not assumption of harmlessness.
- Error-log JSONification deferred; text form is retained.
