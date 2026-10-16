# JSON access log: writer contract, escaping vectors and measurement plan

Issue: freeunit-exp#70. Companion analysis: freeunit-exp#69. No product code here:
a contract, frozen data and a measurement plan.

Verified against freeunit-exp `main` at `08c3b866` (upstream master `b09815f1`).
Every line number below was read in that tree; anything I could not verify is
marked **assumption**.

## 0. What this file decides, and what it does not

Decides: the two layers and their boundary, the bytes the writer must emit for
every input class (as data in `data/json-access-log-escape-vectors.json`), the
record shape and its bound, the behaviour when a record cannot be written whole,
and how the cost will be measured.

Does not decide: the field set and its types (issue #69), where the error log
goes, the configuration surface of the `json` shorthand, or any product code.

## 1. Two layers, one boundary

Nothing in the record path may be hand-assembled, and nothing may be
double-escaped. The split is:

| Layer | Owns | Does not own |
| --- | --- | --- |
| Sink: `nxt_router_access_log_json()` | the value bytes: UTF-8 validity, one U+FFFD per invalid input byte | JSON syntax, record bounding, the write |
| Writer: `nxt_conf_json_escape()` today | JSON syntax: `"`, `\`, every byte `<= 0x1F` | UTF-8 validity: it copies every byte above 0x1F unchanged |

Evidence: the escape test is `ch > 0x1F` with quote and backslash handled inside
it (`src/nxt_conf.c:2745-2798`); the sink sanitizes each value before it reaches
the serializer (`src/nxt_router_access_log.c:353`), deliberately there rather
than in the serializer, because the same serializer writes `state/conf.json` and
answers `GET /config`, where a non-UTF-8 operator path has to round-trip exactly
(`src/nxt_router_access_log.c:337-351`).

Consequence for a test: a table that feeds raw invalid UTF-8 to the writer is
testing a call that must not exist. The vector file carries exactly one such row
(`writer-never-sees-this`) and marks it `refused-by-contract`, so the row fails
if a caller ever starts skipping the sink.

`nxt_utf8_sanitize()` replaces per byte, not per maximal subpart: a truncated
four-byte sequence yields up to four U+FFFD where a maximal-subpart resync
yields one (`src/nxt_utf8.c:185-197`). This is deliberate and it sets the
worst-case expansion used in section 4: at most three output bytes per input
byte.

## 2. The escaping contract, frozen as data

`data/json-access-log-escape-vectors.json` holds 27 vectors. Each row carries
the input bytes (`own`), the exact bytes the writer must produce (`expect`) and
the length the length pass must compute (`jlen`). The rules the rows encode:

1. `"` is `\"`, `\` is `\\` (rows `quote`, `backslash`, `backslash-quote`).
2. Every byte `<= 0x1F` is escaped: `\b \f \n \r \t` in the short form, every
   other as `\u00XX`, and **the hex is uppercase**, because that is what
   `src/nxt_conf.c:2790` writes. A consumer that accepts lowercase is not
   wrong, but a test that expects lowercase is.
3. `/` is **not** escaped. RFC 8259 does not require it and escaping it only
   breaks substring consumers.
4. `0x7F` (DEL) and every byte above it are copied unchanged **once the sink has
   made the value valid UTF-8**. DEL is not a JSON metacharacter.
5. Invalid UTF-8 is replaced by the sink, never by the writer: a lone lead byte,
   a truncated four-byte sequence, a lone continuation byte, a lone surrogate
   (`ED A0 80`) and an overlong encoding (`C0 80`) each become one U+FFFD per
   invalid byte.
6. The forged-line class (#376) is closed for the JSON path by rule 1 plus
   rule 2: a CR, an LF or a quote in a request target cannot leave the value.
   Rows `forged-line-decoded` and `forged-line-request-target` pin both the
   decoded byte level and the literal percent-encoded case.

`data/verify_vector_file.py` is the verifier: it mirrors `nxt_utf8_sanitize()`,
`nxt_utf8_decode2()`, `nxt_conf_json_escape()` and
`nxt_conf_json_escape_length()` from the line ranges named in its docstring,
recomputes every row, and also asserts per row that the escaped value holds no
raw byte below `0x20`, no raw quote, and no backslash outside an escape, and
that it parses back to the sanitized bytes. It exits non-zero on any
disagreement.

Proven able to fail, on the live file, before it was trusted:

```
mutation: control-1f expect "\\u001f"
  FAIL  control-1f: expected b'\\u001f' ... mirrored code gives b'\\u001F'
mutation: del-raw expect "\\u007F"
  FAIL  del-raw: expected b'\\u007F' (5c7530303746), mirrored code gives b'\x7f' (7f)
mutation: lone-surrogate expect the raw bytes
  FAIL  lone-surrogate: expected b'\xed\xa0\x80' ... mirrored code gives b'\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd'
clean: 27 vectors checked, 0 problem(s)
```

## 3. The writer contract

**Shape.** One record is one JSON object, followed by exactly one `\n`. The
trailing newline is the record boundary; it is written by the same call as the
object (`src/nxt_router_access_log.c:376`). A record is never split across two
lines and never more than one line.

**Atomicity.** A record is written whole or not at all. A torn record must never
appear: a consumer that reads a half-written line must be able to drop it and
resume at the next `\n`. This is the one invariant that makes NDJSON safe to ship
without a framing protocol.

**Bound.** The record bound is a configurable property of the access log
(operator can lower it), with a default of 4096 bytes including the trailing
newline, and a hard ceiling of 1 MiB. It is computed, not assumed: the writer
sizes the escaped record before allocating it, and the size of a value is the
**sanitized** length, never the raw input length. `nxt_conf_json_length()`
already reports an unrepresentable length as `SIZE_MAX`
(`src/nxt_conf.h:124-127`, `src/nxt_conf.c:2375-2393`), and the current caller
only checks the addition around it
(`src/nxt_router_access_log.c:362-366`): the writer must refuse `SIZE_MAX`
explicitly as well, because `nxt_mp_nget(r->mem_pool, SIZE_MAX)` is a
pathological allocation attempt rather than a clean refusal
(`src/nxt_router_access_log.c:368`).

**Past the bound.** Drop the whole record. Do not truncate: a truncated JSON
object is invalid by construction, and a consumer that json-parses the line
throws away the record anyway, only later and with less information. The drop is
counted (section 5).

**Buffering.** Values are collected into the request pool the record already
uses; adding a field must not allocate. The existing serializer allocates once
for the object and once for the record buffer
(`src/nxt_router_access_log.c:313`, `:368`); the contract keeps that shape.

**Fast path.** One scan for the first byte that needs escaping, then a bulk copy
of the clean prefix, then escaping from there. Both passes already exist and are
already shaped that way: a length pass (`src/nxt_conf.c:2708-2741`) and a copy
pass (`src/nxt_conf.c:2745-2798`). A new writer must keep the two-pass shape
rather than growing a per-character branch in the hot loop.

**The fd, and what the kernel guarantees.** The destination is opened by the
main process with `O_WRONLY | O_APPEND | O_CREAT` and mode `0600`
(`src/nxt_main_process.c:3323-3388`, `NXT_FILE_OWNER_ACCESS`,
`src/nxt_file.h:184`), and the descriptor is handed to the router over
`SCM_RIGHTS`; the reopen path re-enters the same handler, which is what makes
rotation safe with a privileged reopener. The writer relies on that:
`O_APPEND` moves the offset under the inode lock, so the write is one kernel
operation and the record is appended, not overwritten. It does **not** promise
that a reader sees a whole record: a write larger than a page boundary can be
observed in progress, which is the other reason a record must be bounded and
self-synchronising.

Two consequences the writer must respect:

- **One writer, one fd.** The write must stay a single `write()` on this
  descriptor. `pwrite()` on an `O_APPEND` fd appends on Linux regardless of the
  offset asked for, so mixing modes silently changes the record layout.
- **The descriptor is not `O_CLOEXEC`.** `nxt_file_open()` passes the caller's
  mode straight to `open()` (`src/nxt_file.c:11-42`) and the log open passes no
  close-on-exec flag, while language modules are forked and never `exec`ed
  (`src/nxt_capability.c:443`). The flag belongs on the log open; it is a
  hardening item outside this contract, named here so it is not lost.

**Durability.** `O_APPEND` writes to the page cache and succeeds before the
bytes reach the medium. The default stays asynchronous: `fdatasync` per record
costs hundreds of operations per second at best on an SSD, and a blocking sync
in the request path is a stall, not a log. If the maintainer wants a durability
mode (`sync: off | record | batch`), it is a configuration knob, a batched
flush driven off a timer rather than the event loop, and a documented
worst-case window. Not in the first step.

**Own escaper.** The log path must not borrow `nxt_conf_json_print()`: its
output shape is the configuration document's contract and a future change to
`GET /config` output would silently change the log format. The mirror to write
against is the behaviour in the vector table, not the function.

## 4. The write result (#541)

Today the result is discarded: `nxt_fd_write()` returns the byte count or `-1`
and only alerts on `n <= 0` (`src/nxt_file.c:707-723`), and its caller ignores
the return entirely (`src/nxt_router_access_log.c:388`). A short write loses the
tail of a record silently and nothing counts it.

The contract:

1. **Inspect the result.** Any value other than the full record length is a
   failure, including a positive short write.
2. **Finish the record first.** On a short write, retry the remainder of the
   *same* buffer in a bounded loop. This is what keeps the atomicity invariant:
   resuming with a fresh record would append a complete second record after a
   torn first one.
3. **Give up deterministically.** After a bounded number of retries (2 is
   enough for a blocking fd; see open decision D1) the record is lost. Count it
   once, whichever way it is lost: error, still-short after the retries, or
   dropped for exceeding the bound.
4. **Make the loss visible where the records are**, so a consumer can tell a
   quiet period from a broken sink. Emit the marker line
   `#freeunit: lost N record(s)` on the same fd. `#` is not `{`, so a
   JSON-per-line consumer skips it; a line-oriented consumer sees it. The
   marker is best-effort: if the fd rejects it, the counter still moved.
5. **Expose the counter.** `nxt_router_access_log_t` (`src/nxt_router.h:337-344`)
   already carries `count`; add a `lost` counter beside it and surface it in the
   control API status object next to the existing per-application request
   counters (`src/nxt_status.c:161`) so an operator can alert on a non-zero
   value without reading log contents.
6. **Rate-limit the alert.** One error-log warning per interval through the
   existing moderation path (`src/nxt_log_moderation.c:60-97`), never one per
   dropped record: a full disk would otherwise turn a log loss into a log flood.

**Open decision D1 — blocking or non-blocking fd.** A blocking write to a full
pipe (the `rotatelogs` shape) stalls the router; a non-blocking fd turns
`EAGAIN` into a loss. The recommended reading: keep the fd blocking, treat the
stall as operator-visible back-pressure, and count only what fails outright. No
`O_NONBLOCK` is opened today, so this is a decision to record, not a change to
smuggle into the writer.

## 5. Safety

- Never logged: `Authorization`, `Cookie`, `Set-Cookie`, TLS key material, and
  personal data reachable through a cookie. The fixed field set does not name
  them; the object form must refuse at configuration validation
  (`src/nxt_conf_validation.c`) a member whose variable is one of them, rather
  than documenting the risk.
- Nothing in a logged value may change the record boundary (section 2).
- The write path must not become a request-path crash: a lost record is a
  counter, not an `abort()`.

## 6. Measurement plan

The claim to be made later is "JSON costs within noise of the text format", and
the rule is: **within the A/A noise floor, with a confidence interval attached,
or it is not a result.** The harness is the local one
(`/home/andy/www/freeunit-harness`), not a number invented here.

**Builds.** Three: text format, object format as it exists, JSON path after the
change. Same compile options, same host, same tree except the change.

**Noise floor first.** Point both slots at the same build and run the identical
matrix (`ALLOW_SAME=1 tools/bench-engines.sh base <build> base <build> 3`).
Whatever spread that shows is the smallest difference that may be called real.
An A/A that shows a "significant" difference means the harness is mis-set-up,
not that the machine is fast.

**Counters.** Per request: instructions (`perf stat`), syscalls, and writes per
record. Per record: bytes written, escapes performed, and the drop counter of
section 4. The write count per record is the one to watch: the contract says one
write per record, so any value above one is a contract violation, not noise.

**Matrix.** Small response and large response; keep-alive on and off; one worker
and several. Access logging on, in every case, against the same upstream.

**Isolation.** Server and load generator on disjoint pinned CPU sets, nothing
else on either box, a failed request invalidates the run rather than annotating
it (`MAX_FAILED=0`), and the two builds must be proven to differ by their own
startup line.

**Two cells are not ABBA.** Comparing exactly two builds needs the 8-cell
block counterbalance or `tools/bench-crossover.py`, not rotation and not ABBA.

**Verdict.** `tools/perf-compare.py` prints the delta with its 95% interval; the
acceptance target is the interval covering zero against the text format. Only
then is a number attached, and the number is reported with the interval.

## 7. The C test

`src/test/nxt_conf_json_escape_test.c`, registered in `src/test/nxt_tests.h`,
called from `src/test/nxt_tests.c` and listed in `auto/sources`. It is the C half
of the vector table: 15 records, each compared byte for byte as the whole record
`{"v":"<escaped>"}` through the public path (`nxt_conf_set_member_string()` then
`nxt_conf_json_print()`), not through the static escaper. That is deliberate: the
record path uses the serializer, so a test that reached into the escaper could
pass while the printed record was wrong.

Which half owns which row:

| Row class | Test |
| --- | --- |
| valid UTF-8: `"`, `\`, `/`, the five short escapes, `\u00XX` uppercase, DEL, valid 2- and 4-byte sequences, empty | `nxt_conf_json_escape_test.c` |
| invalid UTF-8: lone lead byte, truncated 4-byte, lone continuation, lone surrogate, overlong | `nxt_utf8_sanitize_test.c`, which already exists |
| the bound, the write result, the loss counter | not written: they belong to the writer implementation |

Built and run at `08c3b866` with `./configure --tests --hardening=strict`:
`make -f build/Makefile build/tests` compiles with `-Werror -Wformat=2` and **0
warnings**, `./build/tests` exits 0, and the log carries
`nxt_conf_json_escape_test() passed, 15 vectors` next to
`utf8 sanitize test passed`.

Proven able to fail on a wrong row before it was trusted:

```
mutation: the DEL row expects "\u007F" instead of the raw byte
  tests: [alert] JSON escape test failed on "DEL is above 0x1F and is copied
  raw" (): got "{"v":""}", expected "{"v":"\u007F"}"
```

(the record prints with the raw DEL, so the terminal shows it as nothing; the
bytes differ, which is the point of the row).

A row that feeds **raw invalid UTF-8** to the serializer is deliberately absent:
the serializer is also what writes `state/conf.json` and answers `GET /config`,
where the operator's bytes must round-trip exactly, and the log path sanitizes
before it serializes (`src/nxt_router_access_log.c:337-351`). The negative half
belongs to the sink test, and the data file pins that split with its
`writer-never-sees-this` row.

## 8. Open decisions for a human

| # | Decision | Options | Recommendation |
| --- | --- | --- | --- |
| D1 | fd blocking on a full pipe | blocking (stall, count only hard failures) or non-blocking (drop and count `EAGAIN`) | blocking; back-pressure is visible, loss is not |
| D2 | record bound | fixed 4096, configurable with a 1 MiB ceiling, or unbounded | configurable, default 4096, ceiling 1 MiB |
| D3 | loss marker | none, `#freeunit: lost N record(s)`, or a JSON field on the next record | the marker line: a consumer skipping it loses nothing, a consumer reading it sees the gap |
| D4 | `request_time` type | integer milliseconds, integer microseconds, or a new numeric kind in `nxt_conf_value_t` | **decided in #74 on 2026-10-16: integer milliseconds**, with the unit in the field name. The variable already truncates to milliseconds (`src/nxt_http_variables.c:237-260`), so an integer is not a loss against the source value, but it *is* a change against the printed form `0.041`, which a consumer reading seconds would misread. The field must therefore say its unit (`request_time_ms`) or keep the decimal. Adding a numeric row to the vector file is the only effect here |
| D5 | uppercase `\u00XX` | keep the current uppercase, or move to lowercase for convention | keep uppercase: changing it is a format change, and every row here would move |
| D6 | U+2028 / U+2029 | copy them as valid JSON, or escape them for JavaScript-embedding consumers | copy them: JSON.parse has accepted them since ES2019, nginx and Caddy copy them, and escaping costs a three-byte lookahead in the escape loop; rows `u2028-raw`, `u2029-raw` and `u2028-mixed` pin the bytes either way |
| D7 | per-field cap | none, or a cap per field in addition to the whole-record bound | a cap per field, because the whole-record bound only decides whether to drop the whole record: one oversized `User-Agent` should not cost the record when the field can be marked; the mechanism is a decision (see the companion analysis) and the gate is the same: counted, never silent |
