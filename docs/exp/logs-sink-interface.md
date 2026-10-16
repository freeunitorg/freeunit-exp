# The log sink: surfaces, boundary, failure contract (freeunit-exp #77)

Design note. No product code. Every claim about today's behaviour carries a
`file:line` read at `08c3b866` unless it says otherwise; measurements carry the
host they were taken on. Items I could not establish are marked **unknown**.

## 0. Vocabulary, because the two tasks use one word for two things

- **Emission path** — where a record is assembled and written *inside* the
  daemon: per-process direct write, an explicit buffer, or one writer fed over
  the IPC. That is #76, and it is measured there.
- **Sink** — the thing a record is handed to: a file, syslog, a socket, a
  module. This note.

They are orthogonal, and both have to exist: the sink says *what destination*,
the emission path says *who writes and when*. A module sink inherits whatever
emission path is chosen, and a buffered emission path changes what a sink's
failure means (a lost flush is many records, not one).

## 1. The surfaces, and which may go through a sink

| Surface | Where it is produced | Destination today | May use a sink? |
| --- | --- | --- | --- |
| Error log | every process: `nxt_log_handler()` `src/nxt_log.c:67-119`, `nxt_log_time_handler()` `src/nxt_app_log.c:20-78` | the `--log` file, via **stderr**: each process opens the file (`nxt_runtime_log_files_create()`, `src/nxt_runtime.c:1440-1462`) and redirects stderr to it (`nxt_file_stderr()`) | **No, not first.** Seams: stderr is a libc-level file handle, the emit sites have no sink table in reach, and this path is used *by* any sink that fails, so it must not be able to fail through a sink |
| Error log ALERT | same, level `NXT_LOG_ALERT` | additionally syslog via `nxt_write_syslog(LOG_ALERT, …)` (`src/nxt_app_log.c:68-75`) | already has a second sink; it is a model, not a candidate |
| Access log | router: `nxt_router_access_log_writer()` `src/nxt_router_access_log.c:243-266`, record built at `:299-381`, written `:388` | the descriptor the **main** process opened and passed over `SCM_RIGHTS` (`src/nxt_main_process.c:3323-3388`); mode `0600`, `O_APPEND`, `O_NONBLOCK` added by `nxt_file_open()` (`src/nxt_file.c:14-19`) | **Yes.** One writer, one fd, and the record is a complete buffer at the point of writing |
| Per-route access logs | same writer, different format per route | same fd for the log object | same as above |
| Application logs | application processes (`src/nxt_app_log.c`) | stderr, i.e. the error-log file | **No**, same reason as the error log |
| Message moderation | `src/nxt_log_moderation.c:60-97` | error log | n/a, it is policy over the error log, not a destination |
| Control API output | controller, `GET /config`, `/status` | the API response | **No.** It is a different contract with a different audience; routing it through a log sink would be a category error |

So exactly one surface is a candidate: **the access log**. That is also the only
one with a measured cost (#76: 2.35 µs CPU per request, 10.7% of throughput at
saturation on two cores) and the only one where the record already exists as a
complete buffer before it is written.

## 2. The boundary: three options

**(a) An in-daemon module.** A table handed to the daemon by a loadable object,
in the shape the TLS work froze: one exported symbol and a version the loader
checks (`const nxt_tls_backend_t *nxt_tls_backend(void)`,
`NXT_TLS_BACKEND_VERSION`, `src/nxt_tls_backend.h` on
`hermes/tls-table-conn-init`). The access log already has the right shape for
it: the writer owns a complete record and one fd, so a `write(record, len)`
vtable entry is a small, honest interface.

**(b) A separate writer process.** Records leave the router over the existing
port queue or shared memory and one process owns every sink. This is #76's
path 3, and it is **unmeasured**; what is known is that the error log cannot
join it (every process produces error records, and a hop per error record is
not affordable), so it would serve the access log alone.

**(c) A documented external shipper.** The daemon keeps writing a file or
stdout, and something else parses and forwards. #75 measured that this works:
the OpenTelemetry Collector's `filelog` receiver with a `json_parser` reads our
records without transformation, and journald captures them (though it keeps the
JSON inside `MESSAGE`).

**Recommendation: (a) for 1.38, with (c) as the supported answer today and (b)
deferred.** Reasons, in order:

1. The user requirement is a *configurable destination* (file, stdout, syslog,
   Loki, plugin). (a) is the only option that can express that in configuration
   without putting a foreign process in the write path, and the daemon already
   knows how to load code (`dlopen()` at `src/nxt_application.c:413`, one `dlsym()` at `:420`).
2. The interface precedent exists and is already reviewed; inventing a second
   pattern would be the expensive choice, not the cheap one.
3. (c) already serves everyone who needs a shipper, and #75 proved it works. A
   module is for operators who cannot run a shipper at all.
4. (b) buys determinism of ordering across writers, which only matters
   multi-worker, and it costs a hop on the request path — the one thing #76
   shows we cannot spare (2.35 µs already). Measure it before choosing it.

## 3. The interface sketch, if the answer is a module

Shaped on the TLS table, because that is the pattern the tree has:

```c
#define NXT_LOG_SINK_VERSION  1u

typedef struct {
    unsigned     version;        /* loader refuses a mismatch */
    const char  *name;           /* "file", "syslog", for logs and /status */

    /* Open a destination from configuration. NULL means "the built-in file". */
    void        *(*open)(nxt_mp_t *mp, const nxt_conf_value_t *conf);
    void         (*close)(void *sink);

    /* Write one complete record, newline included. Returns bytes written, or
     * -1 with errno set. MUST NOT write partially under any circumstance: the
     * caller owns the "whole record or not at all" invariant (#70) and needs
     * to know whether the record landed to decide whether to count a loss. */
    ssize_t      (*write)(void *sink, const u_char *record, size_t len);

    /* Best-effort flush, for a buffering sink. 0 ok, -1 error. */
    int          (*flush)(void *sink);
} nxt_log_sink_t;

/* The only exported symbol the loader resolves. */
const nxt_log_sink_t *nxt_log_sink(void);
```

Rules that belong in the header, because each one is a failure we measured or
can name:

- **Buffer ownership**: the caller owns `record` and keeps it valid only for the
  duration of the call. A sink that wants to keep bytes copies them. That is
  what makes a buffering *sink* (batching inside the module) possible without
  the caller knowing.
- **No allocation per record** in the caller's path; a sink may allocate during
  `open()`, and its own per-record allocation is its cost, reported by #76's
  method.
- **Reentrancy**: the caller holds no lock across the call. A sink that logs
  through the error log on failure is calling back into the daemon's error path
  from inside the access-log write; that is allowed only if the error path
  cannot itself reach the sink. Since the error log is not a sink surface
  (section 1), it cannot. **This must be stated, because it is the reason the
  order of section 1 matters.**
- **`O_NONBLOCK` is a fact the sink inherits.** Anything the daemon opens
  through `nxt_file_open()` is non-blocking (`src/nxt_file.c:14-19`), so a FIFO
  or pipe sink gets `EAGAIN` rather than back-pressure. A module that opens its
  own descriptor may choose blocking, but then it owns the stall, and the
  caller's timeout budget has to allow for it.
- **No global state.** Two access logs with two sinks must not interfere; the
  context comes from `open()`.

**unknown**: the loader's exact refusal behaviour for a version mismatch (the
TLS interface documents the rule; whether it refuses the configuration or falls
back to the built-in file is a decision this note does not make), and whether
`nxt_conf_value_t` is the right shape to hand a sink for its options — the file
sink needs only a path today, syslog needs a facility and a level, an HTTP sink
would need more, and passing the raw object defers that decision without
answering it.

## 4. Which sinks ship in-tree

The rule from the TLS work is *one implementation ships, the interface exists*.
Applied here:

| Sink | In-tree? | Reason |
| --- | --- | --- |
| file | **yes, and it is the current one** | already shipped, already the default, and the only one that can promise `fsync` |
| stdout/stderr | **yes**, and it is the container answer | it is the file sink with a descriptor the manager owns; no new code, but it needs the back-pressure rule below |
| syslog / rsyslog | **no for 1.38; the first candidate for the module** | it fits the interface exactly, and the error log already shows the syslog path exists for `ALERT` (`src/nxt_app_log.c:68-75`) — but a datagram sink cannot promise delivery, so it needs the failure contract below written first |
| HTTP push (Loki) | **no** | a network call near the request path: retry, backoff, a bound, and a decision about duplicates. That is a whole feature, and #76 has not measured it |
| external shipper | **no** | it is not a sink in this sense; it is #75's supported route today |

So: **file and stdout in-tree, the interface present, syslog as the module that
proves the interface.** That satisfies the user requirement (the destination is
configurable) without growing a sink zoo.

## 5. The failure contract, per type, and where the loss count lives

The writer's promise and the sink's promise are different, and #70 already
fixed the writer half: *one record per line, whole or not at all, every loss
counted once, a marker line where the records are*. What each sink can promise:

| Sink | Delivery | What a failure looks like | Who counts |
| --- | --- | --- | --- |
| file | page cache; durable only with `fsync`/`O_DSYNC`, which is the `sync` knob and not per-record by default | short write, `ENOSPC`, a failed reopen | the writer, as #70 section 4 says |
| stdout/pipe | none beyond the pipe buffer; the consumer may be gone | `EAGAIN` (the fd is `O_NONBLOCK`), `EPIPE` | the writer; `EAGAIN` is **retry-then-count**, never a silent skip |
| syslog datagram | none: a datagram sink drops silently under load and at the receiver | an oversized message, a full socket buffer | the sink cannot know; the writer counts what `sendto()` rejects, and the receiver-side loss is unobservable — say so in the docs rather than implying otherwise |
| HTTP push | at-most-once unless the sink keeps state | timeout, 5xx, a retry that duplicates | the sink, and the duplicate question is why it is out of tree for 1.38 |
| module | whatever its interface says: it returns a byte count or -1 | its own error | the writer counts a loss; the module may count finer internally |

**Where the count lives**: one counter per access log object, beside the existing
`count` field (`struct nxt_router_access_log_s`, `src/nxt_router.h:337-344`),
surfaced in the control API status object next to the per-application request
counters (`src/nxt_status.c:161`). Not in the sink: an operator must be able to
alert on it without knowing which sink is configured, and a sink that is gone
cannot report its own absence.

**Startup and runtime loss of a destination** — one answer per type:

- **file, unavailable at start**: refuse the configuration, as today (the
  main-process open fails and the reconfiguration errors out).
- **file, unavailable later**: keep the descriptor, keep counting, alert at a
  rate limit, and expose the counter. A failed *reopen* already behaves this way
  and was measured to keep records flowing into the rotated file.
- **pipe/stdout, consumer gone at start**: that is `EPIPE` on the first write,
  not a configuration error: the daemon started before its collector. Count.
- **syslog, unavailable**: a datagram send either succeeds into the void or
  fails; count what fails, document that the rest is unobservable.
- **module sink, fails to load**: refuse the configuration if the operator
  named it, and never silently fall back to the file, because a silent fallback
  turns "my logs go to Loki" into "my logs went to a local file I am not
  watching".

## 6. Cost and benefit

**What a module buys**: a configurable destination without a foreign process in
the write path; one interface instead of one bespoke path per destination; and
the ability to batch inside the sink, which is where #76's 1.7 µs of the 2.35
can be recovered without the caller knowing.

**What it costs**: a new ABI surface with a version rule to maintain; a new
failure surface on the request path (the sink runs inside the router process);
and review cost proportional to the interface, not the transport.

**Against the external shipper**: the shipper needs no daemon change, already
works (#75), and scales to a fleet; it costs a process per host and a parse. A
module is for the operator who cannot add that process.

**Recommendation for 1.38**: ship the interface and the syslog module, keep
file and stdout in-tree, document the shipper route as the default for anyone
who can run one. **For a later release**: decide (b), the single writer process,
against #76's path-3 measurement — not before it.

## 7. The security surface

**Who may load a sink**: the same rule as language modules — a path from the
daemon's configuration, loaded by the daemon's own user, with no privilege
escalation (`dlopen()` at `src/nxt_application.c:413`, `dlsym()` at `:420`). Configuration is
already the trust boundary: whoever can `PUT /config` can already point an
access log at any path the daemon can write.

**What a sink may see**: a complete record, which means everything the operator
put in the format. #75 measured that this includes
`Authorization`/`Cookie`/`Set-Cookie` in cleartext when the format names them,
and the configuration is accepted silently today. **A sink cannot fix this**: it
receives a record after it is built, so a deny-list inside a sink would be a
second, weaker place to enforce a rule that belongs where the format is parsed.
The refusal belongs in the validator, and it is the one product change this
design recommends landing *before* any sink interface, because a new sink makes
the leak reach further (a network destination, not just a local file).

## 8. Open items

- `unknown`: the exact loader refusal semantics for a version mismatch, and the
  configuration shape for per-sink options (section 3).
- `unknown`: whether any sink other than file needs `fsync`-equivalent
  durability, and what the `sync` knob means for a datagram sink.
- Not measured: the separate-writer-process hop (#76 path 3), and the module
  hop. A performance claim for either needs #76's method and an A/A floor.
- Out of scope here, by the issue's own words: the field set, the record shape,
  and the text-format escaping decision.
