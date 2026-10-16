# Comparative analysis: access log escaping and edge cases (nginx, Apache, Caddy)

> Comparative research drafted in the fu-ops opencode lane. The nginx, Apache and
> Caddy claims are that lane's, checked against their documentation and source, not
> against our tree; the places where they touch our behaviour cite `file:line`.


Follow-up to docs/exp/logs-structured-json.md (freeunit-exp#69) and the writer
contract (freeunit-exp#70). Sources: nginx ngx_http_log_module.c
(ngx_http_log_escape, escape=default|json|none), Apache mod_log_config
(docs + modules/loggers/mod_log_config.c), Caddy logging docs and
modules/logging/encoders.go (Go encoding/json behaviour cited in-tree).

## 1. nginx

- Three escaping modes selected per format with escape=default|json|none
  (1.11.8+; none 1.13.10+):
  - default: escapes ", \, bytes < 0x20, byte 0x7F, and all bytes >= 0x80
    as \xXX. This is exactly the bitmap in ngx_http_log_escape
    (0xFFFFFFFF in the four high words) that issue #376 quotes.
  - json: " and \ as \" and \\, control bytes < 0x20 as \n \r \t \b \f
    or \u00XX.
  - none: copies bytes verbatim (caller assumes responsibility).
- Forging defence: default mode escapes CR/LF and every high byte, so the #376
  CRLF-vector cannot forge a record. json mode also escapes controls. none
  mode deliberately removes that defence.
- UTF-8 handling: default mode escapes any byte >= 0x80, including valid UTF-8,
  which is safe but loses multibyte transparency in text logs. nginx's later
  change (08d8af70760c) extended default-mode escaping into the C1 range
  (0x80-0x9F) specifically because C1 controls survive in ISO-8859-1 clients.
- Buffer safety: nginx added length checks (ngx_http_log_check_length,
  ceff7ca7785a) so an over-long record returns NULL and is discarded rather
  than overrunning the composed buffer. This mirrors our "refuse the record"
  decision, but nginx drops the whole log line attempt rather than aborting the
  request.
- Short writes / drop accounting: nginx writes through ngx_http_log_write;
  accounting of partial failure is not part of the public contract documented
  above (not verified against the fd-write internals). Treat as UNKNOWN.
- Request id: nginx exposes $request_id as a built-in variable; correlation with
  error-log text requires the operator to include it in both formats.

Edge cases from nginx docs and source:
- Default mode changes the on-wire representation of a UTF-8 User-Agent
  into \xNN sequences, which is parseable but ugly; JSON mode keeps the
  UTF-8 bytes.
- none mode plus a client-controlled value is an injection primitive; this is
  documented by the escape=none knob existing at all.
- high bytes above 0x7F are only addressed in default mode, not in JSON mode
  where they pass through; valid-but-surprising C1 controls (0x80-0x9F) are the
  original justification for escaping the high half.

## 2. Apache httpd (mod_log_config)

- No JSON mode built in; formats are percent-directive strings. Since 2.0.46,
  "non-printable and other special characters" in %r, %i, %o, etc. are
  escaped as \xhh (raw byte hex). Exceptions: " and \ are backslash-escaped,
  and whitespace is C-escaped (\n, \t, ...).
- A small fixed table decides what is escaped: string-producing directives
  (C, e, f, h, H, i, l, m, n, o, q, r, R, u, U, v, V, trailers) are escaped;
  numeric/IP/structural ones (%a, %A, %b, %s, %t, %p, %P, %T, %X, ...) are
  NOT, because their values are constrained by construction. This is the model
  FreeUnit should copy for any non-JSON text format: escape only where the value
  is untrusted.
- Literal operator-controlled text in the format string is copied verbatim; \
  escapes in the config (\", \n, \t) are handled at config parse time in
  parse_log_misc_string (src cited to modules/loggers/mod_log_config.c).
- Correlation / request IDs: mod_unique_id generates an identifier for internal
  use; it is not automatically in any log format - the operator must add %{UNIQUE_ID}e.
- Loss/back-pressure: Apache writes through the buffered log (ap_buffered_log)
  path; short writes are retried internally and reopen failures are logged;
  no per-log dropped counter is exposed in the documented contract above
  (UNKNOWN without reading the buffered writer). Edge case to verify later.
- Edge cases:
  - Proxies/clients sending obs-text (0x80-0xFF) arrive intact in %r and come
    out as \x80... in the log - one record per line preserved, but not
    human-readable.
  - CLF vs %b: no bytes sent renders - not 0, a usability trap for
    dashboards - FreeUnit should pick one rendering and document it
    (our shorthand currently sends "-" for absent headers, "" for empty).
  - LogFormat nicknames cannot be chained; operators duplicate formats.

## 3. Caddy

- Logs are strongly typed in memory first; encoding (JSON/console/common-log)
  happens at write time through zapcore encoders. Default access format is
  JSON (json unless stderr is a terminal, then console).
- JSON encoding uses Go encoding/json, whose contract is: invalid UTF-8 bytes
  are replaced with the Unicode replacement rune (U+FFFD) and HTML-escaped
  (<, >, &, U+2028, U+2029 -> \u003c etc.) unless an Encoder with
  SetEscapeHTML(false) is used. Caddy avoids HTML escaping only where
  explicitly disabled; this is an edge case for consumers comparing raw bytes.
- Sensitive data defence is structural and richer than nginx's: the filter
  encoder can delete named fields, ip_mask hashed/masked addresses, and wraps
  another encoder. This is the prior art for our "configuration that would log
  Authorization/Cookie is refused or transformed" rule even though FreeUnit builds
  a fixed field set.
- Max-line edge case: Caddy emits one JSON object per request and does not
  chunk it; consumers (GoAccess) historically assumed 4096 bytes and segfaulted
  on a 40 KB+ Caddy line (issue #2037). This is a reason to keep our refused-
  above-4096 behaviour and to document the refused threshold, while noting
  that very large request targets still need attention (perhaps a per-field cap
  in addition to the whole-record cap).
- Correlation: logger names (http.log.access.<name>) route records to
  arbitrary writers/encoders, so per-site logs are first-class; there is no
  built-in request id by default - the request object includes whatever the
  handler put into it.

## 4. Cross-cutting edge cases and what they imply for FreeUnit

1. Line-forgery via an unescaped variable:
   - Closed by JSON + mandatory escaping, matching nginx JSON/default mode and
     Apache 2.0.46+. Keeping an escape=none-equivalent in FreeUnit would
     resurrect #376 - do not add it. If an operator wants raw bytes, they can
     log fields that are inherently safe (status, bytes) rather than disabling
     escaping.
2. Invalid UTF-8 in a request target/header:
   - nginx default mode emits \xXX (safe text, not JSON); Caddy rewrites to
     U+FFFD (safe JSON). FreeUnit already chose the Caddy route via
     nxt_utf8_sanitize on the JSON path. Also do it before the (still-deferred)
     text format work, or the text format stays a forgery vector for U+2028/U+2029
     as noted in #376.
3. Control characters beyond newline (DEL, C1 controls, U+2028/U+2029):
   - nginx default mode escapes all of them. For JSON, RFC 8259 only requires
     < 0x20; but to close the "Unicode line separator" forgery path our writer
     could also escape U+2028 and U+2029 as \u2028 and \u2029 even though it
     is not required for valid JSON. Recommendation: adopt this as a hardening
     step (documented, measured), not silently.
4. Multi-line operator formats:
   - Apache allows \n/\t in the literal format string by design - two records
     can be emitted for one request if constructed. FreeUnit should refuse a
     format (text or JSON) whose literal portion contains an unescaped newline,
     keeping one-record-per-request invariant at config validation
     (src/nxt_conf_validation.c).
5. Over-long records:
   - nginx refuses when the composed buffer is exhausted; Caddy pushes a huge
     single line and breaks downstream 4096-byte consumers. FreeUnit's 4096-byte
     refuse policy (freeunit-exp#70) aligns with nginx and protects consumers;
     the threshold and the reason must be documented so operators are not
     surprised.
6. Absent vs. empty header values:
   - nginx and Apache render - for not-found. FreeUnit shorthand should document
     which rendering applies per field ("-" for absent scalar header, "" for
     present-but-empty) and add the follow-up tests from PR #196.
7. Sensitive fields:
   - Caddy's filter encoder demonstrates deletion/masking at encode time. FreeUnit
     should keep a denylist validation for any field name resolving to
     Authorization, Cookie/Set-Cookie, TLS material, or request body, in both
     shorthand and object forms; deny at config validation rather than only
     documenting.
8. Loss visibility:
   - Apache buffered logs retry; Caddy relies on OS write; nginx silently drops
     on buffer overrun. None of the three expose a dropped-count the way issue
     #541 asks for - this is a differentiator for FreeUnit to get right
     (per-access-log counter, rate-limited warning, in-band marker).
9. Request id propagation:
   - None of the three guarantees the id in the error log automatically; FreeUnit
     should either compute request_id once per request (stored on r) and emit
     it in the error path too, or explicitly state the gap.

## 5. Conclusion

The contract frozen in data/json-access-log-escape-vectors.json and
docs/exp/logs-json-writer-contract.md is consistent with nginx JSON mode and
Caddy's Go-JSON replacement behaviour, while going further than any of the three
on loss accounting and on rejecting unsafe configuration. Two additions are
worth adopting before implementation: (a) escape U+2028/U+2029 in JSON strings
for the Unicode-line-separator forgery path, and (b) a per-field length cap in
addition to the 4096-byte whole-record cap, learned from the Caddy 40 KB line
incident.
