# PHP `session.upload_progress`, researcher bugs 109618 / 109619: exposure, the 618 verdict, and a patch-validation test

> Workbench note for freeunit-exp#127. The two labels are the researcher's
> (CVE-2026-109618, CVE-2026-109619), not NVD assignments. There is no public php-src
> bug, PR or patch for either as of 2026-10-21, so this note never quotes one.
>
> Every php-src line number below was re-read against the **php-8.4.26 release
> tarball**, which is also the tree the test was built and run against
> (`--enable-debug`, `-fsanitize=address`, `--disable-all --enable-cli --enable-session`).
> The FreeUnit lines are against `88419429e`. Offsets, CVSS values and lab addresses
> from the writeup are not used anywhere.

## 0. Summary

| Question | Answer |
|---|---|
| Is 618 exploitable? | No. Dead by construction: the progress array is addref'd *and* hash-addref'd before it is serialized. The researcher retracted it; the code agrees. |
| Is 619 real? | Yes: a `memory_limit` bailout leaves `BG(unserialize)` with `level != 0` and `data` pointing into request memory; the next request on the same process reuses that context before `RINIT(basic)` can reset it. Memory-safety, not code execution. |
| Is FreeUnit exposed? | Yes, the persistent-worker precondition holds and there is no request-count recycle. The precise path differs from the writeup: Unit's PHP SAPI *skips* `php_request_shutdown()` when `php_request_startup()` fails, so the reported "OOM inside the pre-RINIT `update()`" leaves live-but-stale request memory in Unit rather than a freed one. The same UAF is reachable in Unit when the bailout happens **after** RINIT (a script's `session_start()`/`unserialize()`), because then Unit does run `php_request_shutdown()`. Section 2 has the code lines. |
| Is the test useful? | Yes, and it was proven both ways on 8.4.26: FAIL 3/3 on the unpatched build for both scenarios, PASS 3/3 on each of two independently built fixes (reset before the callback; callback after RINIT). Section 3. |
| Mitigation | `session.upload_progress.enabled=0` in the application's PHP `admin` options closes the cross-request *reuse* path, not the underlying PHP bug. Section 4. |

## 1. Established facts, from the 8.4.26 tree

### 1.1 The ordering (the root of 619)

`php_request_startup()` (`main/main.c:1803`) does, in this order:

    main/main.c:1873        php_hash_environment();
    main/main.c:1874        zend_activate_modules();
    main/main.c:1875        PG(modules_activated) = 1;

`php_hash_environment()` (`main/php_variables.c:785`) calls
`zend_activate_auto_globals()` (`main/php_variables.c:788`), which is not lazy: it invokes
every auto-global callback immediately (`Zend/zend_compile.c:2021-2033`, the callback call
at `:2031`). For `_POST` that is `php_auto_globals_create_post()` →
`sapi_module.treat_data(PARSE_POST, ...)` (`main/php_variables.c:818`), which reads the
request body (`main/SAPI.c:164`, `sapi_handle_post()`).

The multipart parser then raises `MULTIPART_EVENT_FILE_START`
(`main/rfc1867.c:973`), which reaches `php_session_rfc1867_callback()`
(`ext/session/session.c:3228`) and, when a file part starts,
`php_session_rfc1867_update()` (`ext/session/session.c:3175`). That function calls
`php_session_initialize()` at `ext/session/session.c:3196`, which reads and decodes the
session (`ext/session/session.c:502`).

`PHP_RINIT(basic)` — the only place that zeroes the serializer globals — runs later:

    ext/standard/basic_functions.c:391   memset(&BG(serialize), 0, ...);
    ext/standard/basic_functions.c:392   memset(&BG(unserialize), 0, ...);

So everything the pre-RINIT `update()` does with the serializer happens **before** the
per-request reset.

### 1.2 The state machine a bailout breaks

`PHP_VAR_UNSERIALIZE_INIT()` (`ext/standard/var_unserializer.re:60-82`) publishes the
context in the module globals when the nesting level is zero:

    :74   BG(unserialize).data = d;
    :75   BG(unserialize).level = 1;

`PHP_VAR_UNSERIALIZE_DESTROY()` (`:84-93`) is what clears them again. A `zend_bailout`
between the two skips the destroy, so `BG(unserialize)` keeps `level == 1` and `data == d`
while `d` (`struct php_unserialize_data`, `:47-58`) and its `entries` list live in request
memory.

`php_session_decode()` (`ext/session/session.c:274`) catches the bailout only to cancel the
decode and re-throw:

    :283   } zend_catch {
    :284       php_session_cancel_decode();
    :285       zend_bailout();
    :286   } zend_end_try();

`php_session_cancel_decode()` (`:267-272`) calls `php_session_destroy()`, which — for the
`files` handler — unlinks the session file (`ext/session/mod_files.c:593-615`). This detail
matters when reproducing: after the OOM the session file is **gone**, so the next request's
*first* `update()` reads an empty session and the crash happens on a later update in the
same request (section 3.2).

### 1.3 Why 618 is dead

The progress array is stored into `$_SESSION` with both an addref and a hash addref:

    ext/session/session.c:3203   Z_TRY_ADDREF(progress->data);
    ext/session/session.c:3204   zend_hash_update(Z_ARRVAL_P(sess_var), progress->key.s, &progress->data);

The session array therefore holds a counted reference for as long as the session exists.
The line the writeup attributes the stale access to, `ext/standard/var.c:756`
(`data->n += 1;`), is in `php_add_var_hash()`, which runs on the **serialize** side
(call sites `ext/standard/var.c:1029` and `:1080`, both under `php_var_serialize_intern`).
`data` there is the serializer context (a local `php_serialize_data_t`, live), and `var` is
the progress array, which `$_SESSION` keeps alive. Nothing in that path touches freed
memory. Conclusion: 618 is dead by construction, matching the retraction.

Line drift to note for the record: the writeup cites `session.c:3213/3214`; in 8.4.26 the
pair is at `3203/3204`. Pin the release you are reading.

### 1.4 What the pre-RINIT OOM produces, per SAPI

The bailout unwinds to `php_request_startup()`'s `zend_catch` (`main/main.c:1876-1878`),
which returns `FAILURE`. What the SAPI does next decides whether the stale context becomes
a use-after-free:

| SAPI | On startup `FAILURE` | `BG(unserialize)` after teardown |
|---|---|---|
| cli-server | calls `php_request_shutdown(0)` anyway (`sapi/cli/php_cli_server.c:2311-2312` → `:2245`) | points into **freed** request memory → next request is a UAF |
| FPM | `php_module_shutdown()` then returns `FPM_EXIT_SOFTWARE` (`sapi/fpm/fpm/fpm_main.c:1871-1876`) | worker exits; availability, not memory safety |
| FreeUnit PHP | `nxt_unit_request_done(req, NXT_UNIT_ERROR)` and returns, **without** `php_request_shutdown()` (`src/nxt_php_sapi.c:1426-1433`) | still-allocated, stale request memory; engine is left half-initialized (see 2.2) |

## 2. FreeUnit exposure, from the code

### 2.1 The persistent-worker precondition holds

The PHP worker is one process that serves requests in a loop:

    src/nxt_php_sapi.c:591     nxt_unit_run(nxt_php_unit_ctx);
    src/nxt_unit.c:6541        while (nxt_fast_path(ctx_impl->online)) { nxt_unit_run_once_impl(ctx); ... }

Each request goes through `nxt_php_request_handler()` (`src/nxt_php_sapi.c:1164`) →
`nxt_php_execute()` → `php_request_startup()` (`:1422`) and, on success,
`php_request_shutdown(NULL)` (`:1464`). The POST body is fed to PHP by Unit's own
`sapi_module.read_post` hook (`src/nxt_php_sapi.c:377`, implementation at `:1644`), so the
pre-RINIT multipart parse in 1.1 happens in Unit exactly as it does elsewhere.

There is no request-count recycle: `grep -rn max_requests src/ lib/` is empty. Unit
restarts a worker on crash or reconfiguration, not after N requests, so "recycle the
process" is not an available lever.

### 2.2 The startup-failure path is different, and is its own thing to fix

On `php_request_startup() == FAILURE` Unit logs, finishes the request with an error and
returns (`src/nxt_php_sapi.c:1426-1433`). It does **not** call `php_request_shutdown()`,
so `zend_deactivate()` never runs for that request: request memory stays allocated, the
session module's RSHUTDOWN never runs, and the next request re-enters
`php_request_startup()` on a not-deactivated engine (`zend_activate()` has no matching
`zend_deactivate()`).

Consequence for 619: the exact scenario in the report — OOM inside the pre-RINIT `update()`
— does **not** free the context in Unit, so the next request's pre-RINIT `update()` reuses
a stale context in still-mapped memory. Whether that faults depends on what reused the
arena; it is not the clean use-after-free the advisory describes, but it is not safe
either. This path was **not** measured on a running Unit for this note; it is a reading of
the code above. It also looks like an independent Unit bug worth its own issue (missing
request teardown after a failed startup).

### 2.3 The variant that does reach Unit

A bailout **after** RINIT is caught by `php_execute_script_ex()`
(`main/main.c:2522-2584`, `zend_catch` at `:2582`), so Unit continues normally and reaches
`php_request_shutdown(NULL)` at `src/nxt_php_sapi.c:1464`. That frees the request memory
while `BG(unserialize)` still points into it. The next request's pre-RINIT
`session.upload_progress` update then reuses the freed context. The trigger can be any
script that exhausts `memory_limit` inside `session_start()` or `unserialize()`; it does not
have to be the upload-progress request itself. This is the "post-rinit" scenario in the
test, and it fails on unpatched 8.4.26 exactly like the reported one (section 3.3).

Verdict: FreeUnit is in the exposed persistent-worker class, with the caveat above about
the named path. It is not identical to FPM (FPM kills the worker on startup failure) and it
is not identical to cli-server (which frees on startup failure).

## 3. The patch-validation test

`docs/exp/php-session-upload-progress-109619.phpt` is a php-src `.phpt`. It drives a
single-process built-in server (`php -S`) through two requests, and asserts that the second
request neither kills the server nor produces an AddressSanitizer report. Both requests are
made over a raw socket so the request body and cookies are pinned. The `--SKIPIF--` skips
unless the PHP binary is an AddressSanitizer build (detected through `/proc/self/maps`), so
this is a local patch-validation test, not a php-src CI gate.

### 3.1 How the trigger is built

* A session file for the request's SID contains a **10 MiB serialized string**, and the
  server runs with `memory_limit=16M`. The file must be smaller than the limit, because
  `files` reads it into one `zend_string` before decoding
  (`ext/session/mod_files.c:489`); the decode then allocates the payload a second time and
  that allocation fails *inside* `php_var_unserialize()`, after
  `PHP_VAR_UNSERIALIZE_INIT()`.
* `session.upload_progress.enabled=1`, `freq=0`, `cleanup=0`; the POST carries
  `PHP_SESSION_UPLOAD_PROGRESS` and a file part, and the SID arrives in a cookie, so the
  pre-RINIT callback resolves it (`ext/session/session.c:3142-3157`) and reaches
  `update()` at `MULTIPART_EVENT_FILE_START` (`:3342`).
* The stale context is used by the *next* request unconditionally: the `php` session
  serializer calls `var_tmp_var(&var_hash)` for every session variable before it parses
  the value (`ext/session/session.c:1134`), and `tmp_var()` dereferences
  `(*var_hashx)->last_dtor` (`ext/standard/var_unserializer.re:157-168`). Any non-empty
  session value is enough; the 10 MiB string is there only to force the OOM in request 1.

### 3.2 Two scenarios, and a detail a reproducer needs

* `pre-rinit`: request 1 is the upload itself; the OOM happens in the pre-RINIT `update()`.
  Request 2 is the same upload again.
* `post-rinit`: request 1 is `GET /oom.php` whose script calls `session_start()` and OOMs
  after RINIT. Request 2 is the upload.

After run 1's OOM, `php_session_cancel_decode()` has destroyed the session, so the file is
unlinked (`ext/session/mod_files.c:605`). Request 2's first `update()` therefore decodes an
*empty* session and writes the progress array into it. The crash comes from the
`MULTIPART_EVENT_END` update in the same request (`ext/session/session.c:3377-3389`, the
forced update at `:3388`), which decodes that progress array with the stale context;
`FILE_DATA`/`FILE_END` updates are suppressed by `session.upload_progress.min_freq`
(default one second, `:949-950`). That is what the stack in 3.3 shows:
`ps_srlzr_decode_php` → `var_tmp_var` → `tmp_var:168`.

### 3.3 Results on 8.4.26

Build: `./configure --disable-all --enable-cli --enable-session --enable-debug
CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address"`,
then `make -j3`. Run: `TEST_PHP_EXECUTABLE=<build>/sapi/cli/php <build>/sapi/cli/php
run-tests.php -p <build>/sapi/cli/php docs/exp/php-session-upload-progress-109619.phpt`.

| Build | pre-rinit | post-rinit | 3 runs |
|---|---|---|---|
| 8.4.26 unpatched | FAIL | FAIL | 3/3 FAIL |
| 8.4.26 + reset patch (below) | PASS | PASS | 3/3 PASS |

Unpatched failure output (both scenarios):

    FAILED: [pre-rinit] the server died on the second request
    FAILED: [pre-rinit] the second request returned nothing
    FAILED: [pre-rinit] AddressSanitizer reported memory corruption on the second request
    FAILED: [post-rinit] the server died on the second request
    FAILED: [post-rinit] the second request returned nothing
    FAILED: [post-rinit] AddressSanitizer reported memory corruption on the second request

Unpatched stack (all frames from the 8.4.26 tree):

    #0  tmp_var                 ext/standard/var_unserializer.c:168
    #1  var_tmp_var             ext/standard/var_unserializer.c:190
    #2  ps_srlzr_decode_php     ext/session/session.c:1134
    #3  php_session_decode      ext/session/session.c:279
    #4  php_session_initialize  ext/session/session.c:502
    #5  php_session_rfc1867_update ext/session/session.c:3196
    #6  php_session_rfc1867_callback ext/session/session.c:3381
    #7  rfc1867_post_handler    main/rfc1867.c:1273
    #8  sapi_handle_post       main/SAPI.c:164
    #9  php_default_treat_data main/php_variables.c:498
    #10 php_auto_globals_create_post main/php_variables.c:818
    #11 zend_activate_auto_globals Zend/zend_compile.c:2031
    #12 php_hash_environment   main/php_variables.c:788
    #13 php_request_startup    main/main.c:1873
    #14 php_cli_server_request_startup sapi/cli/php_cli_server.c:2235
    #15 php_cli_server_dispatch sapi/cli/php_cli_server.c:2311

Sanitizer verdict: `AddressSanitizer: SEGV` in `tmp_var` (`var_unserializer.c:168`). It is
a SEGV rather than a `heap-use-after-free` because the freed chunk has already been handed
to the next request's allocator by the time `last_dtor` is read. The detection is the same
either way: the server process dies.

Direct evidence that the globals are the difference — gdb, breakpoint on
`php_session_initialize`, printing `basic_globals.unserialize.level` and
`basic_globals.unserialize.data` (the `unpatched` and `fixed` binaries are the same build,
before/after the patch below):

    unpatched:  request 1: level=0 data=(nil)
                request 2: level=1 data=0x7bfff4072000      <- stale, freed
                request 2: level=1 data=0x7bfff4072000      <- reuse, then SIGSEGV
    fixed:      request 1: level=0 data=(nil)
                request 2: level=0 data=(nil)               <- reset before use
                request 2: level=0 data=(nil)

That `level == 0, data == NULL` at every `php_session_initialize()` entry is the state
assertion the task asked for; the `.phpt` observes it through its consequence (no crash)
because `BG()` is not reachable from userland.

### 3.4 Fix shapes the test accepts

Either shape passes; both make the reset happen before any pre-RINIT use of the serializer.

1. **Reset around the pre-RINIT callback.** The validation patch used for the PASS run:

        diff --git a/ext/session/session.c b/ext/session/session.c
        --- a/ext/session/session.c
        +++ b/ext/session/session.c
        @@ static void php_session_rfc1867_update(...)
        +	/* This hook runs before RINIT(basic), which normally resets the
        +	 * serializer globals.  A bailout in an earlier request leaves
        +	 * BG(unserialize) pointing into freed request memory. */
        +	memset(&BG(serialize), 0, sizeof(BG(serialize)));
        +	memset(&BG(unserialize), 0, sizeof(BG(unserialize)));
         	php_session_initialize();

   This is a validation shim, not a proposed php-src patch: it leaves the
   "bailout leaves a dangling context" state itself in place for the rest of the request.
2. **Move the callback after RINIT.** Swapping `php_hash_environment()` and
   `zend_activate_modules()` (`main/main.c:1873-1874`) so `RINIT(basic)` resets the globals
   before the POST parse. This removes the pre-RINIT callback entirely. Built and run the
   same way, it passes the test 3/3 as well: with both requests entered after RINIT, the
   globals are reset before either decode.

The test does **not** pass on an unrelated change: it fails on 8.4.26 as shipped, and each
PASS build differs from it only by one of these two changes.

## 4. FreeUnit mitigation

`session.upload_progress.enabled` is a `PHP_INI_PERDIR` directive
(`ext/session/session.c:940-941`). Unit applies per-application PHP options at
`ZEND_INI_SYSTEM` stage (`src/nxt_php_sapi.c:504-509`, `nxt_php_alter_option()` at
`:880-907`), validated as a string-valued object
(`src/nxt_conf_validation.c:1112-1124`, `:4918-4921`). So this is enough:

    "applications": {
        "app": {
            "type": "php",
            "root": "/var/www/app",
            "options": {
                "admin": {
                    "session.upload_progress.enabled": "0"
                }
            }
        }
    }

What it closes: with `PS(rfc1867_enabled)` false, the pre-RINIT callback returns at
`ext/session/session.c:3236-3238` before any session decode, so a stale
`BG(unserialize)` is never used before `RINIT(basic)` resets it. Both scenarios in
section 3 depend on that pre-RINIT decode, so both are closed. It also removes the
`session.upload_progress` OOM bailout itself.

What it does not close:

* The PHP engine bug. A post-RINIT bailout still leaves `BG(unserialize)` dangling; it
  just has no pre-RINIT consumer left. Any future pre-RINIT unserialize consumer would
  reopen it.
* Availability: an attacker who can make a request OOM in `session_start()` /
  `unserialize()` can still fail requests. That is not fixed by this ini.
* The multipart-parser path the researcher warns about ("limit size and body on every
  part"): request-body handling before/around the upload callback is not governed by this
  directive. That is edge proxy/WAF work, not a FreeUnit configuration change.
* Process recycling: Unit has no `max_requests`, so there is no per-request recycle lever
  to fall back on until a PHP fix ships.

Until a PHP release carries a fix, this is a mitigation, not a fix, and it should be
documented as such wherever FreeUnit PHP guidance lives.

## 5. Do not claim

* That 618 is exploitable. It is not: `session.c:3203/3204` keep the array alive, and
  `var.c:756` runs on the serialize side over live memory.
* That 619 is code execution. It is a use-after-free/SEGV in a persistent worker
  (memory safety, the researcher's own rating is 5.3).
* That FreeUnit is safe. The precondition holds and there is no recycle knob. The exact
  startup-failure path differs from cli-server, and that difference is an unmeasured Unit
  bug of its own, not a protection.
* That the ini mitigation is a fix.
* That this note reproduces the researcher's lab (FPM/WordPress): it reproduces the
  php-src defect on 8.4.26 under the cli-server, which is the SAPI the php-src test runner
  can drive and the one that exhibits the free-then-reuse sequence.
* Any writeup offset, CVSS value or heap address from the public post; none of it is used
  or needed here.

## 6. Files

| File | What it is |
|---|---|
| `docs/exp/php-session-upload-progress-109619.phpt` | the regression test: two scenarios, fails on 8.4.26, passes on a fix |
| this note | exposure verdict, 618 dead note, test design, results, mitigation |

Reproduce (outside the repository, with a disposable build):

    curl -LO https://www.php.net/distributions/php-8.4.26.tar.gz
    tar xzf php-8.4.26.tar.gz && cd php-8.4.26
    ./configure --disable-all --enable-cli --enable-session --enable-debug \
        CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address"
    make -j3
    TEST_PHP_EXECUTABLE=$PWD/sapi/cli/php $PWD/sapi/cli/php run-tests.php \
        -p $PWD/sapi/cli/php <path>/php-session-upload-progress-109619.phpt
