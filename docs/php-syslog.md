# The syslog handle in an application process

An application process is a host that runs a language runtime rather than
a runtime-only program. It starts with whatever the runtime had open, and
in a PHP application one of those descriptors is the process syslog
handle: Unit's own alert path writes through it (`nxt_app_log.c` calls
`syslog(3)` with `LOG_ALERT` when the application log cannot be written).

PHP's syslog request shutdown handler calls `closelog()` on every
request, without asking whether this process ever called `openlog()`
([PHP GH-24308](https://github.com/php/php-src/issues/24308)). The
consequences are:

* the handle the application inherited from its host is closed in the
  application at the end of the first request, so a later request that
  logs connects to `/dev/log` again;
* on musl `closelog()` is `close(log_fd)` with no check, which is
  `close(-1)` on a request that touched nothing -- one wasted syscall per
  request in the application process.

Neither is Unit's to fix: the upstream change is one condition around
that call (`PG(have_called_openlog)`). Until it is in the PHP we build
against, `test/test_php_syslog_handle.py` measures it instead of
asserting it, and skips with the observed count quoted. That test is the
tripwire: the day the fix is in, the same file enforces the contract.

What to do in the meantime, on a deployment where the application logs
per request and the extra `connect()` and `close()` are visible in the
syscall profile:

* keep the application log a file rather than `syslog`, so the request
  path does not reach the handle at all;
* if the application itself must write to syslog, the connection per
  request is PHP's, and a per-request `openlog()` in the application
  costs one more call than the implicit one -- neither is avoided by
  configuration.

The measurement, for reference: on Alpine (musl) versus Debian (glibc),
a Drupal request made 301 syscalls against 252, and the dominant extra
was `fcntl` (27.9 against 21.3) -- a separate finding, from the same
profile.
