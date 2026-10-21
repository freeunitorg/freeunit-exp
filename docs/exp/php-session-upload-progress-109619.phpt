--TEST--
session.upload_progress: a bailout must not leave a serializer context that the next request reuses
--EXTENSIONS--
session
--SKIPIF--
<?php
$maps = @file_get_contents('/proc/self/maps');
if (!$maps) {
    die('skip requires Linux /proc/self/maps to detect the sanitizer');
}
if (!str_contains($maps, 'libasan') && !str_contains($maps, 'libclang_rt.asan')) {
    die('skip requires an AddressSanitizer build (-fsanitize=address); the bug is a use-after-free');
}
?>
--FILE--
<?php
/*
 * php_request_startup() calls php_hash_environment() before zend_activate_modules()
 * (main/main.c), so the multipart parser and session.upload_progress' pre-RINIT
 * update() run before PHP_RINIT(basic) resets BG(serialize)/BG(unserialize)
 * (ext/standard/basic_functions.c).  A bailout leaves BG(unserialize).level != 0
 * with BG(unserialize).data pointing at request memory.  Once that request's
 * memory is freed, the next request on the same process reuses the freed
 * context in php_session_rfc1867_update() and dies in var_tmp_var().
 *
 * Two scenarios, each on its own single-process built-in server:
 *   pre-rinit : the bailout happens inside the pre-RINIT update() itself
 *               (the reported CVE-2026-109619 path);
 *   post-rinit: the bailout happens in session_start() after RINIT, so the SAPI
 *               runs php_request_shutdown() and frees the context.  This is the
 *               variant a SAPI that skips shutdown after a failed startup (as
 *               FreeUnit's PHP handler does) is still exposed to.
 *
 * On unpatched PHP 8.4 each scenario kills the server; the fix (reset the
 * serializer globals before the pre-RINIT callback may use them) keeps both
 * servers alive.
 */

const PAYLOAD = 10 << 20;   /* session payload bigger than memory_limit */
const MEMORY  = '16M';

function free_port(): int
{
    $sock = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
    $name = stream_socket_get_name($sock, false);
    $port = (int) substr(strrchr($name, ':'), 1);
    fclose($sock);
    return $port;
}

function wait_for(callable $test, float $timeout = 10.0): bool
{
    $end = microtime(true) + $timeout;
    while (microtime(true) < $end) {
        if ($test()) {
            return true;
        }
        usleep(100000);
    }
    return false;
}

function upload_body(): array
{
    $b = '----ghuploadprogress';
    $body = "--$b\r\n"
          . "Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n"
          . "job\r\n"
          . "--$b\r\n"
          . "Content-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n"
          . "Content-Type: text/plain\r\n\r\n"
          . "x\r\n"
          . "--$b--\r\n";
    return [$b, $body];
}

function send_request(int $port, string $request): string
{
    $fp = @fsockopen('127.0.0.1', $port, $errno, $errstr, 5);
    if (!$fp) {
        return '';
    }
    @fwrite($fp, $request);
    stream_set_timeout($fp, 10);
    $resp = (string) stream_get_contents($fp);
    fclose($fp);
    return $resp;
}

function scenario(string $mode): array
{
    $fail = [];
    $tmp = sys_get_temp_dir() . '/gh_session_upload_progress_' . $mode . '_' . getmypid();
    foreach (['', '/sess', '/doc'] as $sub) {
        @mkdir($tmp . $sub, 0777, true);
    }
    $sid = 'uaf' . getmypid();

    /* A session that cannot be decoded within memory_limit: the file is read
     * into one zend_string (10 MiB) and decoding allocates the same bytes a
     * second time, so the second allocation fails inside php_var_unserialize(). */
    $payload = str_repeat('A', PAYLOAD);
    file_put_contents("$tmp/sess/sess_$sid",
        'big|s:' . strlen($payload) . ':"' . $payload . '";');
    file_put_contents("$tmp/doc/index.php", "<?php echo 'alive';\n");
    file_put_contents("$tmp/doc/oom.php", "<?php session_start(); echo 'no-bailout';\n");

    $port = free_port();
    $errLog = "$tmp/server.err";
    $env = getenv();
    $env['ASAN_OPTIONS'] = 'detect_leaks=0:abort_on_error=1:halt_on_error=1:exitcode=42';
    $proc = proc_open([PHP_BINARY,
        '-d', 'memory_limit=' . MEMORY,
        '-d', "session.save_path=$tmp/sess",
        '-d', 'session.serialize_handler=php',
        '-d', 'session.gc_probability=0',
        '-d', 'session.upload_progress.enabled=1',
        '-d', 'session.upload_progress.cleanup=0',
        '-d', 'session.upload_progress.freq=0',
        '-d', 'display_errors=1',
        '-d', 'log_errors=1',
        '-d', 'error_log=',
        '-S', "127.0.0.1:$port",
        '-t', "$tmp/doc",
    ], [0 => ['pipe', 'r'], 1 => ['file', "$tmp/server.out", 'w'], 2 => ['file', $errLog, 'w']],
        $pipes, $tmp, $env);
    if (!is_resource($proc)) {
        return ['could not start the built-in server'];
    }

    if (!wait_for(fn() => (bool) @fsockopen('127.0.0.1', $port, $e, $es, 0.2))) {
        $fail[] = 'the built-in server did not start';
    } else {
        [$boundary, $body] = upload_body();
        $base = "Host: 127.0.0.1:$port\r\nCookie: PHPSESSID=$sid\r\nConnection: close\r\n\r\n";
        if ($mode === 'pre-rinit') {
            $upload = "POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n"
                    . "Cookie: PHPSESSID=$sid\r\n"
                    . "Content-Type: multipart/form-data; boundary=$boundary\r\n"
                    . "Content-Length: " . strlen($body) . "\r\nConnection: close\r\n\r\n" . $body;
            $first = $upload;
        } else {
            $first = "GET /oom.php HTTP/1.1\r\n$base";
        }

        send_request($port, $first);
        if (!wait_for(fn() => str_contains((string) @file_get_contents($errLog), 'Allowed memory size'))) {
            $fail[] = "[$mode] the first request did not bail out on memory_limit";
        }

        $upload = "POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n"
                . "Cookie: PHPSESSID=$sid\r\n"
                . "Content-Type: multipart/form-data; boundary=$boundary\r\n"
                . "Content-Length: " . strlen($body) . "\r\nConnection: close\r\n\r\n" . $body;
        $resp = send_request($port, $upload);
        usleep(300000);

        $status = proc_get_status($proc);
        if (!$status['running']) {
            $fail[] = "[$mode] the server died on the second request";
        }
        if ($resp === '') {
            $fail[] = "[$mode] the second request returned nothing";
        }
        $log = (string) @file_get_contents($errLog);
        if (preg_match('/AddressSanitizer.*(use-after-free|SEGV)|Sanitizer:.*(use-after-free|SEGV)/s', $log)) {
            $fail[] = "[$mode] AddressSanitizer reported memory corruption on the second request";
        }
    }

    if (is_resource($proc)) {
        $status = proc_get_status($proc);
        if ($status['running']) {
            proc_terminate($proc);
        }
        proc_close($proc);
    }
    exec('rm -rf ' . escapeshellarg($tmp));

    return $fail;
}

$fail = array_merge(scenario('pre-rinit'), scenario('post-rinit'));
if ($fail) {
    foreach ($fail as $f) {
        echo "FAILED: $f\n";
    }
} else {
    echo "Done\n";
}
?>
--EXPECT--
Done
