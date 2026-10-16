"""PHP's request shutdown closes the syslog handle of the whole process,
even when the request did not open it (PHP GH-24308).

An application process under Unit is a host that runs PHP rather than a
PHP-only program.  It inherits whatever its runtime had open, and its
own alert path writes through the process syslog handle when the
application log cannot be written (nxt_app_log.c writes LOG_ALERT with
syslog(3)).  PHP's syslog RSHUTDOWN handler calls closelog() on every
request without asking whether this process ever called openlog(), so
the handle the application inherited from its host -- the same one
Unit's alert path uses in that process -- is closed at the end of the
first request.  Every later request that logs reconnects, and on musl
closelog() is close(log_fd) with no check at all, which is close(-1)
when there is nothing to close.

The upstream fix is one condition around that call
(PG(have_called_openlog)).  Until it is in the PHP the suite builds
against, the thing worth having here is the measurement, so that the
day it lands the contract is enforced rather than assumed:

  * a request that never called syslog() or openlog() must not make the
    process call closelog() at all;
  * a request that did call openlog() still closes its handle at
    request end -- PHP owns that one, and closing it is not the bug.

Both tests are therefore skipped, with the observed count quoted in the
reason, on a PHP that has not been fixed yet.

The shim (php_syslog_host.c, preloaded into a unitd of this test's own)
is what makes the first half observable: it opens the handle in the main
process before any worker exists, so every application inherits it, and
it records each closelog() call with the pid that made it.  The call is
the observable rather than the socket, so the test needs no /dev/log and
says the same thing on a machine that has none.  A third test proves the
shim is reachable at all, so that the silence the other two read cannot
be the shim's.

No runtime change and nothing user-visible: this is a test with a
helper, so it carries no CHANGES and no docs/changes.xml entry.
"""

import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from unit.http import HTTP1
from unit.option import option
from unit.utils import public_dir, waitforfiles

prerequisites = {'modules': {'php': 'any'}}

client = HTTP1()


@pytest.fixture(scope='module')
def shim():
    """Build test/php_syslog_host.c into a preloadable object.

    The suite has no convention for compiling C helpers -- nothing under
    test/ builds any -- so rather than invent a build system this
    compiles at test time with cc(1) and skips when there is none.
    """
    compiler = shutil.which('cc') or shutil.which('gcc')

    if compiler is None:
        pytest.skip('requires a C compiler')

    source = f'{option.test_dir}/php_syslog_host.c'
    outdir = tempfile.mkdtemp(prefix='unit-test-syslog-')
    library = f'{outdir}/php_syslog_host.so'

    build = subprocess.run(
        [compiler, '-shared', '-fPIC', '-O1', '-o', library, source, '-ldl'],
        check=False,
        capture_output=True,
    )

    assert build.returncode == 0, (
        f'failed to build the syslog host shim:\n{build.stderr.decode()}'
    )

    yield library

    shutil.rmtree(outdir, ignore_errors=True)


class Host:
    """A unitd of our own, since conftest's shared one has no way to
    take an environment."""

    def __init__(self, shim):
        builddir = f'{option.current_dir}/build'
        self.unitd = f'{builddir}/sbin/unitd'

        if not Path(self.unitd).is_file():
            pytest.skip('could not find unitd')

        self.dir = tempfile.mkdtemp(prefix='unit-test-syslog-')
        public_dir(self.dir)

        Path(f'{self.dir}/state').mkdir()

        self.log = f'{self.dir}/unit.log'
        self.stderr = f'{self.dir}/stderr.log'
        self.record = f'{self.dir}/syslog.record'
        self.control = f'{self.dir}/control.unit.sock'
        self.listener = f'{self.dir}/app.sock'
        self.pidfile = f'{self.dir}/unit.pid'

        env = os.environ.copy()

        # Same UNIT_PYTHONHOME dance as conftest.unit_run(): PYTHONHOME
        # must not be set for the pytest interpreter itself.
        pythonhome = env.pop('UNIT_PYTHONHOME', None)
        if pythonhome:
            env['PYTHONHOME'] = pythonhome

        env['LD_PRELOAD'] = shim
        env['NXT_TEST_SYSLOG_RECORD'] = self.record

        self.stderr_file = open(self.stderr, 'w', encoding='utf-8')

        self.process = subprocess.Popen(
            [
                self.unitd,
                '--no-daemon',
                '--modulesdir',
                f'{builddir}/lib/unit/modules',
                '--statedir',
                f'{self.dir}/state',
                '--pid',
                self.pidfile,
                '--log',
                self.log,
                '--control',
                f'unix:{self.control}',
                '--tmpdir',
                self.dir,
            ],
            stdout=subprocess.DEVNULL,
            stderr=self.stderr_file,
            start_new_session=True,
            env=env,
        )

    def stop(self):
        if self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        self.process.wait(timeout=30)
        self.stderr_file.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def read(self, path):
        return Path(path).read_text(encoding='utf-8', errors='ignore')

    def main_pid(self):
        return int(self.read(self.pidfile).strip())

    def entries(self, event):
        """The pids of every "<pid> <event>" line, in the order written.

        A process appends, so a caller that wants the calls made by one
        request takes the tail after the count it saw before it.
        """
        if not Path(self.record).exists():
            return []

        text = self.read(self.record)

        return [int(m.group(1)) for m in re.finditer(rf'^(\d+) {event}$', text, re.M)]

    def configure(self):
        """Load a one-process PHP application that answers with its own
        pid, plus a script that can open the log on request."""
        appdir = f'{self.dir}/app'
        Path(appdir).mkdir()
        public_dir(appdir)

        Path(f'{appdir}/index.php').write_text(
            '<?php echo getmypid();\n', encoding='utf-8'
        )

        # No syslog() here on purpose: openlog() is the call that makes
        # PHP the owner of the handle, and the second test is about what
        # it owes in that case.
        Path(f'{appdir}/probe.php').write_text(
            '<?php\n'
            'if (isset($_GET["openlog"])) {\n'
            '    openlog("unitd-syslog-test", LOG_NDELAY | LOG_PID, LOG_USER);\n'
            '}\n'
            'if (isset($_GET["closelog"])) {\n'
            '    closelog();\n'
            '}\n'
            'echo getmypid(), " ", PHP_VERSION;\n',
            encoding='utf-8',
        )

        conf = {
            "listeners": {f'unix:{self.listener}': {"pass": "applications/app"}},
            "applications": {
                "app": {
                    "type": "php",
                    "processes": {"spare": 0},
                    "root": appdir,
                    "index": "index.php",
                }
            },
        }

        return client.put(
            url='/config',
            sock_type='unix',
            addr=self.control,
            body=json.dumps(conf),
        )

    def get(self, url='/'):
        resp = client.get(url=url, sock_type='unix', addr=self.listener)

        assert resp['status'] == 200, f'application answers: {resp["status"]}'

        return resp

    def plain_request(self):
        """One request that touches no syslog call, and the closelog()
        pids it caused."""
        before = len(self.entries('closed'))

        self.get()

        return self.entries('closed')[before:]

    def php_version(self):
        return self.get('/probe.php')['body'].split()[1]


def wait_for(path, pattern, timeout=150):
    for _ in range(timeout):
        if Path(path).exists():
            text = Path(path).read_text(encoding='utf-8', errors='ignore')
            found = re.search(pattern, text, re.M)

            if found is not None:
                return found

        time.sleep(0.1)

    return None


def skip_until_php_is_fixed(host, closed):
    """The same evidence both tests rest on, quoted where it is found.

    A PHP without the upstream fix closes the handle on every request,
    so there is nothing to enforce yet, and a red suite would be a
    statement about PHP rather than about Unit.
    """
    if closed:
        pytest.skip(
            'this PHP calls closelog() at request shutdown even when the '
            f'request opened nothing: {len(closed)} call(s) in pid(s) '
            f'{sorted(set(closed))}, made by requests that never called '
            f'syslog() or openlog(), PHP {host.php_version()} '
            '(PHP GH-24308 is not fixed in this build)'
        )


@pytest.fixture(scope='module')
def host(shim):
    instance = Host(shim)

    try:
        assert waitforfiles(instance.control), (
            f'unitd started; its stderr was:\n{instance.read(instance.stderr)}'
        )

        assert wait_for(instance.log, r'router started') is not None, (
            'router started'
        )

        assert 'success' in instance.configure()['body'], 'configure'

        yield instance

    finally:
        instance.stop()


def test_php_syslog_shim_is_reachable(host):
    """Without this the silence the other tests assert could be the
    shim's rather than PHP's.

    A request that calls closelog() explicitly must leave a record, on
    both sides of the upstream fix, so the count is not asserted here:
    before the fix the request shutdown adds a second call of its own,
    after it only the explicit one remains.
    """
    before = len(host.entries('closed'))

    resp = host.get('/probe.php?closelog=1')
    app_pid = int(resp['body'].split()[0])

    recorded = host.entries('closed')[before:]

    assert recorded, (
        'the shim did not see a closelog() that PHP made: is the wrapper '
        'still reachable from the PHP module?'
    )
    assert set(recorded) == {app_pid}, (
        f'the call was recorded in the wrong process: {recorded} '
        f'for pid {app_pid}'
    )


def test_php_syslog_host_handle_survives_a_request(host):
    # The premise, without which the record below would say nothing: the
    # shim armed in the process that forks the applications, so each of
    # them inherited an open handle it did not open itself.
    assert host.main_pid() in host.entries('armed'), 'shim armed in unitd'

    closed = host.plain_request() + host.plain_request()

    skip_until_php_is_fixed(host, closed)

    assert closed == [], (
        f'a request that opened nothing closed the host handle: {closed}'
    )


def test_php_syslog_opened_by_a_request_is_closed(host):
    closed = host.plain_request()

    skip_until_php_is_fixed(host, closed)

    assert closed == [], (
        f'a request that opened nothing closed the host handle: {closed}'
    )

    before = len(host.entries('closed'))

    resp = host.get('/probe.php?openlog=1')
    app_pid = int(resp['body'].split()[0])

    # The other half of the contract, and the reason the fix is a
    # condition rather than a removal: PHP closes what PHP opened.
    assert host.entries('closed')[before:] == [app_pid], (
        'a request that called openlog() closes its own handle at request '
        f'end: expected one call in pid {app_pid}, recorded '
        f'{host.entries("closed")[before:]}'
    )
