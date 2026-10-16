/*
 * A host that owns a syslog handle before PHP gets to run.
 *
 * Loaded into a unitd of the test's own with LD_PRELOAD, which is
 * enough because Unit fork()s its application processes and never
 * exec()s them: this constructor runs once, in the main process, and
 * both the mapping and the handle it opens arrive in every application
 * by inheritance.  That is the deployment the test is about -- an
 * application process that inherits a log handle its host opened,
 * which is also how Unit's own alert path gets one (nxt_app_log.c
 * writes LOG_ALERT through syslog(3) when the application log cannot be
 * written).
 *
 * Two events are appended to the file named by NXT_TEST_SYSLOG_RECORD,
 * one "<pid> <event>" line each:
 *
 *   armed   this process ran the constructor and called openlog()
 *   closed  this process called closelog()
 *
 * closelog() is wrapped rather than inferred from /proc, because what
 * is under test is the call PHP's request shutdown makes, not the
 * socket: the record names the process that made it even where there is
 * no /dev/log for a handle to live in.
 *
 * The record path is copied out of the environment in the constructor
 * rather than kept as a getenv() pointer: unitd overwrites the
 * argv+environ block with its process title, so the pointer would name
 * something else by the time a worker logs.
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

static char record_path[4096];

static void
record(const char *event)
{
    char line[64];
    int fd, len;

    if (record_path[0] == '\0') {
        return;
    }

    len = snprintf(line, sizeof(line), "%d %s\n", (int) getpid(), event);

    fd = open(record_path, O_WRONLY | O_CREAT | O_APPEND, 0644);

    /*
     * open()/write()/close() are their own libc stubs, not calls to
     * closelog(), so this cannot recurse back into the wrapper.
     */

    if (fd < 0) {
        return;
    }

    (void) write(fd, line, (size_t) len);
    (void) close(fd);
}


__attribute__((constructor))
static void
host_arm(void)
{
    const char *path;

    path = getenv("NXT_TEST_SYSLOG_RECORD");

    if (path != NULL) {
        strncpy(record_path, path, sizeof(record_path) - 1);
    }

    record("armed");

    /* LOG_NDELAY so the handle exists now, before the fork, instead of
     * appearing at the first message of the first request. */
    openlog("unitd-syslog-host", LOG_NDELAY | LOG_PID, LOG_USER);
}


void
closelog(void)
{
    static void (*real_closelog)(void) = NULL;

    if (real_closelog == NULL) {
        real_closelog = dlsym(RTLD_NEXT, "closelog");
    }

    record("closed");

    /*
     * Best effort on purpose: what the test reads is the call, so a
     * missing symbol must not turn a recorded call into a silent one.
     * Nothing here depends on the handle actually being closed.
     */
    if (real_closelog != NULL) {
        real_closelog();
    }
}
