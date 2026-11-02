
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include "nxt_tests.h"
#include <nxt_ktls.h>


/*
 * This test is a link-level guard as much as a report.  The capability itself is a property
 * of the machine the tests run on, so the test asserts nothing about it: it calls
 * nxt_ktls_supported() and logs the answer.  What it does assert is that src/nxt_ktls.c was
 * actually built — if the configure probe finds the interface but the file never joins the
 * source list, this reference fails to link instead of the build staying green and the file
 * being silently absent (which is exactly what happened once).
 */

nxt_int_t
nxt_ktls_test(nxt_thread_t *thr)
{
#if (NXT_HAVE_KTLS)

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "kTLS offload: %s",
                  (nxt_ktls_supported(NULL) == NXT_OK) ? "supported by this kernel"
                                                       : "not available on this kernel");

#else

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "kTLS: not compiled in");

#endif

    return NXT_OK;
}
