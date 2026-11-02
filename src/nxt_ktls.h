
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_KTLS_H_INCLUDED_
#define _NXT_KTLS_H_INCLUDED_


#if (NXT_HAVE_KTLS)

/*
 * Whether the running kernel can offload the TLS record layer.  The answer is decided by
 * trying it once on a real loopback connection and cached: the header (auto/ktls) says the
 * interface exists, not that the `tls` module is loaded.
 */
nxt_int_t nxt_ktls_supported(nxt_task_t *task);

#endif


#endif /* _NXT_KTLS_H_INCLUDED_ */
