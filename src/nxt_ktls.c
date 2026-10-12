
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/tls.h>

#include <nxt_main.h>
#include "nxt_ktls.h"


#if (NXT_HAVE_KTLS)


/*
 * Kernel TLS: the kernel takes over the TLS record layer, and that is what allows
 * sendfile() to drive a TLS connection again — TLS forces it off today (see
 * nxt_openssl_conn_init()).  What the kernel is handed is the negotiated key material
 * plus a record sequence, so this file deliberately holds no OpenSSL knowledge: getting
 * the keys and the cipher out of the handshake belongs to the TLS backend.
 *
 * The interface (auto/ktls) and the capability are two different questions: the `tls`
 * module may be absent from the running kernel, and only a real connection answers that.
 * The probe below therefore performs it once, on loopback, and caches the verdict.
 *
 * The shape it uses is the one measured against real OpenSSL sessions in CI
 * (docs/exp/ktls-verdict.md): the connection is ESTABLISHED, the TLS ULP is attached, and
 * TLS_TX carries version, cipher, key, salt/IV and the record sequence — where the
 * application-data sequence of a TLS 1.3 connection starts at 0.
 */

static nxt_int_t  nxt_ktls_probe = -1;   /* -1: not probed; NXT_OK or NXT_ERROR after */


static nxt_int_t
nxt_ktls_try(struct tls12_crypto_info_aes_gcm_128 *info)
{
    int                 ls, cs, as, n;
    socklen_t           len;
    nxt_int_t           ret;
    struct sockaddr_in  sa;
    u_char              ulp[] = "tls";

    ls = -1;
    cs = -1;
    as = -1;
    ret = NXT_ERROR;

    ls = socket(AF_INET, SOCK_STREAM, 0);

    if (nxt_slow_path(ls == -1)) {
        goto done;
    }

    nxt_memzero(&sa, sizeof(struct sockaddr_in));

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;

    if (nxt_slow_path(bind(ls, (struct sockaddr *) &sa,
                           sizeof(struct sockaddr_in)) == -1))
    {
        goto done;
    }

    if (nxt_slow_path(listen(ls, 1) == -1)) {
        goto done;
    }

    len = sizeof(struct sockaddr_in);

    if (nxt_slow_path(getsockname(ls, (struct sockaddr *) &sa, &len) == -1)) {
        goto done;
    }

    cs = socket(AF_INET, SOCK_STREAM, 0);

    if (nxt_slow_path(cs == -1)) {
        goto done;
    }

    if (nxt_slow_path(connect(cs, (struct sockaddr *) &sa,
                              sizeof(struct sockaddr_in)) == -1))
    {
        goto done;
    }

    as = accept(ls, NULL, NULL);

    if (nxt_slow_path(as == -1)) {
        goto done;
    }

    /*
     * The TLS ULP is only accepted on an established connection.  EEXIST means a ULP is
     * already attached, which is the state TLS_TX needs — not a failure.
     */
    n = setsockopt(cs, IPPROTO_TCP, TCP_ULP, ulp, sizeof(ulp));

    if (nxt_slow_path(n == -1 && errno != EEXIST)) {
        goto done;
    }

    n = setsockopt(cs, SOL_TLS, TLS_TX, info,
                   sizeof(struct tls12_crypto_info_aes_gcm_128));

    if (nxt_slow_path(n == -1)) {
        goto done;
    }

    ret = NXT_OK;

done:

    if (as != -1) {
        close(as);
    }

    if (cs != -1) {
        close(cs);
    }

    if (ls != -1) {
        close(ls);
    }

    return ret;
}


nxt_int_t
nxt_ktls_supported(nxt_task_t *task)
{
    struct tls12_crypto_info_aes_gcm_128  info;

    if (nxt_ktls_probe != -1) {
        return nxt_ktls_probe;
    }

    nxt_memzero(&info, sizeof(struct tls12_crypto_info_aes_gcm_128));

    info.info.version = TLS_1_2_VERSION;
    info.info.cipher_type = TLS_CIPHER_AES_GCM_128;

    nxt_ktls_probe = nxt_ktls_try(&info);

    if (task != NULL) {
        nxt_log_debug(task->log, "kTLS: %s",
                      (nxt_ktls_probe == NXT_OK) ? "supported" : "not available");
    }

    return nxt_ktls_probe;
}


#endif /* NXT_HAVE_KTLS */
