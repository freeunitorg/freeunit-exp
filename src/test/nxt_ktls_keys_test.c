/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include "nxt_tests.h"


/*
 * Checks the key derivation the kTLS data path will depend on (src/nxt_openssl_ktls.c).
 *
 * The expected values were produced by the step 2a probe's Python derivation -
 * exp/ktls-probe/ktls_keys_probe.py - whose HKDF-Expand-Label and PRF output the kernel and
 * OpenSSL have already accepted end to end on CI (a kernel that took those keys produced
 * records the peer's OpenSSL decrypted).  So this is a cross-check against an implementation
 * that has been validated against something real, not against a remembered constant.
 *
 * The inputs are synthetic on purpose: a secret of 0x00..0x1f, a master secret of 0x00..0x2f,
 * client random 0x00..0x1f, server random 0x20..0x3f.  What is being checked is the
 * derivation, not the handshake that produced the inputs.
 */

#if (NXT_HAVE_OPENSSL)

static nxt_int_t
nxt_ktls_test_hex(const char *hex, u_char *out, size_t out_len)
{
    nxt_uint_t  i;
    u_char      hi, lo;

    for (i = 0; i < out_len; i++) {
        hi = (u_char) hex[2 * i];
        lo = (u_char) hex[2 * i + 1];

        hi = (hi >= 'a') ? (u_char) (hi - 'a' + 10) : (u_char) (hi - '0');
        lo = (lo >= 'a') ? (u_char) (lo - 'a' + 10) : (u_char) (lo - '0');

        out[i] = (u_char) ((hi << 4) | lo);
    }

    return NXT_OK;
}


static nxt_int_t
nxt_ktls_test_cmp(nxt_thread_t *thr, const char *what, const u_char *got,
    size_t got_len, const char *expected_hex)
{
    static const u_char  digits[] = "0123456789abcdef";

    u_char   expected[64], hex[2 * 64 + 1];
    size_t   i;

    nxt_ktls_test_hex(expected_hex, expected, got_len);

    if (memcmp(got, expected, got_len) == 0) {
        return NXT_OK;
    }

    /*
     * Reported at NOTICE and returned as an error rather than logged at ALERT: the
     * test binary aborts on ALERT, which would hide which value disagreed.
     */

    for (i = 0; i < got_len; i++) {
        hex[2 * i] = digits[got[i] >> 4];
        hex[2 * i + 1] = digits[got[i] & 0xf];
    }

    hex[2 * got_len] = '\0';

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "kTLS keys: %s: got %s, expected %s",
                  what, hex, expected_hex);

    return NXT_ERROR;
}

#endif


nxt_int_t
nxt_ktls_keys_test(nxt_thread_t *thr)
{
#if (NXT_HAVE_OPENSSL)

    u_char  secret[48], master[48], cr[32], sr[32], key[32], iv[12];
    size_t  i;

    for (i = 0; i < 48; i++) {
        secret[i] = (u_char) i;
        master[i] = (u_char) i;
    }

    for (i = 0; i < 32; i++) {
        cr[i] = (u_char) i;
        sr[i] = (u_char) (i + 32);
    }

    /* TLS 1.3, AES-128-GCM-SHA256 */

    if (nxt_openssl_ktls_tls13_keys(secret, 32, 0, key, 16, iv) != NXT_OK
        || nxt_ktls_test_cmp(thr, "TLS 1.3 SHA-256 key", key, 16,
                             "9c9783cf77ea32d44f369da41f19f3cc") != NXT_OK
        || nxt_ktls_test_cmp(thr, "TLS 1.3 SHA-256 iv", iv, 12,
                             "2f41c846a431a163814bcd71") != NXT_OK)
    {
        return NXT_ERROR;
    }

    /* TLS 1.3, AES-256-GCM-SHA384 */

    if (nxt_openssl_ktls_tls13_keys(secret, 48, 1, key, 32, iv) != NXT_OK
        || nxt_ktls_test_cmp(thr, "TLS 1.3 SHA-384 key", key, 32,
                             "6877d022f1c61d24ebb7487c16752d9a"
                             "4798e40431c75b39320e537c90e23225") != NXT_OK
        || nxt_ktls_test_cmp(thr, "TLS 1.3 SHA-384 iv", iv, 12,
                             "42822531a0fe88648fc09e9f") != NXT_OK)
    {
        return NXT_ERROR;
    }

    /* TLS 1.2, AES-128-GCM-SHA256 */

    if (nxt_openssl_ktls_tls12_keys(master, 48, cr, sr, 0, key, 16, iv) != NXT_OK
        || nxt_ktls_test_cmp(thr, "TLS 1.2 SHA-256 key", key, 16,
                             "23a44f6bbe6b9f1947cb08ef8ef0efdf") != NXT_OK
        || nxt_ktls_test_cmp(thr, "TLS 1.2 SHA-256 iv", iv, 4,
                             "630b36e5") != NXT_OK)
    {
        return NXT_ERROR;
    }

    /* TLS 1.2, AES-256-GCM-SHA384 */

    if (nxt_openssl_ktls_tls12_keys(master, 48, cr, sr, 1, key, 32, iv) != NXT_OK
        || nxt_ktls_test_cmp(thr, "TLS 1.2 SHA-384 key", key, 32,
                             "e6fa1e701042ca9ee33a9159930b6471"
                             "a374999cf2129b377fd31c0bd37ce169") != NXT_OK
        || nxt_ktls_test_cmp(thr, "TLS 1.2 SHA-384 iv", iv, 4,
                             "e21424ad") != NXT_OK)
    {
        return NXT_ERROR;
    }

    nxt_log_error(NXT_LOG_NOTICE, thr->log,
                  "kTLS keys: TLS 1.3 and TLS 1.2 derivations match the probe");

    return NXT_OK;

#else

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "kTLS keys: no TLS backend, not tested");

    return NXT_OK;

#endif
}
