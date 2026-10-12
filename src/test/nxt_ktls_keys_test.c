/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include "nxt_tests.h"


/*
 * Checks the key derivation the kTLS data path will depend on (src/nxt_openssl_ktls.c).
 *
 * Where the expected values come from, per side, because they are not equally strong evidence:
 *
 *   * TLS 1.3: the step 2a probe's HKDF-Expand-Label output, which the kernel and OpenSSL
 *     accepted end to end on CI (a kernel that took those keys produced records the peer's
 *     OpenSSL decrypted);
 *   * TLS 1.2: OpenSSL's own TLS1-PRF, independent of this code -
 *     `openssl kdf -keylen 72 -kdfopt digest:SHA384 -kdfopt hexsecret:<master>
 *      -kdfopt seed:"key expansion" -kdfopt hexseed:<server_random><client_random> TLS1-PRF`.
 *     The first version of these vectors came from a Python PRF that left the label out of
 *     A(0) exactly as the C did, so the test agreed with the bug and CI stayed green.
 * Neither side is a remembered constant: the 1.3 values are key material a real kernel used
 * and a real peer decrypted, and the 1.2 values are OpenSSL's own PRF over the same inputs.
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

    /* TLS 1.2, AES-128-GCM-SHA256: the client pair, then the server pair */

    if (nxt_openssl_ktls_tls12_keys(master, 48, cr, sr, 0, 0, 4, key, 16, iv) != NXT_OK
        || nxt_ktls_test_cmp(thr, "TLS 1.2 SHA-256 client key", key, 16,
                             "fbe0dbb71e9097fcfe644317a16d334f") != NXT_OK
        || nxt_ktls_test_cmp(thr, "TLS 1.2 SHA-256 client iv", iv, 4,
                             "48092b65") != NXT_OK
        || nxt_openssl_ktls_tls12_keys(master, 48, cr, sr, 0, 1, 4, key, 16, iv) != NXT_OK
        || nxt_ktls_test_cmp(thr, "TLS 1.2 SHA-256 server key", key, 16,
                             "ac721a5f822730468a366a4ef2f22068") != NXT_OK
        || nxt_ktls_test_cmp(thr, "TLS 1.2 SHA-256 server iv", iv, 4,
                             "ca8b00c3") != NXT_OK)
    {
        return NXT_ERROR;
    }

    /* TLS 1.2, AES-256-GCM-SHA384 */

    if (nxt_openssl_ktls_tls12_keys(master, 48, cr, sr, 1, 0, 4, key, 32, iv) != NXT_OK
        || nxt_ktls_test_cmp(thr, "TLS 1.2 SHA-384 client key", key, 32,
                             "de545e3a55fc37510a2c9f4823c15511"
                             "bc0497d6e1245e15574209a947c08351") != NXT_OK
        || nxt_ktls_test_cmp(thr, "TLS 1.2 SHA-384 client iv", iv, 4,
                             "c241a06d") != NXT_OK
        || nxt_openssl_ktls_tls12_keys(master, 48, cr, sr, 1, 1, 4, key, 32, iv) != NXT_OK
        || nxt_ktls_test_cmp(thr, "TLS 1.2 SHA-384 server key", key, 32,
                             "0cdaf95bc7a2a184989c633771e022fa"
                             "683a0c6e362a908f7da3715ca40516a3") != NXT_OK
        || nxt_ktls_test_cmp(thr, "TLS 1.2 SHA-384 server iv", iv, 4,
                             "a740d7a5") != NXT_OK)
    {
        return NXT_ERROR;
    }

    /* The layout this function does not handle must be refused, not answered wrongly */

    if (nxt_openssl_ktls_tls12_keys(master, 48, cr, sr, 0, 0, 12, key, 16, iv) == NXT_OK) {
        nxt_log_error(NXT_LOG_NOTICE, thr->log,
                      "kTLS keys: a 12-byte start IV (RFC 7905 layout) was accepted");
        return NXT_ERROR;
    }

    nxt_log_error(NXT_LOG_NOTICE, thr->log,
                  "kTLS keys: 1.3 matches the probe, 1.2 matches OpenSSL's TLS1-PRF");

    return NXT_OK;

#else

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "kTLS keys: no TLS backend, not tested");

    return NXT_OK;

#endif
}
