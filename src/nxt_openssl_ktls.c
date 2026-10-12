/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>

#include <openssl/hmac.h>


/*
 * Key material for kernel TLS.
 *
 * The kernel negotiates nothing: it is handed the AES key, the static IV and the record
 * sequence, and from then on it produces records the peer's OpenSSL must accept.  Those keys
 * come out of the handshake, which is why this derivation lives in the TLS backend and not
 * in the capability layer - src/nxt_ktls.c knows how to hand the kernel a crypto_info, not
 * where the keys come from.
 *
 *   * TLS 1.3: the traffic secret -> key and static IV through HKDF-Expand-Label
 *     (RFC 8446, section 7.3);
 *   * TLS 1.2: the master secret and both randoms -> the key block through the PRF
 *     (RFC 5246, sections 5 and 6.3), where the AEAD layout puts the client write key first
 *     and the client write IV after both write keys.
 *
 * The record sequence is deliberately not derived here: for TLS 1.3 the application-data
 * epoch starts at 0 (measured, see docs/exp/ktls-verdict.md), and what TLS 1.2 does at the
 * same point has to be measured the same way before that path is switched on.
 *
 * The functions are checked against values derived independently in the step 2a probe
 * (src/test/nxt_ktls_keys_test.c) rather than against published vectors - the probe's
 * derivation is the one OpenSSL has already accepted end to end.
 */

#define NXT_KTLS_LABEL_MAX  32


static nxt_int_t
nxt_openssl_ktls_hmac(const EVP_MD *md, const u_char *key, size_t key_len,
    const u_char *data, size_t data_len, u_char *digest)
{
    unsigned int  len;

    if (HMAC(md, key, (int) key_len, data, data_len, digest, &len) == NULL) {
        return NXT_ERROR;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_openssl_ktls_hkdf_expand_label(const EVP_MD *md, const u_char *secret,
    size_t secret_len, const char *label, const u_char *context,
    size_t context_len, u_char *out, size_t out_len)
{
    u_char      info[2 + 1 + NXT_KTLS_LABEL_MAX + 1 + 255];
    u_char      t[NXT_KTLS_LABEL_MAX * 4], buf[EVP_MAX_MD_SIZE + sizeof(info) + 1];
    size_t      hash_len, info_len, left, step, prev;
    nxt_uint_t  i, prefix_len;

    prefix_len = nxt_strlen("tls13 ");
    i = nxt_strlen(label);

    if (prefix_len + i > NXT_KTLS_LABEL_MAX || context_len > 255 || out_len > 64) {
        return NXT_ERROR;
    }

    hash_len = EVP_MD_size(md);

    if (hash_len == 0 || hash_len > EVP_MAX_MD_SIZE) {
        return NXT_ERROR;
    }

    info[0] = (u_char) (out_len >> 8);
    info[1] = (u_char) (out_len & 0xff);
    info[2] = (u_char) (prefix_len + i);

    nxt_memcpy(info + 3, "tls13 ", prefix_len);
    nxt_memcpy(info + 3 + prefix_len, label, i);

    info[3 + prefix_len + i] = (u_char) context_len;

    if (context_len > 0) {
        nxt_memcpy(info + 3 + prefix_len + i + 1, context, context_len);
    }

    info_len = 3 + prefix_len + i + 1 + context_len;

    prev = 0;
    left = out_len;

    for (i = 1; left > 0; i++) {
        if (i > 255) {
            return NXT_ERROR;
        }

        nxt_memcpy(buf, t, prev);
        nxt_memcpy(buf + prev, info, info_len);
        buf[prev + info_len] = (u_char) i;

        if (nxt_openssl_ktls_hmac(md, secret, secret_len, buf,
                                  prev + info_len + 1, t) != NXT_OK)
        {
            return NXT_ERROR;
        }

        prev = hash_len;
        step = nxt_min(left, hash_len);

        nxt_memcpy(out, t, step);

        out += step;
        left -= step;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_openssl_ktls_prf(const EVP_MD *md, const u_char *secret, size_t secret_len,
    const char *label, const u_char *seed, size_t seed_len, u_char *out,
    size_t out_len)
{
    u_char      a[EVP_MAX_MD_SIZE * 2];
    u_char      buf[EVP_MAX_MD_SIZE + NXT_KTLS_LABEL_MAX + 512];
    size_t      hash_len, label_len, left, step;
    u_char     *p;

    hash_len = EVP_MD_size(md);
    label_len = nxt_strlen(label);

    if (hash_len == 0 || hash_len > EVP_MAX_MD_SIZE
        || hash_len + label_len + seed_len > sizeof(buf))
    {
        return NXT_ERROR;
    }

    /* A(1) = HMAC(secret, seed), then A(i) = HMAC(secret, A(i-1)). */

    if (nxt_openssl_ktls_hmac(md, secret, secret_len, seed, seed_len, a)
        != NXT_OK)
    {
        return NXT_ERROR;
    }

    left = out_len;

    while (left > 0) {
        p = nxt_cpymem(buf, a, hash_len);
        p = nxt_cpymem(p, label, label_len);
        p = nxt_cpymem(p, seed, seed_len);

        /* out += HMAC(secret, A(i) + label + seed) */

        if (nxt_openssl_ktls_hmac(md, secret, secret_len, buf,
                                  (size_t) (p - buf), a + hash_len) != NXT_OK)
        {
            return NXT_ERROR;
        }

        step = nxt_min(left, hash_len);
        nxt_memcpy(out, a + hash_len, step);

        out += step;
        left -= step;

        if (left > 0) {
            /* A(i+1) = HMAC(secret, A(i)) */

            if (nxt_openssl_ktls_hmac(md, secret, secret_len, a, hash_len, a + hash_len)
                != NXT_OK)
            {
                return NXT_ERROR;
            }

            nxt_memcpy(a, a + hash_len, hash_len);
        }
    }

    return NXT_OK;
}


nxt_int_t
nxt_openssl_ktls_tls13_keys(const u_char *secret, size_t secret_len,
    nxt_bool_t sha384, u_char *key, size_t key_len, u_char *iv)
{
    const EVP_MD  *md;

    if (key_len != 16 && key_len != 32) {
        return NXT_ERROR;
    }

    md = sha384 ? EVP_sha384() : EVP_sha256();

    if (nxt_openssl_ktls_hkdf_expand_label(md, secret, secret_len, "key", NULL, 0,
                                           key, key_len) != NXT_OK)
    {
        return NXT_ERROR;
    }

    if (nxt_openssl_ktls_hkdf_expand_label(md, secret, secret_len, "iv", NULL, 0,
                                           iv, 12) != NXT_OK)
    {
        return NXT_ERROR;
    }

    return NXT_OK;
}


nxt_int_t
nxt_openssl_ktls_tls12_keys(const u_char *master, size_t master_len,
    const u_char *client_random, const u_char *server_random, nxt_bool_t sha384,
    u_char *key, size_t key_len, u_char *iv)
{
    u_char        seed[64], block[80];
    size_t        block_len;
    const EVP_MD  *md;

    if (key_len != 16 && key_len != 32) {
        return NXT_ERROR;
    }

    /* key_block = PRF(master_secret, "key expansion", server_random | client_random) */

    nxt_memcpy(seed, server_random, 32);
    nxt_memcpy(seed + 32, client_random, 32);

    block_len = 2 * key_len + 8;   /* two write keys and two four-byte write IVs */

    md = sha384 ? EVP_sha384() : EVP_sha256();

    if (nxt_openssl_ktls_prf(md, master, master_len, "key expansion", seed,
                             sizeof(seed), block, block_len) != NXT_OK)
    {
        return NXT_ERROR;
    }

    /* The AEAD key block: client_write_key, server_write_key, then both write IVs. */

    nxt_memcpy(key, block, key_len);
    nxt_memcpy(iv, block + 2 * key_len, 4);

    return NXT_OK;
}
