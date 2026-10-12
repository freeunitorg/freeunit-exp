/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>

#include <openssl/crypto.h>
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
 * The record sequence is deliberately not derived here, and the side matters.  The TLS 1.3
 * measurement (application data starts at 0) used a client TX key; a TLS 1.3 server sends its
 * session tickets under the application traffic key before any data, so a server TX sequence is
 * not 0.  In TLS 1.2 the encrypted Finished takes sequence 0, so the first application-data
 * record is 1 - measured with the salt wired correctly, the peer decrypts at rec_seq 1 and
 * refuses 0.  OpenSSL does not expose the live sequence, so whoever takes over the record layer
 * has to know where in the stream it is doing so.
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
    u_char      t[EVP_MAX_MD_SIZE], buf[EVP_MAX_MD_SIZE + sizeof(info) + 1];
    size_t      hash_len, info_len, left, step, prev;
    nxt_uint_t  i, prefix_len;
    nxt_int_t   rc;

    rc = NXT_ERROR;

    prefix_len = nxt_strlen("tls13 ");
    i = nxt_strlen(label);

    if (prefix_len + i > NXT_KTLS_LABEL_MAX || context_len > 255 || out_len > 64) {
        goto done;
    }

    hash_len = EVP_MD_size(md);

    if (hash_len == 0 || hash_len > EVP_MAX_MD_SIZE) {
        goto done;
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
            goto done;
        }

        nxt_memcpy(buf, t, prev);
        nxt_memcpy(buf + prev, info, info_len);
        buf[prev + info_len] = (u_char) i;

        if (nxt_openssl_ktls_hmac(md, secret, secret_len, buf,
                                  prev + info_len + 1, t) != NXT_OK)
        {
            goto done;
        }

        prev = hash_len;
        step = nxt_min(left, hash_len);

        nxt_memcpy(out, t, step);

        out += step;
        left -= step;
    }

    rc = NXT_OK;

done:

    /* t and buf hold HMAC state derived from the secret; do not leave it on the stack. */

    OPENSSL_cleanse(t, sizeof(t));
    OPENSSL_cleanse(buf, sizeof(buf));

    return rc;
}


static nxt_int_t
nxt_openssl_ktls_prf(const EVP_MD *md, const u_char *secret, size_t secret_len,
    const char *label, const u_char *seed, size_t seed_len, u_char *out,
    size_t out_len)
{
    u_char      a[EVP_MAX_MD_SIZE * 2];
    u_char      ls[NXT_KTLS_LABEL_MAX + 512];
    u_char      buf[EVP_MAX_MD_SIZE + sizeof(ls)];
    size_t      hash_len, label_len, ls_len, left, step;
    u_char     *p;
    nxt_int_t   rc;

    rc = NXT_ERROR;

    hash_len = EVP_MD_size(md);
    label_len = nxt_strlen(label);
    ls_len = label_len + seed_len;

    if (hash_len == 0 || hash_len > EVP_MAX_MD_SIZE
        || ls_len > sizeof(ls) || hash_len + ls_len > sizeof(buf))
    {
        goto done;
    }

    /*
     * RFC 5246 section 5: PRF(secret, label, seed) = P_hash(secret, label + seed), and
     * P_hash runs A(0) = label + seed, A(i) = HMAC(secret, A(i-1)), with every output block
     * HMAC(secret, A(i) + label + seed).  Leaving the label out of A(0) - which this function
     * did at first - gives different keys for every byte while still looking like a PRF; the
     * test vectors agreed with it because they were generated the same way.
     */

    nxt_memcpy(ls, label, label_len);
    nxt_memcpy(ls + label_len, seed, seed_len);

    /* A(1) = HMAC(secret, label + seed) */

    if (nxt_openssl_ktls_hmac(md, secret, secret_len, ls, ls_len, a) != NXT_OK) {
        goto done;
    }

    left = out_len;

    while (left > 0) {
        p = nxt_cpymem(buf, a, hash_len);
        nxt_memcpy(p, ls, ls_len);

        /* out += HMAC(secret, A(i) + label + seed) */

        if (nxt_openssl_ktls_hmac(md, secret, secret_len, buf,
                                  hash_len + ls_len, a + hash_len) != NXT_OK)
        {
            goto done;
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
                goto done;
            }

            nxt_memcpy(a, a + hash_len, hash_len);
        }
    }

    rc = NXT_OK;

done:

    /* Every buffer here is a function of the master secret. */

    OPENSSL_cleanse(a, sizeof(a));
    OPENSSL_cleanse(ls, sizeof(ls));
    OPENSSL_cleanse(buf, sizeof(buf));

    return rc;
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
    nxt_bool_t server, size_t iv_len, u_char *key, size_t key_len, u_char *iv)
{
    u_char        seed[64], block[80];
    size_t        block_len;
    const EVP_MD  *md;
    nxt_int_t     rc;

    rc = NXT_ERROR;

    if (key_len != 16 && key_len != 32) {
        goto done;
    }

    /*
     * The key block layout here is the AEAD one, where the fixed IV is four bytes.  TLS 1.2
     * ChaCha20-Poly1305 (RFC 7905) fixes twelve, and its block is laid out differently: reject
     * it rather than hand back an IV cut from the wrong offset.
     */

    if (iv_len != 4) {
        goto done;
    }

    /* key_block = PRF(master_secret, "key expansion", server_random | client_random) */

    nxt_memcpy(seed, server_random, 32);
    nxt_memcpy(seed + 32, client_random, 32);

    block_len = 2 * key_len + 2 * iv_len;

    md = sha384 ? EVP_sha384() : EVP_sha256();

    if (nxt_openssl_ktls_prf(md, master, master_len, "key expansion", seed,
                             sizeof(seed), block, block_len) != NXT_OK)
    {
        goto done;
    }

    /*
     * The AEAD key block: client_write_key, server_write_key, then client_write_IV and
     * server_write_IV.  The caller says which side it is: Unit is the server, so its TLS_TX
     * needs the server pair while a client's records arrive under the client pair.
     */

    nxt_memcpy(key, block + (server ? key_len : 0), key_len);
    nxt_memcpy(iv, block + 2 * key_len + (server ? iv_len : 0), iv_len);

    rc = NXT_OK;

done:

    /* block is the whole key block; seed is public, but they live together. */

    OPENSSL_cleanse(block, sizeof(block));
    OPENSSL_cleanse(seed, sizeof(seed));

    return rc;
}
