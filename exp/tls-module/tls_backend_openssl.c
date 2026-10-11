/*
 * Prototype: an OpenSSL implementation of nxt_tls_backend.h.
 *
 * It proves the shape, not the wiring: the ALPN preference decision, the
 * "no overlap means no ALPN" fallback, and the single question the HTTP/2
 * frontend asks (conn_alpn_h2). Build it, run the self test, read the result.
 *
 * Prototype grade. Not part of the server build.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include "nxt_tls_backend.h"

struct nxt_tls_ctx_s {
    SSL_CTX           *ctx;
    char             **protos;      /* server preference list, or client offer */
    size_t             nprotos;
    unsigned char     *wire;        /* client offer in ALPN wire format */
    size_t             wire_len;
};

static char  alpn_buf[64];

static void
ctx_free(nxt_tls_ctx_t *c)
{
    size_t  i;

    if (c == NULL) {
        return;
    }

    for (i = 0; i < c->nprotos; i++) {
        free(c->protos[i]);
    }

    free(c->protos);
    free(c->wire);

    if (c->ctx != NULL) {
        SSL_CTX_free(c->ctx);
    }

    free(c);
}

static int
alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen, void *arg)
{
    nxt_tls_ctx_t  *c = arg;
    const unsigned char  *p, *end;
    size_t          i;

    (void) ssl;

    /* in: sequence of (1-byte length, bytes). First server match wins. */
    for (p = in, end = in + inlen; p < end && *p > 0; p += 1 + *p) {
        for (i = 0; i < c->nprotos; i++) {
            if ((size_t) *p == strlen(c->protos[i])
                && memcmp(p + 1, c->protos[i], *p) == 0)
            {
                *out = p;
                *outlen = *p;
                return SSL_TLSEXT_ERR_OK;
            }
        }
    }

    /* No overlap: no ALPN in the ServerHello, HTTP/1 follows. */
    return SSL_TLSEXT_ERR_NOACK;
}

static nxt_tls_ctx_t *
ctx_create(int server)
{
    nxt_tls_ctx_t  *c;

    c = calloc(1, sizeof(nxt_tls_ctx_t));
    if (c == NULL) {
        return NULL;
    }

    c->ctx = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
    if (c->ctx == NULL) {
        free(c);
        return NULL;
    }

    /* The self test pins TLS 1.2: in TLS 1.3 a NOACK from the ALPN callback is
     * a different code path, and this prototype only needs the 1.2 semantics. */
    SSL_CTX_set_max_proto_version(c->ctx, TLS1_2_VERSION);
    SSL_CTX_set_min_proto_version(c->ctx, TLS1_2_VERSION);

    return c;
}

static int
ctx_set_cert(nxt_tls_ctx_t *c, const char *crt, const char *key)
{
    if (SSL_CTX_use_certificate_chain_file(c->ctx, crt) != 1) {
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(c->ctx, key, SSL_FILETYPE_PEM) != 1) {
        return -1;
    }

    if (SSL_CTX_check_private_key(c->ctx) != 1) {
        return -1;
    }

    return 0;
}

static int
ctx_set_alpn(nxt_tls_ctx_t *c, const char *const *protos, size_t nprotos)
{
    size_t          i, len;
    unsigned char  *p;

    c->protos = calloc(nprotos, sizeof(char *));
    if (c->protos == NULL) {
        return -1;
    }

    for (i = 0; i < nprotos; i++) {
        c->protos[i] = strdup(protos[i]);
        if (c->protos[i] == NULL) {
            return -1;
        }
    }

    c->nprotos = nprotos;

    len = 0;
    for (i = 0; i < nprotos; i++) {
        len += 1 + strlen(protos[i]);
    }

    c->wire = malloc(len);
    if (c->wire == NULL) {
        return -1;
    }

    for (i = 0, p = c->wire; i < nprotos; i++) {
        *p++ = (unsigned char) strlen(protos[i]);
        memcpy(p, protos[i], strlen(protos[i]));
        p += strlen(protos[i]);
    }

    c->wire_len = len;

    if (SSL_CTX_set_alpn_protos(c->ctx, c->wire, (unsigned int) c->wire_len) != 0) {
        return -1;
    }

    SSL_CTX_set_alpn_select_cb(c->ctx, alpn_select, c);

    return 0;
}

static const char *
conn_alpn_selected(void *conn)
{
    const unsigned char  *data = NULL;
    unsigned int          len = 0;

    SSL_get0_alpn_selected(conn, &data, &len);
    if (data == NULL || len == 0 || len >= sizeof(alpn_buf)) {
        return "";
    }

    memcpy(alpn_buf, data, len);
    alpn_buf[len] = '\0';

    return alpn_buf;
}

static int
conn_alpn_h2(void *conn)
{
    const unsigned char  *data = NULL;
    unsigned int          len = 0;

    SSL_get0_alpn_selected(conn, &data, &len);

    return len == 2 && memcmp(data, "h2", 2) == 0;
}

static const nxt_tls_backend_t  backend = {
    NXT_TLS_BACKEND_VERSION,
    "openssl",
    ctx_create,
    ctx_free,
    ctx_set_cert,
    ctx_set_alpn,
    conn_alpn_selected,
    conn_alpn_h2,
};

const nxt_tls_backend_t *
nxt_tls_backend(void)
{
    return &backend;
}

/*
 * Prototype-only self test. Runs a real TLS handshake over a memory BIO pair
 * between two contexts of this module and reports the protocol the CLIENT
 * negotiated into `out`. Returns 0 when the handshake completed.
 */
int
nxt_tls_backend_selftest(const char *crt, const char *key,
    const char *const *client_alpn, size_t n, char *out, size_t outlen)
{
    nxt_tls_ctx_t  *server, *client;
    SSL            *sssl, *cssl;
    BIO            *cbio, *sbio;
    int             i, rc;
    const char     *sel;

    out[0] = '\0';

    server = ctx_create(1);
    client = ctx_create(0);
    if (server == NULL || client == NULL) {
        return -1;
    }

    if (ctx_set_cert(server, crt, key) != 0) {
        return -1;
    }

    {
        const char  *server_protos[] = { "h2", "http/1.1" };

        if (ctx_set_alpn(server, server_protos, 2) != 0) {
            return -1;
        }
    }

    if (n > 0 && ctx_set_alpn(client, client_alpn, n) != 0) {
        return -1;
    }

    if (BIO_new_bio_pair(&cbio, 0, &sbio, 0) != 1) {
        return -1;
    }

    cssl = SSL_new(client->ctx);
    sssl = SSL_new(server->ctx);
    if (cssl == NULL || sssl == NULL) {
        return -1;
    }

    SSL_set_bio(cssl, cbio, cbio);
    SSL_set_bio(sssl, sbio, sbio);
    SSL_set_connect_state(cssl);
    SSL_set_accept_state(sssl);

    rc = -1;

    for (i = 0; i < 100; i++) {
        if (!SSL_is_init_finished(cssl)) {
            SSL_do_handshake(cssl);
        }

        if (!SSL_is_init_finished(sssl)) {
            SSL_do_handshake(sssl);
        }

        if (SSL_is_init_finished(cssl) && SSL_is_init_finished(sssl)) {
            rc = 0;
            break;
        }
    }

    if (rc == 0) {
        sel = conn_alpn_selected(cssl);
        snprintf(out, outlen, "%s", sel);
    }

    SSL_free(cssl);
    SSL_free(sssl);
    ctx_free(client);
    ctx_free(server);

    return rc;
}
