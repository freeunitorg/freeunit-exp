/*
 * Prototype: the TLS backend interface a loadable module must expose.
 *
 * Goal: the core keeps no TLS dependency. A module (tls.unit.so) implements this
 * table and owns the TLS library behind it. The ALPN surface belongs to the
 * module, because the protocol that runs above TLS is chosen through it.
 *
 * This header is a proposal. It is not wired into the server build.
 */

#ifndef NXT_TLS_BACKEND_H
#define NXT_TLS_BACKEND_H

#include <stddef.h>

#define NXT_TLS_BACKEND_VERSION   1u

typedef struct nxt_tls_ctx_s  nxt_tls_ctx_t;

typedef struct {
    /* Interface version. The loader refuses a mismatch. */
    unsigned          version;

    /* Backend name for logs and /status: "openssl", "rustls". */
    const char        *name;

    /* Server side (control API TLS) and client side (ACME). */
    nxt_tls_ctx_t     *(*ctx_create)(int server);
    void              (*ctx_free)(nxt_tls_ctx_t *ctx);

    /* Certificate and key, PEM files. Server side only. Returns 0 on success. */
    int               (*ctx_set_cert)(nxt_tls_ctx_t *ctx, const char *crt,
                                      const char *key);

    /* Protocols this side offers, in preference order, e.g. {"h2","http/1.1"}.
     * On the server the module answers with the first protocol the client
     * offers that appears in this list; with no overlap it sends no ALPN
     * extension, and HTTP/1 follows. Returns 0 on success. */
    int               (*ctx_set_alpn)(nxt_tls_ctx_t *ctx, const char *const *protos,
                                      size_t nprotos);

    /* Connection level. `conn` is the backend's own connection handle. */
    const char        *(*conn_alpn_selected)(void *conn);

    /* The single question the HTTP/2 frontend asks today:
     * nxt_openssl_conn_alpn_h2(). True when "h2" was negotiated. */
    int               (*conn_alpn_h2)(void *conn);
} nxt_tls_backend_t;

/* The only exported symbol. The loader resolves exactly this name. */
const nxt_tls_backend_t *nxt_tls_backend(void);

#endif /* NXT_TLS_BACKEND_H */
