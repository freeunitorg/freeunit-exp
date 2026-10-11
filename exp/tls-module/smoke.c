/*
 * Prototype smoke test.
 *
 * Loads the module the way the core would (dlopen + one symbol), checks the
 * interface version, then runs three ALPN cases through the module's own self
 * test over a real TLS handshake:
 *
 *   1. client offers h2 and http/1.1      -> negotiated "h2"
 *   2. client offers http/1.1 only        -> negotiated "http/1.1"
 *   3. client offers no ALPN              -> negotiated "" (HTTP/1 follows)
 *
 * Exits non-zero if any case fails. Usage: ./smoke cert.pem key.pem
 */

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#include "nxt_tls_backend.h"

#define SO_PATH  "./libnxt_tls_openssl.so"

typedef int (*selftest_fn)(const char *crt, const char *key,
    const char *const *client_alpn, size_t n, char *out, size_t outlen);

static int  failures;

static void
check(const char *what, const char *got, const char *want)
{
    if (strcmp(got, want) == 0) {
        printf("PASS  %-28s negotiated \"%s\"\n", what, got);
    } else {
        printf("FAIL  %-28s negotiated \"%s\", want \"%s\"\n", what, got, want);
        failures++;
    }
}

int
main(int argc, char **argv)
{
    void                      *h;
    const nxt_tls_backend_t   *(*get_backend)(void);
    selftest_fn                selftest;
    const nxt_tls_backend_t   *b;
    char                       got[64];
    int                        rc;

    if (argc < 3) {
        fprintf(stderr, "usage: %s cert.pem key.pem\n", argv[0]);
        return 2;
    }

    h = dlopen(SO_PATH, RTLD_NOW);
    if (h == NULL) {
        fprintf(stderr, "dlopen %s: %s\n", SO_PATH, dlerror());
        return 2;
    }

    get_backend = (const nxt_tls_backend_t *(*)(void)) dlsym(h, "nxt_tls_backend");
    selftest = (selftest_fn) dlsym(h, "nxt_tls_backend_selftest");

    if (get_backend == NULL || selftest == NULL) {
        fprintf(stderr, "missing symbol: %s\n", dlerror());
        return 2;
    }

    b = get_backend();

    if (b->version != NXT_TLS_BACKEND_VERSION) {
        printf("FAIL  interface version %u, want %u\n", b->version,
               NXT_TLS_BACKEND_VERSION);
        return 1;
    }

    printf("PASS  %-28s backend=\"%s\" version=%u\n", "interface", b->name,
           b->version);

    {
        const char  *offer[] = { "h2", "http/1.1" };

        rc = selftest(argv[1], argv[2], offer, 2, got, sizeof(got));
        if (rc != 0) {
            printf("FAIL  handshake h2,http/1.1 did not complete\n");
            return 1;
        }
        check("client offers h2", got, "h2");
    }

    {
        const char  *offer[] = { "http/1.1" };

        rc = selftest(argv[1], argv[2], offer, 1, got, sizeof(got));
        if (rc != 0) {
            printf("FAIL  handshake http/1.1 did not complete\n");
            return 1;
        }
        check("client offers http/1.1", got, "http/1.1");
    }

    rc = selftest(argv[1], argv[2], NULL, 0, got, sizeof(got));
    if (rc != 0) {
        printf("FAIL  handshake without ALPN did not complete\n");
        return 1;
    }
    check("client offers no ALPN", got, "");

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "OK", failures,
           failures == 1 ? "" : "s");

    return failures ? 1 : 0;
}
