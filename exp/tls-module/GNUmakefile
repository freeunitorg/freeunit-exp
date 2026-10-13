# Prototype: the TLS backend interface as a loadable module.
#
#   make        build the module and the smoke test
#   make test   build, make a throwaway certificate, run the smoke test
#   make clean
#
# The prototype is outside the server build. Nothing here is wired into unitd.

CC             ?= cc
CFLAGS         ?= -O1 -g -Wall -Wextra -fPIC
OPENSSL_CFLAGS ?= $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS   ?= $(shell pkg-config --libs openssl 2>/dev/null)

SO      = libnxt_tls_openssl.so
SMOKE   = smoke

.PHONY: all test clean

all: $(SO) $(SMOKE)

$(SO): tls_backend_openssl.c nxt_tls_backend.h
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -shared -o $@ tls_backend_openssl.c $(OPENSSL_LIBS)

$(SMOKE): smoke.c nxt_tls_backend.h
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o $@ smoke.c -ldl $(OPENSSL_LIBS)

cert.pem key.pem:
	openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
		-keyout key.pem -out cert.pem 2>/dev/null

test: all cert.pem key.pem
	./$(SMOKE) cert.pem key.pem

clean:
	rm -f $(SO) $(SMOKE) cert.pem key.pem
