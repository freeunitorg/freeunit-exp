#!/bin/sh
# FreeUnit deploy hook for acme.sh.
#
# acme.sh runs this after --install-cert, through --reloadcmd.  It concatenates
# the full chain and the private key into one PEM bundle and PUTs it to the
# FreeUnit control socket.  A PUT on a name that already exists replaces the
# bundle in place: no restart and no rename/repoint/delete dance, and new
# handshakes get the new certificate (see docs: certificate replacement).
#
# Usage, in the --install-cert step:
#   acme.sh --install-cert -d example.org \
#       --fullchain-file /etc/freeunit/certs/example.org.pem \
#       --key-file       /etc/freeunit/certs/example.org.key \
#       --reloadcmd      "/usr/local/sbin/acme-sh-freeunit-hook.sh \
#                          example.org /etc/freeunit/certs/example.org.pem \
#                          /etc/freeunit/certs/example.org.key"
#
# The control socket defaults to the FreeUnit Debian package; set UNIT_CONTROL
# for another installation (RPM: /var/run/unit/control.sock, Docker:
# /var/run/control.unit.sock, source: <runstatedir>/control.unit.sock).
set -eu

NAME=${1:?certificate bundle name}
FULLCHAIN=${2:?fullchain file}
KEY=${3:?private key file}
SOCK=${UNIT_CONTROL:-/var/run/control.freeunit.sock}

# curl -f returns non-zero for any HTTP answer >= 400, so a failed upload makes
# acme.sh report the failure instead of leaving a stale certificate in place.
cat "$FULLCHAIN" "$KEY" \
    | curl -fsS --unix-socket "$SOCK" -X PUT --data-binary @- \
          "http://localhost/certificates/$NAME"
