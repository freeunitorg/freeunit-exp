#!/bin/sh
# TLS static-file A/B for the kTLS SSL_sendfile path.
#
# Usage: bench-tls.sh TREE LABEL SIZE KTLS CONNS DUR REPS PORT
#
#   TREE  source tree built with --openssl
#   SIZE  body size in bytes, a multiple of 1024
false, the "ktls" listener option
#   CERT_DIR  where unit.key and unit.crt live (override; the default is a
#             scratch path on the measurement host)|false, the "ktls" listener option
#   DUR   wrk duration, carrying its own unit ("5s")
#
# Serves a share over TLS, so the only difference between two runs of the same
# tree is the offload, and between two trees is the file-buffer path.
# KTLS=false is the control: both trees take the memory path, so the trees must
# come out equal there.
#
# Prints one tab-separated row per cell: label size ktls rep rps on_cpu_ns
#
# Server is pinned to core 0 and wrk to core 1.  On-CPU nanoseconds come from
# /proc/<pid>/task/*/schedstat, which works where there is no hardware PMU; it
# is the same on-CPU source tools/perf-lab/cells.sh uses.
#
# Two things this harness had to get right, both found the hard way:
#
#   * The certificate is uploaded as a PEM blob (key then certificate) to
#     PUT /certificates/<name>.  The JSON object form with "certificate" and
#     "key" is refused with "Invalid certificate."
#   * Alternate which tree runs first.  The two trees drift apart by up to 15%
#     across a batch on this 2 vCPU host, so a one-directional A/B attributes
#     that drift to the tree.  See the ktls=false control in the writeup.
#
# Measured with this script: docs/exp/sendfile-throughput.md.
set -u
TREE=$1; LABEL=$2; SIZE=$3; KTLS=$4; CONNS=$5; DUR=$6; REPS=$7; PORT=$8
W=/tmp/benchtls
# Override on the command line; the default is a scratch dir on the
# measurement host, which is not part of this repository.
CERT=${CERT_DIR:?set CERT_DIR to the directory holding unit.key and unit.crt}
die() { echo "benchtls: $*" >&2; exit 1; }

[ -x "$TREE/build/sbin/unitd" ] || die "no unitd in $TREE"
[ -f "$CERT/unit.crt" ] || die "no certificate in $CERT"

# A previous invocation that did not finish leaves a unitd holding a port and
# the control socket we are about to delete.  Clear both before starting.
pkill -f "unitd --no-daemon --pid $W/pid" 2>/dev/null
sleep 0.3

rm -rf "$W"; mkdir -p "$W/state" "$W/tmp" "$W/modules" "$W/share"
dd if=/dev/zero bs=1024 count=$((SIZE / 1024)) 2>/dev/null | tr '\0' 'x' > "$W/share/f.bin"

UPID=""
cleanup() {
    if [ -n "$UPID" ]; then kill -9 "$UPID" 2>/dev/null; wait "$UPID" 2>/dev/null; fi
}
trap cleanup EXIT INT TERM

cpu_ns() {
    awk '{s += $1} END {print s + 0}' /proc/"$UPID"/task/*/schedstat 2>/dev/null
}

tries=0
while :; do
    printf '{"listeners":{"*:%s":{"pass":"routes","tls":{"certificate":"bundle","ktls":%s}}},' \
        "$PORT" "$KTLS" > "$W/conf.json"
    printf '"routes":[{"action":{"share":"%s$uri"}}]}\n' "$W/share" >> "$W/conf.json"

    taskset -c 0 "$TREE/build/sbin/unitd" --no-daemon --pid "$W/pid" \
        --log "$W/log" --control "unix:$W/c.sock" --statedir "$W/state" \
        --tmpdir "$W/tmp" --modulesdir "$W/modules" >"$W/stderr" 2>&1 &
    UPID=$!

    j=0
    while [ "$j" -lt 150 ]; do
        [ -S "$W/c.sock" ] && break
        sleep 0.1
        j=$((j + 1))
    done
    [ -S "$W/c.sock" ] || die "unitd did not start; see $W/stderr"

    cat "$CERT/unit.key" "$CERT/unit.crt" > "$W/bundle.pem"
    curl -sS --unix-socket "$W/c.sock" -X PUT --data-binary "@$W/bundle.pem" \
        http://localhost/certificates/bundle > "$W/cert.out" 2>"$W/cert.err"

    curl -sS --unix-socket "$W/c.sock" -X PUT --data-binary "@$W/conf.json" \
        http://localhost/config > "$W/put.out" 2>"$W/put.err"

    if grep -q success "$W/put.out"; then break; fi

    cleanup
    UPID=""
    tries=$((tries + 1))
    [ "$tries" -gt 15 ] && die "no free port from $PORT: $(tail -2 "$W/log")"
    PORT=$((PORT + 1))
done

# Warm the page cache and the TLS session.
curl -sk -o /dev/null "https://127.0.0.1:$PORT/f.bin" || die "warmup request failed"

cat > "$W/tls.lua" <<'LUA'
wrk.method  = "GET"
wrk.scheme  = "https"
wrk.headers["Host"] = "localhost"
LUA

rep=1
while [ "$rep" -le "$REPS" ]; do
    c0=$(cpu_ns)
    out=$(OPENSSL_CIPHER=TLS_AES_128_GCM_SHA256 taskset -c 1 wrk -t1 -c"$CONNS" \
        -d"$DUR" --latency --script "$W/tls.lua" \
        "https://127.0.0.1:$PORT/f.bin" 2>&1)
    c1=$(cpu_ns)

    rps=$(printf '%s\n' "$out" | awk '/^Requests\/sec:/ {print $2}')
    if [ -z "$rps" ]; then
        die "no rps; wrk said: $(printf '%s' "$out" | tr '\n' '|')"
    fi

    printf '%s\t%s\t%s\t%s\t%s\n' "$LABEL" "$SIZE" "$KTLS" "$rps" "$((c1 - c0))"
    rep=$((rep + 1))
    sleep 1
done