#!/bin/sh
# Static-file A/B for the sendfile path.
#
# Usage: bench-static-sendfile.sh TREE LABEL SIZE CONNS DUR REPS PORT
#
#   TREE  a built source tree; its build/sbin/unitd is the server
#   SIZE  body size in bytes, a multiple of 1024
#   DUR   wrk duration, carrying its own unit ("5s")
#   REPS  cells to run; each prints one row, then sleeps 1 s
#   PORT  first port to try; moves up on EADDRINUSE
#
# Prints one tab-separated row per cell: label size rep rps on_cpu_ns
#
# Server is pinned to core 0 and wrk to core 1: a 2 vCPU host has no SMT
# siblings to spare, and an unpinned server competes with the load generator.
# On-CPU nanoseconds come from /proc/<pid>/task/*/schedstat summed over unitd
# and every descendant, which works where there is no hardware PMU (perf stat
# -e cycles reports "No supported events found").  It is the same on-CPU
# source tools/perf-lab/cells.sh uses.
#
# Measured with this script: see docs/exp/sendfile-throughput.md.
set -u
TREE=$1; LABEL=$2; SIZE=$3; CONNS=$4; DUR=$5; REPS=$6; PORT=$7
W=/tmp/bench
die() { echo "bench: $*" >&2; exit 1; }

[ -x "$TREE/build/sbin/unitd" ] || die "no unitd in $TREE"

# a fresh work dir per run, so a leftover process cannot hold the port
rm -rf "$W"; mkdir -p "$W/state" "$W/tmp" "$W/modules" "$W/share"

# A body of SIZE bytes that does not compress.
dd if=/dev/zero bs=1024 count=$((SIZE / 1024)) 2>/dev/null | tr '\0' 'x' > "$W/share/f.bin"

UPID=""
cleanup() {
    if [ -n "$UPID" ]; then kill -9 "$UPID" 2>/dev/null; wait "$UPID" 2>/dev/null; fi
}
trap cleanup EXIT INT TERM

cpu_ns() {
    awk '{s += $1} END {print s + 0}' /proc/"$UPID"/task/*/schedstat 2>/dev/null
}

# Apply the config, moving to the next port on EADDRINUSE.  The bind failure is
# reported in the log, not in the response, so success is taken from the reply.
tries=0
while :; do
    # $uri is a literal here: the format string is single-quoted.
    printf '{"listeners":{"*:%s":{"pass":"routes"}},"routes":[{"action":{"share":"%s$uri"}}]}\n' \
        "$PORT" "$W/share" > "$W/conf.json"

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

    curl -sS --unix-socket "$W/c.sock" -X PUT --data-binary "@$W/conf.json" \
        http://localhost/config > "$W/put.out" 2>"$W/put.err"

    if grep -q success "$W/put.out"; then
        break
    fi

    cleanup
    UPID=""
    tries=$((tries + 1))
    [ "$tries" -gt 15 ] && die "no free port from $PORT: $(tail -2 "$W/log")"
    PORT=$((PORT + 1))
done

# Warm the page cache for the body, so the first cell does not pay for it.
curl -sS -o /dev/null "http://127.0.0.1:$PORT/f.bin" || die "warmup request failed"

rep=1
while [ "$rep" -le "$REPS" ]; do
    c0=$(cpu_ns)
    out=$(taskset -c 1 wrk -t1 -c"$CONNS" -d"$DUR" --latency \
        "http://127.0.0.1:$PORT/f.bin" 2>&1)
    c1=$(cpu_ns)

    rps=$(printf '%s\n' "$out" | awk '/^Requests\/sec:/ {print $2}')
    [ -n "$rps" ] || die "no rps; wrk said: $(printf '%s' "$out" | tr '\n' '|')"

    printf '%s\t%s\t%s\t%s\t%s\n' "$LABEL" "$SIZE" "$rep" "$rps" "$((c1 - c0))"
    rep=$((rep + 1))
    sleep 1
done