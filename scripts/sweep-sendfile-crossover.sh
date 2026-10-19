#!/bin/sh
# Replicated, order-balanced A/B sweep of the plain sendfile crossover.
#
# Usage: sweep.sh TREE_OLD TREE_NEW "SIZE [SIZE...]" CONNS REPS PORT0 [BENCH]
#
# For each size, runs REPS blocks and alternates which side goes first on every
# rep, so neither tree holds a fixed position in the batch.
#
# Why this exists: a single sample per (size, tree) is not enough on a small
# host.  During the kTLS measurement the two trees drifted apart by up to 15%
# between batches on the same 2 vCPU box, which is larger than most of the
# effects being chased.  One-directional A/B runs also misattribute that drift:
# a control that should read 0% came out at +14.3% in one order and -1.7% in
# the other.  Hence replicated cells, alternating order, and a control.
#
# Prints: conns size rep side rps
set -u
OLD=$1; NEW=$2; SIZES=$3; CONNS=$4; REPS=$5; PORT=$6
BENCH=${7:-$(dirname "$0")/bench-static-sendfile.sh}

[ -x "$OLD/build/sbin/unitd" ] || { echo "sweep: no unitd in $OLD" >&2; exit 1; }
[ -x "$NEW/build/sbin/unitd" ] || { echo "sweep: no unitd in $NEW" >&2; exit 1; }
[ -r "$BENCH" ] || { echo "sweep: no bench script at $BENCH" >&2; exit 1; }

for sz in $SIZES; do
    rep=1
    while [ "$rep" -le "$REPS" ]; do
        if [ $((rep % 2)) -eq 1 ]; then order="old new"; else order="new old"; fi

        for side in $order; do
            if [ "$side" = old ]; then tree=$OLD; else tree=$NEW; fi

            out=$(sh "$BENCH" "$tree" "S${sz}" "$sz" "$CONNS" 5s 1 "$PORT" 2>/dev/null | tail -1)
            rps=$(printf '%s\n' "$out" | cut -f4)

            if [ -n "$rps" ] && [ "$rps" != "rps" ]; then
                printf '%s\t%s\t%s\t%s\t%s\n' "$CONNS" "$sz" "$rep" "$side" "$rps"
            fi

            PORT=$((PORT + 1))
            sleep 1
        done

        rep=$((rep + 1))
    done
done