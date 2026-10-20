#!/bin/bash
# Qualify a host as a benchmark stand before it is used for cells.
# Collects the facts that decide which metrics the host may claim, then measures
# its own A/A floor on a fixed CPU workload (the number every later delta is
# judged against on this host).
#
# Usage: bash exp/bench/host-qualify.sh <label>   e.g. old-laptop, fu-build-arm
set -u
L="${1:-host}"
R="$HOME/host-qualify-$L.txt"
: > "$R"
say() { echo "$@" | tee -a "$R"; }

say "== host qualification: $L =="
say "date: $(date -u +%FT%TZ)"

say "-- identity --"
say "hostname: $(hostname)"
say "kernel: $(uname -r) $(uname -m)"
say "distro: $(grep -E '^PRETTY_NAME' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '\"')"
if command -v lscpu >/dev/null 2>&1; then
  lscpu | grep -E "Model name|Socket|Core|Thread|CPU\(s\)|MHz|NUMA" | tee -a "$R"
else
  grep -m1 "model name" /proc/cpuinfo | tee -a "$R"
fi
say "cpu count: $(nproc)"

say "-- power and clocks (this is what silently invalidates a laptop) --"
for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
  [ -f "$g" ] && say "governor: $(cat "$g") ($g)"; break
done
command -v cpupower >/dev/null 2>&1 && cpupower frequency-info 2>/dev/null | grep -E "driver|governor|current policy" | tee -a "$R"
say "on AC: $(cat /sys/class/power_supply/A*/online 2>/dev/null | head -1 || echo unknown)"
say "thermal zones: $(ls /sys/class/thermal/thermal_zone* 2>/dev/null | wc -l)"

say "-- PMU (what the host may claim) --"
if command -v perf >/dev/null 2>&1; then
  if perf stat -e instructions true >/dev/null 2>&1; then
    say "perf: available, instructions countable"
  else
    say "perf: present but instructions NOT countable (no PMU access) -> server_us only"
  fi
else
  say "perf: not installed -> server_us only"
fi

say "-- tools --"
for t in cc gcc oha ab wrk curl git; do
  printf "%-6s %s\n" "$t" "$(command -v $t || echo missing)" | tee -a "$R"
done

say "-- A/A floor on a fixed CPU workload (10 rounds) --"
W=${TMPDIR:-/tmp}/qualify.$$
if command -v cc >/dev/null 2>&1; then
  cat > "$W.c" <<'EOF'
#include <stdio.h>
int main(void) {
    unsigned long long x = 1, i;
    for (i = 0; i < 200000000ULL; i++) { x = x * 6364136223846793005ULL + 1442695040888963407ULL; }
    printf("%llu\n", x & 0xff);
    return 0;
}
EOF
  if cc -O2 -o "$W" "$W.c" 2>/dev/null; then
    for i in $(seq 1 10); do
      if command -v perf >/dev/null 2>&1 && perf stat -e instructions "$W" >/dev/null 2>/tmp/perf.$$ ; then
        grep -E "instructions" /tmp/perf.$$ | awk '{print $1}' | tr -d ',' | tee -a "$R"
      else
        /usr/bin/time -f "%e s" "$W" 2>&1 | tee -a "$R"
      fi
    done
    rm -f "$W" "$W.c" /tmp/perf.$$
  else
    say "compile failed; no floor measured"
  fi
else
  say "no compiler; no floor measured"
fi

say "-- temperature after the run (throttling check) --"
for z in /sys/class/thermal/thermal_zone*/temp; do
  [ -f "$z" ] && say "$(cat "$z") ($z)"
done

say "== END =="
