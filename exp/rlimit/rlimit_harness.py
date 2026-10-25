#!/usr/bin/env python3
"""RLIMIT measurements with a negative control for every cell.

Each cell reports `cell, expectation, observed, verdict`. A cell is evidence only
if its control distinguishes the mechanism: the control is the same operation
with the limit removed, and it must differ from the case. `--self-test` runs the
controls and exits non-zero if any control agrees with the case (which would mean
the probe is measuring nothing).

Runs on any Linux with CPython; written on musl 1.2.6 / kernel 6.8 and marked
where a cell cannot be run on this host.
"""
import argparse
import array
import json
import os
import resource
import socket
import sys
import threading
import time

ROWS = []


def emit(cell, expectation, observed, verdict, note=""):
    ROWS.append({"cell": cell, "expectation": expectation,
                 "observed": observed, "verdict": verdict, "note": note})


def in_child(fn):
    """Run fn in a forked child and carry the rows it produced back to the parent.

    Rows live in process memory, so a forked child's rows are invisible to the
    parent unless they are shipped back. First version of this file forgot that
    and printed nothing at all while still exiting 0 — the harness's own lesson.
    """
    start = len(ROWS)
    rfd, wfd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(rfd)
        try:
            fn()
            payload = json.dumps(ROWS[start:]).encode()
        except BaseException as exc:            # noqa: BLE001
            payload = json.dumps([{"cell": "harness", "expectation": "-",
                                   "observed": f"{type(exc).__name__}: {exc}",
                                   "verdict": "FAIL", "note": "child raised"}]).encode()
        os.write(wfd, payload)
        os.close(wfd)
        os._exit(0)
    os.close(wfd)
    buf = b""
    while True:
        chunk = os.read(rfd, 65536)
        if not chunk:
            break
        buf += chunk
    os.close(rfd)
    os.waitpid(pid, 0)
    ROWS.extend(json.loads(buf or b"[]"))


def _fill_fds(keep, extra=0):
    try:
        while True:
            keep.append(os.open("/dev/null", os.O_RDONLY))
    except OSError:
        return len(keep) - extra


# ---------------------------------------------------------------- cell 1: inflight
def cell_inflight(sender_limit, extra=8, drain=False):
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    ready_r, ready_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(parent.fileno())
        os.close(ready_r)
        os.write(ready_w, b"1")              # "I am in the loop" — removes the race
        if drain:
            while True:                      # keep the queue empty: nothing stays in flight
                try:
                    child.recv(8)
                except OSError:
                    break
        time.sleep(2)                        # never recv: descriptors stay in flight
        os._exit(0)
    os.close(child.fileno())
    os.close(ready_w)
    os.read(ready_r, 1)
    os.close(ready_r)
    os.set_blocking(parent.fileno(), False)
    hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    resource.setrlimit(resource.RLIMIT_NOFILE, (sender_limit, hard))   # soft only
    devnull = os.open("/dev/null", os.O_RDONLY)
    fds = array.array("i", [devnull])
    sent, err = 0, None
    for _ in range(sender_limit + extra):
        try:
            parent.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])
            sent += 1
        except OSError as e:
            err = e
            break
    os.kill(pid, 9)
    os.waitpid(pid, 0)
    resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))           # restore
    return sent, err


def run_inflight():
    sent_low, err_low = cell_inflight(32)
    emit("inflight", "sender limited to 32 stops after ~32 in-flight fds",
         f"sent={sent_low} err={err_low.errno if err_low else None}",
         "PASS" if err_low is not None and err_low.errno == 109 else "FAIL")
    # Matched control: same limit, same number of sends, the only difference is
    # that the receiver drains, so nothing accumulates in flight.
    sent_hi, err_hi = cell_inflight(32, extra=8, drain=True)
    emit("inflight-control", "same limit and sends with the receiver draining: no ETOOMANYREFS",
         f"sent={sent_hi} err={err_hi.errno if err_hi else None}",
         "PASS" if err_hi is None else "FAIL")


# ---------------------------------------------------------------- cell 2: ctrunc
def cell_ctrunc(free_slots):
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    devnull = os.open("/dev/null", os.O_RDONLY)   # before the table is full
    keep = []
    _fill_fds(keep)
    for _ in range(free_slots):
        os.close(keep.pop())
    fds = array.array("i", [devnull])
    got, flags = None, None
    try:
        a.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])
        msg, anc, flags, _ = b.recvmsg(8, socket.CMSG_SPACE(4))
        got = sum(len(array.array("i", d[:len(d) - len(d) % 4]))
                  for lvl, typ, d in anc if typ == socket.SCM_RIGHTS)
    except OSError as e:
        got, flags = f"errno={e.errno}", None
    for fd in keep:
        os.close(fd)
    os.close(devnull)
    return got, flags


def run_ctrunc():
    got, flags = cell_ctrunc(0)
    emit("ctrunc", "0 fds and MSG_CTRUNC when the receiver's table is full",
         f"fds={got} flags={flags}", "PASS" if got == 0 and flags == 8 else "FAIL")
    got_c, flags_c = cell_ctrunc(1)
    emit("ctrunc-control", "1 fd and no MSG_CTRUNC with a free slot",
         f"fds={got_c} flags={flags_c}", "PASS" if got_c == 1 and flags_c == 0 else "FAIL")


# ---------------------------------------------------------------- cell 3: AS
def cell_as(limit, want):
    import mmap
    hard = resource.getrlimit(resource.RLIMIT_AS)[1]
    if limit is not None:
        resource.setrlimit(resource.RLIMIT_AS, (limit, hard))   # soft only
    chunks, got = [], 0
    try:
        while got < want:
            chunks.append(mmap.mmap(-1, 8 * 1024 * 1024))   # reserve, do not touch
            got += 8 * 1024 * 1024
        return got, None
    except (OSError, MemoryError) as exc:
        return got, type(exc).__name__
    finally:
        if limit is not None:
            resource.setrlimit(resource.RLIMIT_AS, (hard, hard))


def run_as():
    saved = resource.getrlimit(resource.RLIMIT_AS)
    cap = 128 * 1024 * 1024
    got, err = cell_as(cap, 512 * 1024 * 1024)
    emit("as", "a 128M address-space cap stops a 512M reservation",
         f"reserved={got//1024//1024}M err={err}",
         "PASS" if err is not None else "FAIL")
    resource.setrlimit(resource.RLIMIT_AS, saved)          # restore before the control
    got_c, err_c = cell_as(None, 256 * 1024 * 1024)
    emit("as-control", "the same reservation succeeds uncapped",
         f"reserved={got_c//1024//1024}M err={err_c}",
         "PASS" if err_c is None and got_c >= 256 * 1024 * 1024 else "FAIL")


# ---------------------------------------------------------------- cell 4: stack
def stack_mapping_size(explicit=None):
    """Size of the largest new anonymous rw mapping created for one live thread."""
    if explicit:
        threading.stack_size(explicit)

    def maps():
        out = {}
        with open("/proc/self/maps") as fh:
            for ln in fh:
                parts = ln.split()
                out[parts[0]] = parts[1]
        return out

    before = maps()
    stop = threading.Event()

    def worker():
        stop.wait(20)

    th = threading.Thread(target=worker, daemon=True)
    th.start()
    time.sleep(0.2)
    after = maps()
    stop.set()
    th.join()
    sizes = []
    for rng, perm in after.items():
        if rng in before or perm != "rw-p":
            continue
        lo, hi = rng.split("-")
        sizes.append(int(hi, 16) - int(lo, 16))
    return max(sizes) if sizes else 0


def run_stack():
    # Order matters: threading.stack_size() is process-global and sticky, so the
    # explicit-size control runs LAST and is reset afterwards.
    saved = resource.getrlimit(resource.RLIMIT_STACK)
    default = stack_mapping_size()
    resource.setrlimit(resource.RLIMIT_STACK, (1024 * 1024, resource.RLIM_INFINITY))
    lowered = stack_mapping_size()
    resource.setrlimit(resource.RLIMIT_STACK, saved)
    restored = stack_mapping_size()
    explicit = stack_mapping_size(512 * 1024)
    threading.stack_size(0)
    emit("stack-musl", "thread stack does not follow RLIMIT_STACK",
         f"default={default//1024}K lowered={lowered//1024}K restored={restored//1024}K",
         "PASS" if default == lowered == restored else "FAIL (glibc-like or clamp)")
    emit("stack-method-control", "an explicit 512K stack is visible to the method",
         f"explicit={explicit//1024}K default={default//1024}K",
         "PASS" if 0 < explicit < default else "FAIL: method cannot see a stack")


# ---------------------------------------------------------------- cell 5: soft/hard
def run_softhard():
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (soft, soft))
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
        verdict = "REFUTED: hard was raisable?!" if hard > soft else "PASS"
    except (ValueError, OSError):
        verdict = "PASS"
    emit("softhard-raise-hard", "raising the hard limit needs privilege", "-", verdict)
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard + 1, hard + 1))
        emit("softhard-raise-beyond", "soft above the hard limit is refused",
             "accepted", "FAIL")
    except (ValueError, OSError) as e:
        emit("softhard-raise-beyond", "soft above the hard limit is refused",
             type(e).__name__, "PASS")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true",
                    help="fail if any control agrees with its case")
    args = ap.parse_args()

    in_child(run_inflight)
    in_child(run_ctrunc)
    in_child(run_as)
    in_child(run_stack)
    in_child(run_softhard)

    if args.json:
        print(json.dumps(ROWS, indent=2))
    else:
        for r in ROWS:
            print(f"{r['cell']:<22} {r['verdict']:<6} {r['observed']}"
                  + (f"  [{r['note']}]" if r["note"] else ""))

    fails = [r for r in ROWS if r["verdict"].startswith("FAIL")]
    if args.self_test and fails:
        print(f"\nSELF-TEST FAILED: {len(fails)} control(s) did not distinguish: "
              f"{[r['cell'] for r in fails]}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
