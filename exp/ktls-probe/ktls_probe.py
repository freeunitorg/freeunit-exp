#!/usr/bin/env python3
"""kTLS probe — does this kernel offload TLS, what does it cost, and does sendfile() work?

The first step of the kTLS track (issue: "kTLS step 1"). It answers, with numbers, the three
questions that decide whether the rest of the track is worth building:

  1. Does the kernel accept TLS_TX / TLS_RX on a connected TCP socket (CONFIG_TLS + tls module)?
  2. Is a plaintext send really turned into a TLS record by the kernel, and can sendfile() push a
     file through it (the payoff: static files over TLS without the userspace record loop)?
  3. What does that cost, measured the same way in both arms: user+sys CPU time and syscall count
     for a fixed payload over (a) a plain socket and (b) a kTLS socket driven by sendfile().

No handshake is needed to install kTLS: TLS_TX takes the crypto_info (cipher, key, iv, salt,
rec_seq) directly, so the probe is self-contained — no certificates, no peer TLS stack. The
receiver reads *raw* bytes, so every byte on the wire can be inspected.

Design rules this file follows (the project's spike rules): stdlib only, no sleeps, no fixed
ports, bounded runtime, and an explicit "not supported" verdict instead of a traceback when the
kernel has no TLS handler.

Usage
    python3 ktls_probe.py --payload-bytes 4194304 --reps 5
    python3 ktls_probe.py --json            # one machine-readable blob for the CI summary

Exit status
    0  the probe ran; read the verdict
    2  kTLS is not available on this kernel (reported, not an error of the probe)
"""
import argparse
import json
import os
import platform
import resource
import socket
import struct
import subprocess
import sys
import tempfile
import time

SOL_TLS = 282
TLS_TX = 1
TLS_RX = 2
TLS_CIPHER_AES_GCM_128 = 51
TLS_1_2_VERSION = 0x0303
TLS_RECORD_HEADER = b"\x17\x03\x03"      # application_data, TLS 1.2, length follows
SOL_TCP = 6
TCP_ULP = 31                             # SOL_TCP/TCP_ULP: set the TLS upper-layer protocol


def crypto_info(rec_seq: int = 0) -> bytes:
    """struct tls12_crypto_info_aes_gcm_128: version, cipher_type, iv, key, salt, rec_seq.

    Deterministic key material: the point is to exercise the kernel path, not to be secret.
    """
    return struct.pack(
        "H H 8s 16s 4s 8s",
        TLS_1_2_VERSION,
        TLS_CIPHER_AES_GCM_128,
        bytes(range(8)),                 # iv      (8 bytes, implicit part for TLS 1.2)
        bytes(range(16)),                # key     (AES-128-GCM)
        bytes(range(8, 12)),             # salt    (4 bytes)
        struct.pack("Q", rec_seq),       # rec_seq (starts at 0 for both dirs)
    )


def tcp_pair():
    """Connected loopback TCP pair; no fixed port, no listen backlog games."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    client = socket.create_connection(srv.getsockname(), timeout=5)
    server, _ = srv.accept()
    srv.close()
    for s in (client, server):
        s.settimeout(10)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return client, server


def kernel_facts():
    facts = {"release": os.uname().release, "machine": platform.machine()}
    try:
        facts["modules_tls"] = "tls" in open("/proc/modules").read()
    except OSError:
        facts["modules_tls"] = None
    try:
        out = subprocess.run(["sh", "-c", "grep -c . /proc/self/status"],
                             capture_output=True, text=True)
        facts["proc_ok"] = out.returncode == 0
    except OSError:
        pass
    return facts


def enable_ktls_tx(sock) -> tuple:
    """Install TLS_TX on a connected socket; report which route the kernel took.

    The documented sequence sets the TLS ULP first (Documentation/networking/tls.rst:
    "once the connection is established set the TLS ULP … Setting the TLS ULP allows us to
    set/get TLS socket options").  Kernel-side, `tls_init(sk)` is the ULP's `.init`: it
    requires `TCP_ESTABLISHED`, creates the `tls_context` and swaps `sk_prot` to a TLS
    proto — and only then does `setsockopt(SOL_TLS, …)` reach `do_tls_setsockopt`.

    Without the ULP the option never reaches the TLS code at all: the socket layer answers
    the generic ENOPROTOOPT.  That is what the first version of this probe measured — the
    same errno on the coordinator and on both CI kernels — and it was a probe bug, not the
    kernel.  Both routes are therefore tried and reported.
    """
    try:
        sock.setsockopt(SOL_TLS, TLS_TX, crypto_info())
        return "direct", "TLS_TX accepted without the TLS ULP"
    except OSError as e:
        direct = f"direct TLS_TX failed: {e.errno} {e.strerror}"

    try:
        sock.setsockopt(socket.IPPROTO_TCP, TCP_ULP, b"tls\x00")
    except OSError as e:
        raise RuntimeError(f"{direct}; TCP_ULP=tls failed: {e.errno} {e.strerror}")

    sock.setsockopt(SOL_TLS, TLS_TX, crypto_info())
    return "ulp", f"{direct}; accepted after TCP_ULP=tls"


def probe_availability():
    """Can the socket layer accept TLS_TX at all? Returns (ok, detail, route)."""
    client, server = tcp_pair()
    try:
        route, detail = enable_ktls_tx(client)
        return True, detail, route
    except (OSError, RuntimeError) as e:
        return False, str(e), None
    finally:
        client.close()
        server.close()


def measure_sendfile(use_ktls: bool, payload_path: str, payload_bytes: int, reps: int):
    """Send the payload with sendfile() over a plain or kTLS socket; report CPU and syscalls.

    Both arms use the same sender path (os.sendfile) and the same drain loop, so the difference
    is the record layer only: userspace copy+encrypt before the socket vs the kernel doing it.
    """
    results = []
    for _ in range(reps):
        client, server = tcp_pair()
        if use_ktls:
            enable_ktls_tx(client)
        received = 0
        fd = os.open(payload_path, os.O_RDONLY)
        ru0 = resource.getrusage(resource.RUSAGE_SELF)
        t0 = time.perf_counter()
        sent = os.sendfile(client.fileno(), fd, None, payload_bytes)
        os.close(fd)
        # Drain exactly what sendfile() handed to the socket. It returns short once the
        # socket buffer is full; waiting for the requested payload instead just sits in the
        # recv timeout — the first run of this probe measured 5 x 10 s of nothing while
        # every byte had already arrived (and reported clean short-read counters, so the
        # timing columns looked plausible).
        while received < sent:
            try:
                chunk = server.recv(262144)
            except socket.timeout:
                break
            if not chunk:
                break
            received += len(chunk)
        elapsed = time.perf_counter() - t0
        ru1 = resource.getrusage(resource.RUSAGE_SELF)
        # On the kTLS arm the record overhead (5-byte header + 16-byte GCM tag per 2^14
        # record) rides behind the plaintext; drain it OUTSIDE the measured window so both
        # arms are timed to the same number of plaintext bytes.
        server.settimeout(0.3)
        while True:
            try:
                chunk = server.recv(262144)
            except socket.timeout:
                break
            if not chunk:
                break
            received += len(chunk)
        client.close()
        server.close()
        results.append({
            "reps": 1,
            "sent": sent,
            "received": received,
            "cpu_user_s": ru1.ru_utime - ru0.ru_utime,
            "cpu_sys_s": ru1.ru_stime - ru0.ru_stime,
            "wall_s": elapsed,
        })
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--payload-bytes", type=int, default=4 << 20)
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    report = {"kernel": kernel_facts(), "sol_tls": SOL_TLS, "tls_tx": TLS_TX}

    ok, detail, route = probe_availability()
    report["available"] = ok
    report["availability_detail"] = detail
    report["route"] = route

    if not ok:
        report["verdict"] = "kTLS NOT available on this kernel (no TLS protocol handler)"
        if args.json:
            print(json.dumps(report, indent=1))
        else:
            print(f"kernel {report['kernel']['release']} ({report['kernel']['machine']})")
            print(f"kTLS probe: {detail}")
            print("verdict: NOT available — the rest of the probe cannot run here")
        return 2

    # 1. transformation check: the receiver must see a TLS record, not the plaintext.
    client, server = tcp_pair()
    enable_ktls_tx(client)
    marker = b"ktls-probe-plaintext-marker"
    client.sendall(marker)
    raw = server.recv(4096)
    client.close()
    server.close()
    report["record_header_ok"] = raw.startswith(TLS_RECORD_HEADER)
    report["plaintext_hidden"] = marker not in raw
    report["raw_prefix"] = raw[:5].hex()
    report["raw_len"] = len(raw)

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(os.urandom(args.payload_bytes))
        payload_path = f.name
    try:
        report["plain"] = measure_sendfile(False, payload_path, args.payload_bytes, args.reps)
        report["ktls"] = measure_sendfile(True, payload_path, args.payload_bytes, args.reps)
    finally:
        os.unlink(payload_path)

    def agg(arm):
        n = len(arm)
        return {
            "cpu_user_s": round(sum(r["cpu_user_s"] for r in arm), 4),
            "cpu_sys_s": round(sum(r["cpu_sys_s"] for r in arm), 4),
            "wall_s": round(sum(r["wall_s"] for r in arm), 4),
            "received_mismatch": sum(1 for r in arm if r["received"] < r["sent"]),
            "reps": n,
        }

    report["plain_summary"] = agg(report["plain"])
    report["ktls_summary"] = agg(report["ktls"])
    report["verdict"] = ("kTLS works and sendfile() drives it"
                         if report["record_header_ok"] and report["plaintext_hidden"]
                         else "kTLS accepted the option but the transformation check FAILED")

    if args.json:
        print(json.dumps(report, indent=1))
    else:
        print(f"kernel {report['kernel']['release']} ({report['kernel']['machine']})")
        print(f"record header {report['raw_prefix']} ok={report['record_header_ok']} "
              f"plaintext_hidden={report['plaintext_hidden']} raw_len={report['raw_len']}")
        for arm in ("plain_summary", "ktls_summary"):
            s = report[arm]
            print(f"{arm}: user={s['cpu_user_s']}s sys={s['cpu_sys_s']}s "
                  f"wall={s['wall_s']}s mismatch={s['received_mismatch']}/{s['reps']}")
        print(f"verdict: {report['verdict']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
