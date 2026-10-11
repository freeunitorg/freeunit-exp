#!/usr/bin/env python3
"""kTLS key path: hand a real OpenSSL TLS 1.3 session to the kernel. Step 2's risk, measured.

The socket options were step 1 and they are solved. The risk that decides whether a kTLS data
path can exist at all is different: **the key material and the record sequence**. Kernel TLS
does not negotiate anything — it is handed the AES key, the static IV and the record sequence,
after which the kernel produces records that the peer's OpenSSL must accept as valid.

This probe proves that end to end, in the smallest artifact that can:

  1. run a real TLS 1.3 handshake (Python `ssl` over the system OpenSSL) and capture the
     client's traffic secret from the OpenSSL keylog (`CLIENT_TRAFFIC_SECRET_0`);
  2. derive the record key and static IV with HKDF-Expand-Label (RFC 8446 §7.1, §7.3) — the
     same derivation a C implementation must perform;
  3. install `TLS_TX` on the client socket with that key/IV and a candidate record sequence,
     then write plaintext through the **raw fd** (the kernel encrypts it);
  4. require the **OpenSSL server** to decrypt what the kernel produced. If it does, the kernel
     turned real handshake keys into a valid TLS record, and nothing of FreeUnit's plumbing is
     involved in the result.

The record sequence is treated as a parameter, not as a guess: TLS 1.3 continues the sequence
through the handshake records, so the first application-data record is not sequence 0. Each
candidate is tried on a FRESH connection, because a wrong nonce makes the server drop the record
with a bad-MAC alert and that kills the connection. The value the server accepted is exactly the
number a C implementation has to track — which is why it is measured rather than assumed.

Only AEAD-AES suites are installed: the kernel's ChaCha20-Poly1305 crypto_info has a zero-length
salt, a different layout, and no reason to be in the first cut.

Usage
    python3 ktls_keys_probe.py [--max-seq 5] [--cert PATH --key PATH] [--json]

Exit status
    0  spike ran — read `verdict` and `accepted_seq`
    2  kTLS not available on this kernel
    3  no TLS 1.3 session or no certificate (nothing to offload)
"""
import argparse
import hashlib
import hmac
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

SOL_TLS = 282
TLS_TX = 1
SOL_TCP = 6
TCP_ULP = 31
TLS_1_3_VERSION = 0x0304

# name -> (kernel cipher_type, hash, key length)
SUITES = {
    "TLS_AES_128_GCM_SHA256": (51, hashlib.sha256, 16),
    "TLS_AES_256_GCM_SHA384": (52, hashlib.sha384, 32),
}

SNAKEOIL = [("/etc/ssl/certs/ssl-cert-snakeoil.pem", "/etc/ssl/private/ssl-cert-snakeoil.key"),
            ("/etc/ssl/certs/ssl-cert-snakeoil.crt", "/etc/ssl/private/ssl-cert-snakeoil.key")]


def hkdf_expand(prk, info, length, hashmod):
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashmod).digest()
        okm += t
        i += 1
    return okm[:length]


def hkdf_expand_label(secret, label, context, length, hashmod):
    """RFC 8446 §7.1 HkdfLabel — the exact framing the TLS 1.3 key schedule uses."""
    full = b"tls13 " + label
    info = (struct.pack("!H", length) + bytes([len(full)]) + full
            + bytes([len(context)]) + context)
    return hkdf_expand(secret, info, length, hashmod)


def read_keylog(path, kind="CLIENT_TRAFFIC_SECRET_0"):
    try:
        with open(path) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[0] == kind:
                    return bytes.fromhex(parts[2])
    except OSError:
        pass
    return None


def make_cert(dirpath):
    """Self-signed key pair for the spike: openssl CLI first, `cryptography` as fallback.

    A probe that cannot run without an external binary is a probe that reports "cannot run"
    where it should be measuring, so both routes exist.
    """
    cert = os.path.join(dirpath, "spike.crt")
    key = os.path.join(dirpath, "spike.key")
    try:
        r = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
             "-out", cert, "-days", "1", "-subj", "/CN=localhost"],
            capture_output=True, text=True)
        if r.returncode == 0:
            return cert, key, None
        cli_err = (r.stderr or r.stdout or "openssl req failed").strip()[:120]
    except OSError as e:
        cli_err = f"openssl CLI unavailable: {e}"

    try:
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        crt = (x509.CertificateBuilder()
               .subject_name(name).issuer_name(name)
               .public_key(priv.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(minutes=5))
               .not_valid_after(now + datetime.timedelta(days=1))
               .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                              critical=False)
               .sign(priv, hashes.SHA256()))
        with open(key, "wb") as f:
            f.write(priv.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.TraditionalOpenSSL,
                                       serialization.NoEncryption()))
        with open(cert, "wb") as f:
            f.write(crt.public_bytes(serialization.Encoding.PEM))
        return cert, key, None
    except Exception as e:                                     # noqa: BLE001
        return None, None, f"{cli_err}; cryptography fallback failed: {e}"


def pick_cert(args):
    if args.cert and args.key:
        return args.cert, args.key, None
    for c, k in SNAKEOIL:
        if os.path.exists(c) and os.path.exists(k):
            return c, k, None
    return make_cert(args.tmpdir)


def handshake_tls13(cert, key, keylog_path):
    """Real TLS 1.3 handshake; returns (client, server, suite_name) or raises."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    holder = {}

    def accept_side():
        s, _ = srv.accept()
        s.settimeout(15)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        holder["server"] = ctx.wrap_socket(s, server_side=True)

    t = threading.Thread(target=accept_side, daemon=True)
    t.start()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.keylog_filename = keylog_path
    raw = socket.create_connection(srv.getsockname(), timeout=15)
    client = ctx.wrap_socket(raw, server_hostname=None)
    t.join(timeout=15)
    srv.close()
    return client, holder.get("server"), client.cipher()[0]


def install_tx(sock, cipher_type, key, iv, seq):
    """TLS_TX with an explicit record sequence; returns (ok, detail)."""
    info = struct.pack("H H 8s 32s 4s 8s", TLS_1_3_VERSION, cipher_type,
                       iv[4:12], key.ljust(32, b"\x00"), iv[0:4], struct.pack("Q", seq))
    # key length varies per suite; rebuild the struct for the 16-byte case
    if len(key) == 16:
        info = struct.pack("H H 8s 16s 4s 8s", TLS_1_3_VERSION, cipher_type,
                           iv[4:12], key, iv[0:4], struct.pack("Q", seq))
    try:
        sock.setsockopt(socket.IPPROTO_TCP, TCP_ULP, b"tls\x00")
    except OSError as e:
        return False, f"TCP_ULP=tls failed: {e.errno} {e.strerror}"
    try:
        sock.setsockopt(SOL_TLS, TLS_TX, info)
    except OSError as e:
        return False, f"TLS_TX failed: {e.errno} {e.strerror}"
    return True, "TLS_TX accepted"


def try_seq(cert, key, seq, payload, tmpdir):
    """One fresh TLS 1.3 connection, offload at `seq`, and see if the server accepts it."""
    keylog = os.path.join(tmpdir, f"keylog-{seq}.txt")
    if os.path.exists(keylog):
        os.unlink(keylog)
    try:
        client, server, suite = handshake_tls13(cert, key, keylog)
    except (ssl.SSLError, OSError) as e:
        return {"seq": seq, "ok": False, "detail": f"handshake failed: {e}"}
    if suite not in SUITES:
        return {"seq": seq, "ok": False, "detail": f"suite {suite} not installable by this spike",
                "suite": suite}
    if server is None:
        return {"seq": seq, "ok": False, "detail": "server side of the handshake never completed",
                "suite": suite}
    cipher_type, hashmod, keylen = SUITES[suite]
    secret = read_keylog(keylog)
    if secret is None:
        return {"seq": seq, "ok": False, "detail": "no CLIENT_TRAFFIC_SECRET_0 in the keylog",
                "suite": suite}
    rkey = hkdf_expand_label(secret, b"key", b"", keylen, hashmod)
    riv = hkdf_expand_label(secret, b"iv", b"", 12, hashmod)

    fd = os.dup(client.fileno())
    raw = socket.socket(fileno=fd)
    ok, detail = install_tx(raw, cipher_type, rkey, riv, seq)
    if not ok:
        raw.close(); client.close(); server.close()
        return {"seq": seq, "ok": False, "detail": detail, "suite": suite}
    try:
        raw.sendall(payload)
        server.settimeout(5)
        got = b""
        while len(got) < len(payload):
            chunk = server.recv(65536)
            if not chunk:
                break
            got += chunk
    except (ssl.SSLError, OSError) as e:
        got = b""
        detail = f"server rejected: {e}"
    else:
        detail = "server decrypted the kernel's record"
    finally:
        try:
            raw.close()
        except OSError:
            pass
        try:
            client.close()
        except OSError:
            pass
        try:
            server.close()
        except OSError:
            pass
    good = got == payload
    return {"seq": seq, "ok": good, "suite": suite, "detail": detail,
            "received": got[:32].decode("latin-1") if got else ""}


def burst_test(cert, key, seq, total, tmpdir, chunk=7168):
    """Send `total` bytes of random plaintext through one kTLS socket and count them back.

    The single-record check proves the key material; this proves the kernel's record sequence
    keeps incrementing (multiple records, several per write) and that the peer decrypts all of
    them — the case that actually matters for a response body.
    """
    keylog = os.path.join(tmpdir, "keylog-burst.txt")
    if os.path.exists(keylog):
        os.unlink(keylog)
    try:
        client, server, suite = handshake_tls13(cert, key, keylog)
    except (ssl.SSLError, OSError) as e:
        return {"ok": False, "detail": f"handshake failed: {e}"}
    if suite not in SUITES or server is None:
        return {"ok": False, "detail": f"suite {suite} not installable"}
    cipher_type, hashmod, keylen = SUITES[suite]
    secret = read_keylog(keylog)
    if secret is None:
        return {"ok": False, "detail": "no CLIENT_TRAFFIC_SECRET_0 in the keylog"}
    rkey = hkdf_expand_label(secret, b"key", b"", keylen, hashmod)
    riv = hkdf_expand_label(secret, b"iv", b"", 12, hashmod)

    fd = os.dup(client.fileno())
    raw = socket.socket(fileno=fd)
    ok, detail = install_tx(raw, cipher_type, rkey, riv, seq)
    if not ok:
        raw.close(); client.close(); server.close()
        return {"ok": False, "detail": detail}
    payload = os.urandom(total)
    got = b""
    t0 = time.perf_counter()
    try:
        with memoryview(payload) as mv:
            for off in range(0, total, chunk):
                raw.sendall(mv[off:off + chunk])
        server.settimeout(15)
        while len(got) < total:
            piece = server.recv(262144)
            if not piece:
                break
            got += piece
    except (ssl.SSLError, OSError) as e:
        detail = f"server rejected mid-stream: {e}"
    else:
        detail = "all records decrypted in order"
    finally:
        wall = time.perf_counter() - t0
        for s in (raw, client, server):
            try:
                s.close()
            except OSError:
                pass
    return {"ok": got == payload, "detail": detail, "bytes": total, "received": len(got),
            "chunk": chunk, "wall_s": round(wall, 4),
            "mib_per_s": round(total / (1 << 20) / wall, 1) if wall else None,
            "suite": suite, "seq": seq}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-seq", type=int, default=5)
    ap.add_argument("--burst-bytes", type=int, default=1 << 16,
                    help="multi-record transfer size once a sequence is accepted")
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--tmpdir", default=None)
    args = ap.parse_args()

    report = {"kernel": os.uname().release, "openssl": ssl.OPENSSL_VERSION,
              "attempts": [], "accepted_seq": None}

    td = tempfile.TemporaryDirectory() if args.tmpdir is None else None
    tmpdir = args.tmpdir or td.name
    if getattr(args, "cert", None) is None:
        args.tmpdir = tmpdir

    cert, key, err = pick_cert(args)
    if cert is None:
        report["verdict"] = f"cannot run: {err}"
        print(json.dumps(report, indent=1) if args.json else report["verdict"])
        return 3

    payload = b"ktls-keys-probe-payload"
    for seq in range(0, args.max_seq + 1):
        res = try_seq(cert, key, seq, payload, tmpdir)
        report["attempts"].append(res)
        if res.get("ok"):
            report["accepted_seq"] = seq
            report["suite"] = res.get("suite")
            break

    if report["accepted_seq"] is None:
        detail = [a.get("detail") for a in report["attempts"]]
        if all("no CLIENT_TRAFFIC_SECRET_0" in (d or "") for d in detail):
            report["verdict"] = "no TLS 1.3 session could be offloaded (no keylog secret)"
            rc = 3
        elif any("TCP_ULP" in (d or "") for d in detail):
            report["verdict"] = "kTLS not available on this kernel"
            rc = 2
        else:
            report["verdict"] = ("no candidate record sequence was accepted — the key "
                                 "derivation or the nonce mapping needs revision")
            rc = 1 if all(not a.get("ok") for a in report["attempts"]) else 0
    else:
        report["burst"] = burst_test(cert, key, report["accepted_seq"], args.burst_bytes,
                                     tmpdir)
        report["verdict"] = (f"kernel-produced TLS record accepted by OpenSSL at record "
                             f"sequence {report['accepted_seq']} ({report.get('suite')})")
        if not report["burst"].get("ok"):
            report["verdict"] += "; multi-record burst FAILED"
            rc = 1
        else:
            rc = 0

    if args.json:
        print(json.dumps(report, indent=1))
    else:
        print(f"kernel {report['kernel']}, {report['openssl']}")
        for a in report["attempts"]:
            print(f"  seq={a['seq']}: ok={a['ok']} {a['detail']}")
        if report.get("burst"):
            b = report["burst"]
            print(f"  burst: {b.get('bytes')} B in {b.get('chunk')} B writes -> "
                  f"received {b.get('received')} B, ok={b.get('ok')} "
                  f"{b.get('mib_per_s')} MiB/s ({b.get('detail')})")
        print(f"verdict: {report['verdict']}")
    if td is not None:
        td.cleanup()
    return rc


if __name__ == "__main__":
    sys.exit(main())
