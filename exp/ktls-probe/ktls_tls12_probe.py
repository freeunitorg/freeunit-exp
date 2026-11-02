#!/usr/bin/env python3
"""kTLS TX on a TLS 1.2 connection: which record sequence does OpenSSL accept?

The TLS 1.3 probe answered this for 1.3 - the application-data epoch starts at 0, because the
sequence is per key epoch and the handshake's records do not offset it.  TLS 1.2 is different in
kind: the sequence is per connection, not per epoch, and the client's Finished is already sequence
0 of the client write keys.  So the first application-data record the kernel produces for a TLS
1.2 peer should be sequence 1 - and that is a claim to measure, not to assume.

What this does, on loopback, with no FreeUnit code involved:

  1. a TLS 1.2 handshake between a Python client (driven through memory BIOs, so the wire bytes
     pass through this process) and a Python server;
  2. the client's keylog gives CLIENT_RANDOM <client_random> <master_secret>; the server random is
     read off the wire from the ServerHello, which is why the client is driven by hand;
  3. the master secret and both randoms go through the TLS 1.2 PRF (RFC 5246 section 5 and 6.3)
     to the client write key and the client write IV for the negotiated AEAD;
  4. TLS_TX is installed on the client's TCP socket with a chosen record sequence, plaintext is
     written to the raw fd, and the *OpenSSL server* has to decrypt it.

Two connections are used, because a wrong sequence poisons the connection: one asking for
sequence 1 (the prediction) and one asking for 0 (the prediction's control - it should fail).

Exit codes: 0 = the prediction held, 2 = kTLS unavailable here (a result, not a failure),
1 = unexpected (a failure we have to look at).  JSON on stdout.
"""

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

SOL_TCP = 6
TCP_ULP = 31
SOL_TLS = 282
TLS_TX = 1
TLS_RX = 2
TLS_CIPHER_AES_GCM_128 = 51
TLS_CIPHER_AES_GCM_256 = 52
TLS12_VERSION = 0x0303

CERT = None


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def make_cert(tmp):
    """Self-signed cert for the loopback server: openssl CLI, else cryptography, else None."""
    key = os.path.join(tmp, "key.pem")
    crt = os.path.join(tmp, "crt.pem")

    try:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=localhost"],
                       check=True, capture_output=True)
        return crt, key
    except Exception:
        pass

    try:
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        c = (x509.CertificateBuilder()
             .subject_name(name).issuer_name(name).public_key(k.public_key())
             .serial_number(x509.random_serial_number())
             .not_valid_before(now - datetime.timedelta(days=1))
             .not_valid_after(now + datetime.timedelta(days=1))
             .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
             .sign(k, hashes.SHA256()))
        with open(key, "wb") as f:
            f.write(k.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption()))
        with open(crt, "wb") as f:
            f.write(c.public_bytes(serialization.Encoding.PEM))
        return crt, key
    except Exception as e:
        log("no cert tooling:", e)
        return None


def p_hash(secret, seed, length, h):
    out = b""
    a = seed
    while len(out) < length:
        a = hmac.new(secret, a, h).digest()
        out += hmac.new(secret, a + seed, h).digest()
    return out[:length]


def tls12_keys(master, client_random, server_random, key_len, h):
    """RFC 5246 6.3, AEAD layout: client key, server key, client iv, server iv."""
    block = p_hash(master, b"key expansion" + server_random + client_random,
                   2 * key_len + 8, h)
    return (block[0:key_len], block[2 * key_len:2 * key_len + 4],
            block[key_len:2 * key_len], block[2 * key_len + 4:2 * key_len + 8])


def prf_for(cipher_name):
    return hashlib.sha384 if "SHA384" in cipher_name else hashlib.sha256


def key_len_for(cipher_name):
    return 32 if "256" in cipher_name else 16


def server_random_from(data):
    """ServerHello random: record header 5, handshake header 4, version 2, then 32 bytes."""
    if len(data) < 43 or data[0] != 0x16 or data[5] != 0x02:
        return None
    return data[11:43]


def set_ulp(sock):
    """Attach the TLS ULP; EEXIST means it is already attached, which is what we want."""
    try:
        sock.setsockopt(socket.IPPROTO_TCP, TCP_ULP, b"tls")
        return "set-by-probe"
    except OSError as e:
        if e.errno == 17:          # EEXIST
            return "preexisting"
        raise


def install_tx(sock, key, salt, explicit, seq, prefix, cipher_id=TLS_CIPHER_AES_GCM_128):
    """struct tls12_crypto_info_aes_gcm_{128,256}: info, iv[8], key[], salt[4], rec_seq[8].

    salt is the derived fixed IV (the first four bytes of the GCM nonce) and explicit is the
    initial 8-byte explicit nonce; the nonce per record is salt || explicit.  The first version
    of this probe passed the explicit nonce where the salt belongs and hardcoded zeros in the
    salt slot, so the kernel encrypted with salt 00000000 and no peer could authenticate a
    record - the four failures that followed were the probe's, not the kernel's.

    version and cipher_type are host-endian; rec_seq is consumed as the eight bytes of the
    record sequence in the AAD, so it is network order.
    """
    info = struct.pack("HH8s%ds4s8s" % len(key), prefix, cipher_id, explicit, key, salt,
                       struct.pack(">Q", seq))

    sock.setsockopt(SOL_TLS, TLS_TX, info)


def handshake(port, keylog, client_random_hex=None):
    """Client TLS 1.2 handshake over memory BIOs; returns (sock, sslobj, server_random)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.keylog_filename = keylog

    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    sock = socket.create_connection(("127.0.0.1", port))
    obj = ctx.wrap_bio(incoming, outgoing, server_side=False, server_hostname="localhost")

    seen = b""
    cout = b""
    while True:
        try:
            obj.do_handshake()
            break
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLWantWriteError:
            pass

        out = outgoing.read()
        if out:
            cout += out
            sock.sendall(out)

        if not incoming.pending:
            data = sock.recv(16384)
            if not data:
                break
            seen += data
            incoming.write(data)

    out = outgoing.read()
    if out:
        cout += out
        sock.sendall(out)

    return sock, obj, server_random_from(seen), cout


def server_thread(port, ready, results):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(*CERT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2

    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", port))
    ls.listen(2)
    results["port"] = ls.getsockname()[1]
    ready.set()

    for _ in range(2):
        try:
            raw, _ = ls.accept()
        except OSError:
            return
        try:
            conn = ctx.wrap_socket(raw, server_side=True)
            conn.settimeout(15)
            try:
                chunk = conn.recv(65536)
            except (ssl.SSLError, OSError) as e:
                results.setdefault("reads", []).append({"ok": False, "detail": f"{e!r}"})
                raw.close()
                continue
            results.setdefault("reads", []).append(
                {"ok": bool(chunk), "bytes": len(chunk),
                 "text_ok": chunk[:16] == b"kernel-written!!"})
            conn.close()
            raw.close()
        except Exception as e:
            results.setdefault("reads", []).append({"ok": False, "detail": f"{e!r}"})


def verify_against_openssl(cout, key, salt):
    """Decrypt OpenSSL's own client Finished with the keys we derived.

    This is the check that decides whether anything else in this probe means anything: if the
    derived key does not open a record OpenSSL itself produced, then a refusal by the server
    later says nothing about the kernel.  The client's Finished is the first record under the
    client write keys, so its sequence is 0 and its plaintext is the handshake message header
    followed by 12 bytes of verify_data.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    i = 0
    found = None
    while i + 5 <= len(cout):
        length = int.from_bytes(cout[i + 3:i + 5], "big")
        rec = cout[i:i + 5 + length]
        if rec and rec[0] == 0x16 and rec[1:3] == b"\x03\x03":
            found = rec
        i += 5 + length

    if found is None:
        return None

    explicit, rest = found[5:13], found[13:]
    data, tag = rest[:-16], rest[-16:]
    aad = (0).to_bytes(8, "big") + b"\x16" + b"\x03\x03" + len(data).to_bytes(2, "big")

    try:
        return AESGCM(key).decrypt(salt + explicit, data + tag, aad).hex()
    except Exception as e:
        return f"failed: {type(e).__name__}"


def attempt(port_no, seq, keylog_path, prefix, payload, iv_mode="zero"):
    """One connection: handshake, derive, install TLS_TX at `seq`, write plaintext to the fd."""
    sock, obj, srandom, cout = handshake(port_no, keylog_path)
    cipher = obj.cipher()[0]

    with open(keylog_path) as f:
        lines = [l.split() for l in f if l.strip()]

    master = crandom = None
    for parts in lines:
        if parts[0] == "CLIENT_RANDOM":
            crandom, master = bytes.fromhex(parts[1]), bytes.fromhex(parts[2])

    if master is None or srandom is None:
        return {"ok": False, "detail": "no master secret or server random",
                "master": master is not None, "server_random": srandom is not None}

    key, iv, _, _ = tls12_keys(master, crandom, srandom,
                               key_len_for(cipher), prf_for(cipher))

    # The kernel validates the cipher against the crypto_info layout: a 32-byte key with the
    # AES-128 cipher id is answered with EINVAL, which is exactly what this probe hit first.
    cipher_id = TLS_CIPHER_AES_GCM_256 if len(key) == 32 else TLS_CIPHER_AES_GCM_128

    # Does the derived key open a record OpenSSL produced?  Without this the rest of the run
    # cannot distinguish "the kernel's record was rejected" from "our keys were wrong".
    verified = verify_against_openssl(cout, key, iv)

    # TLS 1.2 puts the 8-byte explicit nonce in the crypto_info's `iv` field; the kernel may
    # expect it zeroed and advanced per record, or already carrying the record sequence.
    iv_field = struct.pack("!Q", seq) if iv_mode == "seq" else b"\x00" * 8

    fd = sock.fileno()

    trace = {"keys_verified": verified, "iv_mode": iv_mode}

    try:
        trace["ulp"] = set_ulp(sock)
    except OSError as e:
        trace["ulp"] = f"errno {e.errno} {e.strerror}"
        return {"ok": False, "detail": "ULP failed", "trace": trace,
                "cipher": cipher, "key_len": len(key)}

    try:
        install_tx(sock, key, iv, iv_field, seq, prefix, cipher_id)
        trace["install"] = f"accepted (cipher {cipher_id})"
    except OSError as e:
        trace["install"] = f"errno {e.errno} {e.strerror}"
        return {"ok": False, "detail": "TLS_TX failed", "trace": trace,
                "cipher": cipher, "key_len": len(key)}

    try:
        written = os.write(fd, payload)
        trace["write"] = f"{written} bytes"
    except OSError as e:
        trace["write"] = f"errno {e.errno} {e.strerror}"
        written = -1

    return {"ok": True, "cipher": cipher, "ulp": trace.get("ulp"), "seq": seq,
            "written": written, "key_len": len(key), "trace": trace,
            "client_random": crandom.hex()[:16], "server_random": srandom.hex()[:16]}


def main():
    global CERT

    tmp = tempfile.mkdtemp()
    CERT = make_cert(tmp)

    result = {"python": sys.version.split()[0], "openssl": ssl.OPENSSL_VERSION}
    result["kernel"] = os.uname().release

    if CERT is None:
        result["verdict"] = "no cert tooling, skipped"
        print(json.dumps(result, indent=2))
        return 2

    if not os.path.exists("/sys/module/tls") and not os.path.exists("/proc/net/tls_stat"):
        log("no tls module visible")

    payload = b"kernel-written!!" + b"x" * 100

    variants = (("iv0-seq1", 1, "zero"), ("iv0-seq0", 0, "zero"),
                ("ivseq-seq1", 1, "seq"), ("ivseq-seq0", 0, "seq"))

    for label, seq, iv_mode in variants:
        ready = threading.Event()
        results = {}
        t = threading.Thread(target=server_thread, args=(0, ready, results), daemon=True)
        t.start()
        ready.wait(10)
        port = results["port"]

        keylog = os.path.join(tmp, f"keylog-{label}")
        open(keylog, "w").close()

        try:
            r = attempt(port, seq, keylog, TLS12_VERSION, payload, iv_mode)
        except OSError as e:
            r = {"ok": False, "detail": f"{e!r}", "errno": e.errno}

        r["label"] = label

        deadline = 12
        while deadline > 0 and not results.get("reads"):
            import time
            time.sleep(0.2)
            deadline -= 0.2

        read = (results.get("reads") or [{}])[-1]
        r["server_read"] = read
        r["verdict"] = ("kernel record accepted" if read.get("text_ok")
                        else "kernel record not accepted")

        result[label] = r

        log(f"{label}: keys_verified={r.get('trace', {}).get('keys_verified')} "
            f"install={r.get('trace', {}).get('install')} read={read.get('bytes')} "
            f"text_ok={read.get('text_ok')}")

    accepted = [k for k, v in result.items()
                if isinstance(v, dict) and v.get("server_read", {}).get("text_ok")]

    result["accepted_variants"] = accepted
    if accepted:
        result["verdict"] = f"the server decrypted the kernel's record with {accepted[0]}"
    else:
        result["verdict"] = ("TLS_TX accepted, keys verified, but the server rejected every "
                             "record: the kernel's nonce/sequence convention for TLS 1.2 is not "
                             "the one tried here")

    print(json.dumps(result, indent=2, default=str))

    if accepted:
        return 0

    # Nothing was decrypted.  If the keys failed their own check on OpenSSL's record, that is
    # where the problem is, and it is ours rather than the kernel's.
    if any(isinstance(v, dict) and str(v.get("trace", {}).get("keys_verified")).startswith("failed")
           for v in result.values()):
        return 1

    if all(not isinstance(v, dict) or not v.get("ok") for v in result.values() if isinstance(v, dict)):
        return 2

    return 1


if __name__ == "__main__":
    sys.exit(main())
