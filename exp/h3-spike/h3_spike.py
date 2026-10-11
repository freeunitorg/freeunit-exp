#!/usr/bin/env python3
"""HTTP/3 spike: one request over QUIC on loopback, measured.

Purpose: price the transport before any core work. A userspace stack (aioquic,
same library family as the C options) answers three questions on this host:

  1. does a QUIC handshake complete without a TCP listener,
  2. what does one H3 request cost after that handshake,
  3. is the certificate the only setup the server needs.

Exit code 0 and a body of "hello over h3" means the transport works.
"""

import asyncio
import datetime
import socket
import ssl
import sys
import tempfile
import time
from pathlib import Path

from aioquic.asyncio import connect, serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

CRT = Path(tempfile.gettempdir()) / "h3-spike.crt"
KEY = Path(tempfile.gettempdir()) / "h3-spike.key"
BODY = b"hello over h3\n"


def make_cert() -> None:
    """A throwaway certificate. aioquic refuses to start without one."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    CRT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    KEY.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


class Server(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)

    def quic_event_received(self, event) -> None:
        for http_event in self._http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                sid = http_event.stream_id
                self._http.send_headers(
                    stream_id=sid,
                    headers=[
                        (b":status", b"200"),
                        (b"content-type", b"text/plain"),
                        (b"server", b"freeunit-h3-spike"),
                    ],
                )
                self._http.send_data(stream_id=sid, data=BODY, end_stream=True)
                self.transmit()


class Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self.headers = None
        self.body = b""
        self.done = asyncio.Event()

    def get(self, authority: str, path: str) -> None:
        sid = self._quic.get_next_available_stream_id()
        self._http.send_headers(
            stream_id=sid,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b":path", path.encode()),
            ],
        )
        self._http.send_data(stream_id=sid, data=b"", end_stream=True)
        self.transmit()

    def quic_event_received(self, event) -> None:
        for http_event in self._http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                self.headers = http_event.headers
            elif isinstance(http_event, DataReceived):
                self.body += http_event.data
                if http_event.stream_ended:
                    self.done.set()


def free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def run() -> int:
    make_cert()
    port = free_udp_port()

    server_conf = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    server_conf.load_cert_chain(str(CRT), str(KEY))

    await serve("127.0.0.1", port, configuration=server_conf, create_protocol=Server)

    client_conf = QuicConfiguration(
        is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE
    )

    t0 = time.perf_counter()
    async with connect(
        "127.0.0.1", port, configuration=client_conf, create_protocol=Client
    ) as client:
        handshake_ms = (time.perf_counter() - t0) * 1000

        t1 = time.perf_counter()
        client.get(f"127.0.0.1:{port}", "/")
        await asyncio.wait_for(client.done.wait(), timeout=10)
        request_ms = (time.perf_counter() - t1) * 1000

    status = None
    for name, value in client.headers or []:
        if name == b":status":
            status = value.decode()

    print(f"port                     {port}/udp")
    print(f"quic handshake           {handshake_ms:.1f} ms")
    print(f"h3 request round trip    {request_ms:.1f} ms")
    print(f"status                   {status}")
    print(f"body                     {client.body!r}")

    ok = status == "200" and client.body == BODY
    print("RESULT                   " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(run()))
