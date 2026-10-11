# HTTP/3: what it costs and what it needs (W3 research, 2026-10-11)

Status: research note + one measured spike. No core code. No date promised.

## Why the question is open again

- HTTP/3 replaces the transport, not the protocol above it: QUIC over UDP, TLS 1.3
  inside the handshake, streams without head-of-line blocking across them.
- The earlier plan terminated HTTP/3 in a front proxy. That plan has no champion
  now, so the browser-facing path, if it is wanted, is core work.
- Upstream history: `nginx/unit` issue 554 asks for QUIC and HTTP/3 and has been
  open since 2021 with no implementation. Absence there is not a decision against
  it — it is an unbuilt item.
- The fork already carries an HTTP/2 stack in pull requests. HTTP/2 is a protocol
  above TLS; HTTP/3 is a transport below it. They share the ALPN surface and
  nothing else.

## What the spike measured

`exp/h3-spike/h3_spike.py` runs a QUIC server and an HTTP/3 client on loopback in
one process (aioquic 1.4.0, userspace, Python), makes one `GET /` and prints the
timings. Local run and CI run, same code:

```
quic handshake           32.8 ms
h3 request round trip     2.7 ms
status                   200
body                     b'hello over h3\n'
RESULT                   PASS
```

What this proves: the transport works in a normal Linux userspace with no kernel
support, one UDP socket, one certificate, and each H3 stream is a normal request
with headers and a body. What it does NOT prove: any performance number for a C
implementation. Python numbers price the shape, not the cost.

## The three options

| Option | What it means | Cost drivers | Risks |
|---|---|---|---|
| In-house QUIC in C | own congestion control, loss recovery, connection IDs, timers | a second transport state machine beside the event engine; years of bug surface (nginx carried its own QUIC and shipped HTTP/3 experimental for years) | highest effort, highest expertise needed, slowest to correct |
| A library (ngtcp2 + nghttp3, C) | link the transport, implement the integration | new permanent build, test and packaging dependency; UDP event path; integration with the existing connection object | medium effort, dependency decisions are hard to reverse once shipped |
| Keep it at the edge (nginx, HAProxy, CDN) | the core stays HTTP/1 and HTTP/2 | none in the core | operators who want HTTP/3 from the server itself get nothing; this is what the abandoned plan relied on |

A Rust stack (quiche, Quinn) is reachable only through FFI and brings a second
runtime's timers and state machine into a C event loop — the same objection the
language question always raises here.

## Prerequisites, in order

1. **TLS 1.3.** QUIC requires it. The TLS module work (W1) must carry TLS 1.3 and
   must treat the ALPN token `h3` as a first-class value. This is the hard coupling
   between the two tracks.
2. **HTTP/2 first.** The h2 stack is already in pull requests; it validates the
   protocol-extension path, the ALPN routing and the connection-object split.
3. **Body streaming (D3).** The KB named it a prerequisite for h2 and it was
   downgraded to follow-on there. For HTTP/3 it stays a prerequisite: a QUIC
   connection multiplexes many streams, and a buffered-body upload parks behind
   flow control on every other stream.
4. **A UDP event path.** The engine is TCP-oriented today; connection IDs, stateless
   resets and packet timers are new shapes.

## Recommendation (hypothesis, for the maintainer)

- Do not start HTTP/3 before HTTP/2 has shipped and D3 has landed.
- When it starts, prefer a **library** (ngtcp2 + nghttp3) over an in-house stack:
  the protocol is not the differentiator here, and the failure modes are expensive.
- Keep the edge option documented for operators who cannot wait. It is a legitimate
  deployment, not a missing feature.
- Decide explicitly whether HTTP/3 is a core feature or an edge concern. That
  decision, not the effort estimate, determines the sequence.

## What must not be claimed before it ships

- No performance number from this spike may be quoted as a product number.
- No HTTP/3 support may be mentioned in release notes, the site or a talk while
  this file is the only artifact.
- No date. The estimate 4 to 6 months after D3 is a hypothesis from the KB, not a
  plan, and it assumes a library path.

## Reproduce

```sh
cd exp/h3-spike
pip install aioquic==1.4.0
python3 h3_spike.py     # prints the timings, exits non-zero on failure
```

The certificate is generated per run into the system temporary directory; nothing
is written into the tree.

---

Reviewed-by: FreeUnitOPS (DeepSeek V4.1 Flash, Hermes Agent)
