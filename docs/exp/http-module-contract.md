# HTTP module — the socket / buffer / IPC contract (and H3 vs custom)

Tracks workbench `freeunitorg/freeunit-exp#43`. Scope + rationale: this note is
the contract the issue asks for.

## The three owners (read from the tree)

1. **Client socket** — owned by the HTTP layer. The connection is a
   `nxt_conn_t` (`struct nxt_h1proto_s.conn`, `src/nxt_h1proto.h:86`); it holds
   the fd and the read buffer. The router accepts the connection
   (`nxt_router.c`) and hands it to the HTTP protocol object.
2. **Read buffers** — owned by the HTTP layer. The event engine hands a buf-mem
   block that HTTP takes as `conn->read` (`nxt_h1proto.c:319`, freed with
   `nxt_event_engine_buf_mem_free` when not taken). The parser advances it; HTTP
   frees it after the request is consumed. **Not** handed to IPC.
3. **IPC payload** — the router **serializes** the request into the application
   protocol in **shared memory**: `nxt_router_prepare_msg()`
   (`nxt_router.c:8379`) builds a `nxt_unit_request_t` + `nxt_unit_field_t[]`
   inside a port mmap buffer (`nxt_port_mmap_get_buf(&app->outgoing, …)`),
   size-capped at `PORT_MMAP_DATA_SIZE`. The body follows as a buf chain. IPC
   never sees the client socket or its buffers — it sees a canonical request
   struct in shm.

## The contract

- The HTTP module **owns** the client socket, its read buffers, the parse
  (`nxt_http_request_parse_t`) and the response writing.
- The HTTP module **produces** exactly two things for the rest of the server:
  (a) an `nxt_http_request_t` allocated in the request pool; (b) the serialized
  shm request the router sends.
- The router **owns** the port/IPC and the `outgoing` mmap; it **copies** the
  request into shm and never borrows the socket buffers.
- A new protocol plugs in **above** the socket/buffer seam and **below** the
  `nxt_unit_request_t` serialization — it must supply the same two products.
- The seam must let the IPC layer change without an HTTP change, and vice versa:
  HTTP exposes (socket, parsed request); IPC exposes (shm request + body chain).

## HTTP/3 (QUIC) vs a custom protocol

| | HTTP/3 in the C core | custom protocol (BWP-style) |
|---|---|---|
| cost | a whole QUIC stack — UDP path, handshake, migration, QPACK, TLS-inside — months + new deps | the seam refactor + a protocol impl (~weeks) |
| gain | modern client-facing protocol; parity with Angie (H3 prod) / nginx (H3 exp) | unblocks IPC/perf and a future datagram transport; **no** client-facing H3 |
| risk | large new attack surface in the C core | contained; no new client transport |

**Decision (matches the existing reading — do not put HTTP/2/3 in the C core):**
do **not** implement HTTP/3 in the core. Define the **contract** (this note) and
let an edge (Buran, Rust) terminate H2/H3 and speak a lean transport (BWP) to
FreeUnit. The `exp` #24 h3 spike is the evidence that an in-core QUIC stack is a
large, separate project. The contract is also what the IPC work (#44) needs to
change freely.

## Next

Encode the contract as a module header — a `nxt_http_proto_t`-shaped table
(init, read, write response) — the same move as the TLS module (#42 / #57). Out
of scope here: any protocol implementation.
