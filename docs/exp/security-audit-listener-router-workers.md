# NGINX Unit — Security Audit: Listener, Router, and Workers

**Target:** `freeunitorg/freeunit-exp` `main` @ `d2e585aa`
**Read at:** `b2360a1dc6ad` (`andypost/master`), re-verified at `d2e585aa` —
all 29 findings are still present; line citations re-pinned to `d2e585aa`.
**Scope:** `src/nxt_router.c` (router process, listener state machine, request
dispatch), `src/nxt_conn_accept.c` + `src/nxt_listen_socket.c` (accept path),
`src/nxt_port*.c` / `src/nxt_app_queue.h` / `src/nxt_app_nncq.h` (router↔worker
IPC), `src/nxt_application.c` + `src/nxt_process.c` + `src/nxt_isolation.c`
(worker lifecycle, sandbox), `src/nxt_main_process.c` (control process),
`src/nxt_atomic.h` and every call site of it.

**Method:** full reads of the files above; every atomic call site in the tree
enumerated (`grep -rn nxt_atomic src/`) and checked against the C11 memory
model; the shared-memory queue protocol traced end to end (producer → slot
recycling → consumer claim → router retraction); the worker pid lifecycle
traced from `fork()` through `SCM_CREDENTIALS` to `REMOVE_PID` broadcast.

**Note on the tree:** this is a hardened fork that already contains a partial
audit series (`M-4`…`M-11` in `1acaf803`, `80c24f61`). Many classic Unit issues
are already fixed and commented at length — most notably the `SCM_CREDENTIALS`
sender checks in `nxt_port.c`. The findings below are what is **still** wrong.

---

## Summary

| ID | Severity | Component | Finding |
|----|----------|-----------|---------|
| H-1 | **High** | worker | Application worker can forge a global pid → arbitrary `REMOVE_PID` → cross-tenant teardown of any known process |
| H-2 | **High** | router↔worker | Shared-port claim token lives in a recycled slot → silent request loss + 16 KiB shared-memory leak per occurrence |
| H-3 | **High** | listener | Router-configured `unix:` listeners are created world-writable (`0666`), hardcoded, with a chmod-by-name TOCTOU |
| H-4 | **High** | listener | The connection limit is never applied to the router's accept engines (`max_connections == 0xFFFFFFFF`) |
| M-1 | Medium | atomics | Shared-queue wake-up flag cleared with a plain, unordered store → lost wakeup |
| M-2 | Medium | atomics | Claim token written with a plain store, concurrently with an atomic RMW |
| M-3 | Medium | atomics | NNCQ consumer reads a producer-owned word with a plain load (C11 race; stale read ≡ "empty") |
| M-4 | Medium | atomics | `nxt_app_nncq_new_entry()` overflows a signed `int` at 2³¹ enqueues; 32-bit position counters alias at 2³² |
| M-5 | Medium | worker | `setgroups()` skipped on the credential-namespace path → supplementary groups leak into the app |
| M-6 | Medium | worker | `PR_SET_NO_NEW_PRIVS` is off by default → an `"external"` app regains privilege across `execve()` |
| M-7 | Medium | listener | Persistent `accept()` errors do not disarm the listener → level-triggered hot loop + unmoderated log flood |
| M-8 | Medium | listener | `lev->ready` underflows (`batch == 0`) → `read_ready` stuck at 1 → one wasted `accept()` syscall per connection |
| M-9 | Medium | worker | Router and controller are re-forked with no backoff → unbounded respawn loop |
| M-10 | Medium | worker | No `RLIMIT_*`, no cgroup `pids.max`/`memory.max`, `request_limit` defaults to 0 |
| M-11 | Medium | listener | Listener-close drain has no deadline → one idle client pins the fd and the old configuration's pool |
| M-12 | Medium | listener | A `backlog` change on an existing listener is accepted and silently ignored |
| M-13 | Medium | worker | Language-module setup (e.g. `php.ini` + `extension=` `dlopen`) runs as **root**, before the privilege drop |
| M-14 | Medium | router↔worker | The router's retraction of a never-queued request CASes slot 0 of the shared queue |
| L-1 | Low | listener | The listening descriptor never gets `FD_CLOEXEC` |
| L-2 | Low | router | `nxt_listen_socket_t` leaks on every failed configuration apply |
| L-3 | Low | router | `skcf->listen` is left dangling after `nxt_free(ls)` |
| L-4 | Low | listener | The accept-retry timer and the listener-close timer are the same `nxt_timer_t` |
| L-5 | Low | worker | The prototype waits forever for a silent worker → `unitd` cannot shut down |
| L-6 | Low | worker | App log-redirection failures are silently ignored; the file is created `0666` |
| L-7 | Low | worker | The cgroup path is resolved by string concatenation; symlinks are followed |
| L-8 | Low | router | `nxt_router_conf_ready()` tears the conf pool down differently from `nxt_router_conf_release()` |
| L-9 | Low | router↔worker | `port->messages` is unbounded; only fd-carrying messages are capped |
| L-10 | Low | router↔worker | Dead `cancelled` state on the fragment reassembly path |
| L-11 | Low | router↔worker | `nxt_app_queue_cancel()` indexes `items[cookie]` with no bound check |

**28 findings: 4 High, 14 Medium, 11 Low.**

---

# High

## H-1 — An application worker can forge a global pid and force the teardown of any process

**Component:** worker / process lifecycle
**Files:** `src/nxt_application.c:1068-1102` → `src/nxt_port.c:1285-1338`, `:1341-1388`

The prototype authenticates the *sender* of `PROCESS_CREATED` with the
kernel-supplied `SCM_CREDENTIALS` pid — but then lets the *wire* field override
the authoritative global pid:

```c
/* src/nxt_application.c:1068 */
static void
nxt_proto_process_created_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_pid_t      isolated_pid, pid;
    nxt_process_t  *process;

    isolated_pid = nxt_recv_msg_cmsg_pid(msg);      /* kernel-validated  */

    process = nxt_proto_process_find(task, isolated_pid);
    if (nxt_slow_path(process == NULL)) {
        return;
    }

    process->state = NXT_PROCESS_STATE_CREATED;

    pid = msg->port_msg.pid;                        /* <-- SELF-DECLARED  */
    ...
        process->pid = pid;                         /* <-- overwrites it  */
```

`msg->port_msg.pid` is a plain field of the wire header (`src/nxt_port.h:251-271`),
read verbatim off the socket with no integrity check. A worker inherits its
prototype's port socketpair (`nxt_process_child_fixup()` keeps the parent's
port unconditionally, `src/nxt_process.c:372-394`, and `nxt_process_setup()`
explicitly does `nxt_port_write_enable(task, process->parent_port)`,
`src/nxt_process.c:872`), so it can write arbitrary bytes there.

Contrast the *correct* pattern one file over, `src/nxt_port.c:694-758`, where the
wire pid only **selects** a candidate and the cmsg pid must then match that
candidate's `isolated_pid`:

```c
    process = nxt_runtime_process_find(rt, msg->port_msg.pid);   /* wire: selects */
    ...
    if (nxt_slow_path(process->isolated_pid <= 0
                      || nxt_recv_msg_cmsg_pid(msg) != process->isolated_pid))
    {   /* cmsg: authenticates that the selected candidate is the sender */
```

### Why the forged pid is dangerous

`process->pid` is what gets broadcast as `REMOVE_PID` to main and to the router
when the worker dies:

```c
/* src/nxt_port.c:1285 */
void
nxt_port_remove_notify_others(nxt_task_t *task, nxt_process_t *process)
{
    ...
    pid = process->pid;                       /* the forged value */
    ...
        buf->mem.free = nxt_cpymem(buf->mem.free, &pid, sizeof(pid));
        if (nxt_slow_path(nxt_port_socket_write(task, port,
                                                NXT_PORT_MSG_REMOVE_PID, ...
```

Reaching the router requires no authentication at all — `src/nxt_router.c:2240`
installs `nxt_port_remove_pid_handler` unconditionally. And the receiver acts on
the number without checking who sent it:

```c
/* src/nxt_port.c:1341 */
static void
nxt_port_remove_pid(nxt_task_t *task, nxt_port_recv_msg_t *msg, nxt_pid_t pid)
{
    ...
    nxt_port_rpc_remove_peer(task, msg->port, pid);

    process = nxt_runtime_process_ref(rt, pid);   /* lookup by the pid    */

    if (process) {
        nxt_process_close_ports(task, process);  /* <-- tears it down     */
        nxt_process_use(task, process, -1);
    }
}
```

### Attack and impact

1. Application worker `W` (malicious or compromised) writes a raw
   `NXT_PORT_MSG_PROCESS_CREATED` to the prototype's port with
   `port_msg.pid = <victim pid>`.
2. The prototype authenticates the sender correctly (cmsg pid == `W`'s own
   ns-local pid → hash hit at `nxt_proto_process_find()`) but stores
   `process->pid = <victim pid>`. In the non-isolated case the process is
   already registered under its real pid, so the hash key is unchanged — but
   `process->pid` is now the forged value.
3. `W` exits. The prototype's `SIGCHLD` handler reaps it and calls
   `nxt_proto_child_exited()` → `nxt_port_remove_notify_others()`
   (`src/nxt_application.c:1329`) → `REMOVE_PID(<victim pid>)` to main and to
   the router (`nxt_proc_remove_notify_matrix[APP] = {1,0,0,1,0,0}`,
   `src/nxt_process.c:98-105`).
4. Main and the router both run `nxt_port_remove_pid()` →
   `nxt_runtime_process_ref(rt, victim_pid)` → hit → `nxt_process_close_ports()`.

Consequences:

* **Cross-application DoS.** Any application worker can kill any *other*
  application's workers, any prototype, or the controller.
* **Router kill.** The router registers *itself* in main's process hash
  (`nxt_process_do_start()` → `nxt_runtime_process_add()`, `src/nxt_process.c:902`).
  Forging the router's pid makes main close the router's own ports — the router
  becomes unreachable and dies.
* **RPC cancellation.** `nxt_port_rpc_remove_peer()` retires live RPCs keyed on
  that pid, so in-flight `START_PROCESS` / listen-socket requests are failed too.

This is the one place in the tree where a value the worker reports *about
itself* is trusted; everywhere else the code insists on "the sender is not
trusted" and switches to `nxt_recv_msg_cmsg_pid()`.

### Fix

* In the non-isolated case `process->isolated_pid` **is** the global pid
  (`src/nxt_process.c:802-803`); never overwrite it from the wire. Use
  `process->isolated_pid` for the `REMOVE_PID` broadcast.
* In the pid-isolated case the global pid must come from an authenticated
  source — main already knows it (it is the `SCM_CREDENTIALS` pid in
  `nxt_main_process_whoami_handler()`, `src/nxt_main_process.c:1082-1084`). Have
  main supply the ns-pid→global-pid mapping to the prototype.
* Interim hardening: reject a `PROCESS_CREATED` whose `port_msg.pid` is not the
  value main independently holds for that worker, and refuse to broadcast a
  `REMOVE_PID` built from an unverified pid.

---

## H-2 — The shared-port claim token is recycled before it is claimed

**Component:** router ↔ worker IPC (shared application queue)
**Files:** `src/nxt_app_queue.h:75`, `:109`, `:145`; `src/nxt_unit.c:8883-8917`;
`src/nxt_router.c:1356`

The router hands a request to an application's *shared port*
(`NXT_SHARED_PORT_ID`) by writing a record into the shared `nxt_app_queue_t`
and tagging the queue slot with the request's stream number ("tracking"). The
worker claims the record with a CAS on that same word; the router retracts with
the same CAS.

**Producer** — `src/nxt_app_queue.h:66-82`:

```c
    i = nxt_app_nncq_dequeue(&q->free_items);
    if (i == nxt_app_nncq_empty(&q->free_items)) {
        return NXT_AGAIN;
    }

    qi = (nxt_app_queue_item_t *) &q->items[i];

    qi->size = size;
    nxt_memcpy(qi->data, p, size);
    qi->tracking = tracking;          /* <-- plain store, token lives HERE */
    *cookie = i;                      /* <-- cookie is the slot index */
    ...
    if (nxt_slow_path(nxt_app_nncq_enqueue(&q->queue, i) != NXT_OK)) {
```

**Consumer** — `src/nxt_app_queue.h:113-148`:

```c
    i = nxt_app_nncq_dequeue(&q->queue);
    ...
    qi = (nxt_app_queue_item_t *) &q->items[i];
    ...
    nxt_memcpy(p, qi->data, size);
    *cookie = i;

    (void) nxt_app_nncq_enqueue(&q->free_items, i);   /* <-- SLOT RELEASED HERE */

    return size;
```

**The claim happens after `nxt_app_queue_recv()` has already returned** —
`src/nxt_unit.c:8883-8917`:

```c
retry:

    rbuf->size = nxt_app_queue_recv(queue, rbuf->buf, &cookie);   /* slot freed inside */
    ...
    if (nxt_app_queue_cancel(queue, cookie, port_msg->stream)) {   /* the CLAIM */
```

and the CAS itself — `src/nxt_app_queue.h:101-110`:

```c
    qi = (nxt_app_queue_item_t *) &q->items[cookie];

    return nxt_atomic_cmp_set(&qi->tracking, tracking, 0);
```

The router's retraction is the same CAS on the same slot (`src/nxt_router.c:1356`).

### The defect

The claim and the dequeue are **not atomic**. The token lives in a slot that is
handed back to the free list *before* either side performs the claim CAS.
Concretely, with slot index `i`:

1. Worker `W` dequeues request **A** (slot `i`, `tracking = S_A`).
   `nxt_app_queue_recv()` immediately returns `i` to `free_items`.
2. The router (or another worker) takes slot `i` from `free_items` and stores
   `tracking = S_B` for request **B** (`nxt_app_queue.h:75`).
3. `W` now executes its claim: `cmp_set(&items[i].tracking, S_A, 0)`. The word
   holds `S_B`, so the CAS **fails**.
4. `W` concludes "message cancelled" (`src/nxt_unit.c:8915-8917`, `goto retry`)
   and **drops request A**. A is never executed; the client is never answered.
5. The router's later retraction of A also fails (the word is `S_B` or `0`), so
   the router records `NXT_MSG_CLAIMED` and, at `src/nxt_router.c:8764-8772`,
   **waits for an acknowledgement that will never come**:

   ```c
       if (msg_info->cancel == NXT_MSG_CLAIMED
           && req_rpc_data->app_port != NULL
           && req_rpc_data->app_port->id == NXT_SHARED_PORT_ID)
       {
           nxt_debug(task, "stream #%uD: claimed, waiting for the ack", ...);
           return;                       /* no answer, no re-arm */
       }
   ```
6. The 16 KiB shared-memory chunk that carried A's request body is **never
   released**. `nxt_router_msg_cancel()` keeps `is_port_mmap_sent = 1` because
   the retraction "lost" (`src/nxt_router.c:1395-1397`), and
   `nxt_port_mmap_buf_completion()` deliberately does not free a chunk that
   carries sent data — the peer is supposed to release it. The peer never got
   the message, so **nobody releases the chunk**.

### Impact

* (a) Requests silently dropped — the client hangs until its own timeout.
* (b) 16 KiB of shared memory leaked per dropped request. 640 leaks exhaust the
  10 MiB segment (`PORT_MMAP_DATA_SIZE`), after which
  `nxt_port_mmap_get()` (`src/nxt_port_memory.c:567-643`) can no longer
  allocate a request buffer and **the application stops receiving requests
  entirely**.
* (c) The request's `ack_waiting_req` entry and its application/port
  accounting are held until the client gives up.

### Reachability (honest assessment)

The reuse distance of a slot is the length of the free list.
`|free_items| + |queue| = NXT_APP_NNCQ_SIZE = 131072` (`src/nxt_app_queue.h:25-30`).
In steady state the free list is ~131072 long, so the window between
"worker dequeues" and "worker claims" (~1 µs) is a negligible fraction of the
reuse distance.

The race becomes reachable when the free list is **short** — i.e. when the
application is slow and the queue is deep. With 131000 requests pending, only
~72 slots remain free; the producer then cycles the free list in 72 enqueues,
and the ~1 µs claim window becomes a meaningful fraction of that distance. A
sustained flood against a slow application is exactly the condition an attacker
creates on purpose, and it is the condition under which the shared-port path is
used at all.

Note also that the *plain store* at `nxt_app_queue.h:75` (see M-2) makes the
window wider still: a stale claim CAS and a producer's token store are
unordered with respect to each other, so the producer's store can land *after*
a previous owner's CAS.

### Fix

Make the claim atomic with the dequeue. Either:

* (i) have the consumer claim the token **before** the slot is returned to
  `free_items` (move the CAS into `nxt_app_queue_recv()`, or split "dequeue"
  from "release"); or
* (ii) keep the token out of the recycled slot: give each slot a dedicated
  `claim` word reset only when the slot is *allocated* (under the producer,
  before publication), so a stale claim can never touch a live request.

---

## H-3 — Router-configured `unix:` listeners are created world-writable (`0666`)

**Component:** listener
**File:** `src/nxt_main_process.c:2013-2032`

```c
#if (NXT_HAVE_UNIX_DOMAIN)

    if (sa->u.sockaddr.sa_family == AF_UNIX
        && sa->u.sockaddr_un.sun_path[0] != '\0')
    {
        char          *filename;
        nxt_thread_t  *thr;

        filename = sa->u.sockaddr_un.sun_path;

        if (chmod(filename, 0666) != 0) {
```

This is the code path for **every `unix:` listener in a Unit configuration**.
The router asks the main process to create the socket (`src/nxt_router.c:4342`,
`NXT_PORT_MSG_SOCKET`) and main handles it in `nxt_main_port_socket_handler()`
(`src/nxt_main_process.c:1820`, wired at `src/nxt_main_process.c:968`).

The mode is hard-coded to `0666` — *read/write for every local user*. The
control socket in the same tree does the right thing:

```c
/* src/nxt_listen_socket.c:129 */
    name = (nxt_file_name_t *) sa->u.sockaddr_un.sun_path;
    access = rt->control_mode > 0 ? rt->control_mode : 0600;

    if (nxt_file_set_access(name, access) != NXT_OK) {
```

`rt->control_mode` is operator-configurable (`src/nxt_runtime.c:1196`, default
`0600`). There is **no equivalent knob for data listeners**.

### Impact

Any local account on the host can open the application's Unix listener and
speak HTTP to it. If the application sits behind a route the operator
considered local-only, this is a full local bypass. The mode cannot be changed
short of a source patch.

### Secondary issue in the same block — chmod TOCTOU / symlink

`bind()` happens at `src/nxt_main_process.c:1971` and `chmod(filename, 0666)` at
`:1866`; the path is re-resolved by name *after* the socket file exists. If the
containing directory is writable by an unprivileged user, the attacker can
replace the socket file with a symlink between the two calls, and `chmod()` then
follows it and changes the mode of an arbitrary file. The same "resolve by
name" pattern is used by the unlink handler (`src/nxt_main_process.c:2081-2082`),
although that one does authenticate the sender via `SCM_CREDENTIALS` first
(`:1911-1919`).

### Fix

* Add a `"mode"` (or reuse a `control_mode`-style option) to the listener
  configuration and default it to `0600` rather than `0666`.
* Set the mode with `fchmod()` on the descriptor *before* `bind()`, or use
  `umask(0177)` around the `bind()` so the socket is never briefly
  world-writable, and unlink any pre-existing path with `lstat()` checks
  rather than `unlink()` by name.

---

## H-4 — The connection limit is never applied to the router's accept engines

**Component:** listener
**Files:** `src/nxt_event_engine.c:129`, `src/nxt_conn_accept.c:122`,
`src/nxt_router.c:4840`

The guard that bounds simultaneously-accepted connections:

```c
/* src/nxt_conn_accept.c:113 */
static nxt_conn_t *
nxt_conn_accept_alloc(nxt_task_t *task, nxt_listen_event_t *lev)
{
    ...
    engine = task->thread->engine;

    if (engine->connections < engine->max_connections) {

        mp = nxt_mp_create(1024, 128, 256, 32);
```

`engine->max_connections` is **never set to anything but `0xFFFFFFFF` for the
engines that actually accept connections**:

* `src/nxt_event_engine.c:129` — `engine->max_connections = 0xFFFFFFFF;`
  (hard-coded in `nxt_event_engine_create()`; the function has no
  `max_connections` parameter at all, `src/nxt_event_engine.c:42-45`).
* `src/nxt_runtime.c:438` — `thr->engine->max_connections = rt->engine_connections;`
  is applied **only to the main process's own engine**.
* `src/nxt_runtime.c:923` — `rt->engine_connections = 256;` (hard-coded, not
  operator-configurable, and applied to the wrong engine).
* The engines that own the listen events are the router's worker engines,
  created at `src/nxt_router.c:4840`:
  `recf->engine = nxt_event_engine_create(task, interface, NULL, 0, 0);` —
  these keep `max_connections == 0xFFFFFFFF`.

### Impact

The guard at `src/nxt_conn_accept.c:122` is the *only* bound on the number of
simultaneously accepted connections in the router, and it is
`connections < 4294967295`.

Every accepted connection costs a fresh 1 KiB memory pool
(`nxt_mp_create(1024, 128, 256, 32)`, `:124`), plus a pooled `nxt_sockaddr_t`,
plus a kernel socket buffer pair. A remote client that opens many connections
drives unbounded memory growth in the router worker and unbounded fd
consumption; when the fd table is exhausted the accept path degrades into the
100 ms stall described in M-7, which is a self-inflicted DoS amplifier. The
value `256` shows the intent was there — it is simply never applied to the
engines that matter.

### Fix

Propagate `rt->engine_connections` (and make it operator-configurable) to the
router's engines at creation, and apply it to the existing engines on
reconfiguration. The `nxt_router_engine_conf_update()` /
`nxt_router_engine_conf_create()` paths (`src/nxt_router.c:4858-4925`) are the
natural place.

---

# Medium

## M-1 — The shared-queue wake-up flag is cleared with a plain, unordered store

**Component:** atomics / router↔worker IPC
**File:** `src/nxt_app_queue.h:84-98`

```c
    n = nxt_atomic_cmp_set(&q->notified, 0, 1);      /* producer: atomic RMW */
    ...
nxt_inline void
nxt_app_queue_notification_received(nxt_app_queue_t volatile *q)
{
    q->notified = 0;                                  /* consumer: PLAIN STORE */
}
```

The producer side is a full-barrier RMW (`nxt_atomic_cmp_set` →
`__sync_bool_compare_and_swap`, `src/nxt_atomic.h:29-30`). The consumer side is
a **plain, unordered store** to the same word in shared memory, while the peer
reads that word with an atomic RMW. That is a C11 data race (a non-atomic
store concurrent with an atomic RMW is UB) and it has no release/acquire
semantics.

### The lost wakeup

The protocol the code relies on is "`notified == 1` ⇒ a `READ_QUEUE` marker is
still outstanding in the peer's socket". The worker clears the flag *before* it
re-checks the queue (`src/nxt_unit.c:8731-8738`):

```c
        if (nxt_unit_is_read_queue(rbuf)) {
            nxt_app_queue_notification_received(port_impl->queue);  /* plain store */
            ...
            goto retry;
        }
```

If the worker's plain store has not yet reached the coherence point when the
router performs its CAS, the router's CAS reads the stale `1`, concludes "a
marker is already outstanding", and **skips the wake-up**
(`src/nxt_router.c:8328-8337`):

```c
    if (nxt_fast_path(res == NXT_OK)) {
        if (notify != 0) {
            (void) nxt_port_socket_write(task, port,
                                         NXT_PORT_MSG_READ_QUEUE, ...);
        } else {
            nxt_debug(task, "queue is not empty");
        }
```

The worker has already consumed the marker, so the request sits in the shared
queue with nobody looking for it. It is picked up only when the *next* enqueue
wins the `notified` 0→1 transition — i.e. after the queue has been fully
drained, potentially minutes later, or never if the queue never empties.

### Fix

The clear must be an atomic RMW with a full barrier, so that (a) it does not
race the producer's RMW and (b) it is ordered before the worker's subsequent
queue re-check:

```c
    (void) nxt_atomic_cmp_set(&q->notified, 1, 0);
```

`nxt_atomic_release()` (`src/nxt_atomic.h:45-46`, `__sync_lock_release`) is a
release *store* and is **not** sufficient on its own: the worker needs the store
ordered *before the following load*, not before the preceding ones.

---

## M-2 — The claim token is written non-atomically by the producer

**Component:** atomics / router↔worker IPC
**File:** `src/nxt_app_queue.h:73-76`

```c
    qi->size = size;
    nxt_memcpy(qi->data, p, size);
    qi->tracking = tracking;     /* plain store */
    *cookie = i;
```

`qi->tracking` is concurrently modified with an atomic RMW by the worker
(`nxt_app_queue_cancel()`, `src/nxt_app_queue.h:109`) and by the router's
retraction (`src/nxt_router.c:1356`). A plain store racing an atomic RMW is UB.

For a freshly allocated slot the store is ordered before publication by the
enqueue CAS, so the *initial* value is safe. It is **not** safe for a recycled
slot: the store at line 75 into a slot that a previous owner is still CASing
can land *after* that owner's CAS, destroying the new request's token. The
concrete sequence is the same as H-2 step 2/3 — the producer's plain store and
the previous owner's CAS are unordered, so the previous owner's CAS can land
after the store and zero the *new* request's token, which then makes the new
request unclaimable (the worker's claim CAS expects `S_B`, sees `0`, and drops
the request).

### Fix

Write the token with an atomic store, e.g.
`nxt_atomic_cmp_set(&qi->tracking, 0, tracking)` — and, better, remove the
token from the recycled slot entirely (see H-2's fix).

---

## M-3 — NNCQ consumers read a producer-owned word with a plain load

**Component:** atomics / router↔worker IPC
**File:** `src/nxt_app_nncq.h:139-167` (identical code in `src/nxt_nncq.h:157-185`)

```c
    for (r = 0; r < NXT_APP_NNCQ_RETRIES; r++) {
        h = nxt_app_nncq_head(q);
        j = nxt_app_nncq_map(q, h);
        e = q->entries[j];              /* <-- PLAIN load of a word the producer CASes */

        e_cycle = nxt_app_nncq_cycle(q, e);
        h_cycle = nxt_app_nncq_cycle(q, h);

        if (e_cycle != h_cycle) {
            if (nxt_app_nncq_next_cycle(q, e_cycle) == h_cycle) {
                return nxt_app_nncq_empty(q);   /* "the queue is empty" */
            }

            continue;
        }

        if (nxt_atomic_cmp_set(&q->head, h, h + 1)) {
            return nxt_app_nncq_index(q, e);
        }
    }
```

`q->entries[j]` is written **only** by the producer, with an atomic CAS
(`src/nxt_app_nncq.h:128`). The consumer reads it with a plain load. That is a
data race under C11 (UB), and — more importantly — a *stale* read is
**indistinguishable from "empty"**: if the consumer reads the previous round's
value, `e_cycle == h_cycle - 1`, so line 154-157 returns `nxt_app_nncq_empty()`
even though a published item is sitting there.

The standard fix (Vyukov's bounded MPMC queue) is a per-cell sequence number
loaded with `acquire`; this implementation encodes the sequence in `entries[j]`
and then reads it non-atomically. On x86/TSO the load is not reordered and the
value is fresh in practice; on a weakly-ordered machine (ARM64) the plain load
can observe the pre-publication value, and the queue then reports "empty" for a
published item.

The consequence differs by consumer:

* `nxt_port_queue_read_handler()` (`src/nxt_port_socket.c:2030-2042`) — an
  "empty" answer is what makes the reader go to sleep.
* `nxt_unit_app_queue_recv()` (`src/nxt_unit.c:8885`) — it is what makes the
  worker block on the socket.

The shared application queue has **N consumers** (all workers of an application
read the same queue), so this is not a benign single-producer/single-consumer
situation.

The same plain-read pattern exists on the producer side
(`src/nxt_app_nncq.h:112`), where it is benign only because the producer is
single.

### Fix

Load `q->entries[j]` with an atomic acquire load (or make the whole `entries[]`
array `_Atomic` and use relaxed loads plus an explicit acquire fence), and
treat "cycle older than head" as *retry*, not as "empty".

---

## M-4 — Signed overflow and 32-bit aliasing in the shared-queue entry arithmetic

**Component:** atomics / router↔worker IPC
**File:** `src/nxt_app_nncq.h:17-18`, `:62-83`

```c
typedef uint32_t nxt_app_nncq_atomic_t;
typedef uint16_t nxt_app_nncq_cycle_t;
...
static inline nxt_app_nncq_cycle_t
nxt_app_nncq_cycle(nxt_app_nncq_t const volatile *q, nxt_app_nncq_atomic_t i)
{
    return i / NXT_APP_NNCQ_SIZE;          /* truncated to 16 bits */
}
...
static inline nxt_app_nncq_atomic_t
nxt_app_nncq_new_entry(nxt_app_nncq_t const volatile *q,
    nxt_app_nncq_cycle_t cycle, nxt_app_nncq_atomic_t i)
{
    return cycle * NXT_APP_NNCQ_SIZE + (i % NXT_APP_NNCQ_SIZE);
}
```

`cycle` is `uint16_t` → promoted to `int`; `NXT_APP_NNCQ_SIZE` is `131072` (an
`int` literal). The multiplication is therefore **`int * int`**. `cycle == 16384`
gives `16384 * 131072 == 2^31`, which overflows a signed 32-bit `int` →
**undefined behaviour** (not merely unsigned wrapping: the expression is
signed). `cycle` reaches 16384 when the queue's position counter reaches
`16384 * 131072 == 2^31`, i.e. after **2 147 483 648 enqueues** — one per
request (`nxt_router_app_prepare_request()` → `nxt_app_queue_send()`,
`src/nxt_router.c:8325`). At 10 000 req/s that is ~6 hours; at 100 000 req/s,
~6 hours * 10×* faster — i.e. **hours**, not months, on a busy server.

With two's-complement arithmetic the low bits stay correct, so the practical
symptom is deferred to the next event — the 32-bit wrap of the position
counter:

* `q->tail` and `q->head` are `uint32_t` and are incremented once per
  operation (`nxt_app_nncq_tail_cmp_inc`, `src/nxt_app_nncq.h:42-45`). At
  `t == 2^32` they wrap to 0 while `entries[]` still holds values from cycle
  32767 (`0xFFFF0000 + val`).
* The producer then computes `e_cycle == 65535` for the stale entry and
  `next_cycle(65535) == 0` (`nxt_app_nncq_next_cycle()` returns `i + 1` in a
  `uint16_t` → wraps to 0), so it concludes the slot is **free** and overwrites
  a live item's index (`src/nxt_app_nncq.h:117-131`).
* The consumer at the old head computes `e_cycle != h_cycle` and
  `next_cycle(e_cycle) != h_cycle` → it spins the retry budget and returns
  `nxt_app_nncq_empty()` (`src/nxt_app_nncq.h:153-166`) → the queue reports
  **empty while holding items**.

Once that happens the shared queue is unusable: `nxt_app_queue_send()` returns
`NXT_ERROR` ("shared queue is broken") or the workers never see the messages,
and the application must be restarted to recover. The same 32-bit aliasing
exists in the port queue (`src/nxt_nncq.h:22-29`, `NXT_NNCQ_SIZE = 16384`).

### Fix

Widen the position counters to 64 bits (`uint64_t` head/tail) and compute
`cycle * SIZE` in 64-bit; or use a per-cell sequence number (Vyukov), which
removes the cycle arithmetic entirely.

---

## M-5 — `setgroups()` is skipped on the credential-namespace path

**Component:** worker / privilege drop
**Files:** `src/nxt_process.c:1265-1293`, `src/nxt_credential.c:308-353`

```c
/* src/nxt_process.c:1265 */
    cap_setid = rt->capabilities.setid;

#if (NXT_HAVE_LINUX_NS && NXT_HAVE_CLONE_NEWUSER)
    if (!cap_setid
        && nxt_is_clone_flag_set(process->isolation.clone.flags, NEWUSER))
    {
        cap_setid = 1;                  /* forced on for NEWUSER          */
    }
#endif

    if (cap_setid) {
        ret = nxt_credential_setgids(task, process->user_cred);
        ...
        ret = nxt_credential_setuid(task, process->user_cred);
```

but the inner guard re-tests the *unmodified* `rt->capabilities.setid`:

```c
/* src/nxt_credential.c:308 */
nxt_int_t
nxt_credential_setgids(nxt_task_t *task, nxt_credential_t *uc)
{
    ...
    if (setgid(uc->base_gid) != 0) { ... }

    if (!rt->capabilities.setid) {
        return NXT_OK;                  /* <-- setgroups() never called    */
    }

    if (nxt_slow_path(uc->ngroups > 0
                      && setgroups(uc->ngroups, uc->gids) != 0)) { ... }
```

When unitd runs unprivileged (`rt->capabilities.setid == 0`) and the app
requests `"isolation": {"namespaces": {"credential": true}}`, `cap_setid` is
forced to 1 and `setgid()`/`setuid()` are performed with the app's configured
uid/gid — but `setgroups()` is **not**, so the worker keeps unitd's inherited
supplementary group list.

### Impact

The app process runs with the configured uid/gid but retains unitd's
supplementary groups. If unitd's user is a member of a privileged group, the
application inherits that group membership. It is a silent privilege leak.

### Fix

Make the decision once. Pass the effective `cap_setid` into
`nxt_credential_setgids()` (or into `nxt_credential_t`), or drop the
`rt->capabilities.setid` re-test inside `nxt_credential_setgids()` and rely on
the caller's decision.

---

## M-6 — `PR_SET_NO_NEW_PRIVS` is off by default

**Component:** worker / privilege drop
**Files:** `src/nxt_isolation.c:83-85`, `src/nxt_process.c:1295-1302`,
`src/nxt_external.c:201`

```c
/* src/nxt_isolation.c:83 */
#if (NXT_HAVE_PR_SET_NO_NEW_PRIVS)
    process->isolation.new_privs = 1; /* default:1 == "not requested" */
#endif
```

```c
/* src/nxt_process.c:1295 */
#if (NXT_HAVE_PR_SET_NO_NEW_PRIVS)
    if (nxt_slow_path(process->isolation.new_privs == 0
                      && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0))
```

So `no_new_privs` is only set when the operator explicitly writes
`"new_privs": false`. The source is explicit about the consequence
(`src/nxt_capability.c:576-584`):

> *"The bounding set is deliberately left alone … PR_SET_NO_NEW_PRIVS would
> close even that, but it is off in the default configuration … so it is not
> what makes this safe."*

For an `"type": "external"` application this matters directly, because the
worker `execve()`s a user binary:

```c
/* src/nxt_external.c:201 */
    (void) execve(c->executable, argv, environ);
```

### Impact

The exec'd binary regains full privilege if it is setuid-root or carries file
capabilities, even though Unit deliberately dropped the capability sets before
the exec. The capability-drop machinery (`nxt_capability_drop()`,
`src/nxt_capability.c:601-767`) is otherwise careful and correct —
`no_new_privs` is the missing half.

### Related

`src/nxt_capability.c:609-639` — `nxt_capability_drop()` short-circuits on
`geteuid() == 0`. An application mapped to uid 0 inside its own user namespace
therefore keeps the full namespace capability set (mount, chroot, further user
namespaces). This is documented and intentional, but it means
`"isolation": {"namespaces": {"credential": true}}` with a root-mapped uid is
*not* a privilege reduction.

### Fix

Set `PR_SET_NO_NEW_PRIVS` by default (it costs nothing and closes the
setuid-exec escape), and make the configuration option mean "allow privilege
gain" rather than "request no privilege gain".

---

## M-7 — Persistent `accept()` errors do not disarm the listener

**Component:** listener
**Files:** `src/nxt_conn_accept.c:411-448`, `src/nxt_epoll_engine.c:616-629`

```c
/* src/nxt_conn_accept.c:411 */
void
nxt_conn_accept_error(nxt_task_t *task, nxt_listen_event_t *lev,
    const char *accept_syscall, nxt_err_t err)
{
    ...
    lev->socket.read_ready = 0;

    switch (err) {

    case NXT_EAGAIN:
        nxt_debug(task, "%s(%d) %E", accept_syscall, lev->socket.fd, err);
        return;

    case ECONNABORTED:
        nxt_log_moderate(&nxt_accept_log_moderation, NXT_LOG_WARN, ...);
        return;

    case EMFILE:
    case ENFILE:
    case ENOBUFS:
    case ENOMEM:
        nxt_alert(task, "%s(%d) failed %E", ...);
        nxt_conn_accept_close_idle(task, lev);
        return;

    default:
        nxt_alert(task, "%s(%d) failed %E", ...);
        return;                       /* <-- listener stays armed */
    }
}
```

The `default:` branch only logs. The listener is **not** disarmed, and the
epoll registration is **level-triggered**:

```c
/* src/nxt_epoll_engine.c:616 */
nxt_epoll_enable_accept(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    uint32_t  events;

    ev->read = NXT_EVENT_ACTIVE;

    events = EPOLLIN;

#ifdef EPOLLEXCLUSIVE
    events |= EPOLLEXCLUSIVE;
#endif

    nxt_epoll_change(engine, ev, EPOLL_CTL_ADD, events);
}
```

No `EPOLLONESHOT`. If `accept()` fails with an error that does **not** dequeue
the pending connection, the connection stays in the kernel accept queue, epoll
re-fires immediately, and the router thread spins at 100 % CPU emitting one
`nxt_alert()` per iteration (unmoderated — the `nxt_log_moderation_t` is only
applied to the `ECONNABORTED` branch).

### Concrete trigger

For an `AF_UNIX` listener the accept buffer is only 3 bytes
(`src/nxt_listen_socket.c:284`: `ls->socklen = offsetof(struct sockaddr_un, sun_path) + 1;`),
and `src/nxt_conn_accept.c:189-200` passes exactly that length to `accept()`:

```c
    sa = &c->remote->u.sockaddr;
    socklen = c->remote->socklen;
    ...
    s = accept(lev->socket.fd, sa, &socklen);
```

A client that `bind()`s a *named* Unix path before `connect()` makes the kernel
report a peer address longer than 3 bytes; `accept(2)` then fails with
`EFAULT`/`EINVAL` ("the `len` argument is not large enough to contain the
address"). The comment at `:197-198` acknowledges this ("Only bound
sockaddr_un will be really truncated here") but the code has no handling for
it.

### Impact

A single local client can pin a router thread in a busy loop and flood the log;
with several listeners this is a CPU-exhaustion DoS. The same shape applies to
any other non-transient `accept()` error on TCP.

### Fix

In the `default:` branch, disarm the listener and re-arm it on a timer (the
`nxt_conn_accept_close_idle()` path already does this correctly), and apply the
log moderation to the alert as well.

---

## M-8 — `lev->ready` underflows; the accept batch mechanism is inert

**Component:** listener
**Files:** `src/nxt_conn_accept.c:64`, `:157`, `:186-187`, `:474`;
`src/nxt_router.c:4840`

```c
/* src/nxt_conn_accept.c:64 */
        lev->batch = engine->batch;
...
/* src/nxt_conn_accept.c:151 */
static void
nxt_conn_listen_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_listen_event_t  *lev;

    lev = obj;
    lev->ready = lev->batch;

    lev->accept(task, lev, data);
}
...
/* src/nxt_conn_accept.c:186 */
    lev->ready--;
    lev->socket.read_ready = (lev->ready != 0);
```

`lev->ready` is `uint32_t` and `lev->batch` is **0** for every router worker
engine, because the router creates them with
`nxt_event_engine_create(task, interface, NULL, 0, 0)` (`src/nxt_router.c:4840`)
→ `engine->batch = 0` (`src/nxt_event_engine.c:64`). `lev->ready--` therefore
wraps to `0xFFFFFFFF`, and `lev->socket.read_ready` becomes permanently `1`
(it would take 2³² accepts to reach 0).

### Impact

The batch mechanism is dead code, and `lev->socket.read_ready` is never cleared
except by the error path. The practical effect is at
`src/nxt_conn_accept.c:290-295`:

```c
    next = nxt_conn_accept_next(task, lev);

    if (next != NULL && lev->socket.read_ready) {
        nxt_work_queue_add(lev->socket.read_work_queue,
                           lev->accept, task, lev, next);
    }
```

because `read_ready` is always 1, **one extra `accept()` syscall that always
returns `EAGAIN` is issued after every single accepted connection**. That is a
constant-factor amplification of the accept path under connection floods.

The code is aware of the wrap — `src/nxt_conn_accept.c:469-473`:

```c
    /*
     * Start a new batch, as nxt_conn_listen_handler() does.  A listener
     * that was never armed has ready 0 from nxt_zalloc() here, and the
     * accept would wrap it.
     */
    lev->ready = lev->batch;
```

— but setting it to 0 is exactly what causes the wrap on the following
`lev->ready--`.

### Fix

Either give the router's engines a real `batch` value, or make the counter
saturating (`if (lev->ready > 0) lev->ready--;`) and derive `read_ready` from a
separate flag that the accept path clears explicitly.

---

## M-9 — Router and controller are re-forked in a tight loop with no backoff

**Component:** worker / process lifecycle
**Files:** `src/nxt_main_process.c:1752-1773`, `src/nxt_router.c:575-584`,
`src/nxt_controller.c:196-205`

```c
/* src/nxt_main_process.c:1752 */
                init = *(nxt_process_init_t *) nxt_process_init(process);

                nxt_process_close_ports(task, process);

                if (init.restart) {
                    ...
                    ret = nxt_process_init_start(task, init);
                    if (nxt_slow_path(ret == NXT_ERROR)) {
                        nxt_alert(task, "failed to restart %s", init.name);
                    }
                }
```

`.restart = 1` is set for both long-lived core processes (router at
`src/nxt_router.c:575-584`, controller at `src/nxt_controller.c:196-205`).
`nxt_process_init_start()` → `nxt_process_start()` → `nxt_process_create()` →
`fork()` (`src/nxt_process.c:279`, `:704`). There is **no delay, no attempt
counter and no backoff** between the reap and the re-fork.

### Impact

If the router or controller dies immediately after being forked (a
configuration that crashes it at startup, a transient `ENOMEM`, an `EAGAIN`
storm, a seccomp filter that denies it a syscall it needs at init), main will
re-fork it immediately, at the speed of fork+teardown, indefinitely. This is an
unbounded process-creation loop driven from the daemon's most privileged
process. The capability code accepts the same risk explicitly
(`src/nxt_capability.c:594-599`):

> *"router and controller carry .restart = 1 and are re-forked immediately and
> without backoff, so a filter that denies every attempt turns into an
> unbounded respawn loop."*

### Fix

Add an exponential backoff / minimum inter-restart interval and an attempt
counter with a give-up-and-alert policy, at minimum for the immediately-failing
case (child exits < N ms after fork).

---

## M-10 — No process / FD / memory rlimits for workers

**Component:** worker
**Files:** `src/nxt_cgroup.c:89-176`, `src/nxt_main_process.c:654-655`

There is **no `setrlimit()` anywhere in the tree**, and no `pids.max` /
`memory.max` is written for the cgroup Unit creates.
`nxt_cgroup_proc_add()` (`src/nxt_cgroup.c:89-176`) only *moves* the process
into a directory it creates:

```c
    ret = nxt_fs_mkdir_p((const u_char *) cgprocs, 0777);
    ...
    fp = nxt_file_fopen(task, cgprocs, "we");
    ...
    len = fprintf(fp, "%d\n", pid);
```

No limit files are written. The two limits Unit does implement are:

* `shm` → `app_conf->shm_limit`, default `100 * 1024 * 1024`
  (`src/nxt_main_process.c:654`), enforced inside libunit (`src/nxt_unit.c:648`, `nxt_unit_shm_mmap_limit()`).
* `requests` → `app_conf->request_limit`, default **0 = unlimited**
  (`src/nxt_main_process.c:655`); libunit enforces it only when non-zero
  (`src/nxt_unit.c:8895-8898`).

### Impact

A compromised or misbehaving application worker can:

* fork without bound (no `RLIMIT_NPROC`, no `pids.max` in the cgroup it was
  placed in) → host PID exhaustion;
* open files without bound (no `RLIMIT_NOFILE`) → host FD exhaustion. The code
  is *aware* of the `RLIMIT_NOFILE` interaction: `src/nxt_port.c:851-857`
  documents that at the receiver's `RLIMIT_NOFILE` the kernel silently discards
  `SCM_RIGHTS` and sets `MSG_CTRUNC`, which "nothing here inspects" — Unit
  handles the *consequence* but never sets a limit;
* consume unbounded memory (no `RLIMIT_AS`, no cgroup `memory.max`).

### Fix

Set `RLIMIT_NPROC` / `RLIMIT_NOFILE` / `RLIMIT_AS` in the worker (or write
`pids.max` / `memory.max` into the cgroup Unit creates), and give
`request_limit` a non-zero default.

---

## M-11 — The listener-close drain has no deadline

**Component:** listener
**File:** `src/nxt_router.c:5606-5680`

```c
/* src/nxt_router.c:5646 */
    if (lev->count > 1) {
        nxt_debug(task, "engine %p: listen socket %d drain pending, "
                  "in-flight: %D", engine, lev->socket.fd, lev->count - 1);

        nxt_router_listen_socket_close_ready(task, joint);

        return;
    }
```

`lev->count` is incremented per accepted connection
(`src/nxt_conn_accept.c:271`) and decremented only when the HTTP/1 connection
is finally freed (`src/nxt_h1proto.c:2745-2749`). While `lev->count > 1` the
listener stays in `engine->listen_connections` and:

* the listening descriptor is **not** closed — it is closed only in
  `nxt_router_listen_socket_release()` (`src/nxt_router.c:5791`);
* the socket conf / router conf memory pool is not released
  (`nxt_router_conf_release()` is only reached when `lev->count` hits 0,
  `src/nxt_router.c:5840-5868`).

### Impact

A client that opens a connection to the listener and then sends nothing keeps
`lev->count > 1` for as long as the request/idle timeout allows (default 30 s
per `src/nxt_router.c:3434-3436`, and operator-tunable upward). During that
window:

* the address stays bound, so re-adding the same listener address fails with
  `EADDRINUSE` (acknowledged in the comment at `src/nxt_router.c:5654-5661`);
* the old configuration's memory pool and TLS contexts are pinned;
* the configuration control request is acknowledged *before* the descriptor is
  released (`:5660`), so the caller believes the port is free when it is not.

There is no escalation/deadline on the drain, so the resource-holding time is
entirely under the client's control. The source itself flags the missing
timeout as future work (`src/nxt_router.c:5638-5643`).

### Fix

Add a drain deadline with escalation (e.g. force-close the remaining
connections after N seconds, or after the idle timeout, whichever is shorter),
and have the control request's reply reflect the drain state.

---

## M-12 — A `backlog` change on an existing listener is silently ignored

**Component:** listener / configuration
**Files:** `src/nxt_router.c:4213-4233`, `src/nxt_router.c:5352-5405`,
`src/nxt_listen_socket.c:224-257`

```c
/* src/nxt_router.c:4213 */
    ret = nxt_router_listen_socket_find(tmcf, skcf, sa);

    if (ret != NXT_OK) {

        ls = nxt_zalloc(sizeof(nxt_listen_socket_t) + size);
        ...
        ls->socket = -1;
        ls->backlog = backlog > -1 ? backlog : NXT_LISTEN_BACKLOG;
        ls->flags = NXT_NONBLOCK;
        ls->read_after_accept = 1;
    }
```

When the address is already present (`ret == NXT_OK`),
`nxt_router_listen_socket_find()` (`:4267-4268`) hands back the **old**
`nxt_listen_socket_t`; the freshly parsed `backlog` is dropped, because
`ls->backlog` is only assigned in the `ret != NXT_OK` branch above.

The update job never re-applies it either — `nxt_router_listen_socket_update()`
(`src/nxt_router.c:5352-5405`) only swaps the joint:

```c
    old = lev->socket.data;
    lev->socket.data = joint;
    lev->listen = joint->socket_conf->listen;
```

There is no `listen()` call. The helper that exists for exactly this purpose,
`nxt_listen_socket_update()` (`src/nxt_listen_socket.c:224-257`, which does
`listen(ls->socket, ls->backlog)`), is used **only** by the runtime's
inherited-socket path (`src/nxt_runtime.c:1552`) and never by the router.

### Impact

An operator who raises or lowers `"backlog"` on an existing listener gets a
`200 OK` from the control API and **no change whatsoever** — the kernel
keep-alive queue keeps the old depth. The value is validated
(`src/nxt_conf_validation.c:3774-3797`, `-1 .. INT32_MAX`) and then thrown
away, so there is no way to tune the accept queue of a running listener. This
is a fail-silent configuration defect on a security-relevant knob (queue depth
⇒ SYN/accept-queue pressure).

### Fix

In `nxt_router_listen_socket_update()`, compare the new `backlog` with the
live one and call `nxt_listen_socket_update()` when it differs.

---

## M-13 — Language-module setup runs as root, before the privilege drop

**Component:** worker
**Files:** `src/nxt_application.c:568-645`, `src/nxt_process.c:1102-1173`

Ordering, for the prototype:

| step | where | privilege |
|---|---|---|
| `nxt_app_set_environment()` (putenv) | `nxt_application.c:599` | root |
| `nxt_app->setup()` — language module startup | `nxt_application.c:606-611` | **root** |
| `nxt_isolation_prepare_rootfs()` / `change_root()` | `nxt_application.c:613-627` | root (needs `CAP_SYS_ADMIN`/`CAP_SYS_CHROOT`) |
| `chdir(working_directory)` | `nxt_application.c:629-640` | root |
| `PROCESS_CREATED` → main writes uid_map | `nxt_main_process.c:917-930` | root (main) |
| **`nxt_process_apply_creds()`** — setgid/setuid/capset | `nxt_process.c:1106` | — |

The chroot/mount steps *must* precede the drop, so that part is unavoidable.
The module setup does not. `src/nxt_capability.c:522-531` acknowledges this:

> *"nxt_proto_setup() calls the language module's setup first, and for PHP that
> is php_module_startup() with the php.ini named in the configuration, which
> loads and initialises whatever extensions that file lists. Nothing can be
> dropped before that: the mount, pivot_root and chroot calls later in the
> same function need CAP_SYS_ADMIN and CAP_SYS_CHROOT."*

### Impact

A PHP application whose configuration names a `php.ini` causes that ini to be
parsed and its `extension=` directives to be `dlopen()`ed **as root**, before
any uid change. The path is operator-controlled (via the control API), so this
is not remotely exploitable, but it means a configuration-only input is parsed
by a root-privileged code path (ini parsing + extension load) inside the
daemon, and the resulting module state is inherited by every worker of that
application.

### Fix

Move `nxt_app->setup()` after `nxt_process_apply_creds()`, or split the module
setup into a privileged phase (config load) and an unprivileged phase (runtime
init).

---

## M-14 — The router's retraction of a never-queued request CASes slot 0

**Component:** router ↔ worker IPC
**Files:** `src/nxt_app_queue.h:62-76`, `src/nxt_router.c:1356`,
`src/nxt_router.c:8760-8772`

`nxt_app_queue_send()` sets `*cookie` **only after** it has successfully taken a
slot:

```c
/* src/nxt_app_queue.h:66 */
    i = nxt_app_nncq_dequeue(&q->free_items);
    if (i == nxt_app_nncq_empty(&q->free_items)) {
        return NXT_AGAIN;                 /* <-- *cookie untouched */
    }
    ...
    *cookie = i;
```

When it returns `NXT_AGAIN` the cookie is left untouched. The router stores the
cookie in `req_rpc_data->msg_info.tracking_cookie`
(`src/nxt_router.c:8325-8327`) and later retracts with it
(`src/nxt_router.c:1356`). `req_rpc_data` is zero-initialised
(`nxt_port_rpc_register_handler_ex()` → `nxt_mp_zalloc()`,
`src/nxt_port_rpc.c:240`), so the retraction ends up CASing
**`q->items[0].tracking`** — a slot belonging to some other request.

The value comparison saves it from doing damage today (streams are unique), but
the retraction then records `NXT_MSG_CLAIMED` for a request that was never
queued, which interacts badly with `nxt_router_app_timeout()`'s "claimed,
waiting for the ack" early return (`src/nxt_router.c:8764-8772`) — that path
does not answer the client and does not re-arm the timer.

### Fix

Have `nxt_app_queue_send()` set `*cookie` to a sentinel on every failure path,
and have `nxt_router_msg_retract()` refuse to CAS when the send did not
succeed — e.g. add an `NXT_MSG_NOT_QUEUED` state to `nxt_msg_cancel_t`
(`src/nxt_router_request.h:10-17`).

---

# Low

## L-1 — The listening descriptor never gets `FD_CLOEXEC`

**Component:** listener
**Files:** `src/nxt_router.c:4368-4371`, `src/nxt_main_process.c:1928`

```c
/* src/nxt_router.c:4366 */
    rpc = data;

    s = msg->fd[0];

    /* The listener owns the descriptor now. */
    msg->fd[0] = -1;

    ret = nxt_socket_nonblocking(task, s);
```

`msg->fd[0]` arrived over `SCM_RIGHTS`. The receive path copies the descriptor
out of the control message verbatim and never sets the close-on-exec flag
(`src/nxt_socket_msg.h:298-303`, `nxt_socket_msg_oob_get()`). On Linux,
descriptors received via `SCM_RIGHTS` do **not** inherit `FD_CLOEXEC` unless
`MSG_CMSG_CLOEXEC` is used or the receiver sets the flag itself.

This fork explicitly added `FD_CLOEXEC` to *accepted* sockets for exactly this
reason (`src/nxt_conn_accept.c:207-217`), but the *listening* descriptor was
left without it. The main process also creates it without `SOCK_CLOEXEC`
(`src/nxt_main_process.c:1928`: `s = socket(sa->u.sockaddr.sa_family, sa->type, 0);`).

**Impact:** any `fork()`/`exec()` performed by a process that holds the
listening descriptor inherits it. A leaked listener keeps the TCP port bound
after Unit exits (so a later restart fails with `EADDRINUSE`) and lets the
holder accept connections on Unit's behalf.

## L-2 — `nxt_listen_socket_t` leaks on every failed configuration apply

**Component:** router
**File:** `src/nxt_router.c:2579-2603`

```c
    for (qlk = nxt_queue_first(&creating_sockets);
         qlk != nxt_queue_tail(&creating_sockets);
         qlk = nxt_queue_next(qlk))
    {
        skcf = nxt_queue_link_data(qlk, nxt_socket_conf_t, link);
        s = skcf->listen->socket;

        if (s != -1) {
            nxt_socket_close(task, s);
        }

        nxt_free(skcf->listen);
    }
```

Only `creating_sockets` is walked. The listeners that were parsed but **not
yet** handed to the main process are still in `pending_sockets`
(`src/nxt_router.c:4293`), and their `nxt_listen_socket_t` was heap-allocated
at `src/nxt_router.c:4217` with `nxt_zalloc()` — plain `malloc` storage, **not**
pool memory, so destroying `rtcf->mem_pool` (`:2634`) does not reclaim it.
`pending_sockets` is re-initialised on the next request
(`src/nxt_router.c:2316`), silently dropping the leftovers.

**Impact:** every configuration apply that fails after the first listener (a
second listener whose `bind()` fails with `EADDRINUSE`, a TLS/certificate
failure) leaks one `nxt_listen_socket_t` per not-yet-created listener. A
caller with access to the control API can repeat this indefinitely.

## L-3 — `skcf->listen` is left dangling after `nxt_free(ls)`

**Component:** router
**File:** `src/nxt_router.c:5760-5826`

```c
    ls = skcf->listen;
    ...
    if (--ls->count != 0) {
        ls = NULL;
    }
    ...
    nxt_free(ls);
```

`ls` is `skcf->listen`; after `nxt_free(ls)` the `nxt_socket_conf_t` still
points at the freed block. Any later reader of `skcf->listen` is a
use-after-free. There is such a reader:
`nxt_router_listen_socket_release_stale()` compares and dereferences it
(`src/nxt_router.c:5495-5500`).

Today the stale-joint and close paths are mutually exclusive by construction,
so no reachable double-release could be built; the defect is that the
ownership invariant is not enforced. Clearing `skcf->listen = NULL` after the
free would make the bug impossible.

## L-4 — The accept-retry timer and the listener-close timer are the same `nxt_timer_t`

**Component:** listener
**Files:** `src/nxt_conn_accept.c:78`, `:334`; `src/nxt_router.c:5454-5457`

```c
/* src/nxt_conn_accept.c:77 */
        lev->timer.work_queue = &engine->fast_work_queue;
        lev->timer.handler = nxt_conn_listen_timer_handler;
...
/* src/nxt_conn_accept.c:334 */
    nxt_timer_add(engine, &lev->timer, 100);
```

```c
/* src/nxt_router.c:5454 */
    lev->timer.handler = nxt_router_listen_socket_close;
    lev->timer.work_queue = &engine->fast_work_queue;

    nxt_timer_add(engine, &lev->timer, 0);
```

One `nxt_timer_t` serves two unrelated state transitions, and the handler field
is overwritten **one way only**. `nxt_timer_add()` on a timer already in the
tree replaces the deadline (`src/nxt_timer.c:83-100`); it does not preserve the
previous handler. Consequences:

* If the 100 ms accept-retry timer is pending when the delete job runs, the
  retry is silently dropped.
* If the close timer is pending and the accept path hits `EMFILE`/`ENOMEM`,
  `nxt_conn_accept_close_idle()` re-arms **the same timer** at `:334`; the
  handler is still `nxt_router_listen_socket_close`, so the "retry the spare
  conn" step never happens and `nxt_conn_listen_timer_handler()` is bypassed.
  The listener is left in the `draining` state with `read_ready == 0` and no
  path back to accepting.

A separate timer (or an explicit "timer purpose" discriminator) is required.

## L-5 — The prototype waits forever for a silent worker

**Component:** worker
**Files:** `src/nxt_router.h:144`, `src/nxt_application.c:964-1012`,
`:885-921`, `:1113-1134`

```c
/* src/nxt_router.h:144 */
#define NXT_APP_START_TIMEOUT  0
```

```c
/* src/nxt_application.c:964 */
    if (!silent || nxt_app_conf == NULL || nxt_app_conf->start_timeout == 0) {
        return;                       /* no deadline armed */
    }
```

Both `nxt_proto_quit_handler()` (`:885-921`) and `nxt_proto_sigterm_handler()`
(`:1113-1134`) refuse to exit while `nxt_proto_children` is non-empty.

**Impact:** a worker that never announces itself and ignores the QUIT (an
`"external"` app that `execve()`s a binary which never reads the port, or a
module worker whose `start` never returns) keeps the prototype alive forever.
The source documents the measured consequence at `src/nxt_application.c:936-945`:

> *"Such a worker outlives the request that asked for it and the prototype
> waits on it for good, so the pair survives every drain there is, including
> unitd's own exit. Measured with an external application running /bin/sleep
> and a "limits": {"start_timeout"} that gives up on it: five rejected
> configuration PUTs left five prototypes and five workers alive, and
> replacing the configuration did not collect them either."*

With the default `start_timeout = 0`, `SIGTERM` to `unitd` does not terminate
the tree.

**Fix:** give `start_timeout` a non-zero default, and/or add a bounded
"shutdown grace" kill in the prototype independent of `start_timeout`.

## L-6 — App log-redirection failures are silently ignored; the file is created `0666`

**Component:** worker
**Files:** `src/nxt_process.c:843-845`, `src/nxt_application.c:1585-1635`

```c
/* src/nxt_process.c:843 */
    if (process->parent_port == rt->port_by_type[NXT_PROCESS_PROTOTYPE]) {
        nxt_app_set_logs(); /* return value discarded             */
    }
```

```c
/* src/nxt_application.c:1612 */
    ret = nxt_file_open(task, &file, O_WRONLY | O_APPEND, O_CREAT, 0666);
```

**Impact:** if the configured `"stdout"`/`"stderr"` path cannot be opened by
the app user, the redirection silently fails and the worker keeps writing to
unitd's own log or `/dev/null` — the operator sees no error and the
application's output goes nowhere. The file is created with mode `0666`;
unitd's `umask(0022)` (`src/nxt_process.c:1431`) reduces this to `0644` in the
daemonised case, but with `--no-daemon` the operator's umask applies and the
app log can end up world-writable. `NXT_FILE_OWNER_ACCESS` (0600), which the
rest of the tree uses for state files (`src/nxt_main_process.c:2479-2480`),
would be the consistent choice.

## L-7 — The cgroup path is resolved by string concatenation; symlinks are followed

**Component:** worker
**Files:** `src/nxt_cgroup.c:219-285`, `src/nxt_conf_validation.c:4514-4544`

```c
/* src/nxt_cgroup.c:219 */
    len = snprintf(cgpath, NXT_MAX_PATH_LEN, NXT_CGROUP_ROOT "%s/%s",
                   ptr, dir);
```

`dir` is the app's `"isolation": {"cgroup": {"path": ...}}` value. The only
barrier is the config validator:

```c
/* src/nxt_conf_validation.c:4514 */
    snprintf(path, sizeof(path), "/%.*s/", (int) cgpath.length, cgpath.start);

    if (strstr(path, "/../") != NULL) {
        return nxt_conf_vldt_error(vldt, "The cgroup path \"%V\" is invalid.", &cgpath);
    }
```

The validator rejects a literal `/../` component, but the path is still opened
with `mkdir -p` + `fopen()` by string concatenation, so a **symlink** inside
the cgroup tree is followed. The path is operator-controlled, so this is
defence-in-depth rather than an exploitable path — but `nxt_cgroup_proc_add()`
runs as root and writes to `<path>/cgroup.procs`.

## L-8 — `nxt_router_conf_ready()` tears the conf pool down differently from `nxt_router_conf_release()`

**Component:** router
**Files:** `src/nxt_router.c:2567-2573` vs `:5913-5925`

```c
/* src/nxt_router.c:2567 */
    if (count == 0) {
        nxt_router_apps_hash_use(task, rtcf, -1);

        nxt_router_access_log_release(task, lock, rtcf->access_log);

        nxt_mp_destroy(rtcf->mem_pool);
    }
```

versus:

```c
/* src/nxt_router.c:5927 */
    if (rtcf != NULL) {
        ...
        nxt_router_access_log_release(task, lock, rtcf->access_log);

        nxt_tstr_state_release(rtcf->tstr_state);

        nxt_mp_thread_adopt(rtcf->mem_pool);

        nxt_mp_destroy(rtcf->mem_pool);
    }
```

The `conf_ready` path skips `nxt_tstr_state_release(rtcf->tstr_state)` (a leak
of the template-string state) and `nxt_mp_thread_adopt(rtcf->mem_pool)` (the
pool's memory is released on a thread other than the one that allocated it).
This branch is reached when the applied configuration contains **no** listeners
(`rtcf->count` is incremented once per listener at `src/nxt_router.c:3547`),
which is a realistic configuration (all traffic served by an inherited/external
socket).

## L-9 — `port->messages` is unbounded

**Component:** router ↔ worker
**File:** `src/nxt_port.h:366-387`, `:409`

```c
/*
 * How many queued messages on one port may carry a file descriptor.
 *
 * port->messages itself stays unbounded.  A message with no descriptor costs
 * only memory, which was true before a queued message took ownership of what
 * it names, and bounding it would change behaviour on paths that never hold a
 * descriptor at all -- every ordinary reply and every request body fragment.
 */
```

The only bound is on descriptor-carrying messages (`NXT_PORT_MAX_FD_MSGS = 128`,
enforced at `src/nxt_port_socket.c:563-565` and `:1741-1755`). A peer that
stops reading its socket (a compromised or wedged application worker) makes the
router accumulate request-body fragments and other messages in `port->messages`
without limit, each holding buffers. This is a documented design decision
rather than an oversight, but it is a real memory-exhaustion vector against the
router from a single hostile application.

## L-10 — Dead `cancelled` state on the fragment reassembly path

**Component:** router ↔ worker
**File:** `src/nxt_port_socket.c:2700`, `:2388`, `:2603-2606`, `:2607`,
`:2679`, `:2762`, `:2785`, `:2795`

`msg->cancelled` is set to 0 at `src/nxt_port_socket.c:2700` and is never set
to 1 anywhere in the tree; `fmsg->cancelled` is a copy of it
(`nxt_port_frag_start()`, `:2388`). The branches guarded by it are therefore
always taken. This is not exploitable, but it is misleading: a reader (or a
future auditor) will believe there is a cancellation path in the fragment
reassembler that does not exist. `nxt_port_frag_drop()`'s comment at
`:2603-2606` ("A stream started while cancelled holds copies only") describes
a state that cannot occur.

## L-11 — `nxt_app_queue_cancel()` indexes `items[cookie]` with no bound check

**Component:** router ↔ worker
**File:** `src/nxt_app_queue.h:101-110`

```c
nxt_inline nxt_bool_t
nxt_app_queue_cancel(nxt_app_queue_t volatile *q, uint32_t cookie,
    uint32_t tracking)
{
    nxt_app_queue_item_t  *qi;

    qi = (nxt_app_queue_item_t *) &q->items[cookie];

    return nxt_atomic_cmp_set(&qi->tracking, tracking, 0);
}
```

The cookie is always `< NXT_APP_NNCQ_SIZE` today (it comes from
`nxt_app_nncq_dequeue()` or from `*cookie = i` in `nxt_app_queue_send()`), but
the function is a public inline and performs an unchecked array index into
peer-writable shared memory. See also M-14, where the cookie can be 0 for a
request that was never queued.

---

# Areas reviewed with no findings

These were checked specifically and are **sound** — they are listed so the
report is not read as a blanket indictment.

* **Port queue producer/consumer ordering.** `nxt_port_queue_send()` writes the
  payload (`qi->size`, `qi->data`) *before* the publishing CAS
  (`src/nxt_port_queue.h:78-81`), and the consumer reads it only after winning
  the `head` CAS. The `free_items` list guarantees the payload slot cannot be
  reused while a consumer is still copying out of it
  (`src/nxt_port_queue.h:169`). The `nitems` sleep/wake protocol
  (`src/nxt_port_queue.h:88-90` vs `src/nxt_port_socket.c:2010`, `2003-2010`,
  `2054`) is a correct Dekker pattern: the writer increments `nitems` *after*
  publishing and the reader decrements *before* re-checking, and both use
  `nxt_atomic_fetch_add` (a full barrier).
* **NNCQ MPMC safety.** The `entries[]` CAS + `tail`/`head` CAS scheme is
  MPMC-safe: two consumers at the same head contend on the `head` CAS, and a
  producer that loses the `entries[]` CAS retries with a fresh `tail`. (The
  *memory ordering* of the consumer's plain read of `entries[j]` is M-3, and
  the counter widths are M-4 — the algorithm itself is sound.)
* **Shared-memory allocator (`free_map`).** `nxt_port_mmap_chk_set_chunk_busy()`
  (`src/nxt_port_memory_int.h:292-306`) claims a chunk with a CAS against a
  freshly-read expected value, so a lost race is a safe spurious failure rather
  than a double-claim. The `free_map_padding` sentinel
  (`src/nxt_port_memory_int.h:101-107`) makes a multi-chunk allocation walking
  off the end of the segment fail to claim its continuation instead of reading
  past the struct.
* **mmap record validation.** `nxt_port_mmap_chunk_range_valid()`
  (`src/nxt_port_memory_int.h:220-243`) does the chunk-count arithmetic in
  `size_t` and rejects `chunk_id >= PORT_MMAP_CHUNK_COUNT`; the
  partial-trailing-record case is refused in `nxt_port_mmap_read()`
  (`src/nxt_port_memory.c:970-981`); segment ids are bounded
  (`NXT_PORT_MMAPS_MAX`, `src/nxt_port_memory_int.h:75`).
* **Descriptor lifecycle.** `nxt_port_msg_alloc()` duplicates borrowed
  descriptors (`src/nxt_port_socket.c:657`, `672-710`) so a deferred `sendmsg()`
  cannot send a recycled fd; `nxt_port_msg_close_fd()` /
  `nxt_port_msg_fd_uncount()` are correctly ordered
  (`src/nxt_port_socket.c:1234-1236` before `msg->fd[]` is cleared at
  `1249-1250`); `nxt_port_recv_msg_close_fds()` at the tail of
  `nxt_port_read_msg_process()` (`:2851`) closes descriptors no handler
  claimed.
* **Port message framing.** `qmsg_size = sizeof(nxt_port_msg_t) + payload ≤
  16 + 15 = 31 = NXT_PORT_QUEUE_MSG_SIZE` (`src/nxt_port_socket.c:13-14`,
  `301-304`, `371-375`); the receive side copies at most `n - 16` bytes into a
  `port->max_size` buffer (`:2083-2089`).
* **Fragment reassembly limits.** `NXT_PORT_FRAG_STREAMS_MAX` /
  `NXT_PORT_FRAG_SIZE_MAX` / `NXT_PORT_FRAG_TOTAL_MAX`
  (`src/nxt_port.h:611-613`) and the eviction/drop paths
  (`src/nxt_port_socket.c:2525-2645`) bound a hostile peer's fragment usage.
* **Shared-queue item size.** `NXT_PORT_QUEUE_MSG_SIZE` (31) is enforced on
  both send (`src/nxt_port_queue.h:65-68`) and receive
  (`src/nxt_port_queue.h:162-165`), and `nxt_app_queue_recv()` additionally
  re-clamps `qi->size` against the slot's data bound before the `memcpy`
  (`src/nxt_app_queue.h:137-142`), so a poisoned item cannot overflow the
  caller's buffer.
* **Privilege-drop ordering.** `nxt_process_apply_creds()` orders the
  operations correctly: `setgid()` **before** `setuid()`
  (`src/nxt_process.c:1284`, `:1280`), then `PR_SET_NO_NEW_PRIVS`, then the
  capability drop (`src/nxt_capability.c:601-767`, which also clears the
  ambient set first). `nxt_credential_setuid()` (`src/nxt_credential.c:286-305`)
  uses plain `setuid()`, not `seteuid()`, so the saved-set-uid is cleared and a
  worker cannot regain root. The prototype drops privileges **before** it is
  announced READY, and the router only starts workers after that announcement.
* **Sandbox application.** `nxt_isolation_main_prefork()`
  (`src/nxt_isolation.c:70-161`) fails closed at every step. `nxt_isolation_set()`
  (`:164-215`) propagates every sub-step's failure. `nxt_process_unshare()`
  (`src/nxt_process.c:540-620`) exits the child on any `unshare()`/`fork()`
  failure rather than continuing unshared. `nxt_cgroup_proc_add()` failure kills
  the child (`src/nxt_process.c:756-773`). The `rootfs` path is validated
  against `/` normalisation and embedded NULs
  (`src/nxt_isolation.c:499-582`), and mount destinations are resolved with
  `openat2(RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS)` with a stricter
  `O_NOFOLLOW` fallback (`:869-1057`).
* **Fork safety.** Only **main** and the **prototype** fork
  (`nxt_process_create()` is reached from `src/nxt_main_process.c:191`/`:2174`
  and `src/nxt_application.c:843`). Both are single-threaded at that point:
  `nxt_runtime_start()` destroys the thread pools before starting worker
  processes precisely because "thread pool semaphores will stick in locked
  state in new processes after fork()" (`src/nxt_runtime.c:379-384`), and
  `nxt_thread_pool_create()` creates its threads lazily on the first post
  (`src/nxt_thread_pool.c:41-111`). The router — the only multi-engine
  process — never forks.
* **Signal handling.** On Linux the engine uses `signalfd` and blocks the
  handled signals process-wide (`src/nxt_signal.c:49-59`,
  `src/nxt_epoll_engine.c:722-756`), so handlers run on the event engine
  thread, never in signal context. `SIGPIPE` and `SIGSYS` are ignored
  (`src/nxt_signal.c:41-47`). The prototype's `SIGCHLD` handler
  (`src/nxt_application.c:1137-1232`) drains with `waitpid(-1, …, WNOHANG)` in
  a loop, handles `EINTR`/`ECHILD`, and never blocks. `nxt_proto_kill_timer` is
  a file-scope static (`src/nxt_application.c:94`) and re-arming it twice is
  safe: `nxt_timer_add()` (`src/nxt_timer.c:69-101`) detects the in-tree timer
  and either no-ops or does a delete+insert.
* **Worker count bounding.** `nxt_router_app_can_start()`
  (`src/nxt_router.h:244-250`) bounds
  `processes + pending_processes + unaccounted_processes < max_processes`, and
  the `unaccounted_processes` counter exists specifically so that a worker
  abandoned by a `start_timeout` still consumes a slot
  (`src/nxt_router.h:183-196`). A worker cannot drive the prototype's process
  budget: `nxt_proto_start_process_sender_ok()`
  (`src/nxt_application.c:718-736`) requires the `SCM_CREDENTIALS` pid to equal
  the router's pid.
* **Zombie processes / pid reuse.** `SIGCHLD` is handled in main
  (`src/nxt_main_process.c:1625-1795`), the prototype
  (`src/nxt_application.c:1137-1232`) and, for the store child, explicitly.
  The pid-namespace double fork (`src/nxt_process.c:582-608`) does not leave a
  zombie: the intermediate process is a child of **main**, which reaps it
  (`nxt_runtime_process_find()` returns NULL → `continue`,
  `src/nxt_main_process.c:1699-1703`), and `PR_SET_CHILD_SUBREAPER`
  (`src/nxt_process.c:672-678`) re-parents the grandchild to main.
  `nxt_port_process_ready_handler()` latches `process->start_failed` precisely
  to avoid re-signalling a killed pid that may now name an unrelated process
  (`src/nxt_port.c:799-804`, `:906`; comment at `src/nxt_process.h:126-138`).
  The prototype deliberately refuses to broadcast a namespace-local pid as
  `REMOVE_PID` (`src/nxt_application.c:1438-1448`) and instead uses
  `REMOVE_CHILD_PID`, resolved by main against the sender's own children only
  (`src/nxt_main_process.c:1342-1418`).
  *Residual:* in the non-isolated case a `REMOVE_PID` still carries a global
  pid that the kernel may have recycled between the reap and the message being
  processed; the receiver then closes the ports of whatever now holds that pid
  (`src/nxt_port.c:1381-1387`). The window is small, but the consequence is
  the same as H-1.
* **Environment injection.** `nxt_app_set_environment()`
  (`src/nxt_application.c:1546-1582`) is applied in the prototype, so it is
  inherited by every worker of that application only — it does not leak across
  applications. `nxt_malloc()` is a thin wrapper over libc `malloc()`
  (`src/nxt_malloc.c:30-46`), so `putenv()`'s ownership contract is satisfied.
  The state-file temporary is created `O_EXCL` specifically to defeat a
  symlink planted in `--statedir` (`src/nxt_main_process.c:3157-3183`).
* **Application lifetime bookkeeping.** The `nxt_app_t` lifetime is
  reference-counted with a "joint" and a `use_count` CAS loop;
  `nxt_router_detached_apply()` (`src/nxt_router.c:8855-9060`) explicitly
  takes a reference before touching `app` and returns early if the count has
  already reached zero. `nxt_process_use()` latches `process->released` so
  that a second drop to zero cannot run a second teardown
  (`src/nxt_process.c:139-207`), and `nxt_runtime_process_ref()` takes the
  reference under the same mutex that the unlink uses
  (`src/nxt_runtime.c:1879-1902`), so `{find, ref}` and `{unref to zero,
  unlink}` are mutually exclusive.
* **Accept-path error handling fail-open.** `nxt_conn_accept_error()` never
  treats an error as success; every branch either returns (leaving the
  connection unaccepted) or arms the idle-close recovery. The *loudness*
  problem is M-7, not a fail-open.
* **Double close / use-after-close of the listening descriptor.** The reference
  counting on `ls->count` (`src/nxt_router.c:5291-5293`, `:5762-5771`) and on
  `lev->count` (`:5826`) is symmetric on every path that could be traced
  (create / update / delete / release_stale / close / close_finish), and
  `nxt_conn_free()` asserts `c->socket.fd == -1` (`src/nxt_conn.c:164`). The
  one residual hazard is the dangling `skcf->listen` (L-3).
* **fd 0/1/2 confusion.** The accept path never allocates descriptor numbers
  below 3; `nxt_socket_close()` is used consistently, and `nxt_conn_create()`
  initialises `c->socket.fd = -1` (`src/nxt_conn.c:88`).
* **Privilege escalation in the `SCM_RIGHTS` handoff.** The main process
  authenticates the sender of the socket-creation request via
  `SCM_CREDENTIALS` and requires the router's port
  (`src/nxt_main_process.c:1831-1851`), and the unlink request is likewise
  sender-checked (`:1905-1919`).
* **Integer overflow in the listen-path size computations.**
  `nxt_sockaddr_size()` (`src/nxt_sockaddr.h:99-100`),
  `nxt_sockaddr_alloc()` (`src/nxt_sockaddr.c:63-87`),
  `nxt_zalloc(sizeof(nxt_listen_socket_t) + size)`
  (`src/nxt_router.c:4217`), `nxt_sockaddr_cache_alloc()`
  (`src/nxt_sockaddr.c:19-49`) and `nxt_sockaddr_unix_parse()`
  (`src/nxt_sockaddr.c:571-653`) all derive from the sockaddr `uint8_t` fields
  and the 105-byte cap on Unix paths; no wraparound is reachable from the
  controller. The only underflow in this area is `lev->ready` (M-8).

---

# Recommended remediation order

1. **H-1** — the only finding where an ordinary (unprivileged) application
   worker crosses a boundary it is not supposed to cross. Stop trusting the
   wire pid in `nxt_proto_process_created_handler()`.
2. **H-2 / M-1 / M-2 / M-3 / M-4** — the shared application queue's
   claim-and-wakeup protocol. These five are one subsystem; fix them together:
   move the claim into `nxt_app_queue_recv()` (or out of the recycled slot),
   make the `notified` clear an atomic RMW, write the token with an atomic
   store, load `entries[j]` with acquire, and widen the counters to 64 bits.
3. **H-3 / H-4** — the listener's two most exposed surfaces: a world-writable
   Unix socket and an unbounded connection count. Both are one-line-ish fixes
   with large impact.
4. **M-6 / M-5 / M-10** — the worker's privilege and resource envelope. Set
   `PR_SET_NO_NEW_PRIVS` by default, fix the `setgroups()` decision, and add
   `RLIMIT_*` / cgroup limits.
5. **M-7 / M-8 / M-11 / M-12** — the accept path's error handling, counter
   arithmetic, drain deadline and backlog plumbing.
6. **M-9 / M-5 / M-13** — respawn backoff, the prototype's shutdown path, and
   the privileged module setup.
7. **L-1 … L-11** — hygiene, to be batched into a single maintenance pass.
