# Streams

One discussion per work stream. A stream owns a queue of work, its order, and the
gates a change must pass. Discuss in the stream; record decisions in the tracker or
in the knowledge base.

## Stream map

| Stream | Discussion |
|---|---|
| Release train: 1.37.1 and the following releases | https://github.com/freeunitorg/freeunit-exp/discussions/12 |
| PHP worker mode | https://github.com/freeunitorg/freeunit-exp/discussions/13 |
| Performance and IPC | https://github.com/freeunitorg/freeunit-exp/discussions/14 |
| TLS: module, HTTP/2, HTTP/3 | https://github.com/freeunitorg/freeunit-exp/discussions/15 |
| CI shape and cost | https://github.com/freeunitorg/freeunit-exp/discussions/16 |
| Security and hardening | https://github.com/freeunitorg/freeunit-exp/discussions/17 |
| Docs, knowledge base and adapters | https://github.com/freeunitorg/freeunit-exp/discussions/18 |
| Community and communication | https://github.com/freeunitorg/freeunit-exp/discussions/19 |
| Index: how the work is organised | https://github.com/freeunitorg/freeunit-exp/discussions/20 |

Stream discussions live in the `Roadmap` category. Experiment write-ups go to
`Experiments`. The index discussion stays in `General`.

## Rules that hold in every stream

1. One pull request, one task, one writer. Two pull requests never edit the same
   file in the same wave. A hot file has one owner per wave.
2. A branch is named `hermes/<topic>`. Work leaves as a pull request into `main`.
3. A brief is grounded: the exact files, a do-not-touch list, the definition of
   done, and the command that proves it.
4. A change needs a test that fails on the pre-change code with the failing value
   quoted, a warning-free `./configure --hardening=strict --tests` build, and a
   measured number for any performance claim.
5. Review is cross-vendor: the reviewer's lab differs from the implementer's, and
   every finding is fixed or answered in the pull request body.
6. Cheap models do not commit, push or merge. The maintainer merges and tags.
7. Every commit message, pull request body and comment carries the trailer
   `Reviewed-by: FreeUnitOPS (<model>, <harness>)`. The model and the harness are
   both named: they feed the project's statistics and its evolution record.
8. This repository is public. No advisories, no host names, no private notes.
9. The stream is a channel, not a record. A decision goes to the tracker, to the
   knowledge base, or into a commit.

## Where the streams stand (checked 2026-10-11)

| Stream | State |
|---|---|
| Release train | 1.37.1 is in flight: no tag, the CHANGES block is open. The shortlist below is the only work that belongs in this line. |
| PHP worker mode | Wave 1, target 2026-10-26. |
| TLS: module, HTTP/2, HTTP/3 | Hold lifted. The module prototype is green (pull request 23), the HTTP/3 research and its spike are green (pull request 24), the TLS 1.3 read is done and recorded in the stream discussion. The HTTP/2 stack is still in draft pull requests. |
| Performance and IPC | After worker mode has a measured number. |
| CI shape and cost | Two trackers open; continuous. |
| Security and hardening | Three issues open; see the shortlist below. |
| Docs, knowledge base and adapters | Continuous. |
| Community and communication | Continuous. |

## The 1.37.x shortlist

A patch release carries security and severe-regression fixes. Features, new
configuration members and protocol work wait for the next minor. Inside that rule
three items fit the 1.37 line, each small enough for one review wave:

1. **#537** — http: the body-read deadline restarts on every read, so a slow client
   keeps a request alive indefinitely. Fix: one absolute deadline per request body.
2. **#538** — http: route regexes are matched without PCRE2 match, depth or
   JIT-stack limits. Fix: set the limits at match time; a configuration member is
   optional and not required for the fix.
3. **#539** — http: the concurrent-connection ceiling is a hardcoded 256. Fix: make
   the limit a known, documented value, configurable if the surface allows it.

Each needs the evidence of any change: a test that fails before and passes after,
the failing value quoted, a warning-free strict build, and a CHANGES line. They
carry no `security` label today, and the label is what makes the release process see
them, so labelling them comes first.

Do not hold the 1.37.1 tag for these three. Ready inside the window, they ride with
1.37.1; not ready, they take the next patch release on their own.

**#632** — no CI job compiles for a 32-bit target. Infrastructure, not release
content; it guards the class that already produced two 1.37.1 bugfix entries.

Features that stay out of the 1.37 line: the HTTP/2 stack (#463, #467, #470, #471,
#479, #483, #484), router schedules (#452), USDT probes (#451), the read-only status
socket (#460), router match extensions (#461), opt-in PCRE2 JIT (#551).

## 1.38 scope, in order

1. **HTTP/2 stack**: the staged draft pull requests, with h2spec and the trailer
   limits.
2. **TLS 1.3 as first-class configuration**: minimum and maximum protocol version,
   TLS 1.3 cipher suites and pre-1.3 ciphers; a client CA member with an
   off/request/require policy, a configurable depth and a real verification
   callback. Today 1.3 is reachable only through `conf_commands` — a route that
   works, not a feature a policy can read.
3. **Body streaming (D3)**: the prerequisite for multiplexed HTTP/2 and for any
   HTTP/3.
4. **HTTP/3**: not before the first three. Research and the spike live in the TLS
   stream; the note lists in-house, library and edge, and recommends the library
   path last, after the prerequisites.

## Current order

1. Release train: the 1.37.1 tag, then the artifact check. The shortlist above may
   ride along; it does not set the date.
2. TLS: the hold is lifted — the interface note, the module and the HTTP/3 research
   run in parallel, and the HTTP/2 stages continue.
3. PHP worker mode: wave 1 (target 2026-10-26), wave 2 in parallel.
4. Performance and IPC: after worker mode has a measured number.
5. CI, security, docs and community: continuous.

---

Reviewed-by: FreeUnitOPS (DeepSeek V4.1 Flash, Hermes Agent)
