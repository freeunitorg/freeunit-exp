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

## Current order

1. Release train: the 1.37.1 tag, then the artifact check.
2. PHP worker mode: wave 1 (branch target 2026-10-26), wave 2 in parallel.
3. TLS: held until the 1.37.1 tag. Then the interface note, the module prototype
   and the HTTP/3 research, in parallel.
4. Performance and IPC: after worker mode has a measured number.
5. CI, security, docs and community: continuous.

---

Reviewed-by: FreeUnitOPS (DeepSeek V4.1 Flash, Hermes Agent)
