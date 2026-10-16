# musl allocator gap — the 1.38 plan

Tracks `freeunitorg/freeunit#688` / workbench `freeunitorg/freeunit-exp#40`.
Analysis, measurements and the 7-fix state live in the KB
(`engineering/musl-allocator-cpu-gap.md`); this note is only the **1.38 decision
and the shape of the change**.

## Where we are

- The **1.37.1 slice landed**: fix 1 (per-thread cluster cache, PR #693) and
  fix 2 (PHP opens the script with `access()`, PR #706 + #707).
- The **12–17% Drupal headline still holds** — the churn lives in the PHP
  process (libsqlite3), not the router.
- The **only lever left is fix 5, the allocator.** It must reach the **router
  and the workers**, not only PHP (the worker is a fork of `unitd`).

## Decision

- **Do not ship a FreeUnit-owned malloc.** Not a product feature.
- **Recommend jemalloc** for predictability (faults 17–19/req, anon 65–75 MB).
  mimalloc v3.5.4 release only when the best case matters (faults 2.5–2.7/req,
  but anon 89 MB and a wider spread).
- Give the operator the choice; make the default build unchanged.

## Change (in 1.38)

1. **`./configure --malloc=<default|jemalloc|mimalloc>`** — a build-time
   allocator selector (`auto/options`). It emits the link flags for the chosen
   allocator; the default path is byte-identical to today.
   - Pitfall: a bare `-ljemalloc` is silently dropped under `--as-needed`; the
     option must emit `-Wl,--no-as-needed,-ljemalloc,--as-needed` (same for
     mimalloc).
2. **Buffer reuse** — reuse the static-file and body buffers across requests.
   This is the biggest real-site win: a 200 KiB static file costs 158.6 µs on
   Alpine vs 77.2 µs on Alpine+jemalloc (1.85 `mmap`/response).
3. **Sanitizer hardening** — the remaining items.

## Outside the repo (operator job, documented)

- Alpine: `apk add jemalloc` + `LD_PRELOAD=/usr/lib/libjemalloc.so.2`
  (`/etc/conf.d/freeunit` or a Dockerfile `ENV`); Alpine 3.24 ships
  jemalloc 5.3.0-r6. Add a short note to the installation page.

## Out of scope

- The PHP script-open change is **not** a patch change (it moves `open_basedir`
  and the directory answers) — it ships with the minor.

## Acceptance (commands)

- `./configure --malloc=jemalloc && make` → `ldd unitd | grep jemalloc` is
  non-empty; the default configure's `ldd` is unchanged.
- `c-tests` (and asan/almalinux8) stay green on both configure paths.
- A bench: `hello` and a Drupal anonymous page on Alpine, `cpu.stat`, allocator
  off vs on — the delta recorded in the KB note.
