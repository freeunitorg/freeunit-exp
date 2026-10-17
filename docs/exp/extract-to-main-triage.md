# Triage: what in freeunit-exp can be extracted to freeunitorg/freeunit

Reviewed 2026-10-16 against the open issues and pull requests of
freeunitorg/freeunit-exp. "Extract" means the change lands in the main
repository (upstream source), not that it moves between exp branches.

Verdict key: YES = product change that belongs upstream; DOC = documentation or
CI for upstream only if upstream wants it; NO = exp-only, keep in the fork.

| # | Title | Verdict | Why |
|---|---|---|---|
| 33 | h1p: do not read a h1proto's connection through a foreign object | **YES, top priority** | A real 1.37.0 field crash (32 faults in one week). src/nxt_h1proto.c/h + a C test; the fix is a null/type check on a shared `socket.data` slot. Bug fix with a reproducer and a regression test is exactly what upstream takes. Already carries CHANGES and changes.xml entries. |
| 63 | router: atomic accounting counters, drop the empty unlink lock | **YES, split it** | Two separable changes. (a) Seven accounting counters become atomics: a correctness/robustness fix for the config-apply prefork path, no behaviour change, 92/92 C tests pass. (b) Skipping the fourth `app->mutex` acquisition is a measured optimisation (3.77 -> 3.03 acquisitions/request on a 2 vCPU box, rps within noise) and belongs in its own PR with the perf note attached. Also note this PR carries many CI/workflow edits; upstream wants only the src commits. |
| 39 | tls: send static files through SSL_sendfile when kTLS is active | **YES, after 31** | Real product change (SSL_sendfile path) with measured evidence: 4 MiB transfer 8.8 -> 7.4 ms CPU on aarch64, kTLS regression removed. Depends on the kTLS option PR (31), so upstream order is 31 then 39. Needs a CHANGES entry (it is API surface: `tls.ktls`). |
| 31 | tls: opt-in kernel TLS (kTLS) for listeners | **YES** | Feature, milestone 1.38. New config surface (`tls.ktls`), so it needs the minor-version path and a CHANGES entry. Prototype quality: verify the SHM/worker questions before offering it as a merge request. |
| 28 | tls: reach the connection entry point through the backend table | **YES, refactor, low priority** | `conn_init` moves onto `nxt_tls_lib_t`; no behaviour change; gates: TLS suite green plus a no-OpenSSL build. Worth doing upstream as the step that makes the no-TLS build honest, but it is architecture work, not a fix. |
| 55 | ci: run the layout check when the push creates the branch | **DOC (fork CI only)** | Fixes a fork workflow (`.github/workflows/layout-check.yml` in freeunit-exp). Upstream's workflow is a different file; only extract if the same all-zero-base bug exists in upstream's copy. |
| 26 | ci: make the upstream sync fail loudly | **NO** | Fork-specific branch-mirror maintenance, plus a GitHub App and rulesets the maintainer must configure. Never upstream. |
| 61 | test: pin the PHP-option string rule | **DOC (test only)** | Adds one test to test/test_config_validation_errors.py pinning existing behaviour. Harmless, but upstream may see it as noise; offer as a drive-by, not a PR of its own. |
| 91 | test: measure the syslog handle a PHP request closes | **NO** | The subagent review VERIFIED that the premise is false on master: src/nxt_app_log.c and src/nxt_log.c syslog calls are inside `#if 0`, and Unit never calls openlog(). Upstream owns neither PHP's bug nor any live Unit code here. The finding already lives in freeunitorg/freeunit#688. Also has a confirmed defect (record file 0644 owned by root while workers run as nobody). Keep in the fork until PHP GH-24308 lands. |
| 24 | exp(h3): spike the transport, verdict note | **NO** | Research spike with its own CI. Keep in the fork. |
| 30 | exp(ktls): probe the kernel offload path in CI | **NO** | Experiment; the result justifies 31/39, which are the extractable parts. |
| 23 | exp(tls): TLS backend module prototype | **NO (yet)** | Prototype of the module interface. Upstream value is real (moving OpenSSL out of the core), but it needs 28 first and a stability plan. |
| 60 / 59 | exp(http) socket/IPC contract, exp(musl) allocator plan | **NO** | Plans/notes; they become PRs when the work starts. |
| 21 | docs: stream map | **NO** | Fork process documentation. |
| 5 | reviews: PR 645 review note | **NO** | Review artefact. |

## Suggested upstream order

1. #33 (crash fix) — independent, small, has a regression test.
2. #63a (atomics) then #63b (lock skip) — two PRs.
3. #31 then #39 (kTLS option, then SSL_sendfile) — with CHANGES entries.
4. #28 (TLS table) — architecture, when 1.38 planning allows.
5. Drive-bys: #61 only if the maintainer wants them.

## Notes

- src-only extracts must keep the upstream trailers convention (model +
  `Harness:`) and pass `make lint`, `make check-public`, the ast-grep baseline
  and `tools/check-trailers.py` before each commit.
- Extracts must be rebased on upstream master; the exp branches track the fork,
  not upstream.
- PR 33 already has CHANGES and changes.xml entries; those must be re-checked
  against upstream's changelog format, not copied verbatim.
