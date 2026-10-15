# job: ocapi — OpenCode HTTP API wrapper

- **Status:** done
- **Created:** 2026-10-15
- **Agent:** DeepSeek V4.1 Flash

## What needs to be done

A small, dependency-free way to talk to the shared OpenCode v2 background
service's HTTP API (sessions and agents) from scripts and other agents, without
the TUI and without pulling in `@opencode/client`.

## Findings

OpenCode v2.0.29 runs one shared background service per user:

- URL and password: `~/.local/state/opencode/service.json`
  (`url`, `pid`, `password`); the password is also in
  `~/.config/opencode/service.json`.
- Auth is HTTP Basic, user `opencode`; every route returns
  `401 UnauthorizedError` without it.
- Discovery fallback: `opencode service status` prints the URL.
- API surface: `GET /openapi.json` (142 operations, 285 schemas) or
  <https://opencode.ai/v2/openapi.json>.

Endpoints used:

| Purpose | Call |
|---|---|
| agents | `GET /api/agent`, `GET /api/agent/{id}` |
| list/create/get/delete session | `GET|POST /api/session`, `GET|PATCH|DELETE /api/session/{id}` |
| send prompt (async) | `POST /api/session/{id}/prompt` `{text, files[], agents[], skills[], delivery}` |
| wait for idle | `POST /api/experimental/session/{id}/wait` (204) |
| read messages | `GET /api/session/{id}/message?limit&order&cursor&type` |
| switch agent / model | `POST /api/session/{id}/agent`, `.../model` |
| events (SSE) | `GET /api/event` |

Notes that affected the implementation:

- `Session.Info` has no `model` key until the first prompt.
- Message lists are returned newest-first by default, so "the last reply" must
  be selected by `time.created`, not by list position.
- Assistant text lives in `content[]` parts (`text` / `reasoning` / `tool`),
  not in a top-level `text` field (that is only on user messages).
- Sessions are location-scoped (`location.directory`, e.g. `$HOME`) and are
  visible to every caller of the shared service.

## Deliverable

- `~/src/freeunit-epx/scripts/ocapi` — stdlib-only Python 3 CLI
  (`info`, `agents`, `models`, `sessions`, `active`, `new`, `send`, `ask`,
  `chat`, `messages`, `reply`, `wait`, `rm`, `export`, `watch`).
- Symlink `~/.local/bin/ocapi` for convenience.
- `chat` is a one-shot (create → ask → delete); `--keep` retains the session.

Verified end-to-end against the live service: multi-turn `ask` returns the
newest reply; `chat` returns `pong` and leaves no session behind; `watch`
streams `server.connected` + heartbeats.

## Next steps

- Optional: fold an "unread since cursor" view over `GET /api/session` into the
  cross-agent bus tooling (`bus-watcher.sh`, `bus-hook-preinvocation.py`).
