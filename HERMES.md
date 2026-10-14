# This fork is the Hermes bot's workbench

A fork of [freeunitorg/freeunit](https://github.com/freeunitorg/freeunit). It exists so an
unattended bot can open branches, run CI and file pull requests **without write access to
the release repository**.

## Branch model

| Branch | Holds | Written by |
|---|---|---|
| `master` | an exact mirror of upstream `master`, no other commit | the upstream-sync workflow only |
| `main` (default) | the bot's notes (`findings/`, `reviews/`, later `kb/`), this file, `.github/` | pull requests, merged by the maintainer |
| `hermes/<topic>`, `hermes/pr-<n>-<topic>` | code work | the claim holder |

Bot code branches start from `master`. Notes go to `main` by pull request. A code pull
request inside this fork targets `master` only to get the upstream workflows and a review.
It is closed, never merged, once the upstream pull request exists.

## The rules

1. The bot never pushes to `freeunitorg/freeunit`. All of its commits land on branches in
   this fork; anything meant for upstream goes out as a pull request from this fork.
2. `master` is a mirror. It takes no pull requests and no pushes. Only the upstream-sync
   workflow writes it, and only by fast-forward.
3. Branch names carry the task: `hermes/<topic>` for the bot's own work,
   `hermes/pr-<n>-<topic>` when it is revising a specific upstream pull request.
4. Evidence over opinion. A change here needs the same gates as upstream
   (`AGENTS.md`): the test that fails on the pre-change code with the failing value
   quoted, a warning-free `./configure --hardening=strict` build, a measured number when
   one is claimed, and plain English.
5. This is public. No embargoed advisories, no private notes, no host names, no
   credentials, no text from a private session.
6. CI here is the fork's own. A green run in this fork is evidence for a review, never a
   substitute for the upstream CI on the pull request.

## Staying current

The `upstream-sync` workflow runs daily from `main`. It checks that `master` is behind
upstream `master` with no extra commit, asks GitHub to fast-forward it (the merge-upstream
API, called as the sync App), then reads both branches with `git ls-remote` and checks that
the SHAs are equal. It fails on divergence, on a merge result, and on any API error. If it cannot, the run fails and it opens one
issue labelled `sync-broken`. The issue closes itself when a later run passes. A green run
means `master` equals upstream.

Do not fix a failed sync by hand-merging into `master`. Find the cause in the run log. If
`master` has a commit that upstream does not have, tell the maintainer.

## GitHub App checklist (done once, by the maintainer)

- Install the bot's GitHub App on the `freeunitorg` organisation.
- Repository access: this fork (`freeunitorg/freeunit-exp`) and the research repo. Not the
  upstream `freeunitorg/freeunit` — the bot works through pull requests.
- Permissions: `contents: write` (push branches here), `pull_requests: write` (open and
  update PRs), `issues: write`, `checks: read`, `actions: read`. No `administration`, no
  `members`, no `secrets`.
- The bot's own clone should set `origin` to this fork and `upstream` to
  `freeunitorg/freeunit`.

## Sync App checklist (done once, by the maintainer)

The sync job pushes to a ruleset-protected branch, so it needs its own GitHub App. Do not
reuse the bot's App: a bypass for the bot would let the bot write `master`.

- App permissions: `contents: write` and `workflows: write` (upstream changes
  `.github/workflows/` often, and a push that changes those files needs it). Nothing else.
- Install it on `freeunitorg/freeunit-exp` only.
- Repository secrets: `SYNC_APP_CLIENT_ID` and `SYNC_APP_PRIVATE_KEY`.
- Ruleset `protect-master`: add the App as a bypass actor with mode `always`. The ruleset has
  a pull-request rule, so without the bypass the merge-upstream call is refused.
- Recommended: add the rule "Restrict updates" to `protect-master`, so that only the bypass
  actor can write `master`.
