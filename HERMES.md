# This fork is the Hermes bot's workbench

A fork of [freeunitorg/freeunit](https://github.com/freeunitorg/freeunit), default branch
`master`, kept in sync with upstream. It exists so an unattended bot can open branches,
run CI and file pull requests **without write access to the release repository**.

## The rules

1. The bot never pushes to `freeunitorg/freeunit`. All of its commits land on branches in
   this fork; anything meant for upstream goes out as a pull request from this fork.
2. `master` is protected: changes arrive through a pull request from a branch, not by a
   direct push. Fork `master` only ever tracks upstream.
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

Upstream always moves first. To fast-forward the fork's `master` to upstream:

```sh
gh api -X POST repos/freeunitorg/freeunit-exp/merge-upstream -f branch=master
```

or, from a clone, `git fetch upstream && git merge --ff-only upstream/master`.

## GitHub App checklist (done once, by the maintainer)

- Install the bot's GitHub App on the `freeunitorg` organisation.
- Repository access: this fork (`freeunitorg/freeunit-exp`) and the research repo. Not the
  upstream `freeunitorg/freeunit` — the bot works through pull requests.
- Permissions: `contents: write` (push branches here), `pull_requests: write` (open and
  update PRs), `issues: write`, `checks: read`, `actions: read`. No `administration`, no
  `members`, no `secrets`.
- The bot's own clone should set `origin` to this fork and `upstream` to
  `freeunitorg/freeunit`.
