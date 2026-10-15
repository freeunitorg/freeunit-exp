# acme.sh for FreeUnit + the НУЦ recipe — note

**Date:** 2026-10-15 · **Status:** prototype (workbench fork) · no core change.

## What this is

An acme.sh deploy hook + a recipe for the Russian National Certification
Authority (НУЦ, `nuc.voskhod.ru`), as a **catalog-style** entry: an external
client plus a hook, not a FreeUnit core feature.  See `exp/acme-sh-nuc/`.

## Why external, not core

- FreeUnit's certificate model is "external ACME client + deploy hook → `PUT
  /certificates/<name>`"; the `PUT` is issuer-agnostic and replaces in place
  (docs `certificates.rst`, and the main tree's `docs/acme.md`).
- The docs already list **lego** and **certbot**.  acme.sh is a third client of
  the same shape and needs no FreeUnit code.
- НУЦ is ACME (RSA **DV**, 90-day, Russian Trusted Root CA).  Its acme.sh
  change list (`acme_client_fix.rar` → `acme.sh_changes.docx`) is **entirely
  client-side**; the two request-significant items, subject `C=RU` and the
  `keyUsage` extension, are CSR properties.  A stock acme.sh meets them with
  `--issue --csr <csr>` — no forked client.

## The choice: A vs B

- **A (taken):** stock acme.sh + an `openssl` CSR (`C=RU` + `keyUsage`) +
  `Le_RenewalDays=85` + the deploy hook.  Upgrade-proof; the НУЦ requirements
  live in the CSR, not in a patch.
- **B (not taken):** vendor НУЦ's own acme.sh build — simpler for one operator
  but forks the client and drifts from upstream.

## Not verified here

- The НУЦ ACME directory URL and whether НУЦ requires EAB — take both from the
  НУЦ portal instructions.  `nuc.voskhod.ru` was unreachable from the build
  host (likely geo); the recipe must be run and confirmed from an RU host.

## Do-not-claim

- No product number, no "FreeUnit supports НУЦ" line in release notes or talks.
- No FreeUnit core change; do not describe this as an in-daemon ACME client.

## Related

- FreeUnit docs `source/certificates.rst` (replacement + "Automatic renewal with
  an ACME client"); main tree `docs/acme.md`.
- KB `engineering/acme-nuc-requirements.md`, `strategy/plugins-freeunit-org.md`.
