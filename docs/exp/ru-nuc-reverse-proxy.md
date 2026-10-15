# RU НУЦ reverse proxy — note

**Date:** 2026-10-15 · **Status:** workbench note · no FreeUnit core change.

## Ask

Run a server as a proxy so LAN browsers reach RU sites signed by the regional
НУЦ. The origin sees the proxy's IP; the proxy terminates client TLS; LAN users
do not install the НУЦ root on each machine.

## Findings

- FreeUnit is a **server-side reverse proxy**: it has no forward/MITM mode, and
  its `proxy` action is **plain-HTTP to the upstream** (no upstream TLS). So
  FreeUnit cannot fetch an HTTPS origin today. (KB:
  `engineering/freeunit-upstream-tls-proxy-analysis.md`.)
- **nginx / Angie** do upstream TLS: `proxy_ssl_verify` +
  `proxy_ssl_trusted_certificate`. Recipe: `exp/ru-nuc-reverse-proxy/`.
- **GOST** origins (Минцифры / ЦБ): **cpnginx** (nginx built with CryptoPro).
- **ACME issuance** for НУЦ: acme.sh and wrappers.
- **"No root per machine"** is only solved client-side (a browser with the root
  embedded: «Белый лис», Yandex Browser) or by the operator's own root via
  GPO/MDM.

## Caveat

For arbitrary third-party sites, a client-side root is still required. A reverse
proxy cannot avoid it.

## Catalog angle

This is a candidate `plugins.freeunit.org` recipe: category `reverse-proxy`,
`scope: worldwide`, `trust: in-browser-store` (when the front cert is a public
CA). It complements the `acme-sh-nuc` entry.
