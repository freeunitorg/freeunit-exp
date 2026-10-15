# RU НУЦ reverse proxy — trust the НУЦ upstream once

**Scenario.** LAN clients (browsers that do not carry the НУЦ root) reach RU
sites signed by the Russian Trusted Root CA. The proxy terminates client TLS with
a certificate the clients already trust, and re-originates to the origin over
HTTPS, verifying the origin against the НУЦ root — held once, on the proxy.

## Files

- `nginx-nuc-proxy.conf` — an nginx / Angie server block (upstream TLS + НУЦ trust).

## How it works

- **Downstream:** the proxy presents a certificate the clients trust — a
  public-CA certificate (if you own the domain) or **your own** internal CA
  (deployed to the fleet once).
- **Upstream:** `proxy_pass https://` + `proxy_ssl_verify on` +
  `proxy_ssl_trusted_certificate <russian_trusted_root_ca.pem>`. The proxy holds
  the НУЦ root; clients never do.

## Caveat (fundamental)

This works for domains you control, or a fixed set of origins. For **arbitrary
third-party** RU sites the proxy would have to intercept (MITM), and the browser
would then need **your own** root — the same per-machine install, just with a
different root. There is no tool that avoids a client-side root for arbitrary
sites.

## GOST

If the origin is signed with GOST (Минцифры / ЦБ), use **cpnginx** (nginx built
with CryptoPro). Stock nginx/Angie does not do GOST TLS.

## Notes

- nginx does upstream TLS natively (`proxy_ssl_*`); **Angie** (the RU nginx fork)
  is a drop-in with the same directives.
- **FreeUnit** does not do upstream TLS (its `proxy` action is plain-HTTP to the
  upstream), so it cannot fetch an HTTPS origin today.
- ACME issuance for НУЦ: acme.sh (native + wrappers). See `exp/acme-sh-nuc/`.
