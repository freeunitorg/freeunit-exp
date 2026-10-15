# acme.sh + FreeUnit — deploy hook and a НУЦ recipe

FreeUnit has no built-in ACME client.  An external client gets and renews the
certificate, and a deploy hook uploads the bundle with one
`PUT /certificates/<name>`.  This directory adds **acme.sh** as a third client
next to the documented certbot and lego, and a recipe for the Russian National
Certification Authority (НУЦ, `nuc.voskhod.ru`).

Nothing here touches the FreeUnit tree: FreeUnit only receives the bundle
through the control API.  The deploy hook is the whole integration.

## Files

- `acme-sh-freeunit-hook.sh` — the deploy hook: `cat fullchain key | curl PUT`.

## Why acme.sh needs no FreeUnit change

- **HTTP-01:** acme.sh `--webroot /var/lib/freeunit-acme` writes the token
  under `.well-known/acme-challenge/`; FreeUnit serves that directory with one
  `share` route (same route the certbot how-to uses).
- **Deploy:** acme.sh `--install-cert ... --reloadcmd <hook>` runs the hook,
  which does the `PUT`.  A `PUT` on an existing name replaces the bundle in
  place — no restart, no rename dance.
- **Any CA / EAB:** acme.sh takes `--server <directory URL>` and, when a CA
  requires it, `--eab-kid/--eab-hmac-key` (RFC 8555 §7.3.4).  НУЦ is just
  another ACME server.

## НУЦ recipe (stock acme.sh, no fork)

НУЦ issues RSA **DV** certificates (valid 90 days, chained to the Russian
Trusted Root CA) and publishes its requirements for the certificate request in
`acme_client_fix`'s `acme.sh_changes.docx`.  The two that change the request
are the subject field `C=RU` and the `keyUsage` extension; both are properties
of the **CSR**, so a stock acme.sh is enough if it is given a ready CSR
(`--csr`).  The other НУЦ changes (`idn2`, log hiding, `dns_regru`) are client
detail and are not needed on the FreeUnit side.

1. **Trust the CA on the server** (so acme.sh's curl reaches the НУЦ ACME
   endpoint): copy `russian_trusted_root_ca_pem.crt` into
   `/usr/local/share/ca-certificates/` and run `update-ca-certificates`.

2. **Install acme.sh** (the stock release).

3. **Build the CSR** the НУЦ request requires — subject `C=RU` and the
   `keyUsage` extension:

   ```
   # csr.conf
   [ req ]
   default_bits       = 2048
   prompt             = no
   distinguished_name = dn
   req_extensions     = req_ext
   [ dn ]
   C  = RU
   CN = example.org
   [ req_ext ]
   subjectAltName = DNS:example.org, DNS:www.example.org
   keyUsage       = digitalSignature, keyEncipherment, keyAgreement

   openssl req -new -sha256 -newkey rsa:2048 -nodes \
       -keyout example.org.key -config csr.conf -out example.org.csr
   ```

4. **Register and issue** against the НУЦ directory URL (from the НУЦ portal
   instructions); add `--eab-kid/--eab-hmac-key` if НУЦ requires external
   account binding:

   ```
   acme.sh --register-account --server "$NUC_DIRECTORY" -m ops@example.org
   acme.sh --issue --server "$NUC_DIRECTORY" --csr example.org.csr \
       --webroot /var/lib/freeunit-acme
   ```

5. **Install the certificate and deploy it.**  НУЦ certificates last 90 days,
   so renew at 85 (`Le_RenewalDays=85`); acme.sh's own cron renews and fires
   the hook:

   ```
   Le_RenewalDays=85 acme.sh --install-cert -d example.org \
       --server "$NUC_DIRECTORY" \
       --fullchain-file /etc/freeunit/certs/example.org.pem \
       --key-file       /etc/freeunit/certs/example.org.key \
       --reloadcmd      "/usr/local/sbin/acme-sh-freeunit-hook.sh \
                          example.org /etc/freeunit/certs/example.org.pem \
                          /etc/freeunit/certs/example.org.key"
   ```

6. **FreeUnit config:** the HTTP-01 challenge route on port 80 and the TLS
   listener that names the bundle:

   ```json
   {
     "listeners": {
       "*:80":  { "pass": "routes/http" },
       "*:443": { "pass": "routes/app", "tls": { "certificate": "example.org" } }
     },
     "routes": {
       "http": [
         { "match": { "uri": "/.well-known/acme-challenge/*" },
           "action": { "share": "/var/lib/freeunit-acme$uri",
                       "fallback": { "return": 404 } } },
         { "action": { "return": 301, "location": "https://$host$request_uri" } }
       ],
       "app": [ { "action": { "pass": "applications/app" } } ]
     }
   }
   ```

## Notes

- The `--csr` path keeps acme.sh upgradeable: the НУЦ request requirements live
  in the CSR, not in a patched client.  The alternative is to vendor НУЦ's own
  acme.sh build; the CSR route avoids that.
- Leave out the `*:443` listener until the first bundle exists; FreeUnit refuses
  a configuration where a listener names a missing bundle.
- This is a candidate entry for the `plugins.freeunit.org` catalog (a hook plus
  a recipe), not a FreeUnit core change.
