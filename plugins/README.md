# FreeUnit plugin catalog

A catalog of recipe-style integrations — out-of-process scripts and hooks, not a
runtime ABI. Each entry is one JSON object in `index.json`, validated against
`schema.json`.

## The fields that matter

- **`scope`** — `worldwide` or `country`. "Worldwide" works for any operator;
  "country" is a jurisdiction-specific integration.
- **`country`** — ISO 3166-1 alpha-2, uppercase (`RU`, `KZ`, `IR`). Required when
  `scope` is `country`.
- **`trust`** — `in-browser-store` or `self-installed`. For certificate entries:
  is the root publicly trusted, or must the operator install it?

**Country is not trust.** A national root for public web TLS is usually
`scope: country` *and* `trust: self-installed` (RU/НУЦ, KZ/Qaznet, IR): browsers
do not carry it. A government e-gov CA is often `scope: country` but
`trust: in-browser-store`. A generic client (acme.sh, a Let's Encrypt recipe) is
`worldwide` + `in-browser-store`.

## Example

```json
{
  "id": "acme-sh-nuc",
  "name": "acme.sh + НУЦ (Russian National CA)",
  "category": "cert-hook",
  "scope": "country",
  "country": "RU",
  "trust": "self-installed",
  "depends_on": ["acme-sh"]
}
```

## Validate

```sh
python3 -c 'import json,sys; [json.load(open(f)) for f in sys.argv[1:]]' schema.json index.json
```
