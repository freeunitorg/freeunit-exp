---
name: snunit
description: Scala Native HTTP server on FreeUnit (community project by Lorenzo Gabriele)
type: project
---

# snunit — Scala Native HTTP server on FreeUnit

> **Community project.** snunit is maintained independently of FreeUnit by
> Lorenzo Gabriele ([@lolgab](https://github.com/lolgab),
> [@lorenzogabriele](https://t.me/lorenzogabriele)). It is not officially
> supported by the FreeUnit team.

## Overview

[snunit](https://lolgab.github.io/snunit) runs HTTP servers written in
**Scala Native** on FreeUnit. It moved from the archived NGINX Unit to FreeUnit.
The current line **embeds the `unitd` binary inside the application**, so users
get a plain embedded-HTTP-server experience, and it can embed an
**observability stack** (OpenTelemetry) on unitd as well.

| | |
|---|---|
| Repository | `github.com/lolgab/snunit` |
| Site | https://lolgab.github.io/snunit |
| Language | Scala (Scala Native) |
| Base | FreeUnit (previously NGINX Unit) |
| Model | embeds `unitd` in the app; optional otel stack on unitd |
| Author | Lorenzo Gabriele (lolgab) |

## Migration: NGINX Unit -> FreeUnit

snunit is a **converted straggler**: it was built on the archived NGINX Unit and
now targets FreeUnit — exactly the audience the straggler outreach is for.

## Request to FreeUnit

Lorenzo asks FreeUnit to cover **more of the HTTP stack** so an application can
run **without a reverse proxy**:

> Having to run behind a reverse proxy makes it much less sexy.

The structural reason deployments still front Unit with nginx is the HTTP layer:
the static-file path, TLS offload and protocol coverage. FreeUnit work that
answers this:

- the static handler and `sendfile()`,
- the TLS module (kTLS, `SSL_sendfile()`),
- the HTTP module / protocol contract.

Status: tracked. No timeline.

## Links

- Site: https://lolgab.github.io/snunit
- Repository: https://github.com/lolgab/snunit
- Telegram: https://t.me/lorenzogabriele
