# T1 — Unit rejects a configuration that looks valid: verified in the source

Pinned: `freeunitorg/freeunit` @ `8ffb0036fd119767cc05b770b7c08eefe61a9b6b` (master, 2026-10-10).
This fork's `main` (`e6f31847`) carries the same bytes for every path quoted here; its two extra
commits touch `HERMES.md` and `.github/`.

Both claims hold, and both observed messages are the verbatim source strings. Every anchor below
was re-extracted from the pinned revision rather than copied from notes.

## Claim A — a JSON integer option value is refused: CONFIRMED, and it is documented

`src/nxt_conf_validation.c:4872-4887`:

```c
static nxt_int_t
nxt_conf_vldt_php_option(nxt_conf_validation_t *vldt, nxt_str_t *name,
    nxt_conf_value_t *value)
{
    if (name->length == 0) {
        return nxt_conf_vldt_error(vldt,
                                   "The PHP option name must not be empty.");
    }

    if (nxt_conf_type(value) != NXT_CONF_STRING) {
        return nxt_conf_vldt_error(vldt, "The \"%V\" PHP option must be "
                                   "a string.", name);
    }

    return NXT_OK;
}
```

Wired to the option values at `src/nxt_conf_validation.c:1121-1140` — `options.admin` (`:1131`)
and `options.user` (`:1136`), each an object whose members run through
`nxt_conf_vldt_object_iterator` with `nxt_conf_vldt_php_option` (`:1130-1131`, `:1135-1136`).

The check is **`str`-only by design**, and it is documented in the machine-readable contract:
`docs/unit-openapi.yaml:7463-7464` (`admin`) and `:7473-7474` (`user`) both carry
`additionalProperties: type: string`. `"opcache.enable": "1"` passes; `1` does not; the message
names the key, exactly as observed.

**Nesting decides which message you get.** `options` has exactly three members — `file`, `admin`,
`user` (`src/nxt_conf_validation.c:1121-1140`). A flat `"opcache.enable"` directly under
`options` is an *unknown member*, so it produces Claim B's message, not Claim A's. Claim A's
message requires the key under `options.admin` or `options.user`.

## Claim B — an unknown top-level key aborts the configuration: CONFIRMED

- the message text: `src/nxt_conf_validation.c:2250` —
  `nxt_conf_vldt_error(vldt, "Unknown parameter \"%V\".", name)`, with the "did you mean" suggestion
  computed just above at `:2242-2248`;
- the fixed prefix: `src/nxt_controller.c:449` —
  `nxt_alert(task, "the previous configuration is invalid: %V", &vldt.error)`, reached when
  `nxt_conf_validate()` returns `NXT_DECLINED` (`:444-450`). Together they are the whole observed
  string.

Claim B is already guarded in-tree: `test/test_config_validation_errors.py:213` asserts
`r['detail'] == 'Unknown parameter "foo".'` verbatim, beside `location.path == ''` (`:24-28`).

## Where a non-string could be accepted: nowhere, for an option value

The parser is type-agnostic — `nxt_conf_type()` maps `NXT_CONF_VALUE_INTEGER` and the other
scalars to distinct types (`src/nxt_conf.c:448-459`) and stores `1` without complaint. The refusal
is the validator's rule, not a parse error. Outside `admin`/`user`, `options.file` is a string by
schema (`docs/unit-openapi.yaml:7466-7468`), and the remaining `options` members are the two
objects above, so there is no scalar-accepting path for an option value.

## What this means for the benchmark finding

Not a Unit defect: a string-only contract, documented in the OpenAPI schema, whose error names the
offending key. The improvement belongs on the generating side — a config generator should emit
`"1"`, not `1`. Claim A's message is asserted nowhere in the test suite (Claim B's is, at the line
above); that gap is what T3 proposes to close.

## Verification log

- each quote read with `git show 8ffb0036:<path>` and re-checked against the fork's `main`;
- `docs/unit-openapi.yaml` read at the same revision, not from a branch;
- no anchor in this file was taken from a previous summary: all lines were re-extracted before the
  pull request body was written.
