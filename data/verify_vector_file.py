#!/usr/bin/env python3
"""Verify the frozen escaping vectors of data/json-access-log-escape-vectors.json.

The vectors are data, so their values are the test oracle.  This verifier is the
oracle for the data: it mirrors the two functions the record path uses on master
and reports any row whose expected bytes disagree with them.

    python3 data/verify_vector_file.py [path]

Mirrored from master b09815f1 (freeunit-exp):

  nxt_utf8_sanitize()  src/nxt_utf8.c:199   per-byte U+FFFD replacement
  nxt_utf8_decode2()   src/nxt_utf8.c:74    the decoder the sanitizer calls
  nxt_conf_json_escape()          src/nxt_conf.c:2745
  nxt_conf_json_escape_length()   src/nxt_conf.c:2708

Each mirror carries the upstream line range it came from.  The point of the file
is to be an independent second opinion on the JSON in this directory: if the two
disagree, one of them is wrong and the implementation must not be written against
either until it is settled.

Exit: 0 all rows agree, 1 a row disagrees, 2 the file cannot be read or parsed.
"""

import json
import re
import sys

U_FFFD = "\ufffd"

# /^\\xNN/ -- one byte written as \xNN inside a vector string.
BYTE_RE = re.compile(r"\\x([0-9A-Fa-f]{2})")

# Data file strings hold \xNN for bytes and \uXXXX / \UXXXXXXXX for characters.
# Anything else that is a backslash is a literal backslash and stays.


def decode_notation(text):
    """Turn a vector string into bytes: \\xNN is one byte, everything else is already a character.

    JSON has decoded the standard escapes (\\" \\\\ \\n \\uXXXX ...) before this is
    called, so the only notation left to expand is \\xNN, which JSON does not know.
    """
    out = bytearray()
    i = 0

    while i < len(text):
        m = BYTE_RE.match(text, i)

        if m:
            out.append(int(m.group(1), 16))
            i = m.end()
            continue

        out += text[i].encode("utf-8")
        i += 1

    return bytes(out)


# ---- mirrors of the two master functions ----


def utf8_decode2(buf, start, end):
    """src/nxt_utf8.c:74. Return (codepoint, next_index) or (INVALID, start) on an invalid sequence."""
    INVALID = 0xFFFFFFFF

    p = start
    u = buf[p]

    if u >= 0xE0:
        if u >= 0xF0:
            if u > 0xF4:
                return INVALID, start
            u &= 0x07
            overlong = 0x00FFFF
            n = 3
        else:
            u &= 0x0F
            overlong = 0x07FF
            n = 2
    elif u >= 0xC2:
        u &= 0x1F
        overlong = 0x007F
        n = 1
    else:
        return INVALID, start

    p += 1

    if p + n <= end:
        for _ in range(n):
            c = buf[p] - 0x80
            p += 1
            if c > 0x3F:
                return INVALID, start
            u = (u << 6) | c

        if overlong < u < 0x110000 and not (0xD800 <= u <= 0xDFFF):
            return u, p

    return INVALID, start


def utf8_sanitize(buf):
    """src/nxt_utf8.c:199. Per invalid byte, not per maximal subpart, emit U+FFFD."""
    out = bytearray()
    end = len(buf)
    p = 0

    while p < end:
        if buf[p] < 0x80:
            out.append(buf[p])
            p += 1
            continue

        cp, nxt = utf8_decode2(buf, p, end)

        if cp == 0xFFFFFFFF:
            out += U_FFFD.encode("utf-8")
            p += 1
            continue

        out += buf[p:nxt]
        p = nxt

    return bytes(out)


def escape_length(buf):
    """src/nxt_conf.c:2708."""
    length = len(buf)

    for ch in buf:
        if ch in (0x5C, 0x22):
            length += 1
        elif ch <= 0x1F:
            if ch in (0x0A, 0x0D, 0x09, 0x08, 0x0C):
                length += 1
            else:
                length += 5

    return length


# src/nxt_conf.c:2786-2794, including the uppercase hex of the long form.
SHORT = {0x0A: b"n", 0x0D: b"r", 0x09: b"t", 0x08: b"b", 0x0C: b"f"}
HEX = b"0123456789ABCDEF"


def escape(buf):
    """src/nxt_conf.c:2745."""
    out = bytearray()

    for ch in buf:
        if ch > 0x1F:
            if ch in (0x5C, 0x22):
                out.append(0x5C)
            out.append(ch)
        elif ch in SHORT:
            out += b"\\" + SHORT[ch]
        else:
            out += b"\\u00" + bytes([HEX[ch >> 4], HEX[ch & 0xF]])

    return bytes(out)


# ---- checks ----


def check_vector(v, problems):
    vid = v.get("id", "<no id>")
    own_raw = decode_notation(v["own"])
    own = utf8_sanitize(own_raw)
    expect = None if v.get("expect") is None else decode_notation(v["expect"])

    if v.get("assert") == "refused-by-contract":
        # R6: the row must carry bytes the sink would have rewritten. Detect them
        # with the sanitizer itself rather than trusting the note.
        if utf8_sanitize(own_raw) == own_raw:
            problems.append(f"{vid}: assert=refused-by-contract but the bytes are valid UTF-8")
        return

    got = escape(own)
    jlen = escape_length(own)

    if got != expect:
        problems.append(f"{vid}: expected {expect!r} ({expect.hex()}), mirrored code gives {got!r} ({got.hex()})")
        return

    if v.get("jlen") != jlen:
        problems.append(f"{vid}: jlen {v.get('jlen')}, mirrored length pass gives {jlen}")
        return

    # R1: the escaped value must contain no raw byte below 0x20, no raw quote and
    # no raw backslash other than the start of an escape the writer emitted.
    # This is checked on the bytes the record carries, not on the JSON source,
    # where a quote inside a string is itself escaped.  An escape sequence is
    # stepped over whole: its payload is not a raw byte.
    decoded = got.decode("utf-8")
    i = 0

    while i < len(decoded):
        ch = decoded[i]

        if ord(ch) < 0x20:
            problems.append(f"{vid}: escaped value has a raw 0x{ord(ch):02X} at {i}")
            i += 1
            continue

        if ch == '"':
            problems.append(f"{vid}: escaped value has a raw quote at {i}")
            i += 1
            continue

        if ch != "\\":
            i += 1
            continue

        nxt = decoded[i + 1:i + 2]

        if nxt in ('"', "\\", "b", "f", "n", "r", "t"):
            i += 2
        elif nxt == "u":
            i += 6
        else:
            problems.append(f"{vid}: backslash at {i} does not start an escape")
            i += 1

    # R2: the record is JSON text, so the escaped value inside a JSON string must
    # parse back to exactly the sanitized bytes.
    try:
        back = json.loads('"' + decoded + '"')
    except ValueError as exc:
        problems.append(f"{vid}: escaped value is not a JSON string: {exc}")
        return

    if back.encode("utf-8") != own.decode("utf-8").encode("utf-8"):
        problems.append(f"{vid}: round trip gave {back!r}, sanitized value is {own!r}")


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "data/json-access-log-escape-vectors.json"

    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as exc:
        print(f"verify_vector_file: cannot read {path}: {exc}", file=sys.stderr)
        return 2

    vectors = doc.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        print(f"verify_vector_file: {path} has no vectors", file=sys.stderr)
        return 2

    problems = []
    checked = 0

    for v in vectors:
        try:
            check_vector(v, problems)
            checked += 1
        except (KeyError, TypeError) as exc:
            problems.append(f"{v.get('id', '<no id>')}: malformed row: {exc}")

    ids = [v.get("id") for v in vectors]
    if len(set(ids)) != len(ids):
        problems.append("duplicate vector ids")

    for p in problems:
        print(f"FAIL  {p}")

    print(f"\n{checked} vectors checked, {len(problems)} problem(s)")

    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
